"""POST endpoints that bring data in: events, sensor readings, raw log lines.

All of them follow the same rules as the command-line loaders (step 4):
  - checked first, saved after: if anything is wrong, NOTHING is saved and every problem is listed (422)
  - no duplicates: sending the same thing again saves nothing new
  - times must have a time zone; events outside their capture are refused
"""
from __future__ import annotations

import json
from collections import Counter
from datetime import datetime, timezone
from typing import Annotated, Literal

import psycopg
from fastapi import APIRouter, Body, Depends, HTTPException, Query, Request
from fastapi.concurrency import run_in_threadpool

from ingest.event import ContractError, Event, make_dedup_key
from ingest.flows import ZeekConnParser, load_flows
from ingest.loader import LoadError, load_lines, save_events
from ingest.parsers import FileFormatError, build_parser

from .db import get_conn
from .schemas import HONEYPOT_EVENTS, EventIn, EventList, HoneypotIn, IngestResult, LogIngestResult, Problems, SensorIn

router = APIRouter(prefix="/api/v1/ingest", tags=["Ingest"])
MAX_EVENTS = 5000
Conn = Annotated[psycopg.Connection, Depends(get_conn)]
REFUSED = {422: {"model": Problems, "description": "refused by our checks: nothing was saved"}}


def refuse(problems: list[str], message: str = "Nothing was saved.") -> HTTPException:
    return HTTPException(status_code=422, detail={"message": message, "problems": problems[:50]})


class Lookups:
    """Devices and captures, read once per request."""

    def __init__(self, conn: psycopg.Connection) -> None:
        self.devices = {dev: ip for dev, ip in conn.execute("SELECT device_id, host(ip) FROM devices")}
        self.captures = conn.execute("SELECT capture_id, start_ts, end_ts FROM captures ORDER BY start_ts").fetchall()

    def capture_at(self, ts: datetime) -> str | None:
        """The capture recording at `ts` (the most recently started one, if several)."""
        hits = [cid for cid, start, end in self.captures if start <= ts and (end is None or ts <= end)]
        return hits[-1] if hits else None

    def check_capture(self, capture_id: str, ts: datetime) -> str | None:
        for cid, start, end in self.captures:
            if cid == capture_id:
                if ts < start or (end is not None and ts > end):
                    return f"ts {ts:%Y-%m-%d %H:%M:%S} UTC is outside capture {capture_id} (wrong capture or time zone?)"
                return None
        return f"capture {capture_id!r} does not exist (POST /api/v1/captures first)"


def _prepare(items: list[EventIn], lookups: Lookups) -> tuple[list[Event], list[str]]:
    events, problems = [], []
    for i, item in enumerate(items):
        where = f"item {i}"
        ts = item.ts.astimezone(timezone.utc)
        if item.device_id is not None and item.device_id not in lookups.devices:
            problems.append(f"{where}: device {item.device_id!r} does not exist. Known: {', '.join(sorted(lookups.devices))}")
        if item.capture_id is not None:
            if problem := lookups.check_capture(item.capture_id, ts):
                problems.append(f"{where}: {problem}")
            capture_id = item.capture_id
        else:
            capture_id = lookups.capture_at(ts)
        # Without a dedup_key from the sender, the fingerprint is the event's whole content.
        content = json.dumps(item.model_dump(mode="json", exclude={"dedup_key", "capture_id"}), sort_keys=True)
        try:
            events.append(Event(
                ts=ts, source=item.source, event_type=item.event_type, payload=item.payload,
                dedup_key=item.dedup_key or make_dedup_key(f"api:{item.source}", content),
                device_id=item.device_id, capture_id=capture_id,
                src_ip=str(item.src_ip) if item.src_ip else None, src_port=item.src_port,
                dst_ip=str(item.dst_ip) if item.dst_ip else None, dst_port=item.dst_port,
                proto=item.proto, severity=item.severity))
        except ContractError as exc:                      # unknown event_type, wrong source for it, ...
            problems.append(f"{where}: {exc}")
    return events, problems


def _result(events: list[Event], inserted: int) -> IngestResult:
    return IngestResult(received=len(events), inserted=inserted, duplicates=len(events) - inserted,
                        captures=dict(Counter(e.capture_id or "(none)" for e in events)))


@router.post("/events", response_model=IngestResult, responses=REFUSED,
             summary="Send events (one, or a list of up to 5000)")
def ingest_events(conn: Conn, items: Annotated[EventList, Body()]) -> IngestResult:
    """The contract's event format. `layer` is filled in from the contract; don't send it.

    Leave `capture_id` out and the capture recording at that moment is used."""
    if not items:
        raise refuse(["the list is empty"])
    if len(items) > MAX_EVENTS:
        raise refuse([f"{len(items)} events in one request; send at most {MAX_EVENTS} per request"])
    events, problems = _prepare(items, Lookups(conn))
    if problems:
        raise refuse(problems)
    return _result(events, save_events(conn, events))


@router.post("/sensor", response_model=IngestResult, responses=REFUSED, summary="Send one ESP32 reading")
def ingest_sensor(conn: Conn, reading: SensorIn) -> IngestResult:
    """What the ESP32 sends directly (instead of a CSV file). Saved as a `sensor_reading` event, exactly like
    the CSV parser does, so step 8's sensor features see both the same way."""
    lookups = Lookups(conn)
    if reading.device_id not in lookups.devices:
        raise refuse([f"device {reading.device_id!r} does not exist"])
    payload = {k: v for k, v in reading.model_dump(include={"esp_ms", "smoke", "temperature_c", "humidity_pct"}).items()
               if v is not None}
    if reading.ts is None:
        ts, payload["ts_source"] = datetime.now(timezone.utc), "server"
    else:
        ts = reading.ts.astimezone(timezone.utc)
    if reading.capture_id is not None and (problem := lookups.check_capture(reading.capture_id, ts)):
        raise refuse([problem])
    content = json.dumps({"device": reading.device_id, "ts": ts.isoformat(), **payload}, sort_keys=True)
    event = Event(ts=ts, source="esp32", event_type="sensor_reading", severity="info", payload=payload,
                  dedup_key=make_dedup_key("api:esp32", content), device_id=reading.device_id,
                  capture_id=reading.capture_id or lookups.capture_at(ts), src_ip=lookups.devices[reading.device_id])
    return _result([event], save_events(conn, [event]))


HONEYPOT_SEVERITY = {"connect": "low", "login_failed": "medium", "login_success": "high", "command": "high",
                     "http_request": "low", "disconnect": "info"}         # the same levels the Cowrie parser uses


@router.post("/honeypot", response_model=IngestResult, responses=REFUSED,
             summary="Send one ESP32 honeypot event (connection, login, command, HTTP request)")
def ingest_honeypot(conn: Conn, item: HoneypotIn) -> IngestResult:
    """What the ESP32-S3's fake services send when a client touches them. Saved as the contract's session events
    (`session_open`, `login_failed`, `login_success`, `command`, `http_request`, `session_close`) with
    source `esp32`, so step 8 counts them in `n_login_failed`, `n_commands`, ... exactly like Cowrie's.

    The ESP32 needs no clock: leave `ts` out and the server's time is used (`payload.ts_source = "server"`)."""
    lookups = Lookups(conn)
    if item.device_id not in lookups.devices:
        raise refuse([f"device {item.device_id!r} does not exist. Known: {', '.join(sorted(lookups.devices))}"])
    device_ip = lookups.devices[item.device_id]
    if device_ip is not None and str(item.src_ip) == device_ip:
        raise refuse([f"src_ip {item.src_ip} is the honeypot itself: send the CLIENT's address"])
    payload = item.model_dump(include={"service", "session", "username", "password", "input", "method", "path",
                                       "esp_ms"}, exclude_none=True)
    if item.ts is None:
        ts, payload["ts_source"] = datetime.now(timezone.utc), "server"
    else:
        ts = item.ts.astimezone(timezone.utc)
    if item.capture_id is not None and (problem := lookups.check_capture(item.capture_id, ts)):
        raise refuse([problem])
    content = json.dumps({"device": item.device_id, "ts": ts.isoformat(), "event": item.event,
                          "src": f"{item.src_ip}:{item.src_port}", **payload}, sort_keys=True)
    event = Event(ts=ts, source="esp32", event_type=HONEYPOT_EVENTS[item.event], severity=HONEYPOT_SEVERITY[item.event],
                  payload=payload, dedup_key=make_dedup_key("api:esp32-honeypot", content), device_id=item.device_id,
                  capture_id=item.capture_id or lookups.capture_at(ts), src_ip=str(item.src_ip), src_port=item.src_port,
                  dst_ip=device_ip, dst_port=item.dst_port, proto="tcp")
    return _result([event], save_events(conn, [event]))


@router.post("/logs/{source}", response_model=LogIngestResult, responses=REFUSED,
             summary="Send raw log lines (Cowrie, Mosquitto, ESP32 CSV, Zeek conn.log)",
             openapi_extra={"requestBody": {"required": True, "content": {"text/plain": {
                 "schema": {"type": "string"},
                 "example": '{"eventid": "cowrie.session.connect", "timestamp": "2026-11-22T12:00:00.000000Z", '
                            '"session": "api01", "src_ip": "192.168.56.99", "src_port": 40500, "dst_ip": '
                            '"192.168.56.10", "dst_port": 22, "protocol": "ssh", "sensor": "gw-01"}'}}}})
async def ingest_logs(
    request: Request,
    conn: Conn,
    source: Literal["cowrie", "mosquitto", "esp32", "zeek-conn"],
    device_id: Annotated[str | None, Query(description="cowrie, mosquitto, esp32: the device that wrote the log")] = None,
    capture_id: Annotated[str | None, Query(description="the capture these lines belong to")] = None,
    broker_ip: Annotated[str | None, Query(description="mosquitto: the broker's IP")] = None,
    device_ip: Annotated[str | None, Query(description="esp32: the sensor's IP")] = None,
    tz: Annotated[str, Query(description="esp32: time zone of the CSV time column")] = "UTC",
    allow_outside_capture: bool = False,
) -> LogIngestResult:
    """The body is the log file's text, as is (Content-Type: text/plain). The same parsers as the command line
    read it. Send whole files, or batches that start at a line boundary. An ESP32 batch needs its header line,
    and a Cowrie session's lines should travel together (only the first line of a session has its ports)."""
    lines = (await request.body()).decode("utf-8-sig", errors="replace").splitlines()
    # The parsing and saving is ordinary (blocking) code: run it in a worker thread so the server stays responsive.
    return await run_in_threadpool(_load_log_lines, conn, source, lines, device_id, capture_id, broker_ip, device_ip,
                                   tz, allow_outside_capture)


def _load_log_lines(conn: psycopg.Connection, source: str, lines: list[str], device_id: str | None,
                    capture_id: str | None, broker_ip: str | None, device_ip: str | None, tz: str,
                    allow_outside_capture: bool) -> LogIngestResult:
    try:
        if source == "zeek-conn":
            parser = ZeekConnParser()
            inserted = load_flows(conn, parser, lines, capture_id, allow_outside_capture).inserted
        else:
            parser = build_parser(source, device_id, broker_ip=broker_ip, device_ip=device_ip, tz=tz)
            inserted = load_lines(conn, parser, lines, capture_id, allow_outside_capture=allow_outside_capture).inserted
    except LoadError as exc:
        raise refuse([str(exc)]) from None
    except (FileFormatError, ValueError, TypeError, KeyError) as exc:   # e.g. CSV without a time column, bad tz
        raise refuse([f"{source}: {exc}"]) from None
    s = parser.stats
    return LogIngestResult(lines=s.lines, parsed=s.events, ignored=s.ignored, broken=s.skipped,
                           inserted=inserted, duplicates=s.events - inserted)
