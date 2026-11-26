"""GET endpoints that hand the data out (step 11): to the dashboard, C (windows), D (flows and graph edges), E.

Every list works the same way:
  - `from` / `to` pick a time range (UTC, with Z). `from` is included, `to` is not.
  - at most `limit` items per answer. If there are more, the answer has `next_cursor`: send it back as
    `?cursor=...` (with the same filters) to get the next page. When `next_cursor` is null, you have everything.
  - `order=asc` (oldest first, the default: what models replay) or `order=desc` (newest first: the dashboard).

Why a cursor and not `page=2`? New events keep arriving. With page numbers, a new row pushes everything down
by one and you see a row twice or miss one. The cursor says "continue after THIS row", so nothing shifts.
"""
from __future__ import annotations

import base64
import binascii
import json
from dataclasses import dataclass, field
from typing import Annotated, Any, Literal

import psycopg
from fastapi import APIRouter, Depends, Query
from psycopg.rows import dict_row
from pydantic import AwareDatetime

from ingest.attacks import SCENARIOS
from features import flow, window
from ingest.event import CONTRACT, EVENT_TYPES, SEVERITIES

from .db import get_conn
from .ingest import REFUSED
from .ingest import refuse as _refuse
from .schemas import AlertOut, AttackRunOut, CaptureRow, DeviceOut, EdgeOut, EventOut, FlowOut, Page, Severity, WindowOut

router = APIRouter(prefix="/api/v1", responses=REFUSED)
Conn = Annotated[psycopg.Connection, Depends(get_conn)]
VERSION = CONTRACT["feature_version"]
MAX_LIMIT = 5000


# ------------------------------------------------------------------------------------------- shared parts
def refuse(problems: list[str]):
    return _refuse(problems, "The query was refused: check the parameters.")


@dataclass
class TimeRange:
    start: Any = None
    end: Any = None


def time_range(
        start: Annotated[AwareDatetime | None, Query(alias="from", description="from this time (included), e.g. "
                                                     "2026-11-20T14:00:00Z")] = None,
        end: Annotated[AwareDatetime | None, Query(alias="to", description="up to this time (not included)")] = None,
) -> TimeRange:
    if start and end and start >= end:
        raise refuse([f"'from' ({start.isoformat()}) must be before 'to' ({end.isoformat()})"])
    return TimeRange(start, end)


@dataclass
class Paging:
    limit: int
    cursor: str | None
    order: Literal["asc", "desc"]


def paging(limit: Annotated[int, Query(ge=1, le=MAX_LIMIT, description="items per page")] = 100,
           cursor: Annotated[str | None, Query(description="next_cursor from the previous page")] = None,
           order: Literal["asc", "desc"] = "asc") -> Paging:
    return Paging(limit, cursor, order)


Range = Annotated[TimeRange, Depends(time_range)]
Pages = Annotated[Paging, Depends(paging)]
Label = Annotated[int | None, Query(ge=0, le=1, description="1 = attack, 0 = normal")]


@dataclass
class Where:
    """Collects the WHERE conditions; a filter that was not given is simply left out."""
    clauses: list[str] = field(default_factory=list)
    params: list[Any] = field(default_factory=list)

    def add(self, clause: str, *values: Any) -> None:
        if all(v is not None for v in values):
            self.clauses.append(clause)
            self.params.extend(values)

    def time(self, column: str, r: TimeRange) -> None:
        self.add(f"{column} >= %s", r.start)
        self.add(f"{column} < %s", r.end)


def encode_cursor(values: list[str]) -> str:
    return base64.urlsafe_b64encode(json.dumps(values).encode()).decode().rstrip("=")


def decode_cursor(cursor: str, n: int) -> list[str]:
    try:
        values = json.loads(base64.urlsafe_b64decode(cursor + "=" * (-len(cursor) % 4)))
    except (binascii.Error, ValueError):
        values = None
    if not isinstance(values, list) or len(values) != n or not all(isinstance(v, str) for v in values):
        raise refuse(["this cursor is not valid: send back next_cursor exactly as you got it"])
    return values


def fetch_page(conn: psycopg.Connection, select: str, where: Where, keys: list[tuple[str, str, str]],
               p: Paging) -> dict:
    """Run one page of `select`, sorted by `keys`, continuing after the cursor.

    keys: (SQL column, SQL type, name in the row). Together they must be unique, so the order is exact and
    "after this row" means one thing. We fetch limit + 1 rows: if the extra one exists, there is a next page.
    """
    clauses, params = list(where.clauses), list(where.params)
    if p.cursor:
        values = decode_cursor(p.cursor, len(keys))
        columns = ", ".join(col for col, _, _ in keys)
        placeholders = ", ".join(f"%s::{typ}" for _, typ, _ in keys)
        clauses.append(f"({columns}) {'>' if p.order == 'asc' else '<'} ({placeholders})")
        params += values
    order = ", ".join(f"{col} {p.order.upper()}" for col, _, _ in keys)
    sql = f"{select} WHERE {' AND '.join(clauses) or 'TRUE'} ORDER BY {order} LIMIT %s"
    try:
        with conn.cursor(row_factory=dict_row) as cur:
            rows = cur.execute(sql, [*params, p.limit + 1]).fetchall()
    except psycopg.DataError:
        raise refuse(["this cursor is not valid: send back next_cursor exactly as you got it"]) from None
    more = len(rows) > p.limit
    rows = rows[:p.limit]
    last = rows[-1] if rows else None
    return {"items": rows, "count": len(rows),
            "next_cursor": encode_cursor([str(last[name]) for _, _, name in keys]) if more else None}


def in_contract_order(page: dict, column: str, names: list[str]) -> dict:
    """PostgreSQL keeps JSON keys in its own order; hand them out in the contract's order, as the models expect."""
    for row in page["items"]:
        if row[column] is not None:
            row[column] = {name: row[column][name] for name in names}
    return page


# ------------------------------------------------------------------------------------------- lab
@router.get("/devices", response_model=Page[DeviceOut], tags=["Lab: captures and attack log"],
            summary="The honeypot devices")
def list_devices(conn: Conn, p: Pages) -> dict:
    select = """SELECT device_id, device_type, host(ip) AS ip, mac::text AS mac, is_virtual, platform, description,
                       monitored
                FROM devices"""
    return fetch_page(conn, select, Where(), [("device_id", "text", "device_id")], p)


@router.get("/captures", response_model=Page[CaptureRow], tags=["Lab: captures and attack log"],
            summary="Recording sessions (those overlapping from/to)")
def list_captures(conn: Conn, r: Range, p: Pages,
                  kind: Annotated[str | None, Query(description="normal_only, attack, mixed or live")] = None) -> dict:
    w = Where()
    w.add("start_ts < %s", r.end)
    w.add("(end_ts IS NULL OR end_ts >= %s)", r.start)
    w.add("kind = %s", kind)
    return fetch_page(conn, "SELECT capture_id, start_ts, end_ts, kind, pcap_path, notes FROM captures", w,
                      [("start_ts", "timestamptz", "start_ts"), ("capture_id", "text", "capture_id")], p)


@router.get("/attack-runs", response_model=Page[AttackRunOut], tags=["Lab: captures and attack log"],
            summary="Task A's attack log (runs overlapping from/to)")
def list_attack_runs(conn: Conn, r: Range, p: Pages, capture_id: str | None = None,
                     scenario: Annotated[str | None, Query(description=", ".join(SCENARIOS))] = None) -> dict:
    if scenario is not None and scenario not in SCENARIOS:
        raise refuse([f"scenario {scenario!r} is not one of: {', '.join(SCENARIOS)}"])
    w = Where()
    w.add("start_ts < %s", r.end)
    w.add("end_ts >= %s", r.start)
    w.add("capture_id = %s", capture_id)
    w.add("scenario = %s", scenario)
    select = """SELECT run_id, capture_id, scenario, tool, command, host(attacker_ip) AS attacker_ip, target_device,
                       start_ts, end_ts, notes FROM attack_runs"""
    return fetch_page(conn, select, w, [("start_ts", "timestamptz", "start_ts"), ("run_id", "text", "run_id")], p)


# ------------------------------------------------------------------------------------------- data
@router.get("/events", response_model=Page[EventOut], tags=["Data"], summary="Events (dashboard, E)")
def list_events(conn: Conn, r: Range, p: Pages, label: Label = None, device_id: str | None = None,
                source: str | None = None, event_type: str | None = None, capture_id: str | None = None,
                min_severity: Annotated[Severity | None, Query(description="this severity and above")] = None) -> dict:
    if event_type is not None and event_type not in EVENT_TYPES:
        raise refuse([f"event_type {event_type!r} is not in the contract: {', '.join(sorted(EVENT_TYPES))}"])
    w = Where()
    w.time("ts", r)
    if min_severity is not None:
        w.add("severity = ANY(%s)", list(SEVERITIES[SEVERITIES.index(min_severity):]))
    w.add("label = %s", label)
    w.add("device_id = %s", device_id)
    w.add("source = %s", source)
    w.add("event_type = %s", event_type)
    w.add("capture_id = %s", capture_id)
    select = """SELECT event_id::text AS event_id, ts, source, event_type, layer, device_id, capture_id,
                       host(src_ip) AS src_ip, src_port, host(dst_ip) AS dst_ip, dst_port, proto, severity,
                       label, scenario, run_id, payload
                FROM events"""
    return fetch_page(conn, select, w, [("ts", "timestamptz", "ts"), ("event_id", "uuid", "event_id")], p)


@router.get("/flows", response_model=Page[FlowOut], tags=["Data"],
            summary="Network connections (dashboard, D)")
def list_flows(conn: Conn, r: Range, p: Pages, label: Label = None,
               device_id: Annotated[str | None, Query(description="the honeypot device on either end")] = None,
               capture_id: str | None = None, include_features: bool = False) -> dict:
    w = Where()
    w.time("ts_start", r)
    w.add("label = %s", label)
    w.add("device_id = %s", device_id)
    w.add("capture_id = %s", capture_id)
    features = "features" if include_features else "NULL::jsonb AS features"
    select = f"""SELECT flow_id, zeek_uid, ts_start, ts_end, capture_id, device_id, host(src_ip) AS src_ip, src_port,
                        host(dst_ip) AS dst_ip, dst_port, proto, service, conn_state, history, duration_s,
                        orig_bytes, resp_bytes, orig_pkts, resp_pkts, label, scenario, run_id, feature_version,
                        {features}
                 FROM flows"""
    page = fetch_page(conn, select, w, [("ts_start", "timestamptz", "ts_start"), ("flow_id", "text", "flow_id")], p)
    return in_contract_order(page, "features", flow.FEATURE_NAMES)


# ------------------------------------------------------------------------------------------- for the models
@router.get("/features/windows", response_model=Page[WindowOut], tags=["Features (for the models)"],
            summary="Window features, one row per (device, 10 s) (C, live inference)")
def list_windows(conn: Conn, r: Range, p: Pages, label: Label = None,
                 device_id: Annotated[str | None, Query(description="one device only")] = None,
                 capture_id: str | None = None, include_raw: bool = False) -> dict:
    """Only rows of the current feature version. Sorted by time, then device: with `order=asc` you get every
    device's window for 14:00:00, then every device's window for 14:00:10, and so on."""
    w = Where()
    w.add("feature_version = %s", VERSION)
    w.add("entity_type = %s", "device")
    w.time("window_start", r)
    w.add("label = %s", label)
    w.add("entity_id = %s", device_id)
    w.add("capture_id = %s", capture_id)
    raw = "features_raw" if include_raw else "NULL::jsonb AS features_raw"
    select = f"""SELECT entity_type, entity_id, window_start, window_end, capture_id, feature_version, n_events,
                        label, scenario, run_id, features, {raw}
                 FROM feature_windows"""
    page = fetch_page(conn, select, w, [("window_start", "timestamptz", "window_start"),
                                        ("entity_id", "text", "entity_id")], p)
    in_contract_order(page, "features_raw", window.FEATURE_NAMES)
    return in_contract_order(page, "features", window.FEATURE_NAMES)


@router.get("/graph/edges", response_model=Page[EdgeOut], tags=["Features (for the models)"],
            summary="Graph edges: one per flow, with node ids and the 41 features (D)")
def list_edges(conn: Conn, r: Range, p: Pages, label: Label = None, capture_id: str | None = None) -> dict:
    """Same rows and node ids as `edges_{split}.parquet` (step 9). Only flows whose features were built for the
    current version (`python -m features.build flows`); others are not edges yet."""
    w = Where()
    w.add("f.feature_version = %s", VERSION)
    w.time("f.ts_start", r)
    w.add("f.label = %s", label)
    w.add("f.capture_id = %s", capture_id)
    select = """SELECT f.flow_id, f.ts_start AS ts,
                       COALESCE('dev:' || s.device_id, 'ip:' || host(f.src_ip)) AS src_node,
                       COALESCE('dev:' || d.device_id, 'ip:' || host(f.dst_ip)) AS dst_node,
                       host(f.src_ip) AS src_ip, f.src_port, host(f.dst_ip) AS dst_ip, f.dst_port, f.proto,
                       f.label, f.scenario, f.features
                FROM flows f
                LEFT JOIN devices s ON s.ip = f.src_ip
                LEFT JOIN devices d ON d.ip = f.dst_ip"""
    page = fetch_page(conn, select, w, [("f.ts_start", "timestamptz", "ts"), ("f.flow_id", "text", "flow_id")], p)
    return in_contract_order(page, "features", flow.FEATURE_NAMES)


# ------------------------------------------------------------------------------------------- AI model alerts
@router.get("/alerts", response_model=Page[AlertOut], tags=["Data"],
            summary="Alerts from the AI models (LSTM-AE + VAE), saved by python -m detect")
def list_alerts(conn: Conn, r: Range, p: Pages, device_id: str | None = None,
                entity_id: Annotated[str | None, Query(description="the flagged host: device_id or IP")] = None,
                capture: Annotated[str | None, Query(description="the recording's name given to detect")] = None,
                min_severity: Annotated[Severity | None, Query(description="this severity and above")] = None) -> dict:
    w = Where()
    w.time("ts", r)
    w.add("device_id = %s", device_id)
    w.add("entity_id = %s", entity_id)
    w.add("evidence->>'capture' = %s", capture)
    if min_severity is not None:
        levels = ("low", "medium", "high", "critical")
        w.add("severity = ANY(%s)", list(levels[levels.index(min_severity):]) if min_severity in levels else list(levels))
    select = """SELECT alert_id::text AS alert_id, ts, model_name, model_version, entity_id, device_id, window_start,
                       window_end, score, predicted_scenario, severity, status, evidence
                FROM alerts"""
    return fetch_page(conn, select, w, [("ts", "timestamptz", "ts"), ("alert_id", "uuid", "alert_id")], p)
