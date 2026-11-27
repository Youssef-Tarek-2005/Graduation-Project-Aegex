"""Zeek conn.log -> Flow objects -> rows in the `flows` table.

One flow = one network connection: who talked to whom, on which port, for how long, how many bytes.
Zeek writes one line per connection to conn.log, when the connection ends.

Two formats are read:
  - JSON lines (what our Zeek setup writes, with LogAscii::use_json=T)
  - Zeek's default tab-separated format with "#fields" header lines

The stable flow_id
  Zeek gives each connection a `uid`, but it is random: run Zeek twice on the same pcap and every uid changes.
  If uid were the key, re-processing a pcap would duplicate every flow. So flow_id is a fingerprint of what
  does NOT change: start time (to the microsecond), protocol, and the two IP:port ends. Zeek's uid is still
  kept, in zeek_uid, to join with Zeek's other logs (ssh.log, http.log, ...).
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable

import psycopg

from .loader import LoadError
from .parsers.base import ParseStats

UNSET = {"-", "(empty)", ""}          # how Zeek's TSV format writes "no value"


@dataclass
class Flow:
    flow_id: str
    zeek_uid: str | None
    ts_start: datetime
    ts_end: datetime | None
    src_ip: str
    src_port: int | None
    dst_ip: str
    dst_port: int | None
    proto: str
    service: str | None
    conn_state: str | None
    history: str | None
    duration_s: float | None
    orig_bytes: int | None
    resp_bytes: int | None
    orig_pkts: int | None
    resp_pkts: int | None
    device_id: str | None = None      # filled by the loader from the devices table
    capture_id: str | None = None     # filled by the loader
    fwd_flags: int | None = None      # TCP flags of the originator / responder, from `history` (see history_flags)
    bwd_flags: int | None = None

    def to_row(self) -> dict[str, Any]:
        return asdict(self)


def make_flow_id(ts_start: datetime, proto: str, src_ip: str, src_port: int | None, dst_ip: str, dst_port: int | None) -> str:
    key = f"{ts_start.timestamp():.6f}|{proto}|{src_ip}|{src_port}|{dst_ip}|{dst_port}"
    return "F" + hashlib.sha256(key.encode()).hexdigest()[:24]


# TCP flag bits, as in the AI team's flow table (aegex_prep.py): the unified flow record uses the same numbers.
FIN, SYN, RST, PSH, ACK, URG = 1, 2, 4, 8, 16, 32
_HISTORY = {"S": SYN, "H": SYN | ACK, "A": ACK, "D": PSH, "F": FIN, "R": RST}


def history_flags(history: str | None, proto: str) -> tuple[int | None, int | None]:
    """Zeek `history` -> (originator flags, responder flags). Upper case = originator, lower case = responder;
    'D'/'d' (data seen) counts as PSH. Same rule as the AI team's _zeek_history_flags. Not TCP or no history -> None."""
    if proto != "tcp" or not history:
        return None, None
    of = rf = 0
    for ch in history:
        if ch in _HISTORY:
            of |= _HISTORY[ch]
        elif ch.upper() in _HISTORY:
            rf |= _HISTORY[ch.upper()]
    return of, rf


def _val(d: dict, key: str) -> Any:
    v = d.get(key)
    return None if (v is None or (isinstance(v, str) and v in UNSET)) else v


def _int(v: Any) -> int | None:
    return None if v is None else int(float(v))


def _float(v: Any) -> float | None:
    return None if v is None else float(v)


def _time(v: Any) -> datetime:
    # Zeek writes epoch seconds (1795183500.123456) by default, or ISO 8601 if json_timestamps is changed.
    if isinstance(v, (int, float)) or (isinstance(v, str) and v.replace(".", "", 1).isdigit()):
        return datetime.fromtimestamp(float(v), tz=timezone.utc)
    return datetime.fromisoformat(str(v).replace("Z", "+00:00")).astimezone(timezone.utc)


class ZeekConnParser:
    """Reads conn.log lines (JSON or TSV) and returns Flows. Bad lines are counted and skipped."""

    def __init__(self) -> None:
        self.stats = ParseStats(unit="flows")
        self.fields: list[str] | None = None        # TSV column names, from the "#fields" line
        self.separator = "\t"

    def parse_line(self, line: str) -> list[Flow]:
        line = line.rstrip("\r\n")
        if not line.strip():
            return []
        self.stats.lines += 1
        if line.startswith("#"):                    # TSV header lines: #separator, #fields, #types, #close ...
            if line.startswith("#separator"):
                self.separator = line.split(" ", 1)[1].encode().decode("unicode_escape")
            elif line.startswith("#fields"):
                self.fields = line.split(self.separator)[1:]
            self.stats.ignored += 1
            return []
        try:
            if line.lstrip().startswith("{"):
                d = json.loads(line)
            elif self.fields:
                d = dict(zip(self.fields, line.split(self.separator)))
            else:
                raise ValueError("TSV line before any #fields header")
            flow = self._flow(d)
        except (ValueError, TypeError, KeyError):
            self.stats.skipped += 1
            return []
        self.stats.events += 1
        return [flow]

    def parse_lines(self, lines: Iterable[str]) -> list[Flow]:
        out: list[Flow] = []
        for line in lines:
            out.extend(self.parse_line(line))
        return out

    def parse_file(self, path: str | Path) -> list[Flow]:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return self.parse_lines(fh)

    @staticmethod
    def _flow(d: dict) -> Flow:
        ts = _time(d["ts"])
        src, dst = d["id.orig_h"], d["id.resp_h"]
        sport, dport = _int(_val(d, "id.orig_p")), _int(_val(d, "id.resp_p"))
        proto = str(d["proto"]).lower()
        duration = _float(_val(d, "duration"))
        fwd_flags, bwd_flags = history_flags(_val(d, "history"), proto)
        return Flow(
            flow_id=make_flow_id(ts, proto, src, sport, dst, dport),
            zeek_uid=_val(d, "uid"),
            ts_start=ts,
            ts_end=ts + timedelta(seconds=duration) if duration is not None else None,
            src_ip=src, src_port=sport, dst_ip=dst, dst_port=dport, proto=proto,
            service=_val(d, "service"),
            conn_state=_val(d, "conn_state"),
            history=_val(d, "history"),
            duration_s=duration,
            # Missing byte counts stay None (unknown), never 0: 0 would claim "we saw no data".
            orig_bytes=_int(_val(d, "orig_bytes")), resp_bytes=_int(_val(d, "resp_bytes")),
            orig_pkts=_int(_val(d, "orig_pkts")), resp_pkts=_int(_val(d, "resp_pkts")),
            fwd_flags=fwd_flags, bwd_flags=bwd_flags,
        )


# ------------------------------------------------------------------------------------------- loading
INSERT_FLOW_SQL = """
INSERT INTO flows (flow_id, zeek_uid, ts_start, ts_end, capture_id, device_id, src_ip, src_port, dst_ip, dst_port,
                   proto, service, conn_state, history, duration_s, orig_bytes, resp_bytes, orig_pkts, resp_pkts,
                   fwd_flags, bwd_flags)
VALUES (%(flow_id)s, %(zeek_uid)s, %(ts_start)s, %(ts_end)s, %(capture_id)s, %(device_id)s,
        %(src_ip)s::inet, %(src_port)s, %(dst_ip)s::inet, %(dst_port)s, %(proto)s, %(service)s, %(conn_state)s,
        %(history)s, %(duration_s)s, %(orig_bytes)s, %(resp_bytes)s, %(orig_pkts)s, %(resp_pkts)s,
        %(fwd_flags)s, %(bwd_flags)s)
ON CONFLICT (flow_id, ts_start) DO NOTHING
"""


@dataclass
class FlowLoadResult:
    parse: ParseStats
    inserted: int = 0
    duplicates: int = 0
    with_device: int = 0          # flows that touch one of our honeypot devices

    def __str__(self) -> str:
        return (f"{self.parse}\nsaved {self.inserted} new flows, skipped {self.duplicates} already in the database; "
                f"{self.with_device} of {self.parse.events} touch a honeypot device")


def device_map(conn: psycopg.Connection) -> dict[str, str]:
    """IP address -> device_id, from the devices table."""
    return {host: dev for dev, host in conn.execute("SELECT device_id, host(ip) FROM devices WHERE ip IS NOT NULL")}


def load_flows(conn: psycopg.Connection, parser: ZeekConnParser, lines: Iterable[str], capture_id: str | None = None,
               allow_outside_capture: bool = False) -> FlowLoadResult:
    """Same rules as the events loader: all or nothing, no duplicates, refuse flows outside the capture."""
    start = end = None
    if capture_id is not None:
        row = conn.execute("SELECT start_ts, end_ts FROM captures WHERE capture_id = %s", (capture_id,)).fetchone()
        if row is None:
            raise LoadError(f"capture {capture_id!r} does not exist. Add it to the captures table first.")
        start, end = row
    devices = device_map(conn)
    result = FlowLoadResult(parse=parser.stats)
    outside: list[Flow] = []

    with conn.transaction(), conn.cursor() as cur:
        rows = []
        for line in lines:
            for f in parser.parse_line(line):
                f.capture_id = capture_id
                # The honeypot device on either end. Prefer the destination: that's usually the one being reached.
                f.device_id = devices.get(f.dst_ip) or devices.get(f.src_ip)
                result.with_device += f.device_id is not None
                if start is not None and (f.ts_start < start or (end is not None and f.ts_start > end)):
                    outside.append(f)
                rows.append(f.to_row())
                if len(rows) >= 1000:
                    cur.executemany(INSERT_FLOW_SQL, rows)
                    result.inserted += cur.rowcount
                    rows.clear()
        if rows:
            cur.executemany(INSERT_FLOW_SQL, rows)
            result.inserted += cur.rowcount
        if outside and not allow_outside_capture:
            raise LoadError(f"{len(outside)} of {parser.stats.events} flows are outside capture {capture_id!r}. "
                            f"First one starts {outside[0].ts_start:%Y-%m-%d %H:%M:%S} UTC. Wrong capture? Nothing was saved.")

    result.duplicates = parser.stats.events - result.inserted
    return result


def load_conn_log(conn: psycopg.Connection, path: str | Path, capture_id: str | None = None,
                  allow_outside_capture: bool = False) -> FlowLoadResult:
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        return load_flows(conn, ZeekConnParser(), fh, capture_id, allow_outside_capture)
