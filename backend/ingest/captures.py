"""Captures: one row per recording session (start recording ... stop recording).

Every event, flow and attack run points at a capture, so the capture has to exist first.

    cd backend
    .venv/Scripts/python -m ingest.captures add cap-2026-11-21-a --start 2026-11-21T09:00:00Z --end 2026-11-21T10:00:00Z --kind attack
    .venv/Scripts/python -m ingest.captures list

Times must say their time zone ("Z" = UTC, or "+02:00"). A time without one is refused: guessing the zone
is how data ends up hours away from its labels.
"""
from __future__ import annotations

import argparse
import sys
from datetime import datetime, timezone

import psycopg

from .db import connect, db_url

KINDS = ("normal_only", "attack", "mixed", "live")


class CaptureError(Exception):
    pass


def parse_utc(value: str, what: str = "time") -> datetime:
    """'2026-11-20T14:10:00Z' or '...+02:00' -> aware datetime in UTC. A time without a zone raises ValueError."""
    ts = datetime.fromisoformat(value.strip().replace(" ", "T", 1))
    if ts.tzinfo is None:
        raise ValueError(f"{what} {value!r} has no time zone. Write it in UTC with a Z, e.g. "
                         f"{ts:%Y-%m-%dT%H:%M:%S}Z, or add the offset, e.g. +02:00")
    return ts.astimezone(timezone.utc)


def add_capture(conn: psycopg.Connection, capture_id: str, start: datetime, end: datetime | None = None,
                kind: str = "mixed", pcap_path: str | None = None, notes: str | None = None) -> bool:
    """Add a capture. Returns True if new, False if the exact same capture already exists.

    A capture that exists with different times or kind is refused, not changed: moving a capture's times
    could leave data that is already loaded outside it. Fix that on purpose, in SQL.
    """
    if start.tzinfo is None or (end is not None and end.tzinfo is None):
        raise CaptureError("capture times must have a time zone")
    if end is not None and end <= start:
        raise CaptureError(f"capture {capture_id!r} ends ({end:%H:%M:%S}) before it starts ({start:%H:%M:%S})")
    if kind not in KINDS:
        raise CaptureError(f"kind {kind!r} is not one of {', '.join(KINDS)}")

    with conn.transaction():
        row = conn.execute("SELECT start_ts, end_ts, kind FROM captures WHERE capture_id = %s", (capture_id,)).fetchone()
        if row is not None:
            if row == (start, end, kind):
                return False
            raise CaptureError(f"capture {capture_id!r} already exists with different values "
                               f"(start {row[0]:%Y-%m-%d %H:%M:%S}, end {row[1]}, kind {row[2]}). Nothing was changed.")
        conn.execute("INSERT INTO captures (capture_id, start_ts, end_ts, kind, pcap_path, notes) "
                     "VALUES (%s, %s, %s, %s, %s, %s)", (capture_id, start, end, kind, pcap_path, notes))
    return True


def close_capture(conn: psycopg.Connection, capture_id: str, end: datetime) -> str:
    """Give a capture that is still recording its end time. Returns a short report."""
    row = conn.execute("SELECT start_ts, end_ts FROM captures WHERE capture_id = %s", (capture_id,)).fetchone()
    if row is None:
        raise CaptureError(f"capture {capture_id!r} does not exist")
    start, old_end = row
    if old_end is not None:
        raise CaptureError(f"capture {capture_id!r} is already closed (end {old_end:%Y-%m-%d %H:%M:%S} UTC)")
    if end <= start:
        raise CaptureError(f"end {end:%H:%M:%S} is before the capture's start {start:%H:%M:%S} (UTC)")
    later = conn.execute("SELECT (SELECT count(*) FROM events WHERE capture_id = %(c)s AND ts > %(e)s) + "
                         "(SELECT count(*) FROM flows WHERE capture_id = %(c)s AND ts_start > %(e)s)",
                         {"c": capture_id, "e": end}).fetchone()[0]
    if later:
        raise CaptureError(f"{later} events/flows of {capture_id} are after {end:%H:%M:%S} UTC: choose a later end")
    conn.execute("UPDATE captures SET end_ts = %s WHERE capture_id = %s", (end, capture_id))
    return f"closed capture {capture_id}: {start:%Y-%m-%d %H:%M:%S} - {end:%H:%M:%S} UTC ({(end - start).seconds // 60} min)"


def list_captures(conn: psycopg.Connection) -> list[tuple]:
    return conn.execute("""
        SELECT c.capture_id, c.start_ts, c.end_ts, c.kind,
               (SELECT count(*) FROM attack_runs r WHERE r.capture_id = c.capture_id) AS runs,
               (SELECT count(*) FROM events e WHERE e.capture_id = c.capture_id)      AS events,
               (SELECT count(*) FROM flows f WHERE f.capture_id = c.capture_id)       AS flows
          FROM captures c ORDER BY c.start_ts""").fetchall()


def main() -> int:
    ap = argparse.ArgumentParser(prog="python -m ingest.captures", description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    add = sub.add_parser("add", help="add a capture")
    add.add_argument("capture_id")
    add.add_argument("--start", required=True, help="e.g. 2026-11-21T09:00:00Z, or now")
    add.add_argument("--end", help="leave out while still recording (live)")
    add.add_argument("--kind", default="mixed", choices=KINDS)
    add.add_argument("--pcap", help="where the pcap file is kept")
    add.add_argument("--notes")
    close = sub.add_parser("close", help="give a capture that is still recording its end time")
    close.add_argument("capture_id")
    close.add_argument("--end", default="now", help="e.g. 2026-11-21T10:00:00Z (default: now)")
    sub.add_parser("list", help="show all captures and how much data each has")
    a = ap.parse_args()

    def when(value: str, what: str) -> datetime:
        return datetime.now(timezone.utc).replace(microsecond=0) if value == "now" else parse_utc(value, what)

    try:
        with connect() as conn:
            if a.cmd == "add":
                try:
                    start = when(a.start, "--start")
                    end = when(a.end, "--end") if a.end else None
                except ValueError as exc:
                    raise CaptureError(str(exc)) from None
                new = add_capture(conn, a.capture_id, start, end, a.kind, a.pcap, a.notes)
                print(f"added capture {a.capture_id}, start {start:%Y-%m-%d %H:%M:%S} UTC" if new
                      else f"capture {a.capture_id} already exists (same values)")
            elif a.cmd == "close":
                try:
                    end = when(a.end, "--end")
                except ValueError as exc:
                    raise CaptureError(str(exc)) from None
                print(close_capture(conn, a.capture_id, end))
            else:
                print(f"{'capture':<20} {'start (UTC)':<20} {'end (UTC)':<20} {'kind':<12} runs  events  flows")
                for cid, start, end, kind, runs, events, flows in list_captures(conn):
                    end_s = f"{end:%Y-%m-%d %H:%M:%S}" if end else "(recording)"
                    print(f"{cid:<20} {start:%Y-%m-%d %H:%M:%S}  {end_s:<20} {kind:<12} {runs:>4}  {events:>6}  {flows:>5}")
    except CaptureError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    except psycopg.OperationalError as exc:
        print(f"ERROR: can't reach the database at {db_url()}. Is Docker running?\n{exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
