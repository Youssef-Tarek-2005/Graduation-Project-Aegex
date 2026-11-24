"""The loader: Events from the parsers -> rows in the `events` table.

    parser.parse_line(...) -> Event -> (batch of 1000) -> INSERT ... ON CONFLICT DO NOTHING

How duplicates are skipped: every Event has a dedup_key (a fingerprint of its original log line). The
database has a unique index on (dedup_key, ts), and the INSERT says "ON CONFLICT ... DO NOTHING". So if a row
with the same fingerprint is already there, PostgreSQL quietly skips it. Loading the same file twice, or a
file that overlaps one loaded yesterday, never creates duplicates.

The file is read line by line and saved in batches, so even a very large log never has to fit in memory.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Iterable

import psycopg
from psycopg.types.json import Jsonb

from .event import Event
from .parsers.base import ParseStats, Parser

BATCH_SIZE = 1000

INSERT_SQL = """
INSERT INTO events (ts, source, event_type, layer, device_id, capture_id,
                    src_ip, src_port, dst_ip, dst_port, proto, severity, dedup_key, payload)
VALUES (%(ts)s, %(source)s, %(event_type)s, %(layer)s, %(device_id)s, %(capture_id)s,
        %(src_ip)s::inet, %(src_port)s, %(dst_ip)s::inet, %(dst_port)s, %(proto)s, %(severity)s,
        %(dedup_key)s, %(payload)s)
ON CONFLICT (dedup_key, ts) WHERE dedup_key IS NOT NULL DO NOTHING
"""


class LoadError(Exception):
    """The file was refused (unknown capture or device, or events outside the capture). Nothing was saved."""


@dataclass
class LoadResult:
    parse: ParseStats
    inserted: int = 0           # new rows saved
    duplicates: int = 0         # rows that were already in the database and were skipped
    outside_capture: int = 0    # events whose time is outside the capture's start..end (only when allowed)

    def __str__(self) -> str:
        text = (f"{self.parse}\n"
                f"saved {self.inserted} new rows, skipped {self.duplicates} already in the database")
        if self.outside_capture:
            text += f"\nNOTE: {self.outside_capture} events are outside the capture's time range (allowed on request)"
        return text


def _check_references(conn: psycopg.Connection, capture_id: str | None, device_id: str | None
                      ) -> tuple[datetime | None, datetime | None]:
    """Fail early, with a clear message, instead of a foreign-key error halfway through a big file."""
    start = end = None
    if capture_id is not None:
        row = conn.execute("SELECT start_ts, end_ts FROM captures WHERE capture_id = %s", (capture_id,)).fetchone()
        if row is None:
            raise LoadError(f"capture {capture_id!r} does not exist. Add it to the captures table first.")
        start, end = row
    if device_id is not None:
        if conn.execute("SELECT 1 FROM devices WHERE device_id = %s", (device_id,)).fetchone() is None:
            raise LoadError(f"device {device_id!r} does not exist. Add it to the devices table first.")
    return start, end


def _row(e: Event) -> dict:
    row = e.to_row()
    row["payload"] = Jsonb(row["payload"])
    return row


def _insert_batch(cur: psycopg.Cursor, batch: list[Event]) -> int:
    cur.executemany(INSERT_SQL, [_row(e) for e in batch])
    return cur.rowcount            # psycopg 3: total rows actually inserted (skipped duplicates count 0)


def save_events(conn: psycopg.Connection, events: list[Event]) -> int:
    """Save ready-made Events (e.g. from the API) in one transaction. Returns how many were new."""
    if not events:
        return 0
    with conn.transaction(), conn.cursor() as cur:
        return sum(_insert_batch(cur, events[i:i + BATCH_SIZE]) for i in range(0, len(events), BATCH_SIZE))


def load_lines(conn: psycopg.Connection, parser: Parser, lines: Iterable[str], capture_id: str | None = None,
               batch_size: int = BATCH_SIZE, allow_outside_capture: bool = False) -> LoadResult:
    """Parse lines with `parser` and save the events. All or nothing: one transaction for the whole file.

    If any event falls outside the capture's start..end, the whole file is refused (rolled back). That
    almost always means a wrong time zone or the wrong capture, and a shifted row would get the wrong label.
    The duplicate check can't catch it, because the same line at a different time is a different row.
    """
    start, end = _check_references(conn, capture_id, parser.device_id)
    result = LoadResult(parse=parser.stats)
    batch: list[Event] = []
    first_outside: Event | None = None

    with conn.transaction(), conn.cursor() as cur:
        for line in lines:
            for e in parser.parse_line(line):
                e.capture_id = capture_id
                if start is not None and (e.ts < start or (end is not None and e.ts > end)):
                    result.outside_capture += 1
                    first_outside = first_outside or e
                batch.append(e)
                if len(batch) >= batch_size:
                    result.inserted += _insert_batch(cur, batch)
                    batch.clear()
        if batch:
            result.inserted += _insert_batch(cur, batch)

        if result.outside_capture and not allow_outside_capture:
            # Raising inside the transaction block rolls back everything this file inserted.
            window = f"{start:%Y-%m-%d %H:%M} to {end:%Y-%m-%d %H:%M} UTC" if end else f"from {start:%Y-%m-%d %H:%M} UTC"
            raise LoadError(
                f"{result.outside_capture} of {parser.stats.events} events are outside capture {capture_id!r} "
                f"({window}). First one: {first_outside.ts:%Y-%m-%d %H:%M:%S} UTC. "
                f"Wrong --tz or wrong --capture? Nothing was saved."
            )

    result.duplicates = parser.stats.events - result.inserted
    return result


def load_file(conn: psycopg.Connection, parser: Parser, path: str | Path, capture_id: str | None = None,
              batch_size: int = BATCH_SIZE, allow_outside_capture: bool = False) -> LoadResult:
    with open(path, "r", encoding="utf-8-sig", errors="replace") as fh:
        return load_lines(conn, parser, fh, capture_id, batch_size, allow_outside_capture)


def label_capture(conn: psycopg.Connection, capture_id: str) -> None:
    """Run the labeling procedure from schema_v2.sql (explained fully in step 6)."""
    with conn.transaction():
        conn.execute("CALL label_capture(%s)", (capture_id,))
