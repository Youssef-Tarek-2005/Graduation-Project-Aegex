"""Small summary endpoints for the dashboard: counts and chart-ready series, so the browser doesn't have to
download thousands of rows just to draw a chart. Same `from` / `to` / `capture_id` filters as step 11.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Annotated

import psycopg
from fastapi import APIRouter, Depends, Query

from ingest.event import EVENT_TYPES

from .db import get_conn
from .ingest import REFUSED
from .read import Range, TimeRange, Where, refuse
from .schemas import ChartOut, Series, SummaryOut

router = APIRouter(prefix="/api/v1/stats", tags=["Dashboard"], responses=REFUSED)
Conn = Annotated[psycopg.Connection, Depends(get_conn)]
LAYERS = sorted({spec["layer"] for spec in EVENT_TYPES.values()})
SENSORS = (("temperature_c", "°C"), ("smoke", "ADC"), ("humidity_pct", "%"))
# Bucket sizes that divide a day evenly, so buckets line up with the clock (10:00, 10:05, ...).
NICE_BUCKETS = (10, 30, 60, 120, 300, 600, 900, 1800, 3600, 7200, 10800, 21600, 43200, 86400)
MAX_BUCKETS = 500


def _bucket_sql(column: str) -> str:
    """Floor a timestamp to its bucket (seconds since 1970 // size), the same rule as the 10 s windows."""
    return f"to_timestamp(floor(extract(epoch FROM {column}) / %s) * %s)"


def _span(r: TimeRange) -> tuple[datetime, datetime]:
    if r.start is None:
        raise refuse(["'from' is required for a chart (and 'to', unless the chart should end now)"])
    return r.start, r.end or datetime.now(timezone.utc)


def _choose_bucket(start: datetime, end: datetime, wanted: int | None, target: int) -> int:
    seconds = (end - start).total_seconds()
    if wanted is not None:
        if seconds / wanted > MAX_BUCKETS * 10:
            raise refuse([f"bucket_seconds={wanted} gives too many points for this range: use a bigger bucket"])
        return wanted
    return next((b for b in NICE_BUCKETS if seconds / b <= target), NICE_BUCKETS[-1])


def _axis(start: datetime, end: datetime, bucket: int) -> list[datetime]:
    """Every bucket start in the range, including empty ones (a gap in a chart must show as 0, not vanish)."""
    first = int(start.timestamp() // bucket * bucket)
    last = end.timestamp()
    return [datetime.fromtimestamp(t, timezone.utc) for t in range(first, int(last) + (last % bucket > 0), bucket)
            if t < last]


# ------------------------------------------------------------------------------------------- summary
@router.get("/summary", response_model=SummaryOut, summary="Counts for the dashboard cards")
def summary(conn: Conn, r: Range, capture_id: str | None = None) -> SummaryOut:
    w = Where()
    w.time("ts", r)
    w.add("capture_id = %s", capture_id)
    where = " AND ".join(w.clauses) or "TRUE"

    def counts(column: str, extra: str = "TRUE") -> dict[str, int]:
        sql = f"SELECT {column}, count(*) FROM events WHERE {where} AND {extra} GROUP BY 1 ORDER BY 2 DESC"
        return {str(k): n for k, n in conn.execute(sql, w.params).fetchall()}

    labels = counts("CASE label WHEN 1 THEN 'attack' WHEN 0 THEN 'normal' ELSE 'unlabeled' END")
    fw = Where()
    fw.time("ts_start", r)
    fw.add("capture_id = %s", capture_id)
    flows, attack_flows = conn.execute(f"SELECT count(*), count(*) FILTER (WHERE label = 1) FROM flows "
                                       f"WHERE {' AND '.join(fw.clauses) or 'TRUE'}", fw.params).fetchone()
    fwhere = " AND ".join(fw.clauses) or "TRUE"

    def attacks(column: str) -> dict[str, dict[str, int]]:
        """Per scenario (or run): attack events and attack flows. Scans and floods leave flows, not events."""
        out: dict[str, dict[str, int]] = {}
        for table, w_sql, params in (("events", where, w.params), ("flows", fwhere, fw.params)):
            sql = f"SELECT {column}, count(*) FROM {table} WHERE {w_sql} AND label = 1 GROUP BY 1"
            for key, n in conn.execute(sql, params).fetchall():
                out.setdefault(str(key), {"events": 0, "flows": 0})[table] = n
        return dict(sorted(out.items(), key=lambda kv: -sum(kv[1].values())))

    return SummaryOut(events=sum(labels.values()), flows=flows, attack_flows=attack_flows,
                      layers={layer: 0 for layer in LAYERS} | counts("layer"), sources=counts("source"),
                      labels={"attack": 0, "normal": 0, "unlabeled": 0} | labels,
                      scenarios=attacks("scenario"), runs=attacks("run_id"))


# ------------------------------------------------------------------------------------------- charts
@router.get("/events-histogram", response_model=ChartOut, summary="Events per time bucket, one series per event type")
def events_histogram(conn: Conn, r: Range, capture_id: str | None = None,
                     bucket_seconds: Annotated[int | None, Query(ge=1, description="leave empty: about 60 bars")] = None,
                     ) -> ChartOut:
    start, end = _span(r)
    bucket = _choose_bucket(start, end, bucket_seconds, target=60)
    w = Where()
    w.add("ts >= %s", start)
    w.add("ts < %s", end)
    w.add("capture_id = %s", capture_id)
    rows = conn.execute(f"SELECT {_bucket_sql('ts')} AS b, event_type, count(*) FROM events "
                        f"WHERE {' AND '.join(w.clauses)} GROUP BY 1, 2", [bucket, bucket, *w.params]).fetchall()
    axis = _axis(start, end, bucket)
    index = {t: i for i, t in enumerate(axis)}
    series: dict[str, list[float | None]] = {}
    for b, event_type, n in rows:
        series.setdefault(event_type, [0] * len(axis))[index[b]] = n
    return ChartOut(bucket_seconds=bucket, labels=axis,
                    series=[Series(name=name, data=data) for name, data in sorted(series.items())])


@router.get("/sensors", response_model=ChartOut, summary="ESP32 temperature, smoke and humidity over time")
def sensors(conn: Conn, r: Range, capture_id: str | None = None, device_id: str | None = None,
            bucket_seconds: Annotated[int | None, Query(ge=1, description="leave empty: raw readings for short "
                                                        "ranges, averages for long ones")] = None) -> ChartOut:
    """A reading the sensor marked invalid (e.g. smoke during warm-up) is a gap (null), not a 0."""
    start, end = _span(r)
    w = Where()
    w.add("event_type = %s", "sensor_reading")
    w.add("ts >= %s", start)
    w.add("ts < %s", end)
    w.add("capture_id = %s", capture_id)
    w.add("device_id = %s", device_id)
    where = " AND ".join(w.clauses)
    values = ", ".join(f"(payload->>'{name}')::float AS {name}" for name, _ in SENSORS)
    raw = bucket_seconds is None and (end - start) <= timedelta(hours=2)
    if raw:
        rows = conn.execute(f"SELECT ts, {values} FROM events WHERE {where} ORDER BY ts LIMIT 5000", w.params).fetchall()
        bucket = None
    else:
        bucket = _choose_bucket(start, end, bucket_seconds, target=MAX_BUCKETS)
        averages = ", ".join(f"avg((payload->>'{name}')::float)" for name, _ in SENSORS)
        rows = conn.execute(f"SELECT {_bucket_sql('ts')} AS b, {averages} FROM events WHERE {where} "
                            f"GROUP BY 1 ORDER BY 1", [bucket, bucket, *w.params]).fetchall()
    return ChartOut(bucket_seconds=bucket, labels=[row[0] for row in rows],
                    series=[Series(name=name, unit=unit,
                                   data=[None if row[i + 1] is None else round(row[i + 1], 3) for row in rows])
                            for i, (name, unit) in enumerate(SENSORS)])
