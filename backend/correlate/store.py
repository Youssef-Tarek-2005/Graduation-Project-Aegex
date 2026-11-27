"""Run the correlation baseline on a capture in the database and save its incidents in the `alerts` table.

    cd backend
    .venv\\Scripts\\python -m correlate --capture cap-2026-11-20-a          # one capture (database: AEGEX_DB_URL)
    .venv\\Scripts\\python -m correlate --all                               # every capture
    .venv\\Scripts\\python -m correlate --capture ds-kitsune-mirai --db aegex_datasets --dry-run

The incidents are alerts like the AI models' ones, with model_name = 'rules', so the API, the dashboard's
AI alerts page and the evaluation (Step 8) treat them the same way. Running it again replaces that capture's rule
alerts (no duplicates).
"""
from __future__ import annotations

import argparse
import sys
from datetime import timedelta

import pandas as pd
import psycopg
from psycopg.types.json import Jsonb

from ingest.datastore import url_for
from ingest.db import connect

from .rules import RULES, Incident, correlate

MODEL, VERSION, FEATURE_VERSION = "rules", "baseline-v1", "rules-v1"


def load(conn: psycopg.Connection, capture_id: str, since=None, until=None) -> tuple[pd.DataFrame, pd.DataFrame]:
    """The flows and events of one capture (only between `since` and `until`, if given), as tables for correlate()."""
    extra, params = "", [capture_id]
    if since is not None:
        extra, params = extra + " AND ts_start >= %s", params + [since]
    if until is not None:
        extra, params = extra + " AND ts_start < %s", params + [until]
    cur = conn.execute("SELECT flow_id, ts_start AS ts, host(src_ip) AS src_ip, host(dst_ip) AS dst_ip, dst_port, "
                       "proto, resp_pkts, conn_state, bwd_flags, device_id FROM flows WHERE capture_id = %s" + extra,
                       params)
    flows = pd.DataFrame(cur.fetchall(), columns=[d.name for d in cur.description])
    extra = extra.replace("ts_start", "ts")
    params = tuple(params)
    cur = conn.execute("SELECT ts, host(src_ip) AS src_ip, event_type, device_id FROM events "
                       "WHERE capture_id = %s AND src_ip IS NOT NULL" + extra, params)
    events = pd.DataFrame(cur.fetchall(), columns=[d.name for d in cur.description])
    return flows, events


def run_period(conn: psycopg.Connection, capture_id: str, start, end) -> int:
    """Live mode: re-check only the traffic of [start, end) of a long capture and replace only the rule alerts that
    start in it; everything else of the capture stays. The 10 minutes before `start` are read too, so a brute force
    that began just before is still counted. Returns the number of incidents in the period."""
    flows, events = load(conn, capture_id, start - timedelta(minutes=10), end)
    incidents = [i for i in correlate(flows, events) if start <= i.start < end]
    with conn.transaction():
        conn.execute("DELETE FROM alerts WHERE model_name = %s AND evidence->>'capture' = %s AND window_start >= %s "
                     "AND window_start < %s", (MODEL, capture_id, start, end))
        _insert(conn, capture_id, incidents)
    return len(incidents)


def run(conn: psycopg.Connection, capture_id: str) -> list[Incident]:
    flows, events = load(conn, capture_id)
    return correlate(flows, events)


def save(conn: psycopg.Connection, capture_id: str, incidents: list[Incident]) -> int:
    """Replace this capture's rule alerts with `incidents`. Returns how many were saved."""
    with conn.transaction():
        conn.execute("DELETE FROM alerts WHERE model_name = %s AND evidence->>'capture' = %s", (MODEL, capture_id))
        _insert(conn, capture_id, incidents)
    return len(incidents)


def _insert(conn: psycopg.Connection, capture_id: str, incidents: list[Incident]) -> None:
    ours = {d for (d,) in conn.execute("SELECT device_id FROM devices")}
    conn.execute("INSERT INTO model_versions (model_name, version, feature_version, threshold, metrics, is_active) "
                 "VALUES (%s, %s, %s, 1.0, %s, FALSE) ON CONFLICT (model_name, version) DO UPDATE "
                 "SET metrics = EXCLUDED.metrics",
                 (MODEL, VERSION, FEATURE_VERSION,
                  Jsonb({"thresholds": {r: t for r, (t, _, _) in RULES.items()}, "bucket_s": 60})))
    for inc in incidents:
        device = next((d for d in inc.devices if d in ours), None)
        evidence = {"capture": capture_id, "summary": inc.summary,
                    "rules": {r: {"value": v, "threshold": RULES[r][0], "means": RULES[r][2]}
                              for r, v in inc.rules.items()},
                    "flows": inc.flows, "failed_share": inc.failed_share, "targets": inc.targets,
                    "devices": inc.devices, "events": inc.events, "flow_ids": inc.flow_ids}
        conn.execute(
            "INSERT INTO alerts (ts, model_name, model_version, feature_version, entity_type, entity_id, device_id, "
            "src_ips, window_start, window_end, score, threshold, is_anomaly, predicted_scenario, severity, evidence) "
            "VALUES (%s, %s, %s, %s, 'src_ip', %s, %s, %s::inet[], %s, %s, %s, 1.0, TRUE, %s, %s, %s)",
            (inc.end, MODEL, VERSION, FEATURE_VERSION, inc.src_ip, device, [inc.src_ip], inc.start, inc.end,
             inc.score, inc.scenario, inc.severity, Jsonb(evidence)))


def print_incidents(capture_id: str, incidents: list[Incident]) -> None:
    print(f"\n{capture_id}: {len(incidents)} incident(s)")
    for i in incidents:
        print(f"  {i.start:%Y-%m-%d %H:%M:%S}-{i.end:%H:%M:%S}  {i.severity:<8} {i.scenario:<22} {i.summary}"
              f"  [{i.flows:,} flows" + (f", events {i.events}" if i.events else "") +
              (f", devices {', '.join(i.devices)}" if i.devices else "") + "]")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Step 7: rule-based correlation baseline -> alerts (model 'rules').")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--capture", help="one capture id")
    g.add_argument("--all", action="store_true", help="every capture in the database")
    ap.add_argument("--db", help="database name (default: the one in AEGEX_DB_URL)")
    ap.add_argument("--dry-run", action="store_true", help="print the incidents, save nothing")
    a = ap.parse_args(argv)
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    try:
        with connect(url_for(a.db) if a.db else None) as conn:
            caps = [a.capture] if a.capture else [c for (c,) in conn.execute(
                "SELECT capture_id FROM captures ORDER BY start_ts")]
            total = 0
            for cap in caps:
                incidents = run(conn, cap)
                print_incidents(cap, incidents)
                if not a.dry_run:
                    total += save(conn, cap, incidents)
            print(f"\n{'dry run: nothing saved' if a.dry_run else f'saved {total} rule alert(s) (model rules)'}")
    except psycopg.OperationalError as exc:
        print(f"ERROR: the database server is not reachable ({exc.__class__.__name__}). Start Docker first.")
        return 1
    return 0
