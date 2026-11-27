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

import pandas as pd
import psycopg
from psycopg.types.json import Jsonb

from ingest.datastore import url_for
from ingest.db import connect

from .rules import RULES, Incident, correlate

MODEL, VERSION, FEATURE_VERSION = "rules", "baseline-v1", "rules-v1"


def load(conn: psycopg.Connection, capture_id: str) -> tuple[pd.DataFrame, pd.DataFrame]:
    """The flows and events of one capture, as tables for rules.correlate()."""
    cur = conn.execute("SELECT flow_id, ts_start AS ts, host(src_ip) AS src_ip, host(dst_ip) AS dst_ip, dst_port, "
                       "proto, resp_pkts, conn_state, bwd_flags, device_id FROM flows WHERE capture_id = %s",
                       (capture_id,))
    flows = pd.DataFrame(cur.fetchall(), columns=[d.name for d in cur.description])
    cur = conn.execute("SELECT ts, host(src_ip) AS src_ip, event_type, device_id FROM events "
                       "WHERE capture_id = %s AND src_ip IS NOT NULL", (capture_id,))
    events = pd.DataFrame(cur.fetchall(), columns=[d.name for d in cur.description])
    return flows, events


def run(conn: psycopg.Connection, capture_id: str) -> list[Incident]:
    flows, events = load(conn, capture_id)
    return correlate(flows, events)


def save(conn: psycopg.Connection, capture_id: str, incidents: list[Incident]) -> int:
    """Replace this capture's rule alerts with `incidents`. Returns how many were saved."""
    ours = {d for (d,) in conn.execute("SELECT device_id FROM devices")}
    with conn.transaction():
        conn.execute("INSERT INTO model_versions (model_name, version, feature_version, threshold, metrics, is_active) "
                     "VALUES (%s, %s, %s, 1.0, %s, FALSE) ON CONFLICT (model_name, version) DO UPDATE "
                     "SET metrics = EXCLUDED.metrics",
                     (MODEL, VERSION, FEATURE_VERSION,
                      Jsonb({"thresholds": {r: t for r, (t, _, _) in RULES.items()}, "bucket_s": 60})))
        conn.execute("DELETE FROM alerts WHERE model_name = %s AND evidence->>'capture' = %s", (MODEL, capture_id))
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
    return len(incidents)


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
