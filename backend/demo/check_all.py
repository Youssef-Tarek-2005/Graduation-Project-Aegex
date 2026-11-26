"""End-to-end check of the whole backend, steps 1 to 11, in order, with one command.

    cd backend
    .venv/Scripts/python -m demo.check_all            # about 1 minute
    .venv/Scripts/python -m demo.check_all --keep     # keep the aegex_e2e database afterwards, to look around

It builds a separate, throw-away database called `aegex_e2e` on the same server, so your real `aegex` data is
never touched. Then it does what the lab will do, step by step, and checks each result: create the tables, add
the lab inventory, parse the sample logs, load them, run Zeek on the sample pcap, load the attack log and label,
build flow and window features, build the dataset for C and D, then start the real API and use it over HTTP
like a device and the dashboard would. Each step prints PASS or FAIL with what it saw.

The unit tests (`python -m pytest`) test each piece alone; this checks that the pieces work together.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import socket
import sys
import tempfile
import threading
import time
import traceback
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path

import psycopg
from psycopg.conninfo import make_conninfo

BACKEND = Path(__file__).resolve().parents[1]
REPO = BACKEND.parent
SAMPLES = BACKEND / "samples"
CAP = "cap-2026-11-20-a"
E2E_DB = "aegex_e2e"


@dataclass
class Step:
    number: str
    title: str
    lines: list[str] = field(default_factory=list)
    failures: list[str] = field(default_factory=list)

    def check(self, ok: bool, what: str) -> bool:
        (self.lines if ok else self.failures).append(what)
        return ok

    def note(self, what: str) -> None:
        self.lines.append(what)


class Run:
    def __init__(self) -> None:
        self.steps: list[Step] = []

    def step(self, number: str, title: str, fn, *args) -> None:
        s = Step(number, title)
        print(f"\nSTEP {number}  {title}", flush=True)
        started = time.time()
        try:
            fn(s, *args)
        except Exception as exc:                                    # one broken step doesn't hide the others
            s.failures.append(f"crashed: {type(exc).__name__}: {exc}")
            traceback.print_exc(limit=3)
        for line in s.lines:
            print(f"    ok    {line}")
        for line in s.failures:
            print(f"    FAIL  {line}")
        print(f"  -> {'PASS' if not s.failures else 'FAIL'}  ({time.time() - started:.1f} s)", flush=True)
        self.steps.append(s)


def count(conn, table: str, where: str = "TRUE", params=()) -> int:
    return conn.execute(f"SELECT count(*) FROM {table} WHERE {where}", params).fetchone()[0]


# ------------------------------------------------------------------------------------------- phase 1
def step1_database(s: Step, ctx: dict) -> None:
    from ingest.db import connect, db_url
    with connect(connect_timeout=3) as admin:
        admin.execute(f"DROP DATABASE IF EXISTS {E2E_DB} WITH (FORCE)")
        admin.execute(f"CREATE DATABASE {E2E_DB}")
    s.note(f"server reachable at {db_url().split('@')[-1]}, fresh database {E2E_DB} created")
    ctx["admin_url"] = db_url()
    ctx["url"] = make_conninfo(db_url(), dbname=E2E_DB)
    conn = ctx["conn"] = connect(ctx["url"])
    conn.execute((REPO / "database" / "schema_v2.sql").read_text(encoding="utf-8"))
    version = conn.execute("SELECT extversion FROM pg_extension WHERE extname = 'timescaledb'").fetchone()
    s.check(version is not None, f"TimescaleDB extension {version[0] if version else 'MISSING'}")
    tables = {r[0] for r in conn.execute("SELECT tablename FROM pg_tables WHERE schemaname = 'public'")}
    expected = {"devices", "captures", "attack_runs", "events", "flows", "feature_windows", "model_versions",
                "alerts", "reports"}
    s.check(expected <= tables, f"the 9 tables exist: {', '.join(sorted(expected & tables))}")
    hyper = {r[0] for r in conn.execute("SELECT hypertable_name FROM timescaledb_information.hypertables")}
    s.check({"events", "flows", "feature_windows"} <= hyper, f"time-series tables are hypertables: {sorted(hyper)}")


def step2_seed(s: Step, ctx: dict) -> None:
    conn = ctx["conn"]
    conn.execute((BACKEND / "sql" / "seed_lab.sql").read_text(encoding="utf-8"))
    devices = [r[0] for r in conn.execute("SELECT device_id FROM devices ORDER BY 1")]
    s.check(devices == ["cam-01", "esp32-smoke-01", "gw-01"], f"3 devices: {', '.join(devices)}")
    s.check(count(conn, "captures") == 1, f"1 capture: {CAP} (14:00-15:00 UTC)")
    s.check(count(conn, "attack_runs") == 1, "1 attack run: run-001, hydra brute force 14:10-14:18")


# ------------------------------------------------------------------------------------------- phase 2
LOGS = [("cowrie", "cowrie.json", "gw-01", {}, 11),
        ("mosquitto", "mosquitto.log", "gw-01", {"broker_ip": "192.168.56.10"}, 4),
        ("esp32", "esp32.csv", "esp32-smoke-01", {"device_ip": "192.168.56.20"}, 4)]


def step3_parsers(s: Step, ctx: dict) -> None:
    from ingest.parsers import build_parser
    for source, file, device, opts, expected in LOGS:
        parser = build_parser(source, device, **opts)
        events = parser.parse_file(SAMPLES / file)
        s.check(len(events) == expected, f"{source:<9} {parser.stats}")
    layers = {e.layer for e in build_parser("cowrie", "gw-01").parse_file(SAMPLES / "cowrie.json")}
    s.check(layers == {"session_interaction"}, "every event gets its layer from the contract")


def step4_loader(s: Step, ctx: dict) -> None:
    from ingest.loader import LoadError, load_file
    from ingest.parsers import build_parser
    conn = ctx["conn"]
    for source, file, device, opts, expected in LOGS:
        r = load_file(conn, build_parser(source, device, **opts), SAMPLES / file, CAP)
        s.check(r.inserted == expected, f"{source:<9} saved {r.inserted} rows")
    again = sum(load_file(conn, build_parser(src, dev, **o), SAMPLES / f, CAP).inserted for src, f, dev, o, _ in LOGS)
    s.check(again == 0, f"loading the same files again adds {again} rows (no duplicates)")
    try:
        load_file(conn, build_parser("esp32", "esp32-smoke-01", device_ip="192.168.56.20", tz="Asia/Tokyo"),
                  SAMPLES / "esp32.csv", CAP)
        s.check(False, "a file in the wrong time zone should be refused")
    except LoadError:
        s.check(True, "a file in the wrong time zone is refused (events would fall outside the capture)")
    s.check(count(conn, "events") == 19, f"events table: {count(conn, 'events')} rows")


def step5_zeek(s: Step, ctx: dict, use_pcap: bool) -> None:
    from ingest.flows import load_conn_log
    conn = ctx["conn"]
    conn_log = SAMPLES / "zeek" / "conn.log"
    if use_pcap:
        from ingest.zeek import ZeekError, run_zeek
        out = Path(tempfile.mkdtemp(prefix="aegex_zeek_"))
        try:
            conn_log = run_zeek(SAMPLES / "cap-2026-11-20-a.pcap", out)
            s.note("Zeek (Docker) ran on samples/cap-2026-11-20-a.pcap and wrote conn.log")
        except ZeekError as exc:
            s.note(f"Zeek could not run ({exc}); using the saved samples/zeek/conn.log instead")
    else:
        s.note("--no-zeek: using the saved samples/zeek/conn.log")
    r = load_conn_log(conn, conn_log, CAP)
    s.check(r.inserted > 0, f"{r.parse}; saved {r.inserted} flows, {r.with_device} touch a honeypot device")
    s.check(load_conn_log(conn, conn_log, CAP).inserted == 0, "loading conn.log again adds 0 flows")
    row = conn.execute("SELECT service, conn_state, orig_bytes FROM flows WHERE dst_port = 22 LIMIT 1").fetchone()
    s.check(row is not None and row[0] == "ssh", f"an SSH flow has service/conn_state/bytes: {row}")


def step6_labels(s: Step, ctx: dict) -> None:
    from ingest.attacks import AttackLogError, check_attack_log, label_report, load_attack_log
    from ingest.loader import label_capture
    conn = ctx["conn"]
    try:
        check_attack_log(conn, SAMPLES / "attack_log_mistakes.csv", CAP)
        s.check(False, "the attack log with mistakes should be refused")
    except AttackLogError as exc:
        s.check(len(exc.problems) >= 7, f"attack log with 7 wrong rows refused as a whole, {len(exc.problems)} problems listed")
    result = load_attack_log(conn, SAMPLES / "attack_log.csv", CAP)
    s.check(count(conn, "attack_runs") == 1, f"good attack log accepted: {result.runs} run(s)")
    label_capture(conn, CAP)
    report = label_report(conn, CAP)
    s.check(report.events.get(1) == 11, f"events: {report.events.get(1, 0)} attack, {report.events.get(0, 0)} normal")
    s.check(report.flows.get(1, 0) > 0, f"flows:  {report.flows.get(1, 0)} attack, {report.flows.get(0, 0)} normal")
    s.check(not report.warnings, "label report: every run matched traffic, no attacker traffic outside a run"
            if not report.warnings else f"warnings: {report.warnings}")


# ------------------------------------------------------------------------------------------- phase 3
def step7_flow_features(s: Step, ctx: dict) -> None:
    from features.build import build_flow_features, check_flow_features
    conn = ctx["conn"]
    s.note(str(build_flow_features(conn, CAP)))
    check = check_flow_features(conn, CAP)
    s.check(check.ok, f"{check.rows} flows x {check.n_features} features, no missing values"
            if check.ok else f"problems: {check.problems[:3]}")


def step8_window_features(s: Step, ctx: dict) -> None:
    from features.build import build_window_features, check_window_features
    conn = ctx["conn"]
    r = build_window_features(conn, CAP)
    s.check(r.windows == 1080, f"{r.windows} windows = 3 devices x 360 windows of 10 s (silence counts too)")
    s.check(r.attack > 0, f"{r.active} windows with activity, {r.attack} labeled attack")
    check = check_window_features(conn, CAP)
    s.check(check.ok, f"every window has the {check.n_features} contract features" if check.ok
            else f"problems: {check.problems[:3]}")


def step9_dataset(s: Step, ctx: dict) -> None:
    import numpy as np
    from demo import fake_lab
    from features.dataset import build_dataset
    conn = ctx["conn"]
    work = Path(tempfile.mkdtemp(prefix="aegex_e2e_"))
    ids = fake_lab.build(conn, work / "fake_lab", quiet=True)
    s.check(len(ids) == 6, f"fake lab: {len(ids)} more captures generated and loaded through steps 4-8 "
            f"({ids[0]} .. {ids[-1]})")
    data, artifacts = work / "processed", work / "artifacts"
    summary = build_dataset(conn, data, artifacts)
    for name, part in summary["splits"].items():
        shape = part["X_shape"]
        s.check(len(shape) == 3 and shape[1:] == [30, 24],
                f"{name:<5} {', '.join(part['captures'])}: X {shape}, {part['attack_sequences']} attack sequences")
    scenarios = {name for _, _, attacks in fake_lab.CAPTURES for name, _ in attacks}
    s.check(set(summary["splits"]["test"]["scenarios"]) == scenarios,
            f"test split holds every scenario: {summary['splits']['test']['scenarios']}")
    files = ["flows.parquet", "windows.parquet", "nodes.parquet", "sequences_train.npz", "edges_train.parquet"]
    s.check(all((data / f).exists() for f in files), "files for C and D written: " + ", ".join(files))
    s.check(all((artifacts / f).exists() for f in ("window_scaler.joblib", "flow_scaler.joblib", "feature_order.json")),
            "scalers + feature_order.json written")
    X = np.load(data / "sequences_train.npz")["X"]
    s.check(X.dtype == np.float32 and not np.isnan(X).any(), "sequences are float32 with no NaN")
    s.note(f"(written to a temporary folder, not to data/processed: {work})")


# ------------------------------------------------------------------------------------------- phase 4
def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def start_api(ctx: dict) -> str:
    import uvicorn
    os.environ["AEGEX_DB_URL"] = ctx["url"]                     # the API uses the e2e database
    port = free_port()
    server = uvicorn.Server(uvicorn.Config("api.main:app", host="127.0.0.1", port=port, log_level="warning"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    for _ in range(100):
        if server.started:
            break
        time.sleep(0.1)
    ctx["server"], ctx["thread"] = server, thread
    return f"http://127.0.0.1:{port}"


def step10_api_in(s: Step, ctx: dict) -> None:
    import httpx
    base = ctx["base"] = start_api(ctx)
    conn = ctx["conn"]
    s.note(f"real API started on {base} (same code as port 8001), talking to {E2E_DB}")
    h = httpx.get(f"{base}/health").json()
    s.check(h["status"] == "ok" and h["database"] == "ok", f"/health: {h['status']}, TimescaleDB {h['timescaledb']}")

    now = datetime.now(timezone.utc).replace(microsecond=0)
    live = {"capture_id": "cap-e2e-live", "start_ts": (now - timedelta(minutes=5)).isoformat(), "kind": "live"}
    s.check(httpx.post(f"{base}/api/v1/captures", json=live).status_code == 201, "POST /captures: a live capture opened")
    r = httpx.post(f"{base}/api/v1/ingest/sensor", json={"device_id": "esp32-smoke-01", "smoke": 14.0,
                                                          "temperature_c": 24.5, "humidity_pct": 40.0}).json()
    s.check(r["inserted"] == 1 and r["captures"] == {"cap-e2e-live": 1},
            "POST /ingest/sensor (no clock on the sensor): saved with server time, into the live capture")
    event = {"ts": now.isoformat(), "source": "cowrie", "event_type": "login_failed", "device_id": "gw-01",
             "src_ip": "192.168.56.77", "dst_ip": "192.168.56.10", "dst_port": 22, "proto": "tcp",
             "payload": {"username": "admin", "password": "1234", "session": "e2e"}}
    s.check(httpx.post(f"{base}/api/v1/ingest/events", json=event).json()["inserted"] == 1, "POST /ingest/events: saved")
    s.check(httpx.post(f"{base}/api/v1/ingest/events", json=[event]).json()["duplicates"] == 1,
            "the same event sent again: counted as duplicate, not saved twice")
    before = count(conn, "events")
    bad = httpx.post(f"{base}/api/v1/ingest/events", json=[event, {**event, "device_id": "cam-9"}])
    s.check(bad.status_code == 422 and count(conn, "events") == before,
            f"a batch with one bad event: 422, nothing saved ({bad.json()['detail']['problems'][0]})")
    log = httpx.post(f"{base}/api/v1/ingest/logs/cowrie", params={"device_id": "gw-01", "capture_id": CAP},
                     content=(SAMPLES / "cowrie.json").read_text(encoding="utf-8"),
                     headers={"Content-Type": "text/plain"}).json()
    s.check(log["parsed"] == 11 and log["inserted"] == 0,
            f"POST /ingest/logs/cowrie: raw log parsed ({log['parsed']} events), all already saved in step 4")
    run = {"run_id": "run-001", "capture_id": CAP, "scenario": "bruteforce", "tool": "hydra",
           "command": "hydra -l root -P passwords.txt ssh://192.168.56.10", "attacker_ip": "192.168.56.99",
           "target_device": "gw-01", "start_ts": "2026-11-20T14:10:00Z", "end_ts": "2026-11-20T14:18:00Z"}
    s.check(httpx.post(f"{base}/api/v1/attack-runs", json=run).json()["unchanged"] == ["run-001"],
            "POST /attack-runs: the same run again is 'unchanged'")


def step11_api_out(s: Step, ctx: dict) -> None:
    import httpx
    base, conn = ctx["base"], ctx["conn"]
    get = lambda path, **p: httpx.get(f"{base}/api/v1{path}", params=p, timeout=30).json()   # noqa: E731
    s.check(get("/devices")["count"] == 3, "GET /devices: 3 devices")
    s.check(get("/captures", limit=100)["count"] == 8, "GET /captures: 8 (sample + 6 fake lab + 1 live)")
    items, cursor, pages = [], None, 0
    while True:
        page = get("/events", limit=500, **({"cursor": cursor} if cursor else {}))
        items += page["items"]
        pages += 1
        cursor = page["next_cursor"]
        if not cursor:
            break
    total = count(conn, "events")
    s.check(len(items) == total and len({e["event_id"] for e in items}) == total,
            f"GET /events, following next_cursor: all {total} events in {pages} pages, none twice")
    s.check(get("/events", capture_id=CAP, label=1)["count"] == 11, "GET /events?label=1: the 11 brute-force events")
    w = get("/features/windows", capture_id=CAP, limit=5000)
    s.check(w["count"] == 1080 and len(w["items"][0]["features"]) == 24, "GET /features/windows: 1080 windows x 24")
    e = get("/graph/edges", capture_id=CAP, limit=5000)
    s.check(e["count"] == count(conn, "flows", "capture_id = %s", (CAP,)) and len(e["items"][0]["features"]) == 41,
            f"GET /graph/edges: {e['count']} edges x 41 features, nodes like {e['items'][0]['src_node']}")
    summary = get("/stats/summary", capture_id=CAP)
    s.check(summary["events"] == 19 and summary["labels"]["attack"] == 11,
            f"GET /stats/summary (dashboard cards): {summary['events']} events, {summary['flows']} flows")
    hist = get("/stats/events-histogram", **{"from": "2026-11-20T14:00:00Z", "to": "2026-11-20T15:00:00Z"})
    s.check(sum(sum(x["data"]) for x in hist["series"]) == 19, "GET /stats/events-histogram: 60 bars, 19 events")
    live = get("/stats/sensors", **{"from": (datetime.now(timezone.utc) - timedelta(minutes=10)).isoformat()})
    s.check(len(live["labels"]) == 1, "GET /stats/sensors: the reading sent in step 10 shows up (live data)")
    page = (REPO / "frontend" / "dashboard_new.html").read_text(encoding="utf-8")
    s.check("localhost:8001" in page, "frontend/dashboard_new.html points at the new API (8001)")


# ------------------------------------------------------------------------------------------- run
def main() -> int:
    ap = argparse.ArgumentParser(description="Check the whole backend, steps 1-11, on a throw-away database.")
    ap.add_argument("--keep", action="store_true", help=f"keep the {E2E_DB} database afterwards")
    ap.add_argument("--no-zeek", action="store_true", help="use the saved conn.log instead of running Zeek (Docker)")
    args = ap.parse_args()
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    ctx: dict = {}
    run = Run()
    print(f"AEGEX backend: end-to-end check on a throw-away database ({E2E_DB}). Your 'aegex' data is not touched.")
    run.step("1", "Database: TimescaleDB + the 9 tables", step1_database, ctx)
    if "conn" not in ctx:
        print("\nThe database is not reachable: start it (docker compose up -d) and run again.")
        return 1
    run.step("2", "Lab inventory: devices, capture, attack run", step2_seed, ctx)
    run.step("3", "Parsers: log lines -> events", step3_parsers, ctx)
    run.step("4", "Loader: events -> database, no duplicates", step4_loader, ctx)
    run.step("5", "Zeek: pcap -> conn.log -> flows", step5_zeek, ctx, not args.no_zeek)
    run.step("6", "Attack log + labels", step6_labels, ctx)
    run.step("7", "Flow features (41 per connection)", step7_flow_features, ctx)
    run.step("8", "Window features (24 per device per 10 s)", step8_window_features, ctx)
    run.step("9", "Fake lab + split + scalers + files for C and D", step9_dataset, ctx)
    run.step("10", "API in: health, captures, sensor, events, raw logs, attack runs", step10_api_in, ctx)
    run.step("11", "API out: lists, pages, features, graph, dashboard summaries", step11_api_out, ctx)

    if "server" in ctx:
        ctx["server"].should_exit = True
        ctx["thread"].join(timeout=10)
    ctx["conn"].close()
    if not args.keep:
        from ingest.db import connect
        with connect(ctx["admin_url"]) as admin:
            admin.execute(f"DROP DATABASE IF EXISTS {E2E_DB} WITH (FORCE)")

    failed = [s for s in run.steps if s.failures]
    print("\n" + "=" * 72)
    for s in run.steps:
        print(f"  step {s.number:>2}  {'PASS' if not s.failures else 'FAIL'}  {s.title}")
    print("=" * 72)
    print("ALL STEPS PASS" if not failed else f"{len(failed)} STEP(S) FAILED: " + ", ".join(s.number for s in failed))
    if args.keep:
        print(f"The {E2E_DB} database was kept.")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
