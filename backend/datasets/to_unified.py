"""Step 2 - the unified schema: public datasets -> our `flows` table, in a separate database `aegex_datasets`.

    cd backend
    $env:AEGEX_DATA = "C:\\aegex_data"
    .venv\\Scripts\\python -m datasets.to_unified --datasets kitsune                 # load what is in AEGEX_DATA
    .venv\\Scripts\\python -m datasets.to_unified --datasets xiiotid --max-rows 200000
    .venv\\Scripts\\python -m datasets.to_unified --show                             # what is loaded

Why: our honeypot traffic and the public datasets must look the same, so replay, correlation and evaluation
(steps 6-8) run the same code on both. Every connection becomes one row of the `flows` table
(database/schema_v2.sql); the mapping is written down in contracts/TASK_B_CONTRACT.md, section 2.1.

How, in 3 steps:
  1. each capture is read with the AI team's own adapter (ai-models/lstm-vae-gat/scripts/aegex_datasets) into
     their flow table (aegex_prep.FLOW_COLUMNS): the same reader the models were trained with
  2. every row is converted to our flows columns (to_rows); rows with an unusable IP address or time are
     dropped and counted
  3. one `captures` row per capture (dataset = the catalogue id) + its flows are saved. Running it again replaces
     that capture (no duplicates).

Why a separate database? Public datasets are millions of rows from networks that are not ours. In `aegex_poc`
they would mix with the honeypot's devices, dashboard and models. `aegex_datasets` has the same schema, and
the API / tools read it when AEGEX_DB_URL points at it.
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import math
import re
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import psycopg
from psycopg.conninfo import make_conninfo

from ingest.db import connect, db_url
from ingest.flows import make_flow_id

from . import analyze

DATASETS_DB = "aegex_datasets"
REPO = Path(__file__).resolve().parents[2]
SCHEMA = REPO / "database" / "schema_v2.sql"
DEFAULT_MAX_ROWS = 1_000_000          # per capture: keeps a laptop's disk safe; the first N connections in time

# AI team's attack class -> our `scenario` vocabulary (attack_runs.scenario). Same words as detect.py's SCENARIO.
SCENARIO = {"benign": None, "scanning": "vulnerability_scanning", "ddos": "dos", "mirai": "mirai_botnet",
            "ransomware": "ransomware", "other": "other"}

COLUMNS = ("flow_id", "ts_start", "ts_end", "capture_id", "src_ip", "src_port", "dst_ip", "dst_port", "proto",
           "duration_s", "orig_bytes", "resp_bytes", "orig_pkts", "resp_pkts", "fwd_flags", "bwd_flags",
           "label", "scenario", "attack_class", "label_info")


# --------------------------------------------------------------------------- database
def datasets_url(base: str | None = None) -> str:
    return make_conninfo(base or db_url(), dbname=DATASETS_DB)


def setup(base_url: str | None = None) -> str:
    """Create aegex_datasets if missing and apply the schema (safe to run again). Returns its URL."""
    with connect(base_url, connect_timeout=3) as admin:
        if not admin.execute("SELECT 1 FROM pg_database WHERE datname = %s", (DATASETS_DB,)).fetchone():
            admin.execute(f"CREATE DATABASE {DATASETS_DB}")
            print(f"created database {DATASETS_DB}")
    url = datasets_url(base_url)
    with connect(url) as conn:
        conn.execute(SCHEMA.read_text(encoding="utf-8"))
    return url


# --------------------------------------------------------------------------- convert
def capture_id(dataset: str, capture: str) -> str:
    """'kitsune', 'mirai' -> 'ds-kitsune-mirai' (lower case, safe characters only)."""
    return "ds-" + re.sub(r"[^a-z0-9_.-]+", "-", f"{dataset}-{capture}".lower()).strip("-")


def _ip(v) -> str | None:
    try:
        return str(ipaddress.ip_address(str(v).strip()))
    except ValueError:
        return None


def _num(v, kind=int):
    if v is None or (isinstance(v, float) and math.isnan(v)):
        return None
    return kind(v)


def _port(v) -> int | None:
    p = _num(v)
    return p if p is not None and 0 <= p <= 65535 else None


def _text(v) -> str:
    return "" if v is None or (isinstance(v, float) and math.isnan(v)) else str(v)


def to_rows(df, cap_id: str) -> tuple[list[tuple], dict]:
    """AI team's flow table -> our flows rows (tuples in COLUMNS order). Returns (rows, counts of dropped rows)."""
    ips = {v: _ip(v) for v in set(df["src_ip"].dropna()) | set(df["dst_ip"].dropna())}
    dropped = {"bad_ip": 0, "bad_time": 0, "duplicate": 0}
    seen: set = set()
    rows = []
    for r in df.itertuples(index=False):
        src, dst = ips.get(r.src_ip), ips.get(r.dst_ip)
        if src is None or dst is None:
            dropped["bad_ip"] += 1
            continue
        ts = _num(r.ts, float)
        if ts is None:
            dropped["bad_time"] += 1
            continue
        start = datetime.fromtimestamp(ts, timezone.utc)
        te = _num(r.ts_end, float)
        end = datetime.fromtimestamp(te, timezone.utc) if te is not None and te >= ts else None
        proto, sport, dport = _text(r.proto).lower() or "other", _port(r.src_port), _port(r.dst_port)
        fid = make_flow_id(start, proto, src, sport, dst, dport)
        if (fid, start) in seen:                   # same start time + 5-tuple twice: keep the first
            dropped["duplicate"] += 1
            continue
        seen.add((fid, start))
        cls = _text(r.attack_class) or ("benign" if int(r.is_attack) == 0 else "other")
        info = {k: _text(getattr(r, k, "")) for k in ("original_label", "label_note", "campaign")}
        info = {k: v for k, v in info.items() if v}
        mal = _num(getattr(r, "mal_frac", None), float)
        if mal is not None and 0 < mal < 1:        # only interesting when the packets were mixed
            info["mal_frac"] = round(mal, 4)
        rows.append((fid, start, end, cap_id, src, sport, dst, dport, proto,
                     _num(r.duration, float), _num(r.fwd_bytes), _num(r.bwd_bytes), _num(r.fwd_pkts),
                     _num(r.bwd_pkts), _num(r.fwd_flags), _num(r.bwd_flags),
                     int(r.is_attack), SCENARIO.get(cls, "other"), cls, json.dumps(info) if info else None))
    return rows, dropped


# --------------------------------------------------------------------------- save
def save(conn: psycopg.Connection, dataset: str, cap_id: str, rows: list[tuple], notes: str) -> int:
    """One capture: its captures row + its flows, all or nothing. A re-run replaces the capture's flows."""
    if not rows:
        return 0
    start = min(r[1] for r in rows)
    end = max((r[2] or r[1]) for r in rows)
    if end <= start:                               # the captures table needs end > start
        end = start + timedelta(microseconds=1)
    attacks = sum(r[16] for r in rows)
    kind = "attack" if attacks == len(rows) else "normal_only" if attacks == 0 else "mixed"
    with conn.transaction():
        conn.execute("INSERT INTO captures (capture_id, start_ts, end_ts, kind, notes, dataset) "
                     "VALUES (%s, %s, %s, %s, %s, %s) ON CONFLICT (capture_id) DO UPDATE SET start_ts = EXCLUDED.start_ts, "
                     "end_ts = EXCLUDED.end_ts, kind = EXCLUDED.kind, notes = EXCLUDED.notes, dataset = EXCLUDED.dataset",
                     (cap_id, start, end, kind, notes, dataset))
        conn.execute("DELETE FROM flows WHERE capture_id = %s", (cap_id,))
        with conn.cursor().copy(f"COPY flows ({', '.join(COLUMNS)}) FROM STDIN") as cp:
            for r in rows:
                cp.write_row(r)
    return len(rows)


def load_dataset(conn: psycopg.Connection, reg, dataset: str, max_rows: int, log=print) -> dict:
    """Every capture of one dataset whose files are in AEGEX_DATA -> the database."""
    mod = reg.get(dataset)
    if hasattr(mod, "run"):
        log(f"{dataset}: streaming adapter (too big for one table), not loaded; use the AI team's step1_flows.py")
        return {}
    out = {}
    for cap in mod.captures():
        t = time.time()
        try:
            df, _ = mod.build(cap)
        except FileNotFoundError as e:
            log(f"  [{dataset}/{cap}] skipped: {str(e).split(' not found')[0]} not in the data folder")
            continue
        total = len(df)
        df = df.sort_values("ts", kind="stable").head(max_rows)
        cap_id = capture_id(dataset, str(cap))
        rows, dropped = to_rows(df, cap_id)
        part = f"first {len(df):,} of {total:,} connections" if total > len(df) else f"all {total:,} connections"
        notes = f"{getattr(mod, 'TITLE', dataset)} / {cap}: public dataset, {part} (datasets.to_unified)"
        n = save(conn, dataset, cap_id, rows, notes)
        out[cap_id] = {"connections": total, "loaded": n, "attacks": sum(r[16] for r in rows), **dropped}
        log(f"  [{dataset}/{cap}] {n:,} flows saved as {cap_id} ({part}; dropped {dropped}) in {time.time() - t:.0f} s")
    return out


def show(conn: psycopg.Connection) -> list[tuple]:
    """What is loaded: one line per dataset capture."""
    return conn.execute(
        "SELECT c.dataset, c.capture_id, count(f.*) AS flows, count(*) FILTER (WHERE f.label = 1) AS attacks, "
        "       string_agg(DISTINCT f.attack_class, ', ') AS classes, min(f.ts_start), max(f.ts_start) "
        "FROM captures c LEFT JOIN flows f ON f.capture_id = c.capture_id "
        "WHERE c.dataset IS NOT NULL GROUP BY c.dataset, c.capture_id ORDER BY c.dataset, c.capture_id").fetchall()


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    p.add_argument("--datasets", nargs="+", help="catalogue ids to load, e.g. kitsune xiiotid")
    p.add_argument("--data", type=Path, default=analyze.DEFAULT_DATA, help="folder with the originals (AEGEX_DATA)")
    p.add_argument("--max-rows", type=int, default=DEFAULT_MAX_ROWS, help="per capture, first N connections in time")
    p.add_argument("--show", action="store_true", help="only list what is loaded")
    p.add_argument("--no-compress", action="store_true",
                   help="leave the loaded rows uncompressed (default: compress, see ingest/datastore.py)")
    a = p.parse_args(argv)
    if not a.show and not a.datasets:
        p.error("give --datasets (e.g. --datasets kitsune) or --show")
    try:
        url = setup()
    except psycopg.OperationalError as exc:
        print(f"ERROR: the database server is not reachable ({exc.__class__.__name__}). Start Docker first.")
        return 1
    with connect(url) as conn:
        if not a.show:
            if not a.data.is_dir():
                p.error(f"data folder {a.data} does not exist (set AEGEX_DATA or pass --data)")
            reg = analyze.load_adapters(a.data)
            for ds in a.datasets:
                print(f"{ds}:")
                load_dataset(conn, reg, ds, a.max_rows)
            if not a.no_compress:
                from ingest.datastore import compress, mb
                for table, (n, before, after) in compress(conn).items():
                    if n:
                        print(f"compressed {table}: {mb(before)} -> {mb(after)}")
        print(f"\n{DATASETS_DB}: loaded dataset captures")
        for ds, cap, n, att, classes, t0, t1 in show(conn):
            span = f"{t0:%Y-%m-%d %H:%M} -> {t1:%H:%M}" if t0 else "-"
            print(f"  {ds:<9} {cap:<28} {n:>10,} flows  {att:>9,} attacks  [{classes or '-'}]  {span}")
    print(f'\nRead it with the API / tools:  $env:AEGEX_DB_URL = "postgresql://aegex:aegex@127.0.0.1:5433/{DATASETS_DB}"')
    return 0


if __name__ == "__main__":
    sys.exit(main())
