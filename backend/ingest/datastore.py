"""Step 4 - the datastore: what is stored, how big it is, compression, backup and restore.

    cd backend
    .venv\\Scripts\\python -m ingest.datastore status                          # every aegex* database
    .venv\\Scripts\\python -m ingest.datastore compress --db aegex_datasets    # shrink a database's flows/events
    .venv\\Scripts\\python -m ingest.datastore backup --db aegex_poc           # -> backend/backups/aegex_poc_<time>.dump
    .venv\\Scripts\\python -m ingest.datastore restore backups\\aegex_poc_20261127-1500.dump --db aegex_poc_restored

The store itself is database/schema_v2.sql: PostgreSQL 16 + TimescaleDB, one schema in three databases:
    aegex            the sample lab (fake devices, sample captures)
    aegex_poc        the proof-of-concept lab: laptop hotspot + ESP32-S3 (the dashboard reads it)
    aegex_datasets   the public datasets (Step 2), the same tables

Compression (TimescaleDB): rows of finished time chunks are stored per column and per capture instead of row by
row, typically 10-20x smaller, and they can still be read, inserted, updated and deleted. It is switched on per
database, on purpose: `compress` is run by hand. aegex_datasets is history (2018-2020 traffic) and gets it right
after loading; for the honeypot databases use --older-than so this week's data stays uncompressed.
Rows are grouped by capture_id (the most common filter) and kept in time order.

Backup: pg_dump inside the database container (no PostgreSQL tools needed on Windows), one .dump file per
database. Restore always goes into a NEW database name, so a restore can never overwrite live data; switch to it
by pointing AEGEX_DB_URL at it.
"""
from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import psycopg
from psycopg.conninfo import make_conninfo

from .db import connect, db_url

BACKUPS = Path(__file__).resolve().parents[1] / "backups"
CONTAINER = os.environ.get("AEGEX_DB_CONTAINER", "aegex-db")
DATABASES = ("aegex", "aegex_poc", "aegex_datasets")
SMALL_TABLES = ("devices", "captures", "attack_runs", "model_versions", "alerts", "reports")
# how each hypertable is compressed: rows grouped by (segmentby), sorted by (orderby) inside a group
COMPRESSION = {
    "flows": ("capture_id", "ts_start DESC, flow_id"),
    "events": ("capture_id", "ts DESC, event_id"),
}
NAME = re.compile(r"^[a-z_][a-z0-9_]{0,62}$")


class DatastoreError(Exception):
    pass


def url_for(dbname: str, base: str | None = None) -> str:
    return make_conninfo(base or db_url(), dbname=dbname)


def mb(n: int | None) -> str:
    return "-" if n is None else f"{n / 1e6:,.1f} MB" if n < 1e9 else f"{n / 1e9:,.2f} GB"


def _check_name(name: str) -> str:
    if not NAME.match(name):
        raise DatastoreError(f"{name!r} is not a plain database name (lower case letters, digits, _)")
    return name


# --------------------------------------------------------------------------- status
def existing_databases(base: str | None = None) -> list[str]:
    with connect(base, connect_timeout=3) as c:
        names = {r[0] for r in c.execute("SELECT datname FROM pg_database WHERE datname LIKE 'aegex%'")}
    return [d for d in DATABASES if d in names] + sorted(names - set(DATABASES) - {"aegex_test", "aegex_e2e"})


def status(conn: psycopg.Connection) -> dict:
    """Sizes, rows, compression and time range of one database."""
    db = conn.execute("SELECT current_database(), pg_database_size(current_database())").fetchone()
    out = {"database": db[0], "bytes": db[1], "hypertables": [], "tables": {}, "datasets": []}
    for (name,) in conn.execute("SELECT hypertable_name FROM timescaledb_information.hypertables ORDER BY 1").fetchall():
        rows = conn.execute("SELECT approximate_row_count(%s::regclass)", (name,)).fetchone()[0]
        size = conn.execute("SELECT hypertable_size(%s::regclass)", (name,)).fetchone()[0]
        chunks, done = conn.execute(
            "SELECT count(*), count(*) FILTER (WHERE is_compressed) FROM timescaledb_information.chunks "
            "WHERE hypertable_name = %s", (name,)).fetchone()
        before = after = None
        if done:
            before, after = (int(v or 0) for v in conn.execute(
                "SELECT sum(before_compression_total_bytes), sum(after_compression_total_bytes) "
                "FROM hypertable_compression_stats(%s::regclass)", (name,)).fetchone())
        out["hypertables"].append({"table": name, "rows": int(rows), "bytes": int(size or 0), "chunks": chunks,
                                   "compressed_chunks": done, "before_compression": before,
                                   "after_compression": after})
    for t in SMALL_TABLES:
        out["tables"][t] = conn.execute(f"SELECT count(*) FROM {t}").fetchone()[0]
    rng = conn.execute("SELECT min(ts_start), max(ts_start) FROM flows").fetchone()
    out["flows_from"], out["flows_to"] = rng
    out["datasets"] = conn.execute(
        "SELECT coalesce(dataset, 'honeypot'), count(*) FROM captures GROUP BY 1 ORDER BY 1").fetchall()
    return out


def print_status(s: dict) -> None:
    print(f"\n{s['database']}: {mb(s['bytes'])}")
    for h in s["hypertables"]:
        comp = (f"{h['compressed_chunks']}/{h['chunks']} chunks compressed, {mb(h['before_compression'])} -> "
                f"{mb(h['after_compression'])}") if h["compressed_chunks"] else f"{h['chunks']} chunks, not compressed"
        print(f"  {h['table']:<16} {h['rows']:>12,} rows  {mb(h['bytes']):>10}   {comp}")
    print("  " + ", ".join(f"{t} {n:,}" for t, n in s["tables"].items()))
    if s["flows_from"]:
        print(f"  flows from {s['flows_from']:%Y-%m-%d %H:%M} to {s['flows_to']:%Y-%m-%d %H:%M} UTC")
    print("  captures: " + (", ".join(f"{d} {n}" for d, n in s["datasets"]) or "none"))


# --------------------------------------------------------------------------- compression
def enable_compression(conn: psycopg.Connection) -> None:
    """Switch compression on for flows and events (safe to run again)."""
    for table, (segment, order) in COMPRESSION.items():
        on = conn.execute("SELECT compression_enabled FROM timescaledb_information.hypertables "
                          "WHERE hypertable_name = %s", (table,)).fetchone()
        if on and not on[0]:
            conn.execute(f"ALTER TABLE {table} SET (timescaledb.compress, timescaledb.compress_segmentby = "
                         f"'{segment}', timescaledb.compress_orderby = '{order}')")


def compress(conn: psycopg.Connection, older_than: str | None = None) -> dict:
    """Compress the chunks of flows and events (only chunks older than `older_than`, e.g. '7 days', if given).
    Returns {table: (chunks compressed now, bytes before, bytes after)}."""
    enable_compression(conn)
    out = {}
    for table in COMPRESSION:
        chunks = conn.execute(
            "SELECT c FROM show_chunks(%s::regclass" + (", older_than => %s::interval" if older_than else "") + ") c",
            (table, older_than) if older_than else (table,)).fetchall()
        before = conn.execute("SELECT hypertable_size(%s::regclass)", (table,)).fetchone()[0] or 0
        n = 0
        for (chunk,) in chunks:
            if conn.execute("SELECT compress_chunk(%s::regclass, if_not_compressed => true)", (chunk,)).fetchone()[0]:
                n += 1
        after = conn.execute("SELECT hypertable_size(%s::regclass)", (table,)).fetchone()[0] or 0
        out[table] = (n, int(before), int(after))
    return out


# --------------------------------------------------------------------------- backup / restore
def _docker(args: list[str], **kw) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(["docker", "exec", *args], **kw)
    except FileNotFoundError:
        raise DatastoreError("the docker command was not found (is Docker Desktop installed and running?)") from None


def backup(dbname: str, out_dir: Path = BACKUPS, container: str = CONTAINER) -> Path:
    """pg_dump (custom format) of one database, run inside the container. Returns the .dump file."""
    _check_name(dbname)
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / f"{dbname}_{datetime.now(timezone.utc):%Y%m%d-%H%M%S}.dump"
    with open(path, "wb") as fh:
        r = _docker([container, "pg_dump", "-U", "aegex", "-Fc", "-d", dbname], stdout=fh, stderr=subprocess.PIPE)
    if r.returncode != 0 or path.stat().st_size == 0:
        path.unlink(missing_ok=True)
        raise DatastoreError(f"pg_dump of {dbname} failed: {r.stderr.decode(errors='replace').strip()[-500:]}")
    return path


def restore(dump: Path, target: str, base: str | None = None, container: str = CONTAINER) -> dict:
    """Restore a .dump into a NEW database `target` (refused if it exists). Returns row counts of the result."""
    _check_name(target)
    if not dump.is_file():
        raise DatastoreError(f"{dump} not found")
    with connect(base, connect_timeout=3) as admin:
        if admin.execute("SELECT 1 FROM pg_database WHERE datname = %s", (target,)).fetchone():
            raise DatastoreError(f"database {target} already exists: restore goes into a new name only "
                                 "(drop it yourself first if you really mean to replace it)")
        admin.execute(f"CREATE DATABASE {target}")
    url = url_for(target, base)
    with connect(url) as c:                         # TimescaleDB's documented restore procedure
        c.execute("CREATE EXTENSION IF NOT EXISTS timescaledb")
        c.execute("SELECT timescaledb_pre_restore()")
    with open(dump, "rb") as fh:
        r = _docker(["-i", container, "pg_restore", "-U", "aegex", "-d", target, "--no-owner"],
                    stdin=fh, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    with connect(url) as c:
        c.execute("SELECT timescaledb_post_restore()")
        counts = {t: c.execute(f"SELECT count(*) FROM {t}").fetchone()[0]
                  for t in ("captures", "flows", "events", "alerts")}
    errors = [ln for ln in r.stderr.decode(errors="replace").splitlines()
              if "error" in ln.lower() and "already exists" not in ln]
    if r.returncode != 0 and errors:
        raise DatastoreError(f"pg_restore into {target} reported errors: {' | '.join(errors[:5])}")
    return counts


# --------------------------------------------------------------------------- main
def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Step 4 datastore: status, compression, backup, restore.")
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("status", help="size, rows and compression of every aegex* database")
    s.add_argument("--db", help="only this database")
    c = sub.add_parser("compress", help="compress flows and events of one database")
    c.add_argument("--db", required=True)
    c.add_argument("--older-than", help="only chunks older than this, e.g. '7 days' (default: every chunk)")
    b = sub.add_parser("backup", help="pg_dump one database into backend/backups/")
    b.add_argument("--db", required=True)
    r = sub.add_parser("restore", help="restore a .dump into a NEW database")
    r.add_argument("dump", type=Path)
    r.add_argument("--db", required=True, help="name of the new database, e.g. aegex_poc_restored")
    a = ap.parse_args(argv)
    try:
        if a.cmd == "status":
            for name in ([a.db] if a.db else existing_databases()):
                with connect(url_for(_check_name(name))) as conn:
                    print_status(status(conn))
        elif a.cmd == "compress":
            with connect(url_for(_check_name(a.db))) as conn:
                t = time.time()
                for table, (n, before, after) in compress(conn, a.older_than).items():
                    print(f"{a.db}.{table}: {n} chunk(s) compressed, {mb(before)} -> {mb(after)}")
                print(f"done in {time.time() - t:.1f} s")
        elif a.cmd == "backup":
            path = backup(a.db)
            print(f"{a.db} -> {path} ({mb(path.stat().st_size)})")
        elif a.cmd == "restore":
            counts = restore(a.dump, a.db)
            print(f"restored into {a.db}: " + ", ".join(f"{t} {n:,}" for t, n in counts.items()))
            print(f'use it:  $env:AEGEX_DB_URL = "postgresql://aegex:aegex@127.0.0.1:5433/{a.db}"')
    except DatastoreError as exc:
        print(f"ERROR: {exc}")
        return 2
    except psycopg.OperationalError as exc:
        print(f"ERROR: the database server is not reachable ({exc.__class__.__name__}). Start Docker first.")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
