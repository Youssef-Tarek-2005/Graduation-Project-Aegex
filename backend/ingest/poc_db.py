"""Create (or update) the database for the proof-of-concept lab: laptop hotspot + ESP32-S3.

    .venv/Scripts/python -m ingest.poc_db --esp32-ip 192.168.137.57     # first time, or when the ESP32's IP changes
    .venv/Scripts/python -m ingest.poc_db                               # just show what is in it

Why a separate database? The old sample lab (gw-01, esp32-smoke-01, cam-01, the fake lab captures) lives in
`aegex`. Every monitored device gets a feature window every 10 s of every capture, so if the two labs shared one
database, each real recording would also get silent windows for three devices that don't exist in it, and the
models would learn from them. In `aegex_poc` there is only the ESP32-S3 (monitored) and the laptop (known, but
not monitored).

Safe to run again: it never deletes data. Afterwards, point every terminal at it (PowerShell):

    $env:AEGEX_DB_URL = "postgresql://aegex:aegex@127.0.0.1:5433/aegex_poc"
"""
from __future__ import annotations

import argparse
import ipaddress
import sys
from pathlib import Path

import psycopg
from psycopg.conninfo import make_conninfo

from .db import connect, db_url

POC_DB = "aegex_poc"
HOTSPOT = ipaddress.ip_network("192.168.137.0/24")
REPO = Path(__file__).resolve().parents[2]
SCHEMA = REPO / "database" / "schema_v2.sql"
SEED = REPO / "backend" / "sql" / "seed_poc.sql"


def poc_url(base: str | None = None) -> str:
    return make_conninfo(base or db_url(), dbname=POC_DB)


def setup(esp32_ip: str | None = None, base_url: str | None = None) -> str:
    """Create aegex_poc if missing, apply the schema and the PoC devices, set the ESP32's IP. Returns its URL."""
    with connect(base_url, connect_timeout=3) as admin:
        if not admin.execute("SELECT 1 FROM pg_database WHERE datname = %s", (POC_DB,)).fetchone():
            admin.execute(f"CREATE DATABASE {POC_DB}")
            print(f"created database {POC_DB}")
    url = poc_url(base_url)
    with connect(url) as conn:
        conn.execute(SCHEMA.read_text(encoding="utf-8"))
        conn.execute(SEED.read_text(encoding="utf-8"))
        if esp32_ip:
            conn.execute("UPDATE devices SET ip = %s WHERE device_id = 'esp32s3-01'", (esp32_ip,))
    return url


def main() -> int:
    ap = argparse.ArgumentParser(description="Create / update the proof-of-concept database (laptop + ESP32-S3).")
    ap.add_argument("--esp32-ip", help="the ESP32-S3's address on the laptop hotspot, e.g. 192.168.137.57 "
                                       "(see it in Windows: Settings > Mobile hotspot > connected devices)")
    a = ap.parse_args()
    if a.esp32_ip:
        try:
            ip = ipaddress.ip_address(a.esp32_ip)
        except ValueError:
            print(f"ERROR: {a.esp32_ip!r} is not an IP address")
            return 2
        if ip not in HOTSPOT or ip == HOTSPOT[1]:
            print(f"WARNING: {ip} is not a hotspot client address (192.168.137.2-254). "
                  "Saved anyway: use it only if your hotspot really uses another subnet.")
    try:
        url = setup(a.esp32_ip)
    except psycopg.OperationalError as exc:
        print(f"ERROR: the database server is not reachable ({exc.__class__.__name__}). Start it: docker compose up -d")
        return 1
    with connect(url) as conn:
        print(f"\n{POC_DB}: devices")
        for dev, typ, ip, mon in conn.execute("SELECT device_id, device_type, host(ip), monitored FROM devices "
                                              "ORDER BY device_id"):
            print(f"  {dev:<12} {typ:<13} {ip or '-':<16} {'monitored (feature windows)' if mon else 'known, not monitored'}")
        caps = conn.execute("SELECT count(*) FROM captures").fetchone()[0]
        events = conn.execute("SELECT count(*) FROM events").fetchone()[0]
        flows = conn.execute("SELECT count(*) FROM flows").fetchone()[0]
        print(f"  {caps} captures, {events} events, {flows} flows")
    print("\nUse it in every terminal (PowerShell), then start the API / tools as usual:")
    print(f'  $env:AEGEX_DB_URL = "postgresql://aegex:aegex@127.0.0.1:5433/{POC_DB}"')
    return 0


if __name__ == "__main__":
    sys.exit(main())
