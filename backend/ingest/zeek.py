"""pcap -> Zeek -> conn.log -> flows table, in one command.

    cd backend
    .venv/Scripts/python -m ingest.zeek samples/cap-2026-11-20-a.pcap --capture cap-2026-11-20-a --label

Or load a conn.log that Zeek already wrote (for example from the live Zeek on the virtual Pi):

    .venv/Scripts/python -m ingest.zeek --conn-log samples/zeek/conn.log --capture cap-2026-11-20-a

Zeek runs in Docker (image zeek/zeek:8.0, the same as the team's live setup), so nothing has to be installed.
"""
from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import psycopg

from .db import connect, db_url
from .flows import load_conn_log
from .loader import LoadError, label_capture

ZEEK_IMAGE = "zeek/zeek:8.0"


class ZeekError(Exception):
    pass


def run_zeek(pcap: str | Path, out_dir: str | Path, image: str = ZEEK_IMAGE) -> Path:
    """Run Zeek on a pcap. All of Zeek's logs (conn.log, ssh.log, http.log, ...) land in out_dir.

    -C          ignore bad checksums (captures taken on the sending machine often have them)
    -r file     read a pcap instead of a live network interface
    use_json=T  write JSON lines, like the live setup
    """
    pcap, out_dir = Path(pcap).resolve(), Path(out_dir).resolve()
    if not pcap.is_file():
        raise ZeekError(f"pcap not found: {pcap}")
    if shutil.which("docker") is None:
        raise ZeekError("docker is not installed or not on PATH")
    out_dir.mkdir(parents=True, exist_ok=True)
    shutil.copy2(pcap, out_dir / pcap.name)            # Zeek sees only out_dir, mounted as /data
    cmd = ["docker", "run", "--rm", "-v", f"{out_dir}:/data", "-w", "/data", image,
           "zeek", "-C", "-r", pcap.name, "LogAscii::use_json=T"]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    (out_dir / pcap.name).unlink(missing_ok=True)
    if proc.returncode != 0:
        raise ZeekError(f"zeek failed (exit {proc.returncode}):\n{proc.stderr.strip() or proc.stdout.strip()}")
    conn_log = out_dir / "conn.log"
    if not conn_log.exists():
        raise ZeekError("zeek ran but wrote no conn.log (the pcap has no connections?)")
    return conn_log


def main() -> int:
    ap = argparse.ArgumentParser(prog="python -m ingest.zeek", description=__doc__.splitlines()[0])
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("pcap", nargs="?", help="pcap file to run Zeek on")
    src.add_argument("--conn-log", help="skip Zeek and load an existing conn.log")
    ap.add_argument("--capture", help="capture_id for every flow (must exist in the captures table)")
    ap.add_argument("--logs-dir", help="keep Zeek's logs in this folder (default: a temporary folder, deleted after)")
    ap.add_argument("--label", action="store_true", help="run label_capture for --capture after loading")
    ap.add_argument("--allow-outside-capture", action="store_true", help="save even if flows fall outside the capture's time range")
    a = ap.parse_args()
    if a.label and not a.capture:
        ap.error("--label needs --capture")

    tmp = None
    try:
        if a.conn_log:
            conn_log = Path(a.conn_log)
        else:
            out = Path(a.logs_dir) if a.logs_dir else Path(tmp := tempfile.mkdtemp(prefix="aegex-zeek-"))
            conn_log = run_zeek(a.pcap, out)
            print(f"zeek wrote: {', '.join(sorted(p.name for p in out.glob('*.log')))}")
        with connect() as conn:
            result = load_conn_log(conn, conn_log, a.capture, a.allow_outside_capture)
            print(f"{conn_log.name}:\n{result}")
            if a.label:
                label_capture(conn, a.capture)
                print(f"labeled capture {a.capture}")
    except (ZeekError, LoadError, FileNotFoundError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    except psycopg.OperationalError as exc:
        print(f"ERROR: can't reach the database at {db_url()}. Is Docker running?\n{exc}", file=sys.stderr)
        return 1
    finally:
        if tmp:
            shutil.rmtree(tmp, ignore_errors=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
