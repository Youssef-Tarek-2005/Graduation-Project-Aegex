"""Load a log file into the database.

    cd backend
    .venv/Scripts/python -m ingest.load cowrie    samples/cowrie.json   --device gw-01 --capture cap-2026-11-20-a
    .venv/Scripts/python -m ingest.load mosquitto samples/mosquitto.log --device gw-01 --capture cap-2026-11-20-a --broker-ip 192.168.56.10
    .venv/Scripts/python -m ingest.load esp32     samples/esp32.csv     --device esp32-smoke-01 --capture cap-2026-11-20-a --tz UTC

Add --label to run the labeling procedure for the capture afterwards.
The database address comes from AEGEX_DB_URL (default: the local dev database on port 5433).
"""
from __future__ import annotations

import argparse
import sys

import psycopg

from .db import connect, db_url
from .loader import LoadError, label_capture, load_file
from .parsers import build_parser


def main() -> int:
    ap = argparse.ArgumentParser(prog="python -m ingest.load", description=__doc__.splitlines()[0])
    ap.add_argument("source", choices=["cowrie", "mosquitto", "esp32"])
    ap.add_argument("file")
    ap.add_argument("--device", help="device_id for every event (must exist in the devices table)")
    ap.add_argument("--capture", help="capture_id for every event (must exist in the captures table)")
    ap.add_argument("--broker-ip", help="mosquitto only: the broker's IP")
    ap.add_argument("--device-ip", help="esp32 only: the sensor's IP")
    ap.add_argument("--tz", default="UTC", help="esp32 only: time zone of the CSV time column (default UTC)")
    ap.add_argument("--label", action="store_true", help="run label_capture for --capture after loading")
    ap.add_argument("--allow-outside-capture", action="store_true",
                    help="save the file even if some events fall outside the capture's time range (normally refused)")
    a = ap.parse_args()

    if a.label and not a.capture:
        ap.error("--label needs --capture")

    parser = build_parser(a.source, a.device, broker_ip=a.broker_ip, device_ip=a.device_ip, tz=a.tz)
    try:
        with connect() as conn:
            result = load_file(conn, parser, a.file, capture_id=a.capture,
                               allow_outside_capture=a.allow_outside_capture)
            print(f"{a.file}:\n{result}")
            if a.label:
                label_capture(conn, a.capture)
                print(f"labeled capture {a.capture}")
    except LoadError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    except psycopg.OperationalError as exc:      # database not running / wrong address
        print(f"ERROR: can't reach the database at {db_url()}. Is Docker running?\n{exc}", file=sys.stderr)
        return 1
    except FileNotFoundError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
