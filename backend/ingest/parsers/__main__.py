"""Try a parser on a file and print what comes out. Nothing is written to the database.

    cd backend
    .venv/Scripts/python -m ingest.parsers cowrie    samples/cowrie.json   --device gw-01
    .venv/Scripts/python -m ingest.parsers mosquitto samples/mosquitto.log --device gw-01 --broker-ip 192.168.56.10
    .venv/Scripts/python -m ingest.parsers esp32     samples/esp32.csv     --device esp32-smoke-01 --tz UTC
"""
from __future__ import annotations

import argparse
import json

from . import build_parser


def main() -> None:
    ap = argparse.ArgumentParser(prog="python -m ingest.parsers", description=__doc__.splitlines()[0])
    ap.add_argument("source", choices=["cowrie", "mosquitto", "esp32"])
    ap.add_argument("file")
    ap.add_argument("--device", help="device_id to put on every event, e.g. gw-01")
    ap.add_argument("--broker-ip", help="mosquitto only: the broker's IP (the dst_ip of MQTT events)")
    ap.add_argument("--device-ip", help="esp32 only: the sensor's IP")
    ap.add_argument("--tz", default="UTC", help="esp32 only: time zone of the CSV time column (default UTC)")
    ap.add_argument("--json", action="store_true", help="print full rows as JSON lines instead of a table")
    a = ap.parse_args()

    parser = build_parser(a.source, a.device, broker_ip=a.broker_ip, device_ip=a.device_ip, tz=a.tz)

    events = parser.parse_file(a.file)
    for e in events:
        if a.json:
            print(json.dumps(e.to_row(), default=str))
        else:
            print(f"{e.ts:%Y-%m-%d %H:%M:%S}  {e.event_type:<15} {e.layer:<20} {e.src_ip or '-':<15} "
                  f"{json.dumps(e.payload)[:70]}")
    print(f"\n{a.file}: {parser.stats}")


if __name__ == "__main__":
    main()
