"""Start the API:  .venv/Scripts/python -m api [--port 8001] [--reload]"""
import argparse

import uvicorn

ap = argparse.ArgumentParser(prog="python -m api")
ap.add_argument("--host", default="127.0.0.1", help="0.0.0.0 to accept devices from the lab network")
ap.add_argument("--port", type=int, default=8001)
ap.add_argument("--reload", action="store_true", help="restart automatically when the code changes")
a = ap.parse_args()

from psycopg.conninfo import conninfo_to_dict  # noqa: E402

from ingest.db import db_url  # noqa: E402

info = conninfo_to_dict(db_url())
print(f"AEGEX API -> database '{info.get('dbname')}' on {info.get('host')}:{info.get('port')}"
      f"{'   (proof-of-concept lab)' if info.get('dbname') == 'aegex_poc' else ''}", flush=True)
if a.host == "127.0.0.1":
    print("Only this computer can reach it. For the ESP32 on the hotspot: python -m api --host 0.0.0.0", flush=True)
uvicorn.run("api.main:app", host=a.host, port=a.port, reload=a.reload)
