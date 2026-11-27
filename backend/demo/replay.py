"""Step 6 - the replay harness (emulator): play a recorded capture back as LIVE traffic, through the real API.

    cd backend
    .venv\\Scripts\\python -m api                                                          # terminal 1 (aegex_poc)
    .venv\\Scripts\\python -m demo.replay --capture ds-kitsune-mirai --from 2018-10-25T06:58:00Z --speed 10
    .venv\\Scripts\\python -m demo.replay --capture ds-kitsune-mirai --dry-run             # only show the plan
    .venv\\Scripts\\python -m demo.replay --clean                                          # delete every replay

Why: a real attack (e.g. the Mirai infection in Kitsune, or one of our own recordings) can be shown on the
dashboard as if it were happening now, without attacking anything, and repeated as often as needed for the demo
and for testing detection.

How:
  1. reads the capture's flows (the unified record of Step 2) from the source database, in time order
     (default aegex_datasets; any database with the schema works, e.g. aegex_poc for our own recordings)
  2. moves them to now: replay time = start + (original time - first time) / speed
  3. sends them as Zeek conn.log lines to POST /api/v1/ingest/logs/zeek-conn, in small batches as their time
     comes, the same way the real Zeek sensor does, into a new live capture cap-replay-<name>-<time>.
     TCP flags travel in Zeek's `history` field, so they arrive unchanged.
  4. --map 192.168.2.110=192.168.137.57 gives a host of the recording the address of one of our devices, so the
     dashboard shows that device being attacked
  5. the ground truth (which replayed flow was an attack, and of which class) goes to backend/replays/<capture>.json:
     live data stays unlabelled in the database, like real traffic, and Step 8 can still score detection on it.

Ctrl+C stops it; the capture then gets its end time either way.
"""
from __future__ import annotations

import argparse
import json
import secrets
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import httpx

from ingest.db import connect
from ingest.flows import ACK, FIN, PSH, RST, SYN, make_flow_id
from ingest.datastore import url_for

PREFIX = "cap-replay-"
TRUTH_DIR = Path(__file__).resolve().parents[1] / "replays"
BATCH = 2000                      # most lines per POST
TICK = 0.5                        # seconds between sends


# --------------------------------------------------------------------------- one flow -> one conn.log line
def flags_to_history(fwd: int | None, bwd: int | None) -> str | None:
    """TCP flags -> a Zeek history string that ingest.flows.history_flags turns back into the same flags."""
    if fwd is None and bwd is None:
        return None
    out = ""
    for flags, upper in ((fwd or 0, True), (bwd or 0, False)):
        for bit, ch in ((SYN, "S"), (ACK, "A"), (PSH, "D"), (FIN, "F"), (RST, "R")):
            if flags & bit:
                out += ch if upper else ch.lower()
    return out or None


def remap(ip: str, ip_map: dict[str, str]) -> str:
    return ip_map.get(ip, ip)


def conn_line(row: dict, t: float, ip_map: dict[str, str]) -> dict:
    """One stored flow, moved to replay time t (epoch seconds), as a Zeek conn.log JSON line."""
    line = {"ts": t, "uid": "R" + secrets.token_hex(8), "id.orig_h": remap(row["src_ip"], ip_map),
            "id.orig_p": row["src_port"] if row["src_port"] is not None else 0,
            "id.resp_h": remap(row["dst_ip"], ip_map),
            "id.resp_p": row["dst_port"] if row["dst_port"] is not None else 0, "proto": row["proto"]}
    for key, col in (("duration", "duration_s"), ("orig_bytes", "orig_bytes"), ("resp_bytes", "resp_bytes"),
                     ("orig_pkts", "orig_pkts"), ("resp_pkts", "resp_pkts"), ("service", "service"),
                     ("conn_state", "conn_state")):
        if row.get(col) is not None:
            line[key] = row[col]
    history = row.get("history") or flags_to_history(row.get("fwd_flags"), row.get("bwd_flags"))
    if history:
        line["history"] = history
    return line


def replayed_flow_id(line: dict) -> str:
    """The flow_id the loader will give this line (same function, same inputs), for the ground truth file."""
    return make_flow_id(datetime.fromtimestamp(float(line["ts"]), tz=timezone.utc), str(line["proto"]).lower(),
                        line["id.orig_h"], line["id.orig_p"], line["id.resp_h"], line["id.resp_p"])


# --------------------------------------------------------------------------- read + plan
COLUMNS = ("ts_start", "host(src_ip) AS src_ip", "src_port", "host(dst_ip) AS dst_ip", "dst_port", "proto",
           "duration_s", "orig_bytes", "resp_bytes", "orig_pkts", "resp_pkts", "service", "conn_state", "history",
           "fwd_flags", "bwd_flags", "label", "attack_class", "scenario")


def read_flows(conn, capture: str, t_from: datetime | None = None, t_to: datetime | None = None) -> list[dict]:
    where, params = ["capture_id = %s"], [capture]
    if t_from:
        where.append("ts_start >= %s")
        params.append(t_from)
    if t_to:
        where.append("ts_start < %s")
        params.append(t_to)
    cur = conn.execute(f"SELECT {', '.join(COLUMNS)} FROM flows WHERE {' AND '.join(where)} ORDER BY ts_start",
                       params)
    names = [d.name for d in cur.description]
    return [dict(zip(names, r)) for r in cur.fetchall()]


def plan(rows: list[dict], speed: float) -> dict:
    if not rows:
        return {"flows": 0, "attack_flows": 0, "source_minutes": 0.0, "replay_minutes": 0.0}
    span = (rows[-1]["ts_start"] - rows[0]["ts_start"]).total_seconds()
    attacks = [r for r in rows if r["label"] == 1]
    return {"flows": len(rows), "attack_flows": len(attacks),
            "classes": {c: sum(1 for r in rows if r["attack_class"] == c) for c in {r["attack_class"] for r in rows}},
            "source_from": rows[0]["ts_start"].isoformat(), "source_to": rows[-1]["ts_start"].isoformat(),
            "first_attack": attacks[0]["ts_start"].isoformat() if attacks else None,
            "source_minutes": round(span / 60, 1), "replay_minutes": round(span / 60 / speed, 1)}


def schedule(rows: list[dict], start: float, speed: float) -> list[float]:
    """Replay time (epoch s) of every row: start + (its time - first time) / speed, rounded to the microsecond."""
    t0 = rows[0]["ts_start"].timestamp() if rows else 0.0
    return [round(start + (r["ts_start"].timestamp() - t0) / speed, 6) for r in rows]


# --------------------------------------------------------------------------- send
class Replayer:
    def __init__(self, api: str, capture_id: str, http: httpx.Client | None = None, log=print):
        self.api, self.capture_id = api.rstrip("/"), capture_id
        self.http = http or httpx.Client(timeout=30)
        self.log = log
        self.sent = self.saved = self.attacks = 0

    def post(self, path: str, **kw) -> dict:
        r = self.http.post(self.api + path, **kw)
        if r.status_code >= 300:
            raise RuntimeError(f"{path} answered {r.status_code}: {r.text[:300]}")
        return r.json()

    def send(self, lines: list[dict]) -> None:
        for i in range(0, len(lines), BATCH):
            part = lines[i:i + BATCH]
            r = self.post("/api/v1/ingest/logs/zeek-conn", content="\n".join(json.dumps(x) for x in part),
                          headers={"Content-Type": "text/plain"}, params={"capture_id": self.capture_id})
            self.sent += len(part)
            self.saved += r.get("inserted", 0)

    def run(self, rows: list[dict], times: list[float], ip_map: dict[str, str], clock=time.time,
            sleep=time.sleep) -> list[dict]:
        """Send every row when its replay time comes. Returns the ground truth rows."""
        truth, i, last_note = [], 0, clock()
        while i < len(rows):
            now = clock()
            due = []
            while i < len(rows) and times[i] <= now:
                line = conn_line(rows[i], times[i], ip_map)
                due.append(line)
                truth.append({"flow_id": replayed_flow_id(line), "label": rows[i]["label"],
                              "attack_class": rows[i]["attack_class"], "scenario": rows[i]["scenario"],
                              "src_ip": line["id.orig_h"], "ts": times[i]})
                self.attacks += rows[i]["label"] == 1
                i += 1
            if due:
                self.send(due)
            if clock() - last_note >= 10:
                src = rows[i - 1]["ts_start"] if i else rows[0]["ts_start"]
                self.log(f"  {self.sent:>8,} flows sent ({self.attacks:,} attack)  recording time {src:%H:%M:%S}")
                last_note = clock()
            if i < len(rows):
                sleep(max(0.0, min(TICK, times[i] - clock())))
        return truth


# --------------------------------------------------------------------------- main
def parse_map(items: list[str]) -> dict[str, str]:
    out = {}
    for item in items or []:
        if "=" not in item:
            raise ValueError(f"--map {item!r}: write it as RECORDED_IP=OUR_IP")
        a, b = (x.strip() for x in item.split("=", 1))
        out[a] = b
    return out


def utc(value: str | None) -> datetime | None:
    if not value:
        return None
    t = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if t.tzinfo is None:
        raise ValueError(f"{value!r} has no time zone: write it in UTC with a Z")
    return t


def clean(dbname: str) -> int:
    with connect(url_for(dbname)) as conn, conn.transaction():
        total = 0
        for table in ("feature_windows", "flows", "events", "attack_runs", "captures"):
            n = conn.execute(f"DELETE FROM {table} WHERE capture_id LIKE %s", (PREFIX + "%",)).rowcount
            total += n
            print(f"deleted {n} rows from {table}")
    return total


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Replay a recorded capture as live traffic through the API.")
    ap.add_argument("--capture", help="capture to replay, e.g. ds-kitsune-mirai")
    ap.add_argument("--source-db", default="aegex_datasets", help="database it is in (default: %(default)s)")
    ap.add_argument("--api", default="http://127.0.0.1:8001", help="the API to send to (default: %(default)s)")
    ap.add_argument("--speed", type=float, default=10.0, help="10 = ten times faster than recorded (default)")
    ap.add_argument("--from", dest="t_from", help="start at this recording time (UTC, with Z)")
    ap.add_argument("--to", dest="t_to", help="stop at this recording time (UTC, with Z)")
    ap.add_argument("--map", action="append", default=[], metavar="RECORDED_IP=OUR_IP",
                    help="give a recorded host one of our addresses (repeatable)")
    ap.add_argument("--dry-run", action="store_true", help="show what would be sent, send nothing")
    ap.add_argument("--clean", action="store_true", help="delete every replay capture from the API's database")
    a = ap.parse_args(argv)
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    api = a.api.rstrip("/")
    try:
        target_db = httpx.get(api + "/health", timeout=10).json().get("database_name")
    except httpx.HTTPError as exc:
        if not a.dry_run:
            print(f"The API is not reachable at {api} ({type(exc).__name__}). Start it first: python -m api")
            return 1
        target_db = None
    if a.clean:
        clean(target_db)
        return 0
    if not a.capture:
        ap.error("give --capture (e.g. ds-kitsune-mirai) or --clean")
    if a.speed <= 0:
        ap.error("--speed must be above 0")
    try:
        ip_map, t_from, t_to = parse_map(a.map), utc(a.t_from), utc(a.t_to)
    except ValueError as exc:
        ap.error(str(exc))
    with connect(url_for(a.source_db)) as src:
        rows = read_flows(src, a.capture, t_from, t_to)
    p = plan(rows, a.speed)
    print(f"{a.capture} ({a.source_db}): {p['flows']:,} flows, {p['attack_flows']:,} attack, "
          f"{p['source_minutes']} min of recording -> {p['replay_minutes']} min at {a.speed:g}x")
    if p.get("first_attack"):
        print(f"  first attack flow at {p['first_attack']}; classes {p['classes']}")
    if not rows:
        print("nothing to replay (check --capture, --from, --to)")
        return 1
    if a.dry_run:
        print("dry run: nothing sent")
        return 0

    capture_id = f"{PREFIX}{a.capture.removeprefix('ds-')}-{datetime.now(timezone.utc):%Y%m%d-%H%M%S}"[:100]
    rep = Replayer(api, capture_id)
    start = time.time() + 2
    rep.post("/api/v1/captures", json={
        "capture_id": capture_id, "start_ts": datetime.fromtimestamp(start - 5, timezone.utc).isoformat(),
        "kind": "live", "notes": f"demo.replay: {a.capture} from {a.source_db} at {a.speed:g}x"
                                 f"{' (from ' + a.t_from + ')' if a.t_from else ''}; IP map {ip_map or 'none'}"})
    print(f"replaying into {target_db} as {capture_id}; open the dashboard in Live mode. Ctrl+C to stop.")
    truth = []
    try:
        truth = rep.run(rows, schedule(rows, start, a.speed), ip_map)
    except KeyboardInterrupt:
        print("\nstopped")
    finally:
        with connect(url_for(target_db)) as conn:
            conn.execute("UPDATE captures SET end_ts = now() WHERE capture_id = %s AND end_ts IS NULL", (capture_id,))
        TRUTH_DIR.mkdir(exist_ok=True)
        out = TRUTH_DIR / f"{capture_id}.json"
        out.write_text(json.dumps({"capture_id": capture_id, "source": a.capture, "source_db": a.source_db,
                                   "speed": a.speed, "ip_map": ip_map, "plan": p, "flows": truth}, default=str),
                       encoding="utf-8")
        print(f"sent {rep.sent:,} flows ({rep.saved:,} saved, {rep.attacks:,} attack). Capture {capture_id} closed.")
        print(f"ground truth: {out}\ndelete replays with: .venv\\Scripts\\python -m demo.replay --clean")
    return 0


if __name__ == "__main__":
    sys.exit(main())
