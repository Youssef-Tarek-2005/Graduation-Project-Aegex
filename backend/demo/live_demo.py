"""The live demo lab: every page of the dashboard moves by itself, on every time range (15 min, 1 h, 6 h, 24 h).

    cd backend
    .venv\\Scripts\\python -m api                        # terminal 1, on aegex_poc (start_demo.ps1 does all of this)
    .venv\\Scripts\\python -m demo.live_demo              # terminal 2: Ctrl+C to stop
    .venv\\Scripts\\python -m demo.live_demo --clean      # delete everything the demo made

SIMULATION, said plainly: the network TRAFFIC is generated (the PoC lab: the ESP32-S3 honeypot, a phone, the
laptop, and attackers). Everything after that is the real system, exactly as for a real recording:

  every minute, for the minute that just passed:
    1. real packets (scapy) of the lab's normal traffic, sometimes with an attack mixed in, chosen at random:
       port scan, HTTP flood, Telnet brute force, or a Mirai-style bot spreading over Telnet
       (different attackers, sizes and times, so the numbers keep changing)
    2. pcap -> Zeek (Docker) -> flows                       (the pipeline, Step 3)
    3. the honeypot's events (page visits, failed logins)   -> POST /api/v1/ingest/events
    4. the attack goes into Task A's attack log            -> POST /api/v1/attack-runs, then labels
    5. the rule baseline on the last 15 minutes            -> alerts (model 'rules', Step 7)
    6. LSTM-AE + VAE + temporal GAT on that minute's pcap -> alerts (calibrated on pcaps/poc-normal.pcap)
  every 2 s: an ESP32 sensor reading                        -> POST /api/v1/ingest/sensor

On start it fills the gap of the last 24 hours (newest first, in the background), so every time range has data
from the first minute, and it deletes demo data older than 25 hours. Everything goes into one live capture,
cap-live-demo, so `--clean` knows what is the demo's.
"""
from __future__ import annotations

import argparse
import logging
import os
import random
import shutil
import sys
import tempfile
import threading
import time
import traceback
from datetime import datetime, timedelta, timezone
from pathlib import Path

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

import httpx                                               # noqa: E402
from scapy.layers.inet import IP, TCP                      # noqa: E402
from scapy.layers.l2 import Ether                          # noqa: E402
from scapy.utils import PcapWriter                         # noqa: E402

from ingest.datastore import url_for                       # noqa: E402
from ingest.db import connect                              # noqa: E402

BACKEND = Path(__file__).resolve().parents[1]
NORMAL_PCAP = BACKEND / "pcaps" / "poc-normal.pcap"        # what the AI models calibrate on (demo.make_poc_pcaps)
CAPTURE = "cap-live-demo"
ESP_DEVICE = "esp32s3-01"
LAPTOP, ESP, PHONE = "192.168.137.1", "192.168.137.57", "192.168.137.20"
ATTACKERS = ["192.168.137.50", "192.168.137.66", "192.168.137.77", "192.168.137.91"]
BOTS = ["192.168.137.88", "192.168.137.112"]               # "smart plugs" that turn into Mirai bots
CHUNK = 60                                                 # seconds of traffic per round
KEEP = timedelta(hours=25)
PAGE = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 180\r\n\r\n<html>" + b"x" * 168 + b"</html>"
CREDS = [("root", "admin"), ("admin", "admin"), ("root", "12345"), ("user", "user"), ("root", "vizxv"),
         ("admin", "password"), ("support", "support"), ("root", "xc3511"), ("guest", "guest"), ("root", "default")]
ATTACKS = {   # kind: (scenario in the attack log, tool, weight)
    "port_scan": ("vulnerability_scanning", "nmap -sS", 3),
    "http_flood": ("dos", "http flood", 2),
    "telnet_brute": ("bruteforce", "hydra telnet", 3),
    "mirai": ("mirai_botnet", "mirai-style telnet spread", 2),
}
log_lock = threading.Lock()


def say(msg: str) -> None:
    with log_lock:
        print(f"{datetime.now():%H:%M:%S} {msg}", flush=True)


# --------------------------------------------------------------------------- packets
def mac(ip: str) -> str:
    return "02:00:" + ":".join(f"{int(x):02x}" for x in ip.split("."))


def pkt(src: str, dst: str, l4, t: float):
    p = Ether(src=mac(src), dst=mac(dst)) / IP(src=src, dst=dst) / l4
    p.time = t
    return p


def tcp_conn(c: str, cport: int, s: str, sport: int, t0: float, request: bytes, response: bytes, dur: float) -> list:
    """Handshake, one request, one response, clean close (the same shape as demo.make_poc_pcaps)."""
    step, out, t = dur / 10, [], t0
    sc, ss = 1000, 5000

    def send(frm, to, fp, tp, flags, seq, ack, data=b""):
        nonlocal t
        out.append(pkt(frm, to, TCP(sport=fp, dport=tp, flags=flags, seq=seq, ack=ack, window=64240) / data, t))
        t += step
    send(c, s, cport, sport, "S", sc, 0)
    send(s, c, sport, cport, "SA", ss, sc + 1)
    send(c, s, cport, sport, "A", sc + 1, ss + 1)
    send(c, s, cport, sport, "PA", sc + 1, ss + 1, request)
    send(s, c, sport, cport, "A", ss + 1, sc + 1 + len(request))
    send(s, c, sport, cport, "PA", ss + 1, sc + 1 + len(request), response)
    send(c, s, cport, sport, "A", sc + 1 + len(request), ss + 1 + len(response))
    send(c, s, cport, sport, "FA", sc + 1 + len(request), ss + 1 + len(response))
    send(s, c, sport, cport, "FA", ss + 1 + len(response), sc + 2 + len(request))
    send(c, s, cport, sport, "A", sc + 2 + len(request), ss + 2 + len(response))
    return out


def iso(t: float) -> str:
    return datetime.fromtimestamp(t, timezone.utc).isoformat().replace("+00:00", "Z")


SEVERITY = {"http_request": "low", "session_open": "low", "login_failed": "medium", "login_success": "high",
            "command": "high"}                             # the levels the honeypot endpoint uses (api/ingest.py)


def honeypot_event(t: float, kind: str, src: str, port: int, **payload) -> dict:
    return {"ts": iso(t), "source": "esp32", "event_type": kind, "device_id": ESP_DEVICE, "capture_id": CAPTURE,
            "src_ip": src, "dst_ip": ESP, "dst_port": port, "proto": "tcp", "severity": SEVERITY.get(kind, "info"),
            "payload": payload}


def device_events(rng: random.Random, t0: float, t1: float, sensors: bool) -> list[dict]:
    """The ESP32's own logs (a heartbeat every minute) and, for history, a sensor reading every 10 s."""
    out, t = [], t0 + rng.uniform(0, 60)
    while t < t1:
        out.append({"ts": iso(t), "source": "esp32", "event_type": "device_log", "device_id": ESP_DEVICE,
                    "capture_id": CAPTURE, "src_ip": ESP, "severity": "info",
                    "payload": {"msg": "heartbeat", "free_heap": rng.randint(180000, 210000),
                                "rssi_dbm": rng.randint(-67, -48), "services": "telnet,http"}})
        t += 60
    if sensors:
        t, temp, hum, smoke = t0, rng.uniform(23, 25), rng.uniform(38, 44), rng.uniform(9, 14)
        while t < t1:
            temp, hum = min(30, max(20, temp + rng.uniform(-.15, .15))), min(60, max(30, hum + rng.uniform(-.4, .4)))
            smoke = min(40, max(5, smoke + rng.uniform(-.6, .6)))
            out.append({"ts": iso(t), "source": "esp32", "event_type": "sensor_reading", "device_id": ESP_DEVICE,
                        "capture_id": CAPTURE, "src_ip": ESP, "severity": "info",
                        "payload": {"temperature_c": round(temp, 2), "humidity_pct": round(hum, 1),
                                    "smoke": round(smoke, 1)}})
            t += 10
    return out


def normal_traffic(rng: random.Random, t0: float, t1: float) -> tuple[list, list]:
    """The lab's everyday traffic, at the same rates as the calibration recording (demo.make_poc_pcaps)."""
    packets, events = [], []
    t = t0 + rng.uniform(0, 2)
    while t < t1:                                          # ESP32 -> laptop API, every ~5 s
        body = f'{{"device_id":"{ESP_DEVICE}","smoke":{rng.uniform(8, 16):.1f}}}'.encode()
        packets += tcp_conn(ESP, rng.randint(49152, 65000), LAPTOP, 8001, t,
                            b"POST /api/v1/ingest/sensor HTTP/1.1\r\nHost: 192.168.137.1:8001\r\n\r\n" + body,
                            b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}', rng.uniform(0.04, 0.12))
        t += rng.uniform(4.5, 5.5)
    t = t0 + rng.uniform(0, 5)
    while t < t1:                                          # a phone opens the ESP32's web page, every ~10 s
        packets += tcp_conn(PHONE, rng.randint(40000, 60000), ESP, 80, t,
                            b"GET / HTTP/1.1\r\nHost: 192.168.137.57\r\nUser-Agent: Mozilla/5.0\r\n\r\n", PAGE,
                            rng.uniform(0.08, 0.3))
        events.append(honeypot_event(t, "http_request", PHONE, 80, method="GET", path="/", service="http"))
        t += rng.uniform(6, 14)
    return packets, events


def port_scan(rng, src, t0):
    packets, t, n = [], t0, rng.randint(250, 1000)
    for port in rng.sample(range(1, 1025), n):
        sport = rng.randint(40000, 60000)
        packets.append(pkt(src, ESP, TCP(sport=sport, dport=port, flags="S", seq=1), t))
        packets.append(pkt(ESP, src, TCP(sport=port, dport=sport, flags="RA", seq=0, ack=2), t + 0.002))
        t += rng.uniform(0.002, 0.02)
    return packets, [honeypot_event(t0, "session_open", src, 80, service="http")], t, f"SYN scan of {n} ports"


def http_flood(rng, src, t0):
    packets, events, n, span = [], [], rng.randint(200, 600), rng.uniform(15, 30)
    for i in range(n):
        t = t0 + i * span / n
        packets += tcp_conn(src, rng.randint(40000, 60000), ESP, 80, t, b"GET / HTTP/1.1\r\nHost: 192.168.137.57\r\n\r\n",
                            PAGE, rng.uniform(0.2, 1.5))
        if i % 10 == 0:                                    # the honeypot logs a sample of the requests
            events.append(honeypot_event(t, "http_request", src, 80, method="GET", path="/", service="http"))
    return packets, events, t0 + span + 1.5, f"{n} HTTP connections in {span:.0f} s"


def telnet_brute(rng, src, t0):
    packets, events, t, n = [], [], t0, rng.randint(12, 30)        # at most ~40 s, so it fits in its minute
    for _ in range(n):
        user, pw = rng.choice(CREDS)
        packets += tcp_conn(src, rng.randint(40000, 60000), ESP, 23, t, f"{user}\r\n{pw}\r\n".encode(),
                            b"\r\nLogin incorrect\r\nlogin: ", rng.uniform(0.3, 0.9))
        events.append(honeypot_event(t, "login_failed", src, 23, service="telnet", username=user, password=pw))
        t += rng.uniform(0.6, 1.3)
    return packets, events, t, f"{n} Telnet logins with default passwords"


def mirai(rng, bot, t0):
    """A bot sweeping the subnet on Telnet (most addresses don't exist: no answer), then trying default logins."""
    packets, events, t = [], [], t0
    targets = rng.sample([f"192.168.137.{i}" for i in range(2, 255) if f"192.168.137.{i}" not in (bot, ESP)],
                         rng.randint(30, 70))
    for dst in targets + [ESP]:
        sport = rng.randint(40000, 60000)
        packets.append(pkt(bot, dst, TCP(sport=sport, dport=rng.choice([23, 23, 2323]), flags="S", seq=1), t))
        if dst in (LAPTOP, PHONE):
            packets.append(pkt(dst, bot, TCP(sport=23, dport=sport, flags="RA", seq=0, ack=2), t + 0.003))
        t += rng.uniform(0.05, 0.3)
    for _ in range(rng.randint(3, 8)):
        user, pw = rng.choice(CREDS)
        packets += tcp_conn(bot, rng.randint(40000, 60000), ESP, 23, t, f"{user}\r\n{pw}\r\n".encode(),
                            b"\r\nLogin incorrect\r\nlogin: ", rng.uniform(0.3, 0.8))
        events.append(honeypot_event(t, "login_failed", bot, 23, service="telnet", username=user, password=pw))
        t += rng.uniform(0.8, 2.0)
    return packets, events, t, f"Telnet sweep of {len(targets)} addresses + default logins"


GENERATORS = {"port_scan": port_scan, "http_flood": http_flood, "telnet_brute": telnet_brute, "mirai": mirai}


def pick_attack(rng: random.Random) -> tuple[str, str]:
    kinds = list(ATTACKS)
    kind = rng.choices(kinds, weights=[ATTACKS[k][2] for k in kinds])[0]
    return kind, rng.choice(BOTS if kind == "mirai" else ATTACKERS)


# --------------------------------------------------------------------------- one slice of time, end to end
class Lab:
    def __init__(self, api: str, db_url: str, ai: bool = True):
        self.api, self.db_url, self.ai = api.rstrip("/"), db_url, ai
        self.http = httpx.Client(timeout=60)
        self.stats = {"rounds": 0, "attacks": 0, "flows": 0, "events": 0, "rule_incidents": 0, "ai_alerts": 0}

    def post(self, path: str, **kw) -> dict:
        r = self.http.post(self.api + path, **kw)
        if r.status_code >= 300:
            raise RuntimeError(f"{path} answered {r.status_code}: {r.text[:300]}")
        return r.json()

    def slice(self, t0: float, t1: float, attacks: list[tuple[float, str, str]], rng: random.Random,
              tag: str = "live") -> None:
        """Traffic of [t0, t1) with these (time, kind, attacker) attacks, through the whole system."""
        from correlate.store import run_period
        from ingest.flows import load_conn_log
        from ingest.zeek import run_zeek
        packets, events = normal_traffic(rng, t0, t1)
        events += device_events(rng, t0, t1, sensors=tag.startswith("history"))   # live readings: sensor_loop
        runs = []
        for at, kind, src in attacks:
            p, e, end, what = GENERATORS[kind](rng, src, at)
            packets += p
            events += e
            scenario, tool, _ = ATTACKS[kind]
            runs.append({"run_id": f"demo-{datetime.fromtimestamp(at, timezone.utc):%Y%m%d-%H%M%S}-{kind}",
                         "capture_id": CAPTURE, "scenario": scenario, "tool": tool, "command": what,
                         "attacker_ip": src, "target_device": ESP_DEVICE, "start_ts": iso(at),
                         "end_ts": iso(max(end, at + 1)), "notes": "demo.live_demo (simulated attack)"})
        packets.sort(key=lambda p: p.time)
        work = Path(tempfile.mkdtemp(prefix="aegex-live-"))
        try:
            pcap = work / f"{tag}.pcap"
            with PcapWriter(str(pcap), linktype=1, sync=False) as w:
                for p in packets:
                    w.write(p)
            with connect(self.db_url) as conn:
                flows = load_conn_log(conn, run_zeek(pcap, work / "zeek"), CAPTURE)          # 2. Zeek -> flows
                self.stats["flows"] += flows.inserted
                for i in range(0, len(events), 4000):                                         # 3. events
                    self.stats["events"] += self.post("/api/v1/ingest/events", json=events[i:i + 4000])["inserted"]
                if runs:                                                                       # 4. attack log
                    self.post("/api/v1/attack-runs", json=runs)
                    self.stats["attacks"] += len(runs)
                label_period(conn, t0, t1 + 5, runs)
                start = datetime.fromtimestamp(t0, timezone.utc)                              # 5. rule baseline
                n = run_period(conn, CAPTURE, start - timedelta(minutes=14), datetime.fromtimestamp(t1, timezone.utc))
                self.stats["rule_incidents"] = n
            if self.ai and NORMAL_PCAP.exists():                                               # 6. AI models
                self.stats["ai_alerts"] += run_ai(pcap, tag)
            self.stats["rounds"] += 1
        finally:
            shutil.rmtree(work, ignore_errors=True)


def label_period(conn, t0: float, t1: float, runs: list[dict]) -> None:
    """Task A's labelling rule (label_capture) for just this slice: attacker on either end inside a run = 1,
    everything else of the slice = 0. Re-labelling the whole day every minute would be wasted work."""
    a, b = datetime.fromtimestamp(t0, timezone.utc), datetime.fromtimestamp(t1, timezone.utc)
    with conn.transaction():
        conn.execute("UPDATE flows SET label = 0 WHERE capture_id = %s AND ts_start >= %s AND ts_start < %s "
                     "AND label IS NULL", (CAPTURE, a, b))
        conn.execute("UPDATE events SET label = 0 WHERE capture_id = %s AND ts >= %s AND ts < %s AND label IS NULL",
                     (CAPTURE, a, b))
        for r in runs:
            args = (r["scenario"], r["run_id"], CAPTURE, r["attacker_ip"], r["attacker_ip"], r["start_ts"], r["end_ts"])
            conn.execute("UPDATE flows SET label = 1, scenario = %s, run_id = %s WHERE capture_id = %s AND "
                         "(src_ip = %s::inet OR dst_ip = %s::inet) AND ts_start BETWEEN %s AND %s", args)
            conn.execute("UPDATE events SET label = 1, scenario = %s, run_id = %s WHERE capture_id = %s AND "
                         "(src_ip = %s::inet OR dst_ip = %s::inet) AND ts BETWEEN %s AND %s", args)


def run_ai(pcap: Path, tag: str) -> int:
    """LSTM-AE + VAE + GAT on this slice's pcap, calibrated on the normal recording; alerts ADDED to the capture."""
    import detect
    name = f"live-{tag}-{os.getpid()}-{threading.get_ident()}"
    try:
        results = detect.run_models(pcap, NORMAL_PCAP, name, gat=True, quiet=True)
        n = detect.save_alerts(results, CAPTURE, replace=False)
        n += detect.save_gat_alerts(results, CAPTURE)
        return n
    except Exception as exc:                               # the AI failing must never stop the lab
        say(f"AI models skipped this round: {type(exc).__name__}: {str(exc)[:200]}")
        return 0
    finally:
        shutil.rmtree(detect.RUNS / name, ignore_errors=True)


# --------------------------------------------------------------------------- capture, history, retention
def prepare(db_url: str) -> list[tuple[float, float]]:
    """The live capture (created 24 h back if new); demo data older than 25 h deleted.
    Returns the parts of the last 24 h that have no traffic yet (newest first), for backfill()."""
    now = datetime.now(timezone.utc)
    cutoff = now - KEEP
    with connect(db_url) as conn, conn.transaction():
        if not conn.execute("SELECT 1 FROM captures WHERE capture_id = %s", (CAPTURE,)).fetchone():
            conn.execute("INSERT INTO captures (capture_id, start_ts, kind, notes) VALUES (%s, %s, 'live', %s)",
                         (CAPTURE, now - timedelta(hours=24, minutes=5),
                          "demo.live_demo: SIMULATED lab traffic (real pipeline, detection and threat intelligence)"))
        conn.execute("DELETE FROM alerts WHERE evidence->>'capture' = %s AND window_end < %s", (CAPTURE, cutoff))
        for table, col in (("flows", "ts_start"), ("events", "ts"), ("attack_runs", "end_ts")):
            conn.execute(f"DELETE FROM {table} WHERE capture_id = %s AND {col} < %s", (CAPTURE, cutoff))
        conn.execute("UPDATE captures SET start_ts = LEAST(start_ts, %s) WHERE capture_id = %s",
                     (now - timedelta(hours=24, minutes=5), CAPTURE))
        day = now - timedelta(hours=24)
        first, last = conn.execute("SELECT min(ts_start), max(ts_start) FROM flows WHERE capture_id = %s AND "
                                   "ts_start >= %s", (CAPTURE, day)).fetchone()
    end = now.timestamp() - CHUNK
    if first is None:
        return [(day.timestamp(), end)]
    gaps = [(last.timestamp(), end), (day.timestamp(), first.timestamp())]
    return [(a, b) for a, b in gaps if b - a > 120]


def device_history(lab: Lab, stop: threading.Event) -> None:
    """Sensor readings + device logs for every 10-minute block of the last 24 h that has none (e.g. history made
    before this existed, or a gap while the demo was off). Cheap: no packets, no models."""
    now = datetime.now(timezone.utc)
    with connect(lab.db_url) as conn:
        have = {r[0] for r in conn.execute(
            "SELECT DISTINCT time_bucket('10 minutes', ts) FROM events WHERE capture_id = %s AND "
            "event_type = 'sensor_reading' AND ts >= %s", (CAPTURE, now - timedelta(hours=24)))}
    rng, events = random.Random(), []
    t = (now - timedelta(hours=24)).timestamp() // 600 * 600 + 600
    while t < now.timestamp() - 600 and not stop.is_set():
        if datetime.fromtimestamp(t, timezone.utc) not in have:
            events += device_events(rng, t, t + 600, sensors=True)
        t += 600
    for i in range(0, len(events), 4000):
        lab.post("/api/v1/ingest/events", json=events[i:i + 4000])
    if events:
        say(f"history: {len(events):,} sensor readings and device logs added")


def backfill(lab: Lab, gaps: list[tuple[float, float]], stop: threading.Event) -> None:
    for start, end in gaps:
        fill(lab, start, end, stop)
    say("history: the last 24 hours are filled")


def fill(lab: Lab, start: float, end: float, stop: threading.Event) -> None:
    """History for [start, end), newest first, in 30-minute slices with an attack every ~10-25 minutes."""
    rng = random.Random(int(start))
    t1 = end
    while t1 - start > 30 and not stop.is_set():
        t0 = max(start, t1 - 1800)
        attacks, t = [], t0 + rng.uniform(120, 600)
        while t < t1 - 60:
            kind, src = pick_attack(rng)
            attacks.append((t, kind, src))
            t += rng.uniform(600, 1500)
        try:
            lab.slice(t0, t1, attacks, rng, tag=f"history-{int(t0)}")
            say(f"history: {datetime.fromtimestamp(t0):%d %b %H:%M}-{datetime.fromtimestamp(t1):%H:%M} filled "
                f"({len(attacks)} attack(s))")
        except Exception as exc:
            say(f"history slice failed: {type(exc).__name__}: {exc}")
        t1 = t0


def sensor_loop(api: str, stop: threading.Event) -> None:
    """An ESP32 reading every 2 s, stamped by the server, like the real sensor."""
    rng, temp, hum, smoke = random.Random(), 24.0, 40.0, 12.0
    http = httpx.Client(timeout=10)
    while not stop.is_set():
        temp = min(30, max(20, temp + rng.uniform(-0.15, 0.15)))
        hum = min(60, max(30, hum + rng.uniform(-0.4, 0.4)))
        smoke = min(40, max(5, smoke + rng.uniform(-0.6, 0.6)))
        try:
            http.post(api + "/api/v1/ingest/sensor", json={"device_id": ESP_DEVICE, "capture_id": CAPTURE,
                      "temperature_c": round(temp, 2), "humidity_pct": round(hum, 1), "smoke": round(smoke, 1)})
        except httpx.HTTPError:
            pass
        stop.wait(2)


def clean(db_url: str) -> None:
    with connect(db_url) as conn, conn.transaction():
        n = conn.execute("DELETE FROM alerts WHERE evidence->>'capture' = %s", (CAPTURE,)).rowcount
        print(f"deleted {n} alerts")
        for table in ("feature_windows", "flows", "events", "attack_runs", "captures"):
            print(f"deleted {conn.execute(f'DELETE FROM {table} WHERE capture_id = %s', (CAPTURE,)).rowcount} "
                  f"rows from {table}")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="The live demo lab: simulated traffic through the real system.")
    ap.add_argument("--api", default="http://127.0.0.1:8001")
    ap.add_argument("--attack-every", type=float, default=150, help="average seconds between live attacks")
    ap.add_argument("--no-backfill", action="store_true", help="don't fill the last 24 hours")
    ap.add_argument("--no-ai", action="store_true", help="skip the AI models (faster; rules still run)")
    ap.add_argument("--clean", action="store_true", help="delete everything the demo made")
    a = ap.parse_args(argv)
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    api = a.api.rstrip("/")
    try:
        health = httpx.get(api + "/health", timeout=10).json()
    except httpx.HTTPError as exc:
        print(f"The API is not reachable at {api} ({type(exc).__name__}). Start it first (start_demo.ps1).")
        return 1
    db = health.get("database_name")
    db_url = url_for(db)
    os.environ["AEGEX_DB_URL"] = db_url                    # detect.py saves into the same database as the API
    if a.clean:
        clean(db_url)
        return 0
    with connect(db_url) as conn:
        if not conn.execute("SELECT 1 FROM devices WHERE device_id = %s", (ESP_DEVICE,)).fetchone():
            print(f"The API's database '{db}' has no {ESP_DEVICE}: start the API on aegex_poc (python -m ingest.poc_db).")
            return 1
    if not NORMAL_PCAP.exists() and not a.no_ai:
        print("making the calibration recording first (python -m demo.make_poc_pcaps) ...")
        from demo import make_poc_pcaps
        make_poc_pcaps.main()
    gaps = prepare(db_url)
    lab = Lab(api, db_url, ai=not a.no_ai)
    stop = threading.Event()
    threading.Thread(target=sensor_loop, args=(api, stop), daemon=True).start()
    now = time.time()
    if not a.no_backfill:
        threading.Thread(target=device_history, args=(Lab(api, db_url, ai=False), stop), daemon=True).start()
    if not a.no_backfill and gaps:
        hist = Lab(api, db_url, ai=not a.no_ai)
        threading.Thread(target=backfill, args=(hist, gaps, stop), daemon=True).start()
        say("filling history in the background (newest first): " + ", ".join(
            f"{datetime.fromtimestamp(x):%d %b %H:%M}-{datetime.fromtimestamp(y):%H:%M}" for x, y in gaps))
    say(f"live demo running on {db} (capture {CAPTURE}); open the dashboard. Ctrl+C to stop.")
    rng = random.Random()
    next_attack = time.time() + rng.uniform(20, 60)
    t0 = now - CHUNK
    try:
        while True:
            t1 = t0 + CHUNK
            wait = t1 + 2 - time.time()                    # the slice is processed once its minute is over
            if wait > 0:
                time.sleep(wait)
            attacks = []
            while next_attack < t1:
                kind, src = pick_attack(rng)
                at = min(max(next_attack, t0 + 1), t1 - 42)          # every attack ends inside its minute
                attacks.append((at, kind, src))
                next_attack = at + rng.uniform(0.6, 1.4) * a.attack_every
            try:
                lab.slice(t0, t1, attacks, rng, tag=f"{int(t0)}")
                s = lab.stats
                say(f"minute {datetime.fromtimestamp(t0):%H:%M}: " + (", ".join(f"{k} from {src}" for _, k, src in attacks)
                    or "normal traffic") + f" | totals: {s['flows']:,} flows, {s['events']:,} events, "
                    f"{s['attacks']} attacks, {s['ai_alerts']} AI alerts")
            except Exception as exc:
                say(f"round failed (it goes on): {type(exc).__name__}: {exc}")
                traceback.print_exc(limit=2)
            t0 = t1
    except KeyboardInterrupt:
        stop.set()
        print("\nstopped. The data stays (delete it with: python -m demo.live_demo --clean)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
