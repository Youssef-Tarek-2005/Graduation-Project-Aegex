"""Make two test recordings of the proof-of-concept lab, so the AI models can be tried before the real ones exist.

    .venv/Scripts/python -m demo.make_poc_pcaps          # writes pcaps/poc-normal.pcap and pcaps/poc-attack.pcap

Both are made-up but look like what Wireshark on the hotspot laptop will record (real TCP handshakes, HTTP):
  poc-normal.pcap   30 min of normal traffic only:
                      the ESP32-S3 (.57) POSTs a sensor reading to the laptop's API (.1:8001) every 5 s
                      a phone (.20) opens the ESP32's web page every ~10 s
  poc-attack.pcap   15 min of the same normal traffic, plus the second laptop's (.50) attacks:
                      minute 5   port scan (SYN to 1000 ports; closed ports answer with a reset)
                      minute 10  HTTP flood (600 connections to port 80 in 20 s)

The normal one is the CALIBRATION recording: the models learn from it what "normal" looks like on our network.
Same seed -> same files every run.
"""
from __future__ import annotations

import logging
import random
from datetime import datetime, timezone
from pathlib import Path

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.layers.inet import IP, TCP              # noqa: E402
from scapy.layers.l2 import Ether                  # noqa: E402
from scapy.utils import PcapWriter                 # noqa: E402

LAPTOP, ESP, PHONE, ATTACKER = "192.168.137.1", "192.168.137.57", "192.168.137.20", "192.168.137.50"
MAC = {LAPTOP: "f0:de:f1:00:00:01", ESP: "34:85:18:00:00:57", PHONE: "a8:5b:78:00:00:20",
       ATTACKER: "3c:52:82:00:00:50"}
OUT = Path(__file__).resolve().parents[1] / "pcaps"
PAGE = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 180\r\n\r\n" + b"<html>" + b"x" * 168 + b"</html>"


def pkt(src: str, dst: str, l4, t: float):
    p = Ether(src=MAC[src], dst=MAC[dst]) / IP(src=src, dst=dst) / l4
    p.time = t
    return p


def tcp_conn(c: str, cport: int, s: str, sport: int, t0: float, request: bytes, response: bytes, dur: float) -> list:
    """Handshake, one request, one response, clean close: 10 packets."""
    step, out, t = dur / 10, [], t0
    seq_c, seq_s = 1000, 5000
    def send(frm, to, fp, tp, flags, seq, ack, data=b""):
        nonlocal t
        out.append(pkt(frm, to, TCP(sport=fp, dport=tp, flags=flags, seq=seq, ack=ack, window=64240) / data, t))
        t += step
    send(c, s, cport, sport, "S", seq_c, 0)
    send(s, c, sport, cport, "SA", seq_s, seq_c + 1)
    send(c, s, cport, sport, "A", seq_c + 1, seq_s + 1)
    send(c, s, cport, sport, "PA", seq_c + 1, seq_s + 1, request)
    send(s, c, sport, cport, "A", seq_s + 1, seq_c + 1 + len(request))
    send(s, c, sport, cport, "PA", seq_s + 1, seq_c + 1 + len(request), response)
    send(c, s, cport, sport, "A", seq_c + 1 + len(request), seq_s + 1 + len(response))
    send(c, s, cport, sport, "FA", seq_c + 1 + len(request), seq_s + 1 + len(response))
    send(s, c, sport, cport, "FA", seq_s + 1 + len(response), seq_c + 2 + len(request))
    send(c, s, cport, sport, "A", seq_c + 2 + len(request), seq_s + 2 + len(response))
    return out


def normal_traffic(rng: random.Random, start: float, minutes: float) -> list:
    out, end = [], start + minutes * 60
    t = start + rng.uniform(0, 2)
    while t < end:                                               # ESP32 -> laptop API, every 5 s
        body = f'{{"device_id":"esp32s3-01","smoke":{rng.uniform(8, 16):.1f},"temperature_c":{rng.uniform(23, 25):.2f}}}'
        req = (f"POST /api/v1/ingest/sensor HTTP/1.1\r\nHost: 192.168.137.1:8001\r\nContent-Type: application/json\r\n"
               f"Content-Length: {len(body)}\r\n\r\n{body}").encode()
        out += tcp_conn(ESP, rng.randint(49152, 65000), LAPTOP, 8001, t, req,
                        b'HTTP/1.1 200 OK\r\nContent-Length: 40\r\n\r\n{"received":1,"inserted":1,"duplicates":0}',
                        rng.uniform(0.04, 0.12))
        t += rng.uniform(4.5, 5.5)
    t = start + rng.uniform(0, 5)
    while t < end:                                               # phone opens the ESP32's page, every ~10 s
        out += tcp_conn(PHONE, rng.randint(40000, 60000), ESP, 80, t,
                        b"GET / HTTP/1.1\r\nHost: 192.168.137.57\r\nUser-Agent: Mozilla/5.0\r\n\r\n", PAGE,
                        rng.uniform(0.08, 0.3))
        t += rng.uniform(6, 14)
    return out


def port_scan(rng: random.Random, t0: float) -> list:
    out, t = [], t0
    for port in rng.sample(range(1, 1025), 1000):
        sport = rng.randint(40000, 60000)
        out.append(pkt(ATTACKER, ESP, TCP(sport=sport, dport=port, flags="S", seq=1), t))
        if port == 80:                                           # the one open port answers SYN-ACK
            out.append(pkt(ESP, ATTACKER, TCP(sport=80, dport=sport, flags="SA", seq=7, ack=2), t + 0.002))
            out.append(pkt(ATTACKER, ESP, TCP(sport=sport, dport=80, flags="R", seq=2), t + 0.003))
        else:                                                    # closed ports answer with a reset
            out.append(pkt(ESP, ATTACKER, TCP(sport=port, dport=sport, flags="RA", seq=0, ack=2), t + 0.002))
        t += rng.uniform(0.002, 0.02)
    return out


def http_flood(rng: random.Random, t0: float) -> list:
    out = []
    for i in range(600):
        out += tcp_conn(ATTACKER, rng.randint(40000, 60000), ESP, 80, t0 + i * 20 / 600,
                        b"GET / HTTP/1.1\r\nHost: 192.168.137.57\r\n\r\n", PAGE, rng.uniform(0.2, 1.5))
    return out


def write(name: str, packets: list) -> Path:
    OUT.mkdir(exist_ok=True)
    path = OUT / name
    packets.sort(key=lambda p: p.time)
    with PcapWriter(str(path), linktype=1, sync=False) as w:
        for p in packets:
            w.write(p)
    print(f"{path}: {len(packets):,} packets, {(packets[-1].time - packets[0].time) / 60:.0f} min")
    return path


def main() -> None:
    day = datetime(2026, 11, 25, tzinfo=timezone.utc).timestamp()
    write("poc-normal.pcap", normal_traffic(random.Random(1), day + 10 * 3600, 30))
    rng = random.Random(2)
    start = day + 11 * 3600
    write("poc-attack.pcap", normal_traffic(rng, start, 15) + port_scan(rng, start + 5 * 60)
          + http_flood(rng, start + 10 * 60))
    print("attack times (UTC): port scan 11:05:00-11:05:12, HTTP flood 11:10:00-11:10:21")


if __name__ == "__main__":
    main()
