"""Step 3 tests: each parser turns real-looking log lines into the right Events.

Run from the backend folder:  .venv/Scripts/python -m pytest -v
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from ingest.event import EVENT_TYPES, ContractError, Event, make_dedup_key
from ingest.parsers import CowrieParser, Esp32CsvParser, FileFormatError, MosquittoLogParser

SAMPLES = Path(__file__).resolve().parents[1] / "samples"
UTC = timezone.utc


# ------------------------------------------------------------------------------------------- Cowrie
def test_cowrie_sample_file_tells_the_bruteforce_story():
    p = CowrieParser(device_id="gw-01")
    events = p.parse_file(SAMPLES / "cowrie.json")

    assert [e.event_type for e in events] == [
        "session_open", "login_failed", "session_close",
        "session_open", "login_failed", "session_close",
        "session_open", "login_success", "command", "file_download", "session_close",
    ]
    # 13 lines: 11 events, 1 we don't need (client.version), 1 broken
    assert (p.stats.lines, p.stats.events, p.stats.ignored, p.stats.skipped) == (13, 11, 1, 1)

    for e in events:
        assert e.src_ip == "192.168.56.99" and e.dst_ip == "192.168.56.10" and e.dst_port == 22
        assert e.device_id == "gw-01" and e.proto == "tcp" and e.layer == "session_interaction"
        assert e.ts.tzinfo is not None and e.ts.utcoffset().total_seconds() == 0


def test_cowrie_copies_ports_from_the_connect_line():
    # The login line itself has no ports. They must come from the session's connect line.
    login = next(e for e in CowrieParser().parse_file(SAMPLES / "cowrie.json") if e.event_type == "login_success")
    assert login.src_port == 40188 and login.dst_port == 22
    assert login.payload["username"] == "root" and login.payload["password"] == "raspberry"
    assert login.ts == datetime(2026, 11, 20, 14, 12, 40, 10000, tzinfo=UTC)


def test_cowrie_payload_keeps_source_fields_but_not_the_columns():
    dl = next(e for e in CowrieParser().parse_file(SAMPLES / "cowrie.json") if e.event_type == "file_download")
    assert dl.payload["url"] == "http://192.168.56.99/bot.arm" and dl.payload["shasum"].startswith("e3b0c442")
    assert "src_ip" not in dl.payload and "timestamp" not in dl.payload     # already real columns
    assert dl.severity == "critical"


def test_cowrie_bad_lines_are_skipped_not_fatal():
    p = CowrieParser()
    assert p.parse_lines(["not json", "[1, 2]", '{"eventid": "cowrie.login.failed"}', ""]) == []
    assert p.stats.skipped == 3          # the empty line is not even counted


# ---------------------------------------------------------------------------------------- Mosquitto
def test_mosquitto_sample_file():
    p = MosquittoLogParser(device_id="gw-01", broker_ip="192.168.56.10")
    events = p.parse_file(SAMPLES / "mosquitto.log")

    assert [e.event_type for e in events] == ["mqtt_connect", "mqtt_subscribe", "mqtt_publish", "mqtt_publish"]
    assert (p.stats.events, p.stats.ignored, p.stats.skipped) == (4, 4, 1)
    for e in events:
        assert e.src_ip == "192.168.56.20" and e.src_port == 50112        # remembered from the connect line
        assert e.dst_ip == "192.168.56.10" and e.dst_port == 1883
        assert e.payload["client_id"] == "esp32-smoke-01" and e.layer == "device_service_logs"
    assert events[0].ts == datetime(2026, 11, 20, 14, 4, 58, tzinfo=UTC)
    assert events[2].payload == {"client_id": "esp32-smoke-01", "topic": "aegex/sensors/smoke", "qos": 0,
                                 "retain": False, "payload_bytes": 58}


REAL_MOSQUITTO_2_0_18 = """\
1793133159: mosquitto version 2.0.18 running
1793133160: New connection from 127.0.0.1:44142 on port 1883.
1793133160: New client connected from 127.0.0.1:44142 as watcher (p2, c1, k60).
1793133160: watcher 0 home/#
1793133161: New client connected from 127.0.0.1:44146 as aegex-monitor (p2, c1, k60).
1793133161: aegex-monitor 0 #
1793133161: Client watcher disconnected.
1793133162: some-unknown 0 topic
""".splitlines()      # captured from a real broker (reused from the old tests/test_feeds.py)


def test_mosquitto_real_log_lines():
    events = MosquittoLogParser(ignore_clients=("aegex-monitor",)).parse_lines(REAL_MOSQUITTO_2_0_18)
    assert [(e.event_type, e.payload.get("topic")) for e in events] == [("mqtt_connect", None), ("mqtt_subscribe", "home/#")]
    # "some-unknown 0 topic" looks like a subscribe, but that client never connected, so it is not trusted


def test_mosquitto_username_is_kept():
    line = "1793133160: New client connected from 10.0.0.5:5000 as bot (p2, c1, k60, u'admin')."
    (e,) = MosquittoLogParser().parse_lines([line])
    assert e.payload["username"] == "admin"


# -------------------------------------------------------------------------------------------- ESP32
def test_esp32_sample_file():
    p = Esp32CsvParser(device_id="esp32-smoke-01", device_ip="192.168.56.20", tz="UTC")
    events = p.parse_file(SAMPLES / "esp32.csv")

    assert len(events) == 4 and all(e.event_type == "sensor_reading" for e in events)
    assert (p.stats.ignored, p.stats.skipped) == (1, 1)          # the header, and the row with no valid time
    first = events[0]
    assert first.ts == datetime(2026, 11, 20, 14, 5, 0, tzinfo=UTC)
    assert first.payload == {"esp_ms": 3664, "smoke": 12.0, "temperature_c": 24.1, "humidity_pct": 41.0}
    assert first.layer == "telemetry_media" and first.src_ip == "192.168.56.20"


def test_esp32_bad_value_keeps_the_row_and_marks_it():
    bad = Esp32CsvParser().parse_file(SAMPLES / "esp32.csv")[2]
    assert bad.payload["smoke"] is None and bad.payload["invalid_fields"] == ["smoke"]
    assert bad.payload["temperature_c"] == 24.2


def test_esp32_time_zone_is_converted_to_utc():
    lines = ["time,smoke", "2026-11-20 23:05:00,12"]
    (e,) = Esp32CsvParser(tz="Asia/Tokyo").parse_lines(lines)      # Tokyo is UTC+9, no daylight saving
    assert e.ts == datetime(2026, 11, 20, 14, 5, 0, tzinfo=UTC)


def test_esp32_header_aliases_match_the_real_csv():
    # The header of data/my_data.csv, and the old spelling "tempeture"
    for header in ("time,esp_ms,smoke,temperature_C,humidity_pct", "time,esp_ms,smoke,tempeture,humidity_pct"):
        (e,) = Esp32CsvParser().parse_lines([header, "2026-10-23 10:14:52,3664,403,26.9,62"])
        assert e.payload["temperature_c"] == 26.9


def test_esp32_file_without_time_column_stops_the_load():
    with pytest.raises(FileFormatError):
        Esp32CsvParser().parse_lines(["smoke,temp", "1,2"])


# ------------------------------------------------------------------------------- shared behaviour
def test_reading_the_same_file_twice_gives_the_same_keys():
    a = [e.dedup_key for e in CowrieParser().parse_file(SAMPLES / "cowrie.json")]
    b = [e.dedup_key for e in CowrieParser().parse_file(SAMPLES / "cowrie.json")]
    assert a == b and len(set(a)) == len(a)


def test_two_identical_lines_get_different_keys():
    line = "1793133160: New client connected from 10.0.0.5:5000 as bot (p2, c1, k60)."
    e1, e2 = MosquittoLogParser().parse_lines([line, line])
    assert e1.dedup_key != e2.dedup_key
    assert e1.dedup_key == make_dedup_key("mosquitto", line, 0)


def test_every_event_fits_the_contract_and_the_table():
    events = (CowrieParser().parse_file(SAMPLES / "cowrie.json")
              + MosquittoLogParser().parse_file(SAMPLES / "mosquitto.log")
              + Esp32CsvParser().parse_file(SAMPLES / "esp32.csv"))
    columns = {"ts", "source", "event_type", "layer", "device_id", "capture_id", "src_ip", "src_port", "dst_ip",
               "dst_port", "proto", "severity", "dedup_key", "payload"}
    for e in events:
        assert e.event_type in EVENT_TYPES
        row = e.to_row()
        assert set(row) == columns                  # exactly the events table's columns
        json.dumps(row["payload"])                  # payload must be valid JSON for the JSONB column


def test_contract_violations_fail_loudly():
    ts = datetime(2026, 11, 20, tzinfo=UTC)
    with pytest.raises(ContractError):
        Event(ts=ts, source="cowrie", event_type="made_up_type", dedup_key="x")
    with pytest.raises(ContractError):
        Event(ts=ts, source="esp32", event_type="login_failed", dedup_key="x")      # ESP32 can't log logins
    with pytest.raises(ContractError):
        Event(ts=datetime(2026, 11, 20), source="esp32", event_type="sensor_reading", dedup_key="x")  # no tz
