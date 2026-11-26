"""Step 8 tests: 24 numbers per device per 10-second window.

The first tests need no database. The rest use the throw-away `aegex_test` database (see conftest.py).
"""
from __future__ import annotations

import math
from datetime import datetime, timedelta
from pathlib import Path

import pytest
from psycopg.types.json import Jsonb

from features import window as W
from features.build import build_window_features, check_window_features, window_table
from ingest.event import CONTRACT
from ingest.flows import load_conn_log
from ingest.loader import label_capture, load_file
from ingest.parsers import CowrieParser, Esp32CsvParser, MosquittoLogParser

SAMPLES = Path(__file__).resolve().parents[1] / "samples"
SEED = Path(__file__).resolve().parents[1] / "sql" / "seed_lab.sql"
CAP = "cap-2026-11-20-a"


def utc(hh_mm_ss: str) -> datetime:
    return datetime.fromisoformat(f"2026-11-20T{hh_mm_ss}+00:00")


# ------------------------------------------------------------------------------------------- the list and the clock
def test_24_features_in_contract_order():
    assert len(W.FEATURE_NAMES) == 24 == CONTRACT["window_features"]["dimension"]
    assert W.FEATURE_NAMES[:20] == [f["name"] for f in CONTRACT["window_features"]["numeric"]]
    assert W.FEATURE_NAMES[20:] == ["device_type_esp32_sensor", "device_type_ip_camera", "device_type_gateway",
                                    "device_type_other"]
    assert not set(CONTRACT["forbidden_as_features"]["fields"]) & set(W.FEATURE_NAMES)


@pytest.mark.parametrize("ts, start", [("14:10:05.4", "14:10:00"), ("14:10:00", "14:10:00"),
                                       ("14:10:09.999", "14:10:00"), ("14:10:10", "14:10:10")])
def test_windows_are_aligned_to_the_clock(ts, start):
    assert W.window_start(utc(ts)) == utc(start)


def test_one_hour_capture_has_360_windows():
    windows = W.capture_windows(utc("14:00:00"), utc("15:00:00"))
    assert len(windows) == 360
    assert (windows[0], windows[-1]) == (utc("14:00:00"), utc("14:59:50"))
    assert W.capture_windows(utc("14:00:03"), utc("14:00:25")) == [utc("14:00:00"), utc("14:00:10"), utc("14:00:20")]


def test_transform_follows_the_contract():
    raw = dict.fromkeys(W.FEATURE_NAMES, 0.0) | {"n_conn_in": 99.0, "ratio_failed_conn": 0.5,
                                                 "sensor_n_readings": 3.0, "device_type_gateway": 1.0}
    out = W.transform(raw)
    assert out["n_conn_in"] == pytest.approx(math.log1p(99))       # log1p
    assert out["ratio_failed_conn"] == 0.5                         # none
    assert out["sensor_n_readings"] == 3.0                         # none (contract)
    assert out["device_type_gateway"] == 1.0


def test_sensor_jumps_compare_with_the_previous_valid_reading():
    rows = [("esp", utc("14:00:00"), {"smoke": 10.0, "temperature_c": 24.0}),
            ("esp", utc("14:00:10"), {"smoke": 11.0, "temperature_c": 24.0}),
            ("esp", utc("14:00:20"), {"smoke": None, "temperature_c": 24.5}),   # smoke "ERR": skipped
            ("esp", utc("14:00:30"), {"smoke": 90.0, "temperature_c": 24.5}),   # spike vs 11, the last valid smoke
            ("esp", utc("14:00:31"), {"smoke": 88.0, "temperature_c": 24.5})]
    out = W._sensor_features(rows)
    assert out[("esp", utc("14:00:00"))]["sensor_smoke_delta_max"] == 0      # first reading: nothing to compare
    assert out[("esp", utc("14:00:10"))]["sensor_smoke_delta_max"] == 1
    assert out[("esp", utc("14:00:20"))]["sensor_temp_delta_max"] == 0.5
    assert out[("esp", utc("14:00:30"))]["sensor_smoke_delta_max"] == 79     # biggest jump in the window
    assert out[("esp", utc("14:00:30"))]["sensor_n_readings"] == 2


def test_window_label_rules():
    assert W._window_label([], labeled=True) == (0, None, None)                         # silence in a labeled capture
    assert W._window_label([], labeled=False) == (None, None, None)                     # not labeled yet: unknown
    assert W._window_label([(0, None, None, 5)], labeled=True) == (0, None, None)
    assert W._window_label([(0, None, None, 5), (1, "dos", "r2", 1)], labeled=True) == (1, "dos", "r2")
    assert W._window_label([(1, "dos", "r2", 1), (1, "bruteforce", "r1", 3)], labeled=True) == (1, "bruteforce", "r1")
    assert W._window_label([(1, "dos", "r2", 2), (1, "bruteforce", "r1", 2)], labeled=True) == (1, "bruteforce", "r1")
    assert W._window_label([(None, None, None, 1), (1, "dos", "r2", 1)], labeled=False) == (1, "dos", "r2")


# ------------------------------------------------------------------------------------------- database
@pytest.fixture
def lab(db):
    db.execute("DELETE FROM feature_windows")
    db.execute("DELETE FROM attack_runs")
    db.execute("DELETE FROM captures WHERE capture_id <> %s", (CAP,))
    db.execute(SEED.read_text(encoding="utf-8"))
    load_file(db, CowrieParser("gw-01"), SAMPLES / "cowrie.json", CAP)
    load_file(db, MosquittoLogParser("gw-01", broker_ip="192.168.56.10"), SAMPLES / "mosquitto.log", CAP)
    load_file(db, Esp32CsvParser("esp32-smoke-01", device_ip="192.168.56.20"), SAMPLES / "esp32.csv", CAP)
    load_conn_log(db, SAMPLES / "zeek" / "conn.log", CAP)
    label_capture(db, CAP)
    yield db
    db.execute("DELETE FROM feature_windows")


def windows_by_key(db) -> dict[tuple[str, str], dict]:
    return {(r["device_id"], r["window_start"][11:19]): r for r in window_table(db, CAP)}


def add_event(db, ts: str, event_type: str, src_ip: str, payload: dict, device_id: str = "gw-01",
              capture_id: str = CAP, layer: str = "device_service_logs", source: str = "mosquitto", label=0):
    db.execute("INSERT INTO events (ts, source, event_type, layer, device_id, capture_id, src_ip, dst_ip, payload, label) "
               "VALUES (%s, %s, %s, %s, %s, %s, %s, '192.168.56.10', %s, %s)",
               (utc(ts), source, event_type, layer, device_id, capture_id, src_ip, Jsonb(payload), label))


def test_every_device_gets_every_window(lab):
    result = build_window_features(lab, CAP)
    assert (result.windows, result.devices, result.unlabeled) == (1080, 3, 0)
    check = check_window_features(lab, CAP)
    assert check.ok and check.rows == 1080


def test_attack_windows_are_exactly_the_attackers_activity(lab):
    build_window_features(lab, CAP)
    attack = sorted((r["device_id"], r["window_start"][11:19], r["scenario"], r["run_id"])
                    for r in window_table(lab, CAP) if r["label"] == 1)
    assert attack == [("gw-01", t, "bruteforce", "run-001")
                      for t in ("14:10:00", "14:12:30", "14:12:40", "14:13:00", "14:13:20")]


def test_counts_in_the_first_attack_window(lab):
    build_window_features(lab, CAP)
    raw = windows_by_key(lab)[("gw-01", "14:10:00")]["_raw"]
    assert (raw["n_conn_in"], raw["n_unique_src_ip"], raw["n_unique_dst_port"]) == (2, 1, 1)
    assert (raw["n_ssh_telnet_conn"], raw["n_login_failed"], raw["ratio_failed_conn"]) == (2, 2, 0)
    assert raw["bytes_in_total"] == 654 and raw["device_type_gateway"] == 1


def test_silent_window_is_real_zeros(lab):
    build_window_features(lab, CAP)
    row = windows_by_key(lab)[("gw-01", "14:20:00")]
    assert all(row["_raw"][n] == 0 for n in W.NUMERIC)
    assert (row["n_events"], row["label"], row["device_type_gateway"]) == (0, 0, 1.0)


def test_stored_features_are_raw_after_the_transform(lab):
    build_window_features(lab, CAP)
    row = windows_by_key(lab)[("cam-01", "14:06:00")]
    assert row["bytes_out_total"] == pytest.approx(math.log1p(row["_raw"]["bytes_out_total"]))
    assert row["_raw"]["bytes_out_total"] == 84069


def test_ping_without_answer_counts_as_failed(lab):
    build_window_features(lab, CAP)
    assert windows_by_key(lab)[("esp32-smoke-01", "14:30:00")]["_raw"]["ratio_failed_conn"] == 1   # Zeek: OTH


def test_own_telemetry_is_not_counted_but_a_spoofed_publish_is(lab):
    build_window_features(lab, CAP)
    assert all(r["_raw"]["n_mqtt_publish"] == 0 for r in window_table(lab, CAP))      # only the ESP32's own readings
    add_event(lab, "14:50:01", "mqtt_publish", "192.168.56.99", {"topic": "aegex/sensors/smoke", "client_id": "evil"})
    build_window_features(lab, CAP)
    assert windows_by_key(lab)[("gw-01", "14:50:00")]["_raw"]["n_mqtt_publish"] == 1


def test_rebuilding_replaces_instead_of_duplicating(lab):
    build_window_features(lab, CAP)
    build_window_features(lab, CAP)
    assert lab.execute("SELECT count(*) FROM feature_windows").fetchone()[0] == 1080


def test_unlabeled_capture_gives_unknown_labels_but_keeps_known_attacks(lab):
    lab.execute("UPDATE events SET label = NULL WHERE event_type = 'sensor_reading'")
    result = build_window_features(lab, CAP)
    assert result.unlabeled == 1080 - 5 and result.attack == 5
    assert "WARNING" in str(result)


def test_live_capture_goes_up_to_the_newest_data(lab):
    lab.execute("INSERT INTO captures (capture_id, start_ts, kind) VALUES ('cap-live', %s, 'live')",
                (utc("16:00:00"),))
    add_event(lab, "16:00:25", "mqtt_connect", "192.168.56.20", {"client_id": "esp32-smoke-01"},
              capture_id="cap-live", label=None)
    result = build_window_features(lab, "cap-live")
    assert result.windows == 3 * 3                                 # 16:00:00, :10, :20 for 3 devices
    assert result.unlabeled == 9                                    # live data has no labels
    lab.execute("DELETE FROM events WHERE capture_id = 'cap-live'")
    lab.execute("DELETE FROM feature_windows WHERE capture_id = 'cap-live'")
