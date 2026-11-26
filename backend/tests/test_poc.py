"""The proof-of-concept lab (laptop hotspot + ESP32-S3): the honeypot endpoint, `monitored`, and seed_poc.sql.

Runs against the throw-away `aegex_test` database like the other API tests. The PoC devices are added only for
the tests that need them and removed afterwards, so the sample-lab tests still see their 3 devices.
"""
from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from api.main import app
from features.window import capture_window_features

BACKEND = Path(__file__).resolve().parents[1]
SEED = BACKEND / "sql" / "seed_lab.sql"
SEED_POC = BACKEND / "sql" / "seed_poc.sql"
CAP = "cap-2026-11-20-a"
HIT = {"device_id": "esp32-smoke-01", "event": "login_failed", "service": "telnet", "src_ip": "192.168.56.99",
       "src_port": 51234, "dst_port": 23, "session": "s1", "username": "root", "password": "admin"}


@pytest.fixture
def client(db, test_db_url, monkeypatch):
    def reset():
        for sql in ("DELETE FROM feature_windows", "DELETE FROM events", "DELETE FROM flows", "DELETE FROM attack_runs"):
            db.execute(sql)
        db.execute("DELETE FROM captures WHERE capture_id <> %s", (CAP,))
        db.execute(SEED.read_text(encoding="utf-8"))
    reset()
    monkeypatch.setenv("AEGEX_DB_URL", test_db_url)
    with TestClient(app) as c:
        yield c
    reset()


@pytest.fixture
def poc_devices(db):
    db.execute(SEED_POC.read_text(encoding="utf-8"))
    yield
    db.execute("DELETE FROM events WHERE device_id IN ('esp32s3-01', 'laptop-gw')")
    db.execute("DELETE FROM devices WHERE device_id IN ('esp32s3-01', 'laptop-gw')")


def problems(response) -> str:
    return " | ".join(response.json()["detail"]["problems"])


def test_honeypot_event_without_clock_gets_server_time(client, db):
    r = client.post("/api/v1/ingest/honeypot", json=HIT)
    assert r.status_code == 200, r.text
    assert (r.json()["inserted"], r.json()["duplicates"]) == (1, 0)
    row = db.execute("SELECT source, event_type, layer, severity, host(src_ip), host(dst_ip), dst_port, "
                     "payload->>'ts_source', payload->>'service', payload->>'username', ts > now() - interval '1 minute' "
                     "FROM events").fetchone()
    assert row == ("esp32", "login_failed", "session_interaction", "medium", "192.168.56.99", "192.168.56.20", 23,
                   "server", "telnet", "root", True)


def test_honeypot_session_events_map_to_contract_types(client, db):
    ts = "2026-11-20T14:30:00Z"
    for i, event in enumerate(["connect", "login_failed", "login_success", "command", "disconnect"]):
        extra = {"input": "uname -a"} if event == "command" else {}
        r = client.post("/api/v1/ingest/honeypot", json={**HIT, "event": event, "ts": ts, "esp_ms": i, **extra})
        assert r.status_code == 200, r.text
        assert r.json()["captures"] == {CAP: 1}           # the capture recording at ts is found by itself
    types = [t for (t,) in db.execute("SELECT event_type FROM events ORDER BY payload->>'esp_ms'")]
    assert types == ["session_open", "login_failed", "login_success", "command", "session_close"]
    again = client.post("/api/v1/ingest/honeypot", json={**HIT, "event": "connect", "ts": ts, "esp_ms": 0})
    assert (again.json()["inserted"], again.json()["duplicates"]) == (0, 1)   # sent twice, saved once


def test_honeypot_refuses_mistakes(client, db):
    r = client.post("/api/v1/ingest/honeypot", json={**HIT, "device_id": "nope"})
    assert r.status_code == 422 and "does not exist" in problems(r)
    r = client.post("/api/v1/ingest/honeypot", json={**HIT, "src_ip": "192.168.56.20"})
    assert r.status_code == 422 and "the honeypot itself" in problems(r)
    r = client.post("/api/v1/ingest/honeypot", json={**HIT, "event": "hack"})
    assert r.status_code == 422                                   # not one of the 6 events
    r = client.post("/api/v1/ingest/honeypot", json={**HIT, "ts": "2026-11-20T18:00:00Z", "capture_id": CAP})
    assert r.status_code == 422 and "outside capture" in problems(r)
    assert db.execute("SELECT count(*) FROM events").fetchone()[0] == 0


def test_poc_seed_and_monitored_flag(client, db, poc_devices):
    devices = {d["device_id"]: d for d in client.get("/api/v1/devices").json()["items"]}
    assert devices["esp32s3-01"]["monitored"] is True and devices["esp32s3-01"]["device_type"] == "esp32_sensor"
    assert devices["laptop-gw"]["monitored"] is False and devices["laptop-gw"]["ip"] == "192.168.137.1"
    windows = capture_window_features(db, CAP)
    entities = {w.device_id for w in windows}
    assert "esp32s3-01" in entities and "laptop-gw" not in entities   # the laptop is known, but gets no windows


def test_honeypot_logins_reach_window_features(client, db, poc_devices):
    db.execute("UPDATE devices SET ip = '192.168.137.57' WHERE device_id = 'esp32s3-01'")
    for i in range(3):
        r = client.post("/api/v1/ingest/honeypot", json={**HIT, "device_id": "esp32s3-01", "src_ip": "192.168.137.50",
                                                         "ts": f"2026-11-20T14:40:0{i}Z"})
        assert r.status_code == 200, r.text
    hits = [w for w in capture_window_features(db, CAP)
            if (w.device_id) == "esp32s3-01" and w.features_raw["n_login_failed"]]
    assert len(hits) == 1 and hits[0].features_raw["n_login_failed"] == 3.0


def test_health_names_the_database(client):
    assert client.get("/health").json()["database_name"] == "aegex_test"


def test_closed_live_capture_gets_normal_labels(client, db, poc_devices):
    """A real PoC recording is often opened as 'live' and closed later. Once closed and labeled, its quiet
    windows must be label 0 (normal), or the autoencoders would have nothing to train on."""
    from ingest.loader import label_capture
    r = client.post("/api/v1/captures", json={"capture_id": "cap-poc-test", "start_ts": "2026-11-21T10:00:00Z",
                                               "kind": "live"})
    assert r.status_code in (200, 201), r.text
    r = client.post("/api/v1/ingest/honeypot", json={**HIT, "device_id": "esp32s3-01", "event": "http_request",
                                                     "service": "http", "src_ip": "192.168.137.20", "dst_port": 80,
                                                     "path": "/", "ts": "2026-11-21T10:00:15Z"})
    assert r.json()["captures"] == {"cap-poc-test": 1}
    label_capture(db, "cap-poc-test")
    still_open = capture_window_features(db, "cap-poc-test")
    assert still_open and all(w.label is None for w in still_open)        # recording: not judged yet
    db.execute("UPDATE captures SET end_ts = '2026-11-21T10:01:00Z' WHERE capture_id = 'cap-poc-test'")
    label_capture(db, "cap-poc-test")
    closed = capture_window_features(db, "cap-poc-test")
    monitored = db.execute("SELECT count(*) FROM devices WHERE monitored").fetchone()[0]
    assert len(closed) == 6 * monitored and all(w.label == 0 for w in closed)   # 6 windows per monitored device
