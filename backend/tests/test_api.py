"""Step 10 tests: the API's /health and POST endpoints, against the throw-away `aegex_test` database.

FastAPI's TestClient calls the app directly (no server, no network), exactly as a real client would.
"""
from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import api.db
from api.main import app

SAMPLES = Path(__file__).resolve().parents[1] / "samples"
SEED = Path(__file__).resolve().parents[1] / "sql" / "seed_lab.sql"
CAP = "cap-2026-11-20-a"
EVENT = {"ts": "2026-11-20T14:20:03.120Z", "source": "cowrie", "event_type": "login_failed", "device_id": "gw-01",
         "src_ip": "192.168.56.99", "src_port": 51234, "dst_ip": "192.168.56.10", "dst_port": 22, "proto": "tcp",
         "payload": {"username": "root", "password": "admin", "session": "t1"}}


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


def count(db, table: str = "events", where: str = "TRUE") -> int:
    return db.execute(f"SELECT count(*) FROM {table} WHERE {where}").fetchone()[0]


def problems(response) -> str:
    return " | ".join(response.json()["detail"]["problems"])


# ------------------------------------------------------------------------------------------- health
def test_health(client):
    r = client.get("/health")
    assert r.status_code == 200
    body = r.json()
    assert (body["status"], body["database"], body["feature_version"]) == ("ok", "ok", "1.0.0")
    assert body["timescaledb"] and body["counts"]["captures"] == 1


def test_database_down_gives_503_not_a_crash(monkeypatch):
    original = api.db.open_pool
    # Nothing listens on port 1: every connection fails. Short timeout so the test is quick.
    monkeypatch.setattr(api.db, "open_pool", lambda: original("postgresql://x:y@127.0.0.1:1/none", timeout=0.5))
    with TestClient(app) as c:
        r = c.get("/health")
        assert r.status_code == 503 and r.json()["status"] == "degraded"
        assert c.post("/api/v1/ingest/events", json=EVENT).status_code == 503


def test_swagger_lists_the_endpoints(client):
    paths = client.get("/openapi.json").json()["paths"]
    assert {"/health", "/api/v1/ingest/events", "/api/v1/ingest/sensor", "/api/v1/ingest/logs/{source}",
            "/api/v1/captures", "/api/v1/attack-runs"} <= set(paths)
    assert client.get("/docs").status_code == 200


# ------------------------------------------------------------------------------------------- events
def test_one_event_is_saved_and_sending_it_again_adds_nothing(client, db):
    r = client.post("/api/v1/ingest/events", json=EVENT)
    assert r.status_code == 200
    assert r.json() == {"received": 1, "inserted": 1, "duplicates": 0, "captures": {CAP: 1}}   # capture found by time
    row = db.execute("SELECT layer, capture_id, host(src_ip), payload->>'username' FROM events").fetchone()
    assert row == ("session_interaction", CAP, "192.168.56.99", "root")                   # layer from the contract
    assert client.post("/api/v1/ingest/events", json=[EVENT]).json()["duplicates"] == 1
    assert count(db) == 1


def test_own_dedup_key_lets_identical_events_through(client, db):
    r = client.post("/api/v1/ingest/events", json=[{**EVENT, "dedup_key": "a"}, {**EVENT, "dedup_key": "b"}])
    assert r.json()["inserted"] == 2


def test_one_bad_event_saves_none_and_lists_every_problem(client, db):
    batch = [EVENT,
             {**EVENT, "device_id": "cam-9"},
             {**EVENT, "source": "mosquitto"},                              # mosquitto can't report a login
             {**EVENT, "event_type": "hacked"},
             {**EVENT, "capture_id": "cap-nope"},
             {**EVENT, "capture_id": CAP, "ts": "2026-11-20T16:00:00Z"}]   # after the capture ended
    r = client.post("/api/v1/ingest/events", json=batch)
    assert r.status_code == 422
    text = problems(r)
    for expected in ("item 1: device 'cam-9' does not exist", "item 2: source 'mosquitto' is not allowed",
                     "item 3: event_type 'hacked'", "item 4: capture 'cap-nope' does not exist",
                     "item 5: ts 2026-11-20 16:00:00 UTC is outside capture"):
        assert expected in text
    assert count(db) == 0


@pytest.mark.parametrize("change, where", [({"ts": "2026-11-20T14:20:03"}, "ts"),         # no time zone
                                           ({"dst_port": 70000}, "dst_port"),
                                           ({"src_ip": "not-an-ip"}, "src_ip"),
                                           ({"colour": "red"}, "colour")])                # unknown field
def test_bad_shapes_are_refused_by_the_schema(client, db, change, where):
    r = client.post("/api/v1/ingest/events", json=[{**EVENT, **change}])
    assert r.status_code == 422 and r.json()["detail"][0]["loc"][-1] == where
    assert count(db) == 0


def test_event_outside_every_capture_is_saved_without_capture(client, db):
    r = client.post("/api/v1/ingest/events", json={**EVENT, "ts": "2026-12-01T09:00:00+02:00"})
    assert r.json()["captures"] == {"(none)": 1}
    assert db.execute("SELECT ts, capture_id FROM events").fetchone()[1] is None


def test_too_many_events_in_one_request(client):
    r = client.post("/api/v1/ingest/events", json=[{**EVENT, "dedup_key": str(i)} for i in range(5001)])
    assert r.status_code == 422 and "at most 5000" in problems(r)


# ------------------------------------------------------------------------------------------- sensor
def test_sensor_reading(client, db):
    r = client.post("/api/v1/ingest/sensor", json={"device_id": "esp32-smoke-01", "ts": "2026-11-20T14:30:00Z",
                                                   "smoke": 12.5, "temperature_c": 24.0})
    assert r.json()["inserted"] == 1
    row = db.execute("SELECT source, event_type, host(src_ip), capture_id, payload FROM events").fetchone()
    assert row == ("esp32", "sensor_reading", "192.168.56.20", CAP, {"smoke": 12.5, "temperature_c": 24.0})


def test_sensor_without_clock_gets_server_time(client, db):
    assert client.post("/api/v1/ingest/sensor", json={"device_id": "esp32-smoke-01", "smoke": 1}).json()["inserted"] == 1
    assert db.execute("SELECT payload->>'ts_source' FROM events").fetchone()[0] == "server"
    assert client.post("/api/v1/ingest/sensor", json={"device_id": "nope"}).status_code == 422


# ------------------------------------------------------------------------------------------- raw logs
def post_log(client, source: str, file: str, **params):
    text = (SAMPLES / file).read_text(encoding="utf-8")
    return client.post(f"/api/v1/ingest/logs/{source}", content=text, params=params,
                       headers={"Content-Type": "text/plain"})


def test_raw_logs_use_the_same_parsers_as_the_command_line(client, db):
    r = post_log(client, "cowrie", "cowrie.json", device_id="gw-01", capture_id=CAP)
    assert r.json() == {"lines": 13, "parsed": 11, "ignored": 1, "broken": 1, "inserted": 11, "duplicates": 0}
    assert post_log(client, "cowrie", "cowrie.json", device_id="gw-01", capture_id=CAP).json()["inserted"] == 0
    assert post_log(client, "mosquitto", "mosquitto.log", device_id="gw-01", capture_id=CAP,
                    broker_ip="192.168.56.10").json()["inserted"] == 4
    assert post_log(client, "esp32", "esp32.csv", device_id="esp32-smoke-01", capture_id=CAP,
                    device_ip="192.168.56.20").json()["inserted"] == 4
    assert post_log(client, "zeek-conn", "zeek/conn.log", capture_id=CAP).json()["inserted"] == 9
    assert (count(db), count(db, "flows")) == (19, 9)


def test_raw_log_refusals(client, db):
    r = post_log(client, "esp32", "esp32.csv", device_id="esp32-smoke-01", capture_id=CAP, tz="Asia/Tokyo")
    assert r.status_code == 422 and "outside capture" in problems(r)                      # wrong time zone
    assert post_log(client, "esp32", "esp32.csv", device_id="esp32-smoke-01", tz="Mars/Base").status_code == 422
    assert post_log(client, "cowrie", "cowrie.json", device_id="nope").status_code == 422
    assert post_log(client, "syslog", "cowrie.json").status_code == 422                   # not a supported source
    assert count(db) == 0


# ------------------------------------------------------------------------------------------- captures
def test_captures(client, db):
    cap = {"capture_id": "cap-x", "start_ts": "2026-11-27T09:00:00Z", "end_ts": "2026-11-27T10:00:00Z", "kind": "attack"}
    assert client.post("/api/v1/captures", json=cap).status_code == 201
    r = client.post("/api/v1/captures", json=cap)
    assert r.status_code == 200 and r.json() == {"capture_id": "cap-x", "created": False}
    assert client.post("/api/v1/captures", json={**cap, "end_ts": "2026-11-27T11:00:00Z"}).status_code == 409
    assert client.post("/api/v1/captures", json={**cap, "capture_id": "y", "end_ts": "2026-11-27T08:00:00Z"}).status_code == 422
    assert client.post("/api/v1/captures", json={**cap, "kind": "weird"}).status_code == 422
    assert count(db, "captures") == 2


# ------------------------------------------------------------------------------------------- attack runs
RUN = {"run_id": "run-017", "capture_id": CAP, "scenario": "vulnerability_scanning", "tool": "nmap",
       "attacker_ip": "192.168.56.77", "target_device": "cam-01",
       "start_ts": "2026-11-20T14:45:00Z", "end_ts": "2026-11-20T14:47:00Z"}


def test_attack_run_is_saved_then_updated(client, db):
    r = client.post("/api/v1/attack-runs", json=RUN)
    assert r.status_code == 200 and r.json()["inserted"] == ["run-017"]
    assert client.post("/api/v1/attack-runs", json=[RUN]).json()["unchanged"] == ["run-017"]
    r = client.post("/api/v1/attack-runs", json={**RUN, "end_ts": "2026-11-20T14:48:00Z"})
    assert r.json()["updated"] == {"run-017": ["end_ts"]}


def test_attack_runs_label_the_data(client, db):
    post_log(client, "cowrie", "cowrie.json", device_id="gw-01", capture_id=CAP)
    seed_run = {**RUN, "run_id": "run-001", "scenario": "bruteforce", "tool": "hydra", "attacker_ip": "192.168.56.99",
                "target_device": "gw-01", "start_ts": "2026-11-20T14:10:00Z", "end_ts": "2026-11-20T14:18:00Z",
                "command": "hydra -l root -P passwords.txt ssh://192.168.56.10"}
    r = client.post("/api/v1/attack-runs", params={"label": True}, json=seed_run)
    assert r.json()["labeled_captures"] == [CAP]
    assert count(db, where="label = 1") == 11


def test_bad_attack_log_saves_nothing(client, db):
    batch = [RUN, {**RUN, "run_id": "run-018", "attacker_ip": "192.168.56.10"},          # attacker = honeypot
             {**RUN, "run_id": "run-019", "start_ts": "2026-11-20T15:30:00Z", "end_ts": "2026-11-20T15:40:00Z"},
             {**RUN, "run_id": "run-017"}]                                                  # same id twice
    r = client.post("/api/v1/attack-runs", json=batch)
    assert r.status_code == 422
    text = problems(r)
    assert "is our own lab device gw-01" in text and "outside capture" in text and "used twice" in text
    assert client.post("/api/v1/attack-runs", json=[{**RUN, "scenario": "brute force"}]).status_code == 422
    assert count(db, "attack_runs") == 1                                                    # only the seed's run-001
