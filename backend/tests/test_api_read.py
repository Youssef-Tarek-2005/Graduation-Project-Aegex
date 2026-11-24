"""Step 11 tests: the GET endpoints, on the step 2 story loaded through the real pipeline.

Data (loaded once for this file): the sample Cowrie, Mosquitto, ESP32 and Zeek logs of cap-2026-11-20-a,
labeled with run-001, then flow and window features built. 19 events, 9 flows, 3 devices x 360 windows.
"""
from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from api.main import app
from features import flow, window
from features.build import build_flow_features, build_window_features
from ingest.db import connect
from ingest.loader import label_capture

SAMPLES = Path(__file__).resolve().parents[1] / "samples"
SEED = Path(__file__).resolve().parents[1] / "sql" / "seed_lab.sql"
CAP = "cap-2026-11-20-a"


def reset(conn) -> None:
    for sql in ("DELETE FROM feature_windows", "DELETE FROM events", "DELETE FROM flows", "DELETE FROM attack_runs"):
        conn.execute(sql)
    conn.execute("DELETE FROM captures WHERE capture_id <> %s", (CAP,))
    conn.execute(SEED.read_text(encoding="utf-8"))


def post_log(client, source: str, file: str, **params) -> None:
    r = client.post(f"/api/v1/ingest/logs/{source}", content=(SAMPLES / file).read_text(encoding="utf-8"),
                    params={"capture_id": CAP, **params}, headers={"Content-Type": "text/plain"})
    assert r.status_code == 200, r.text


@pytest.fixture(scope="module")
def client(test_db_url):
    mp = pytest.MonkeyPatch()
    mp.setenv("AEGEX_DB_URL", test_db_url)
    with connect(test_db_url) as conn, TestClient(app) as c:
        reset(conn)
        post_log(c, "cowrie", "cowrie.json", device_id="gw-01")
        post_log(c, "mosquitto", "mosquitto.log", device_id="gw-01", broker_ip="192.168.56.10")
        post_log(c, "esp32", "esp32.csv", device_id="esp32-smoke-01", device_ip="192.168.56.20")
        post_log(c, "zeek-conn", "zeek/conn.log")
        label_capture(conn, CAP)
        build_flow_features(conn, CAP)
        build_window_features(conn, CAP)
        yield c
        reset(conn)
    mp.undo()


def get(client, path: str, **params) -> dict:
    r = client.get(path, params=params)
    assert r.status_code == 200, r.text
    return r.json()


def walk(client, path: str, cursor: str | None = None, **params) -> list[dict]:
    """Follow next_cursor until the last page, like a real client would."""
    items = []
    while True:
        page = get(client, path, **params, **({"cursor": cursor} if cursor else {}))
        assert page["count"] == len(page["items"]) <= params.get("limit", 100)
        items += page["items"]
        cursor = page["next_cursor"]
        if cursor is None:
            return items


def refused(client, path: str, **params) -> str:
    r = client.get(path, params=params)
    assert r.status_code == 422, r.text
    detail = r.json()["detail"]
    return " | ".join(detail["problems"]) if isinstance(detail, dict) else json.dumps(detail)


# ------------------------------------------------------------------------------------------- lab
def test_swagger_lists_the_read_endpoints(client):
    paths = client.get("/openapi.json").json()["paths"]
    for path in ("/api/v1/devices", "/api/v1/events", "/api/v1/flows", "/api/v1/features/windows",
                 "/api/v1/graph/edges", "/api/v1/captures", "/api/v1/attack-runs"):
        assert "get" in paths[path], path


def test_devices(client):
    page = get(client, "/api/v1/devices")
    assert [d["device_id"] for d in page["items"]] == ["cam-01", "esp32-smoke-01", "gw-01"]
    assert page["items"][2]["ip"] == "192.168.56.10" and page["next_cursor"] is None


def test_captures_and_attack_runs(client):
    assert [c["capture_id"] for c in get(client, "/api/v1/captures")["items"]] == [CAP]
    assert get(client, "/api/v1/captures", **{"from": "2026-11-20T15:30:00Z"})["count"] == 0    # ended before
    assert get(client, "/api/v1/captures", **{"from": "2026-11-20T14:30:00Z"})["count"] == 1    # overlaps
    run = get(client, "/api/v1/attack-runs", scenario="bruteforce")["items"][0]
    assert (run["run_id"], run["attacker_ip"], run["target_device"]) == ("run-001", "192.168.56.99", "gw-01")
    assert get(client, "/api/v1/attack-runs", capture_id="cap-nope")["count"] == 0
    assert "is not one of" in refused(client, "/api/v1/attack-runs", scenario="brute force")


# ------------------------------------------------------------------------------------------- events
def test_events_and_their_filters(client):
    events = get(client, "/api/v1/events")["items"]
    assert len(events) == 19 and events[0]["ts"] <= events[-1]["ts"]                 # oldest first
    assert get(client, "/api/v1/events", label=1)["count"] == 11                    # the brute force
    assert get(client, "/api/v1/events", source="esp32")["count"] == 4
    assert get(client, "/api/v1/events", device_id="esp32-smoke-01", source="cowrie")["count"] == 0
    logins = get(client, "/api/v1/events", event_type="login_failed")["items"]
    assert logins and {e["event_type"] for e in logins} == {"login_failed"}
    attack = get(client, "/api/v1/events", label=1, limit=1)["items"][0]
    assert (attack["scenario"], attack["run_id"], attack["src_ip"]) == ("bruteforce", "run-001", "192.168.56.99")
    inside = get(client, "/api/v1/events", **{"from": "2026-11-20T14:10:00Z", "to": "2026-11-20T14:18:00Z"})
    assert all("14:10:00" <= e["ts"][11:19] < "14:18:00" for e in inside["items"])


def test_events_refusals(client):
    assert "is not in the contract" in refused(client, "/api/v1/events", event_type="hacked")
    assert "must be before" in refused(client, "/api/v1/events", **{"from": "2026-11-20T15:00:00Z",
                                                                   "to": "2026-11-20T14:00:00Z"})
    refused(client, "/api/v1/events", **{"from": "2026-11-20T14:00:00"})            # no time zone
    refused(client, "/api/v1/events", limit=5001)
    refused(client, "/api/v1/events", label=2)


# ------------------------------------------------------------------------------------------- pagination
@pytest.mark.parametrize("order", ["asc", "desc"])
def test_walking_the_pages_gives_every_event_once_in_order(client, order):
    items = walk(client, "/api/v1/events", limit=5, order=order)
    stamps = [(e["ts"], e["event_id"]) for e in items]
    assert len(items) == 19 and len(set(stamps)) == 19
    assert stamps == sorted(stamps, reverse=(order == "desc"))


def test_new_rows_arriving_between_pages_do_not_shift_the_pages(client, test_db_url):
    first = get(client, "/api/v1/events", limit=5)
    # A new event arrives while the client is reading (end of the capture, so it sorts last).
    r = client.post("/api/v1/ingest/events", json={"ts": "2026-11-20T14:59:00Z", "source": "cowrie",
                                                    "event_type": "login_failed", "device_id": "gw-01",
                                                    "src_ip": "192.168.56.77", "payload": {"session": "late"}})
    assert r.json()["inserted"] == 1
    try:
        rest = walk(client, "/api/v1/events", limit=5, cursor=first["next_cursor"])
        ids = [e["event_id"] for e in first["items"] + rest]
        assert len(ids) == 20 and len(set(ids)) == 20                                  # none twice, none missed
    finally:
        with connect(test_db_url) as conn:
            conn.execute("DELETE FROM events WHERE payload->>'session' = 'late'")


def test_bad_cursors_are_refused(client):
    assert "cursor is not valid" in refused(client, "/api/v1/events", cursor="not-a-cursor")
    wrong = base64.urlsafe_b64encode(json.dumps(["yesterday", "x"]).encode()).decode()   # right shape, bad values
    assert "cursor is not valid" in refused(client, "/api/v1/events", cursor=wrong)


# ------------------------------------------------------------------------------------------- flows
def test_flows(client):
    flows = get(client, "/api/v1/flows")["items"]
    assert len(flows) == 9 and all(f["features"] is None for f in flows)              # features only on request
    attack = get(client, "/api/v1/flows", label=1)["items"]
    assert attack and all(f["scenario"] == "bruteforce" for f in attack)
    with_features = get(client, "/api/v1/flows", include_features=True, limit=1)["items"][0]
    assert list(with_features["features"]) == flow.FEATURE_NAMES                       # 41, in contract order
    assert get(client, "/api/v1/flows", device_id="cam-01")["count"] >= 1


# ------------------------------------------------------------------------------------------- for the models
def test_windows(client):
    rows = walk(client, "/api/v1/features/windows", limit=500)
    assert len(rows) == 1080 and len({(w["entity_id"], w["window_start"]) for w in rows}) == 1080
    assert [w["entity_id"] for w in rows[:3]] == ["cam-01", "esp32-smoke-01", "gw-01"]   # time first, then device
    assert get(client, "/api/v1/features/windows", device_id="gw-01", limit=5000)["count"] == 360
    assert get(client, "/api/v1/features/windows", label=1)["count"] == 5
    row = get(client, "/api/v1/features/windows", label=1, include_raw=True, limit=1)["items"][0]
    assert list(row["features"]) == window.FEATURE_NAMES and list(row["features_raw"]) == window.FEATURE_NAMES
    assert row["features_raw"]["n_login_failed"] >= 1 and row["n_events"] >= 1
    assert get(client, "/api/v1/features/windows", limit=1)["items"][0]["features_raw"] is None


def test_graph_edges(client):
    edges = get(client, "/api/v1/graph/edges")["items"]
    assert len(edges) == 9 and list(edges[0]["features"]) == flow.FEATURE_NAMES
    attack = get(client, "/api/v1/graph/edges", label=1)["items"]
    # the 3 SSH connections in, and the gateway fetching the malware from the attacker
    assert {(e["src_node"], e["dst_node"]) for e in attack} == {("ip:192.168.56.99", "dev:gw-01"),
                                                                ("dev:gw-01", "ip:192.168.56.99")}
    assert all(e["src_node"].startswith(("dev:", "ip:")) for e in edges)


# ------------------------------------------------------------------------------------------- dashboard summaries
HOUR = {"from": "2026-11-20T14:00:00Z", "to": "2026-11-20T15:00:00Z"}


def test_min_severity(client):
    high = get(client, "/api/v1/events", min_severity="high")["items"]
    assert high and {e["severity"] for e in high} <= {"high", "critical"}
    assert get(client, "/api/v1/events", min_severity="info")["count"] == 19


def test_summary_counts(client):
    s = get(client, "/api/v1/stats/summary", capture_id=CAP)
    assert (s["events"], s["flows"]) == (19, 9)
    assert s["labels"] == {"attack": 11, "normal": 8, "unlabeled": 0}
    assert s["layers"] == {"device_service_logs": 4, "network_traffic": 0, "session_interaction": 11,
                           "telemetry_media": 4}                      # every layer present, even at 0
    assert s["sources"] == {"cowrie": 11, "mosquitto": 4, "esp32": 4}
    assert s["attack_flows"] == get(client, "/api/v1/flows", label=1)["count"]
    assert s["scenarios"] == {"bruteforce": {"events": 11, "flows": s["attack_flows"]}} == {
        k.replace("run-001", "bruteforce"): v for k, v in s["runs"].items()}
    assert get(client, "/api/v1/stats/summary", **{"from": "2026-11-21T00:00:00Z"})["events"] == 0


def test_events_histogram(client):
    h = get(client, "/api/v1/stats/events-histogram", **HOUR)
    assert h["bucket_seconds"] == 60 and len(h["labels"]) == 60                 # one bar per minute, empty ones too
    assert h["labels"][0] == "2026-11-20T14:00:00Z"
    assert sum(sum(s["data"]) for s in h["series"]) == 19
    assert {s["name"] for s in h["series"]} >= {"login_failed", "sensor_reading"}
    assert len(get(client, "/api/v1/stats/events-histogram", **HOUR, bucket_seconds=600)["labels"]) == 6
    assert "'from' is required" in refused(client, "/api/v1/stats/events-histogram")
    assert "too many points" in refused(client, "/api/v1/stats/events-histogram", bucket_seconds=1,
                                        **{"from": "2026-11-20T00:00:00Z", "to": "2026-11-25T00:00:00Z"})


def test_sensor_series(client):
    raw = get(client, "/api/v1/stats/sensors", **HOUR)
    assert raw["bucket_seconds"] is None and len(raw["labels"]) == 4             # the 4 readings, as read
    assert [s["name"] for s in raw["series"]] == ["temperature_c", "smoke", "humidity_pct"]
    assert all(len(s["data"]) == 4 for s in raw["series"])
    averaged = get(client, "/api/v1/stats/sensors", **HOUR, bucket_seconds=3600)
    assert averaged["bucket_seconds"] == 3600 and len(averaged["labels"]) == 1
    assert get(client, "/api/v1/stats/sensors", **HOUR, device_id="cam-01")["labels"] == []
