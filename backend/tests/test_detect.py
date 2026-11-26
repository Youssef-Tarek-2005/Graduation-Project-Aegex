"""The backend <-> AI models connection (detect.py): the models' alerts.csv ends up in the alerts table and the API.

The models themselves aren't run here (that needs PyTorch and takes seconds); a small alerts.csv in exactly the
format score_traffic.py writes stands in for their output.
"""
from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient

import detect
from api.main import app

CSV = """device,start_utc,end_utc,lstm_score,flows_in_window,worst_features,vae_score,vae_confidence,closest_known_class,zero_day_candidate
192.168.137.50,2026-11-25 11:05:01,2026-11-25 11:05:03,4.2,32,log_dst_port_entropy,1.3,1.0,scanning,False
192.168.56.20,2026-11-25 11:10:00,2026-11-25 11:10:05,1.1,32,log_dev_flows_10s,12.5,0.999,ddos,False
"""


@pytest.fixture
def results(tmp_path):
    (tmp_path / "alerts.csv").write_text(CSV, encoding="utf-8")
    (tmp_path / "run.json").write_text(json.dumps({"threshold": 1.38, "vae_threshold": 0.9}), encoding="utf-8")
    return tmp_path


@pytest.fixture
def client(db, test_db_url, monkeypatch):
    monkeypatch.setenv("AEGEX_DB_URL", test_db_url)
    db.execute("DELETE FROM alerts")
    with TestClient(app) as c:
        yield c
    db.execute("DELETE FROM alerts")


def test_alerts_csv_goes_into_the_database_and_the_api(client, db, results):
    assert detect.save_alerts(results, "cap-x") == 2
    assert detect.save_alerts(results, "cap-x") == 2                 # running again replaces, no duplicates
    assert db.execute("SELECT count(*) FROM alerts").fetchone()[0] == 2

    items = {a["entity_id"]: a for a in client.get("/api/v1/alerts?capture=cap-x").json()["items"]}
    scan, flood = items["192.168.137.50"], items["esp32-smoke-01"]  # .56.20 is one of our devices -> its device_id
    assert (scan["device_id"], scan["model_name"], scan["score"]) == (None, "lstm_ae", 4.2)   # LSTM higher
    assert scan["predicted_scenario"] == "vulnerability_scanning" and scan["severity"] == "high"
    assert (flood["device_id"], flood["model_name"], flood["score"]) == ("esp32-smoke-01", "vae", 12.5)
    assert flood["predicted_scenario"] == "dos" and flood["severity"] == "critical"
    assert flood["evidence"]["worst_features"] == "log_dev_flows_10s"

    assert client.get("/api/v1/alerts?min_severity=critical").json()["count"] == 1
    assert client.get("/api/v1/alerts?capture=other").json()["count"] == 0
