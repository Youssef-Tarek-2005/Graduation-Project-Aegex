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


GAT_ALERT = {"alert_key": "gat-0123456789abcdef", "model_name": "temporal_gat", "model_version": "gat_v5",
             "feature_version": "lstm-vae-gat", "entity_type": "device", "entity_id": "192.168.137.50",
             "device_id": None, "src_ips": ["192.168.137.50"], "window_start": "2026-11-25T11:05:00Z",
             "window_end": "2026-11-25T11:08:00Z", "score": 0.998, "threshold": 0.483, "is_anomaly": True,
             "predicted_scenario": "vulnerability_scanning", "severity": "low",
             "evidence": {"attention_edges": [{"src": "192.168.137.50", "dst": "192.168.56.20", "p_link": 0.99}],
                          "predicted_scenario_from": "behaviour rule on the flagged links (not the GAT)"}}


def test_gat_incidents_go_into_the_database_and_the_api(client, db, results):
    (results / "handoff").mkdir()
    (results / "handoff" / "alerts.json").write_text(json.dumps([GAT_ALERT]), encoding="utf-8")
    (results / "handoff" / "handoff_summary.json").write_text(json.dumps({"threshold": 0.483}), encoding="utf-8")
    detect.save_alerts(results, "cap-g")                                # replaces this capture's alerts first
    assert detect.save_gat_alerts(results, "cap-g") == 1
    items = client.get("/api/v1/alerts?capture=cap-g").json()["items"]
    gat = [a for a in items if a["model_name"] == "temporal_gat"]
    assert len(gat) == 1 and gat[0]["model_version"] == "gat_v5" and gat[0]["score"] == 0.998
    assert gat[0]["evidence"]["attention_edges"][0]["dst"] == "192.168.56.20"
    detect.save_alerts(results, "cap-g")                                # re-run: GAT rows replaced too
    assert detect.save_gat_alerts(results, "cap-g") == 1
    assert db.execute("SELECT count(*) FROM alerts WHERE model_name = 'temporal_gat'").fetchone()[0] == 1


def test_a_rerun_keeps_other_detectors_alerts(client, db, results):
    """Re-scoring a capture replaces the AI models' alerts only: the rule baseline's incidents stay."""
    from correlate import store
    from correlate.rules import Incident
    from datetime import datetime, timezone
    t = datetime(2026, 11, 25, 11, 5, tzinfo=timezone.utc)
    store.save(db, "cap-keep", [Incident("192.168.137.50", t, t, {"port_scan": 40})])
    detect.save_alerts(results, "cap-keep")
    detect.save_alerts(results, "cap-keep")
    models = dict(db.execute("SELECT model_name, count(*) FROM alerts WHERE evidence->>'capture' = 'cap-keep' "
                             "GROUP BY 1").fetchall())
    assert models.get("rules") == 1 and sum(models.values()) == 3
    db.execute("DELETE FROM alerts WHERE evidence->>'capture' = 'cap-keep'")
