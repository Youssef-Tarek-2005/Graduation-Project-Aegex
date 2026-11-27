"""Step 5 API: datasets, the new flow filters and columns, pipeline run reports, the datastore status."""
import json

import pytest
from fastapi.testclient import TestClient

from api import operations
from api.main import app
from datasets import to_unified as tu
from ingest import pipeline

from test_datasets_unified import ai_flows

CAP = "ds-api-aci"          # its own dataset id, so other tests' dataset rows don't change the counts here


@pytest.fixture
def client(db, test_db_url, monkeypatch):
    monkeypatch.setenv("AEGEX_DB_URL", test_db_url)
    rows, _ = tu.to_rows(ai_flows(), CAP)
    tu.save(db, "aci", CAP, rows, "api test")
    with TestClient(app) as c:
        yield c
    db.execute("DELETE FROM flows WHERE capture_id = %s", (CAP,))
    db.execute("DELETE FROM captures WHERE capture_id = %s", (CAP,))


def get(client, path, status=200, **params):
    r = client.get(path, params=params)
    assert r.status_code == status, r.text
    return r.json()


def test_datasets_lists_the_whole_catalogue_with_what_is_loaded(client):
    items = get(client, "/api/v1/datasets")
    assert [d["id"] for d in items] == ["edge", "kitsune", "iot23", "iot23x", "xiiotid", "gotham", "aci", "nf_toniot"]
    aci = next(d for d in items if d["id"] == "aci")
    assert aci["loaded"] == {"captures": 1, "flows": 3, "attack_flows": 2}
    assert aci["host"] == "kaggle" and aci["url"].startswith("https://") and aci["used_by_models"]
    assert next(d for d in items if d["id"] == "nf_toniot")["loaded"]["flows"] == 0


def test_one_dataset_shows_its_captures_and_classes(client):
    d = get(client, "/api/v1/datasets/aci")
    cap = next(c for c in d["captures"] if c["capture_id"] == CAP)
    assert cap["flows"] == 3 and cap["attack_flows"] == 2 and cap["classes"] == {"mirai": 2, "benign": 1}
    assert cap["kind"] == "mixed"
    get(client, "/api/v1/datasets/made-up", status=404)


def test_flows_carry_the_unified_columns_and_new_filters(client):
    page = get(client, "/api/v1/flows", dataset="aci")
    assert page["count"] == 3
    first = page["items"][0]
    assert (first["fwd_flags"], first["bwd_flags"], first["attack_class"]) == (2, 4, "mirai")
    assert first["label_info"]["label_note"] == "relabel R2"
    assert get(client, "/api/v1/flows", dataset="aci", attack_class="mirai")["count"] == 2
    assert get(client, "/api/v1/flows", dataset="aci", scenario="mirai_botnet")["count"] == 2
    assert get(client, "/api/v1/flows", dataset="aci", src_ip="192.168.2.110")["count"] == 2
    assert all(f["capture_id"] != CAP for f in get(client, "/api/v1/flows", dataset="honeypot")["items"])


def test_wrong_flow_filters_are_refused_all_at_once(client):
    r = client.get("/api/v1/flows", params={"attack_class": "worm", "scenario": "x", "src_ip": "not-an-ip"})
    assert r.status_code == 422
    text = r.text
    assert "attack_class 'worm'" in text and "scenario 'x'" in text and "src_ip 'not-an-ip'" in text


def test_captures_show_and_filter_the_dataset(client):
    items = get(client, "/api/v1/captures", dataset="aci")["items"]
    assert [c["capture_id"] for c in items] == [CAP] and items[0]["dataset"] == "aci"
    assert all(c["dataset"] is None for c in get(client, "/api/v1/captures", dataset="honeypot")["items"])


def test_pipeline_runs_are_listed_and_readable(client, tmp_path, monkeypatch):
    monkeypatch.setattr(pipeline, "RUNS_DIR", tmp_path)
    report = {"session": "sessions/sample-lab.json", "kind": "session", "started": "2026-11-27 14:01:28 UTC",
              "ok": True, "stages": [{"name": "check inputs", "status": "PASS", "counts": {"files": 5},
                                      "lines": ["ok"], "seconds": 0.0},
                                     {"name": "logs -> events", "status": "WARN", "counts": {"saved": 0},
                                      "lines": ["WARNING: 3 broken log lines were skipped"], "seconds": 0.2}]}
    (tmp_path / "cap-2026-11-20-a_20261127-140128.json").write_text(json.dumps(report), encoding="utf-8")
    (tmp_path / "broken.json").write_text("{not json", encoding="utf-8")       # skipped, not a crash
    runs = get(client, "/api/v1/pipeline/runs")
    assert len(runs) == 1 and runs[0]["run_id"] == "cap-2026-11-20-a_20261127-140128"
    assert runs[0]["stages"] == {"check inputs": "PASS", "logs -> events": "WARN"} and runs[0]["ok"]
    one = get(client, "/api/v1/pipeline/runs/cap-2026-11-20-a_20261127-140128")
    assert one["stages"][1]["lines"] == ["WARNING: 3 broken log lines were skipped"]
    get(client, "/api/v1/pipeline/runs/nope", status=404)
    get(client, "/api/v1/pipeline/runs/..%5C..%5Csecrets", status=404)        # only plain file names


def test_datastore_reports_this_database(client):
    s = get(client, "/api/v1/datastore")
    assert s["database"] == "aegex_test" and s["bytes"] > 0
    assert {h["table"] for h in s["hypertables"]} == {"events", "flows", "feature_windows"}
    assert s["captures_by_source"]["aci"] == 1 and "captures" in s["tables"]


def test_measured_numbers_come_from_the_step1_report(client, tmp_path, monkeypatch):
    path = tmp_path / "datasets_report.json"
    path.write_text(json.dumps({"datasets": [{"id": "aci", "total": {"flows": 1234}}]}), encoding="utf-8")
    monkeypatch.setattr(operations, "REPORT", path)
    aci = next(d for d in get(client, "/api/v1/datasets") if d["id"] == "aci")
    assert aci["measured"] == {"flows": 1234}
