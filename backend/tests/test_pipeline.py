"""Step 3 pipeline: one session file -> every stage in order, stop at the first failure, safe to re-run."""
import json
from pathlib import Path

import pytest

from ingest import pipeline as pl

SAMPLES = Path(__file__).resolve().parents[1] / "samples"


def session(tmp_path, **changes):
    """The sample lab as a session file; conn_log instead of the pcap so no Docker/Zeek is needed."""
    s = {
        "capture": {"id": "cap-2026-11-20-a", "start": "2026-11-20T14:00:00Z", "end": "2026-11-20T15:00:00Z",
                    "kind": "mixed"},
        "conn_log": str(SAMPLES / "zeek" / "conn.log"),
        "logs": [{"source": "cowrie", "path": str(SAMPLES / "cowrie.json"), "device": "gw-01"},
                 {"source": "mosquitto", "path": str(SAMPLES / "mosquitto.log"), "device": "gw-01",
                  "broker_ip": "192.168.56.10"},
                 {"source": "esp32", "path": str(SAMPLES / "esp32.csv"), "device": "esp32-smoke-01",
                  "device_ip": "192.168.56.20", "tz": "UTC"}],
        "attack_log": str(SAMPLES / "attack_log.csv"),
    }
    s.update(changes)
    path = tmp_path / "session.json"
    path.write_text(json.dumps(s), encoding="utf-8")
    return path


def stage(report, name):
    return next(s for s in report.stages if s.name.startswith(name))


def quiet(_):
    pass


def test_a_session_runs_every_stage_in_order(db, tmp_path):
    r = pl.run(session(tmp_path), conn=db, save=False, log=quiet)
    # the sample logs have one broken line each, on purpose: skipped, counted, a WARN - and the run goes on
    assert r.ok and [s.status for s in r.stages] == ["PASS", "PASS", "PASS", "WARN", "PASS", "PASS", "SKIP"]
    flows = stage(r, "flows").counts
    assert flows["saved"] > 0 and flows["saved"] == flows["flows"] and flows["broken_lines"] == 0
    logs = stage(r, "logs").counts
    assert logs["saved"] == 19 and logs["broken_lines"] == 3             # 11 Cowrie + 4 Mosquitto + 4 ESP32
    labels = stage(r, "attack log").counts
    assert labels["attack_events"] == 11 and labels["attack_flows"] > 0 and labels["attack_runs"] == 1
    feats = stage(r, "features").counts
    assert feats["flow_features"] == flows["saved"] and feats["attack_windows"] > 0
    assert db.execute("SELECT count(*) FROM flows WHERE capture_id = 'cap-2026-11-20-a' AND features IS NULL"
                      ).fetchone()[0] == 0


def test_running_the_same_session_again_saves_nothing_new(db, tmp_path):
    path = session(tmp_path)
    first = pl.run(path, conn=db, save=False, log=quiet)
    again = pl.run(path, conn=db, save=False, log=quiet)
    assert again.ok
    assert stage(again, "flows").counts["saved"] == 0
    assert stage(again, "flows").counts["already_saved"] == stage(first, "flows").counts["saved"]
    assert stage(again, "logs").counts["saved"] == 0
    assert stage(again, "attack log").counts == stage(first, "attack log").counts     # same labels


def test_every_input_problem_is_listed_and_nothing_is_saved(db, tmp_path):
    bad = session(tmp_path, capture={"id": "cap-x", "start": "2026-11-20T14:00:00", "kind": "weekly"},
                  logs=[{"source": "syslog", "path": str(tmp_path / "missing.log")}])
    r = pl.run(bad, conn=db, save=False, log=quiet)
    assert not r.ok and len(r.stages) == 1                              # stopped after the check
    text = "\n".join(r.stages[0].lines)
    assert "no time zone" in text and "'weekly'" in text and "'syslog'" in text and "missing.log" in text
    assert db.execute("SELECT count(*) FROM events").fetchone()[0] == 0
    assert db.execute("SELECT count(*) FROM captures WHERE capture_id = 'cap-x'").fetchone()[0] == 0


def test_a_wrong_attack_log_stops_the_run_before_anything_is_saved(db, tmp_path):
    r = pl.run(session(tmp_path, attack_log=str(SAMPLES / "attack_log_mistakes.csv")), conn=db, save=False,
               log=quiet)
    assert not r.ok and len(r.stages) == 1
    assert any(line.startswith("attack_log:") for line in r.stages[0].lines)
    assert db.execute("SELECT count(*) FROM flows").fetchone()[0] == 0


def test_check_only_runs_just_the_check(db, tmp_path):
    r = pl.run(session(tmp_path), check_only=True, conn=db, log=quiet)
    assert r.ok and [s.name for s in r.stages] == ["check inputs"]
    assert db.execute("SELECT count(*) FROM flows").fetchone()[0] == 0


def test_detect_needs_the_pcap_and_a_normal_recording(tmp_path):
    s = pl.read_session(session(tmp_path, detect={"normal": "nowhere.pcap"}))
    problems = pl.session_problems(s)
    assert any("detect needs a pcap" in p for p in problems) and any("detect.normal" in p for p in problems)


def test_paths_are_relative_to_the_session_file(tmp_path):
    (tmp_path / "logs").mkdir()
    (tmp_path / "logs" / "c.json").write_text("{}", encoding="utf-8")
    p = tmp_path / "s.json"
    p.write_text(json.dumps({"capture": {}, "logs": [{"source": "cowrie", "path": "logs/c.json"}]}), encoding="utf-8")
    assert pl.read_session(p)["logs"][0]["path"] == str((tmp_path / "logs" / "c.json").resolve())


def test_the_run_report_is_saved_as_json(db, tmp_path, monkeypatch):
    monkeypatch.setattr(pl, "RUNS_DIR", tmp_path / "runs")
    pl.run(session(tmp_path, logs=[], attack_log=None), conn=db, log=quiet)
    saved = json.loads(next((tmp_path / "runs").glob("cap-2026-11-20-a_*.json")).read_text(encoding="utf-8"))
    assert saved["ok"] and saved["kind"] == "session"
    assert [s["status"] for s in saved["stages"]][3] == "SKIP"           # no logs in this session


def test_datasets_check_refuses_unknown_names_and_missing_files(tmp_path):
    p = tmp_path / "d.json"
    p.write_text(json.dumps({"datasets": ["kitsune", "made-up"], "data": str(tmp_path)}), encoding="utf-8")
    r = pl.run(p, check_only=True, log=quiet)
    assert not r.ok and "made-up" in r.stages[0].lines[0]
    p.write_text(json.dumps({"datasets": ["kitsune"], "data": str(tmp_path)}), encoding="utf-8")
    r = pl.run(p, check_only=True, log=quiet)
    assert not r.ok and "none of the listed datasets' files" in r.stages[0].lines[-1]
    assert any("kitsune: no files yet" in line for line in r.stages[0].lines)


def test_the_shipped_session_files_are_valid(tmp_path):
    folder = Path(pl.__file__).resolve().parents[1] / "sessions"
    lab = pl.read_session(folder / "sample-lab.json")
    assert pl.session_problems(lab) == []
    assert json.loads((folder / "datasets-small.json").read_text(encoding="utf-8"))["datasets"]
