"""Step 6 tests: the attack log is checked strictly, saved without duplicates, and drives the labels.

The first tests need no database. The rest use the throw-away `aegex_test` database (see conftest.py).
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from ingest.attacks import (AttackLogError, check_attack_log, label_report, load_attack_log, parse_attack_log)
from ingest.captures import CaptureError, add_capture, parse_utc
from ingest.flows import load_conn_log
from ingest.loader import label_capture, load_file
from ingest.parsers import CowrieParser, Esp32CsvParser, MosquittoLogParser

BACKEND = Path(__file__).resolve().parents[1]
SAMPLES = BACKEND / "samples"
SEED = BACKEND / "sql" / "seed_lab.sql"
CAP = "cap-2026-11-20-a"
HEADER = "run_id,capture_id,scenario,tool,command,attacker_ip,target_device,start_ts,end_ts,notes\n"


def utc(hh_mm_ss: str) -> datetime:
    return datetime.fromisoformat(f"2026-11-20T{hh_mm_ss}+00:00")


def write_log(tmp_path: Path, *rows: str, name: str = "attacks.csv") -> Path:
    path = tmp_path / name
    path.write_text(HEADER + "".join(r + "\n" for r in rows), encoding="utf-8")
    return path


def problems(exc: pytest.ExceptionInfo) -> str:
    return "\n".join(exc.value.problems)


# ------------------------------------------------------------------------------------------- file checks (no database)
def test_sample_attack_log_is_read():
    [run] = parse_attack_log(SAMPLES / "attack_log.csv")
    assert (run.run_id, run.scenario, run.attacker_ip, run.target_device) == ("run-001", "bruteforce", "192.168.56.99", "gw-01")
    assert (run.start_ts, run.end_ts) == (utc("14:10:00"), utc("14:18:00"))
    assert run.notes is None                                        # empty cell = no value


def test_csv_json_list_and_json_lines_give_the_same_runs(tmp_path):
    [csv_run] = parse_attack_log(SAMPLES / "attack_log.csv")
    row = {k: v for k, v in csv_run.to_row().items() if v is not None}
    row["start_ts"], row["end_ts"] = "2026-11-20T16:10:00+02:00", "2026-11-20T14:18:00Z"     # same moments, other spelling
    (tmp_path / "a.json").write_text(json.dumps([row], default=str), encoding="utf-8")
    (tmp_path / "a.jsonl").write_text(json.dumps(row, default=str) + "\n", encoding="utf-8")
    assert parse_attack_log(tmp_path / "a.json") == [csv_run]
    assert parse_attack_log(tmp_path / "a.jsonl") == [csv_run]


def test_every_file_mistake_is_reported_at_once(tmp_path):
    path = write_log(
        tmp_path,
        "r1,cap,brute force,,,192.168.56.99,,2026-11-20T14:20:00Z,2026-11-20T14:25:00Z,",
        "r2,cap,dos,,,192.168.56.99,,2026-11-20 14:30:00,2026-11-20T14:35:00Z,",
        "r3,cap,dos,,,192.168.56.999,,2026-11-20T14:40:00Z,2026-11-20T14:39:00Z,",
        "r4,,dos,,,192.168.56.99,,2026-11-20T14:50:00Z,2026-11-20T14:55:00Z,",
        "r5,cap,dos,,,192.168.56.99,,2026-11-20T14:50:00Z,2026-11-20T14:55:00Z,",
        "r5,cap,dos,,,192.168.56.98,,2026-11-20T14:56:00Z,2026-11-20T14:57:00Z,",
    )
    with pytest.raises(AttackLogError) as exc:
        parse_attack_log(path)
    text = problems(exc)
    assert "scenario 'brute force' is not one of" in text
    assert "start_ts '2026-11-20 14:30:00' has no time zone" in text
    assert "'192.168.56.999' is not an IP address" in text
    assert "ends (14:39:00) before it starts (14:40:00)" in text
    assert "line 5 (r4): missing capture_id" in text
    assert "run_id r5 is used twice" in text


def test_unknown_column_is_refused(tmp_path):
    path = tmp_path / "typo.csv"
    path.write_text("run_id,capture_id,scenario,atacker_ip,start_ts,end_ts\n"
                    "r1,cap,dos,192.168.56.99,2026-11-20T14:20:00Z,2026-11-20T14:25:00Z\n", encoding="utf-8")
    with pytest.raises(AttackLogError) as exc:
        parse_attack_log(path)
    assert "unknown column(s) atacker_ip" in problems(exc)
    assert "missing attacker_ip" in problems(exc)


def test_same_attacker_overlapping_itself_is_refused(tmp_path):
    path = write_log(tmp_path,
                     "r1,cap,dos,,,192.168.56.99,,2026-11-20T14:20:00Z,2026-11-20T14:30:00Z,",
                     "r2,cap,mqtt_spoofing,,,192.168.56.99,,2026-11-20T14:29:00Z,2026-11-20T14:35:00Z,",
                     "r3,cap,dos,,,192.168.56.77,,2026-11-20T14:20:00Z,2026-11-20T14:30:00Z,")   # other attacker: fine
    with pytest.raises(AttackLogError) as exc:
        parse_attack_log(path)
    assert exc.value.problems == [exc.value.problems[0]]
    assert "overlaps r2" in problems(exc)


def test_back_to_back_runs_do_not_overlap(tmp_path):
    path = write_log(tmp_path,
                     "r1,cap,dos,,,192.168.56.99,,2026-11-20T14:20:00Z,2026-11-20T14:30:00Z,",
                     "r2,cap,dos,,,192.168.56.99,,2026-11-20T14:30:00Z,2026-11-20T14:35:00Z,")
    assert len(parse_attack_log(path)) == 2


def test_default_capture_fills_empty_cells(tmp_path):
    path = write_log(tmp_path, "r1,,dos,,,192.168.56.99,,2026-11-20T14:20:00Z,2026-11-20T14:30:00Z,")
    assert parse_attack_log(path, default_capture=CAP)[0].capture_id == CAP


def test_parse_utc():
    assert parse_utc("2026-11-20T16:10:00+02:00") == utc("14:10:00")
    assert parse_utc("2026-11-20 14:10:00Z") == utc("14:10:00")
    with pytest.raises(ValueError, match="no time zone"):
        parse_utc("2026-11-20T14:10:00")


# ------------------------------------------------------------------------------------------- database
@pytest.fixture
def lab(db):
    """Start (and end) every test with only the seed's attack run and capture, so other test files are unaffected."""
    def reset():
        db.execute("DELETE FROM attack_runs")
        db.execute("DELETE FROM captures WHERE capture_id <> %s", (CAP,))
        db.execute(SEED.read_text(encoding="utf-8"))
    reset()
    yield db
    reset()


def load_all_data(db):
    load_file(db, CowrieParser("gw-01"), SAMPLES / "cowrie.json", CAP)
    load_file(db, MosquittoLogParser("gw-01", broker_ip="192.168.56.10"), SAMPLES / "mosquitto.log", CAP)
    load_file(db, Esp32CsvParser("esp32-smoke-01", device_ip="192.168.56.20"), SAMPLES / "esp32.csv", CAP)
    load_conn_log(db, SAMPLES / "zeek" / "conn.log", CAP)


def runs_in_db(db) -> int:
    return db.execute("SELECT count(*) FROM attack_runs").fetchone()[0]


def test_sample_log_is_already_saved_by_the_seed(lab):
    result = load_attack_log(lab, SAMPLES / "attack_log.csv")
    assert (result.inserted, result.updated, result.unchanged) == ([], {}, ["run-001"])


def test_new_run_is_saved_and_loading_again_adds_nothing(lab, tmp_path):
    path = write_log(tmp_path, f"run-002,{CAP},dos,hping3,hping3 -S --flood 192.168.56.30,192.168.56.99,cam-01,"
                               f"2026-11-20T14:50:00Z,2026-11-20T14:55:00Z,")
    assert load_attack_log(lab, path).inserted == ["run-002"]
    assert load_attack_log(lab, path).unchanged == ["run-002"]
    assert runs_in_db(lab) == 2
    ip, start = lab.execute("SELECT host(attacker_ip), start_ts FROM attack_runs WHERE run_id = 'run-002'").fetchone()
    assert (ip, start) == ("192.168.56.99", utc("14:50:00"))


def test_mistakes_sample_saves_nothing_and_lists_every_problem(lab):
    with pytest.raises(AttackLogError) as exc:
        load_attack_log(lab, SAMPLES / "attack_log_mistakes.csv")
    text = problems(exc)
    for expected in ("run-101", "run-102", "run-103): attacker_ip 192.168.56.10 is our own lab device gw-01",
                     "run-104", "run-105): overlaps run-001", "run-106): runs 2026-11-20 15:30:00",
                     "run-107): target_device 'cam-02' does not exist"):
        assert expected in text
    lines = [int(p.split()[1]) for p in exc.value.problems]
    assert lines == sorted(lines)                                   # in file order
    assert runs_in_db(lab) == 1


def test_unknown_capture_is_refused(lab, tmp_path):
    path = write_log(tmp_path, "run-002,cap-nope,dos,,,192.168.56.99,,2026-11-20T14:50:00Z,2026-11-20T14:55:00Z,")
    with pytest.raises(AttackLogError, match="capture 'cap-nope' does not exist"):
        check_attack_log(lab, path)


def test_one_bad_row_saves_none_of_the_good_rows(lab, tmp_path):
    path = write_log(tmp_path,
                     f"run-002,{CAP},dos,,,192.168.56.99,cam-01,2026-11-20T14:50:00Z,2026-11-20T14:55:00Z,",
                     f"run-003,{CAP},dos,,,192.168.56.99,cam-99,2026-11-20T14:56:00Z,2026-11-20T14:58:00Z,")
    with pytest.raises(AttackLogError):
        load_attack_log(lab, path)
    assert runs_in_db(lab) == 1


def test_labeling_report_for_the_sample_capture(lab):
    load_all_data(lab)
    label_capture(lab, CAP)
    report = label_report(lab, CAP)
    [run] = report.runs
    assert (run.run_id, run.flows, run.events) == ("run-001", 4, 11)
    assert report.flows == {0: 5, 1: 4} and report.events == {0: 8, 1: 11}
    assert report.leftovers == [] and report.warnings == []
    summary = dict(lab.execute("SELECT scenario, n_flows FROM v_label_summary WHERE capture_id = %s", (CAP,)).fetchall())
    assert summary == {"bruteforce": 4, "normal": 5}


def test_correcting_a_run_moves_the_labels_and_warns_about_leftovers(lab, tmp_path):
    load_all_data(lab)
    label_capture(lab, CAP)
    # A typed the end time 6 minutes too early: the last SSH session (14:12:39) and the download (14:13:20) fall out.
    path = write_log(tmp_path, f"run-001,{CAP},bruteforce,hydra,hydra -l root -P passwords.txt ssh://192.168.56.10,"
                               f"192.168.56.99,gw-01,2026-11-20T14:10:00Z,2026-11-20T14:12:00Z,")
    result = load_attack_log(lab, path)
    assert result.updated == {"run-001": ["end_ts"]}
    label_capture(lab, CAP)
    report = label_report(lab, CAP)
    assert report.runs[0].flows == 2
    flow_leftovers = [(kind, ts) for kind, ts, *_ in report.leftovers if kind == "flow"]
    assert flow_leftovers == [("flow", utc("14:12:39")), ("flow", utc("14:13:20"))]
    assert any("outside every run" in w for w in report.warnings)

    # Loading the right file again puts everything back.
    load_attack_log(lab, SAMPLES / "attack_log.csv")
    label_capture(lab, CAP)
    assert label_report(lab, CAP).warnings == []


def test_run_that_matches_no_traffic_is_warned_about(lab, tmp_path):
    load_all_data(lab)
    # Behind NAT the honeypot sees the router's address, not the attacker's, so nothing matches .77.
    path = write_log(tmp_path, f"run-002,{CAP},dos,hping3,,192.168.56.77,cam-01,2026-11-20T14:50:00Z,2026-11-20T14:55:00Z,")
    load_attack_log(lab, path)
    label_capture(lab, CAP)
    report = label_report(lab, CAP)
    assert [r.run_id for r in report.runs] == ["run-001", "run-002"]
    assert any(w.startswith("run-002 matched no traffic") for w in report.warnings)


def test_resubmitting_a_run_with_new_times_is_not_an_overlap_with_itself(lab, tmp_path):
    path = write_log(tmp_path, f"run-001,{CAP},bruteforce,hydra,,192.168.56.99,gw-01,2026-11-20T14:09:00Z,2026-11-20T14:18:00Z,")
    assert set(load_attack_log(lab, path).updated["run-001"]) == {"command", "start_ts"}


# ------------------------------------------------------------------------------------------- captures
def test_add_capture(lab):
    start, end = parse_utc("2026-11-21T09:00:00Z"), parse_utc("2026-11-21T10:00:00Z")
    assert add_capture(lab, "cap-2026-11-21-a", start, end, "attack") is True
    assert add_capture(lab, "cap-2026-11-21-a", start, end, "attack") is False          # same again: fine
    with pytest.raises(CaptureError, match="already exists with different values"):
        add_capture(lab, "cap-2026-11-21-a", start, parse_utc("2026-11-21T11:00:00Z"), "attack")
    with pytest.raises(CaptureError, match="ends"):
        add_capture(lab, "cap-x", end, start)
    with pytest.raises(CaptureError, match="time zone"):
        add_capture(lab, "cap-x", datetime(2026, 11, 21, 9, 0))
    assert add_capture(lab, "cap-live", datetime(2026, 11, 22, 8, 0, tzinfo=timezone.utc), kind="live") is True
