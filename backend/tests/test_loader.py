"""Step 4 tests: the loader saves parsed events into a real database, and never duplicates them.

These run against the throw-away `aegex_test` database (see conftest.py).
"""
from __future__ import annotations

from pathlib import Path

import pytest

from ingest.loader import LoadError, label_capture, load_file, load_lines
from ingest.parsers import CowrieParser, Esp32CsvParser, MosquittoLogParser

SAMPLES = Path(__file__).resolve().parents[1] / "samples"
CAP = "cap-2026-11-20-a"


def count(db, where: str = "TRUE") -> int:
    return db.execute(f"SELECT count(*) FROM events WHERE {where}").fetchone()[0]


def load_all_samples(db):
    return [
        load_file(db, CowrieParser("gw-01"), SAMPLES / "cowrie.json", CAP),
        load_file(db, MosquittoLogParser("gw-01", broker_ip="192.168.56.10"), SAMPLES / "mosquitto.log", CAP),
        load_file(db, Esp32CsvParser("esp32-smoke-01", device_ip="192.168.56.20"), SAMPLES / "esp32.csv", CAP),
    ]


def test_samples_are_saved(db):
    results = load_all_samples(db)
    assert [r.inserted for r in results] == [11, 4, 4]
    assert count(db) == 19
    assert count(db, f"capture_id = '{CAP}'") == 19                      # every row got the capture
    assert all(r.outside_capture == 0 for r in results)


def test_loading_the_same_file_twice_adds_nothing(db):
    first = load_file(db, CowrieParser("gw-01"), SAMPLES / "cowrie.json", CAP)
    second = load_file(db, CowrieParser("gw-01"), SAMPLES / "cowrie.json", CAP)
    assert (first.inserted, first.duplicates) == (11, 0)
    assert (second.inserted, second.duplicates) == (0, 11)
    assert count(db) == 11


def test_a_file_that_grew_only_adds_the_new_lines(db):
    lines = (SAMPLES / "cowrie.json").read_text(encoding="utf-8").splitlines()
    load_lines(db, CowrieParser("gw-01"), lines[:7], CAP)                # yesterday: the first 7 lines
    later = load_lines(db, CowrieParser("gw-01"), lines, CAP)            # today: the whole file
    assert later.inserted == 11 - 6 and count(db) == 11                  # the first 7 lines held 6 events


def test_saved_row_matches_the_log_line(db):
    load_file(db, CowrieParser("gw-01"), SAMPLES / "cowrie.json", CAP)
    row = db.execute("""SELECT host(src_ip), src_port, host(dst_ip), dst_port, layer, severity, device_id,
                               payload->>'username', payload->>'password'
                          FROM events WHERE event_type = 'login_success'""").fetchone()
    assert row == ("192.168.56.99", 40188, "192.168.56.10", 22, "session_interaction", "high", "gw-01",
                   "root", "raspberry")


def test_labeling_marks_only_the_attackers_rows(db):
    load_all_samples(db)
    label_capture(db, CAP)
    by_label = dict(db.execute("SELECT label, count(*) FROM events GROUP BY label").fetchall())
    assert by_label == {1: 11, 0: 8}                                     # 11 Cowrie rows from .99; MQTT + sensor normal
    assert count(db, "label = 1 AND (source <> 'cowrie' OR scenario <> 'bruteforce' OR run_id <> 'run-001')") == 0


def test_unknown_capture_or_device_is_refused_before_saving_anything(db):
    with pytest.raises(LoadError, match="capture"):
        load_file(db, CowrieParser("gw-01"), SAMPLES / "cowrie.json", "cap-does-not-exist")
    with pytest.raises(LoadError, match="device"):
        load_file(db, CowrieParser("gw-99"), SAMPLES / "cowrie.json", CAP)
    assert count(db) == 0


def test_wrong_time_zone_is_refused(db):
    # Pretend the ESP32 clock was read as Tokyo time: every reading moves 9 hours, out of the 14:00-15:00 capture.
    with pytest.raises(LoadError, match="4 of 4 events are outside capture"):
        load_file(db, Esp32CsvParser("esp32-smoke-01", tz="Asia/Tokyo"), SAMPLES / "esp32.csv", CAP)
    assert count(db) == 0                                                # nothing was saved


def test_wrong_time_zone_after_a_correct_load_is_still_refused(db):
    # The same lines at a different time are NOT duplicates, so only the capture check can catch this.
    load_file(db, Esp32CsvParser("esp32-smoke-01"), SAMPLES / "esp32.csv", CAP)
    with pytest.raises(LoadError):
        load_file(db, Esp32CsvParser("esp32-smoke-01", tz="Asia/Tokyo"), SAMPLES / "esp32.csv", CAP)
    assert count(db) == 4


def test_outside_capture_can_be_allowed_on_purpose(db):
    r = load_file(db, Esp32CsvParser("esp32-smoke-01", tz="Asia/Tokyo"), SAMPLES / "esp32.csv", CAP,
                  allow_outside_capture=True)
    assert r.outside_capture == r.inserted == 4


def test_small_batches_give_the_same_result(db):
    r = load_file(db, CowrieParser("gw-01"), SAMPLES / "cowrie.json", CAP, batch_size=2)
    assert r.inserted == 11 and count(db) == 11


def test_failure_mid_file_saves_nothing(db, monkeypatch):
    # All or nothing: if the database fails after the first batch, the first batch is rolled back too.
    import ingest.loader as loader
    real = loader._insert_batch
    calls = {"n": 0}

    def flaky(cur, batch):
        calls["n"] += 1
        if calls["n"] == 2:
            raise RuntimeError("database fell over")
        return real(cur, batch)

    monkeypatch.setattr(loader, "_insert_batch", flaky)
    with pytest.raises(RuntimeError):
        load_file(db, CowrieParser("gw-01"), SAMPLES / "cowrie.json", CAP, batch_size=3)
    assert count(db) == 0
