"""Step 9 tests: split by whole captures, scalers fitted on train-normal only, export files as the contract says.

The first tests need no database. The rest build the fake lab (6 captures) in the throw-away `aegex_test` database
once, export it into a temp folder, and check the files.
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import joblib
import numpy as np
import pandas as pd
import pytest

from demo import fake_lab
from features import split as S
from features import window as W
from features.dataset import DatasetError, build_dataset, fit_scaler, make_sequences
from ingest.db import connect
from ingest.event import CONTRACT

DAY = datetime(2026, 12, 1, tzinfo=timezone.utc)


def cap(cid: str, day: int, scenarios=(), minutes: int = 30, unlabeled: int = 0) -> S.CaptureInfo:
    start = DAY + timedelta(days=day)
    return S.CaptureInfo(cid, start, start + timedelta(minutes=minutes), windows=540,
                         attack_windows=10 if scenarios else 0, unlabeled_windows=unlabeled, scenarios=set(scenarios))


SIX = [cap("c1", 1), cap("c2", 2, ["bruteforce"]), cap("c3", 3, ["dos", "mqtt_spoofing"]), cap("c4", 4),
       cap("c5", 5, ["dos"]), cap("c6", 6, ["bruteforce", "dos", "mqtt_spoofing"])]


# ------------------------------------------------------------------------------------------- split
def test_split_is_by_time_70_15_15():
    assert S.propose_split(SIX) == {"train": ["c1", "c2", "c3", "c4"], "val": ["c5"], "test": ["c6"]}
    assert S.check_split(S.propose_split(SIX), SIX).ok


def test_split_uses_recorded_time_not_capture_count():
    caps = [cap("long", 1, minutes=600), cap("a", 2, ["dos"]), cap("b", 3, ["dos"])]
    assert S.propose_split(caps)["train"] == ["long"]          # 10 h of 11 h = 91% of the time


def test_zero_day_goes_to_test_only():
    split = S.propose_split(SIX, zero_day="mqtt_spoofing")
    assert split["test"] == ["c3", "c6"] and "c3" not in split["train"]
    assert S.check_split(split, SIX, zero_day="mqtt_spoofing").ok


def test_unlabeled_captures_are_left_out():
    caps = SIX + [cap("live", 7, unlabeled=540)]
    split = S.propose_split(caps)
    assert "live" not in sum(split.values(), [])
    assert any("not in any split" in w for w in S.check_split(split, caps).warnings)


def test_test_split_must_hold_every_scenario():
    split = {"train": ["c1", "c2", "c3", "c4"], "val": ["c6"], "test": ["c5"]}
    check = S.check_split(split, SIX)
    assert not check.ok and "has no bruteforce, mqtt_spoofing" in check.problems[0]


def test_split_mistakes_are_refused():
    assert "both train and test" in " ".join(S.check_split({"train": ["c1", "c6"], "val": ["c5"], "test": ["c6"]}, SIX).problems)
    assert "the val split is empty" in " ".join(S.check_split({"train": ["c1"], "val": [], "test": ["c6"]}, SIX).problems)
    assert "has no windows" in " ".join(S.check_split({"train": ["nope"], "val": ["c5"], "test": ["c6"]}, SIX).problems)
    leak = S.check_split({"train": ["c1", "c3"], "val": ["c5"], "test": ["c6"]}, SIX, zero_day="mqtt_spoofing")
    assert "appears in train/val" in " ".join(leak.problems)


def test_split_warnings():
    check = S.check_split({"train": ["c5", "c2"], "val": ["c1"], "test": ["c6"]}, SIX)
    assert check.ok
    assert any("validation has no attack" in w for w in check.warnings)
    assert any("not in time order" in w for w in check.warnings)


# ------------------------------------------------------------------------------------------- sequences and scaler
def fake_windows(captures: dict[str, int], attack_at: dict[tuple[str, int], int] | None = None) -> pd.DataFrame:
    rows = []
    for i, (cid, n) in enumerate(captures.items()):
        start = DAY + timedelta(days=i)
        for k in range(n):
            rows.append({"capture_id": cid, "entity_id": "gw-01", "window_start": start + timedelta(seconds=10 * k),
                         "label": (attack_at or {}).get((cid, k), 0), **{f: float(k) for f in W.FEATURE_NAMES}})
    return pd.DataFrame(rows)


def test_sequences_are_30_windows_and_never_cross_captures():
    seq = make_sequences(fake_windows({"a": 40, "b": 35}, attack_at={("a", 39): 1}))
    assert seq["X"].shape == (11 + 6, 30, 24) and seq["X"].dtype == np.float32
    assert seq["X"][0, :, 0].tolist() == list(range(30))                    # window k has value k
    assert seq["y"].tolist() == [0] * 10 + [1] + [0] * 6                     # only the last sequence of "a" holds k=39
    assert seq["y_window"][10, -1] == 1 and seq["y_window"].shape == (17, 30)
    assert seq["window_start"][11] == np.datetime64("2026-12-02T00:00:00")   # capture b starts fresh


def test_sequences_break_at_a_gap():
    w = fake_windows({"a": 70})
    w = w[w["window_start"] != DAY + timedelta(seconds=10 * 35)]             # window 35 missing
    assert len(make_sequences(w)["y"]) == (35 - 29) + (34 - 29)


def test_too_short_capture_gives_no_sequences():
    assert make_sequences(fake_windows({"a": 29}))["X"].shape == (0, 30, 24)


def test_scaler_is_fitted_on_train_normal_rows_only():
    df = fake_windows({"a": 50})
    df["split"] = ["train"] * 40 + ["test"] * 10
    df.loc[30:39, "label"] = 1
    scaler = fit_scaler(df, W.FEATURE_NAMES, ["n_conn_in"])
    assert scaler.mean_[W.FEATURE_NAMES.index("n_conn_in")] == pytest.approx(14.5)       # rows 0..29 only
    df.loc[40:, W.FEATURE_NAMES] = 1e6                                                    # change the test data...
    again = fit_scaler(df, W.FEATURE_NAMES, ["n_conn_in"])
    assert np.allclose(scaler.mean_, again.mean_)                                         # ...the scaler doesn't move
    i = W.FEATURE_NAMES.index("ratio_failed_conn")                                        # not in the scaled list
    assert (scaler.mean_[i], scaler.scale_[i]) == (0.0, 1.0)


# ------------------------------------------------------------------------------------------- the fake lab, end to end
@pytest.fixture(scope="module")
def exported(test_db_url, tmp_path_factory):
    with connect(test_db_url) as conn:
        for table in ("feature_windows", "events", "flows"):
            conn.execute(f"DELETE FROM {table}")
        fake_lab.remove(conn)
        fake_lab.build(conn, tmp_path_factory.mktemp("lab"), quiet=True)
        out = tmp_path_factory.mktemp("export")
        summary = build_dataset(conn, out / "data", out / "artifacts")
        yield conn, out, summary
        fake_lab.remove(conn)


def test_fake_lab_split_and_shapes(exported):
    _, _, summary = exported
    s = summary["splits"]
    assert [s[n]["captures"] for n in S.SPLITS] == [["cap-demo-01", "cap-demo-02", "cap-demo-03", "cap-demo-04"],
                                                    ["cap-demo-05"], ["cap-demo-06"]]
    assert [s[n]["X_shape"] for n in S.SPLITS] == [[4 * 3 * 151, 30, 24], [453, 30, 24], [453, 30, 24]]
    assert s["test"]["scenarios"] == ["bruteforce", "dos", "mqtt_spoofing", "vulnerability_scanning"]
    assert all(s[n]["attack_sequences"] > 0 for n in S.SPLITS)


def test_exported_files_follow_the_contract(exported):
    _, out, _ = exported
    data, art = out / "data", out / "artifacts"
    flows = pd.read_parquet(data / "flows.parquet")
    windows = pd.read_parquet(data / "windows.parquet")
    outputs = CONTRACT["outputs"]
    assert list(flows.columns)[:13] == outputs["flows.parquet"]["columns"][:13] and flows.shape[1] == 13 + 41
    assert list(windows.columns)[:6] == outputs["windows.parquet"]["columns"][:6] and windows.shape[1] == 6 + 24
    order = json.loads((art / "feature_order.json").read_text(encoding="utf-8"))
    assert order["flow"] == list(flows.columns[13:]) and order["window"] == list(windows.columns[6:])
    for name in S.SPLITS:
        seq = np.load(data / f"sequences_{name}.npz")
        assert set(seq.files) == {"X", "y", "y_window", "entity_id", "window_start"}
        assert not np.isnan(seq["X"]).any()
        edges = pd.read_parquet(data / f"edges_{name}.parquet")
        assert edges["ts"].is_monotonic_increasing
        assert list(edges.columns)[:10] == outputs["edges_{split}.parquet"]["columns"][:10]
    nodes = pd.read_parquet(data / "nodes.parquet").set_index("node_id")
    assert nodes.loc["dev:gw-01", "node_type"] == "device" and nodes.loc["ip:192.168.56.99", "device_type"] is None
    assert json.loads((art / "splits.json").read_text(encoding="utf-8"))["unit"] == "capture"


def test_scalers_can_be_used_like_c_and_d_will(exported):
    _, out, _ = exported
    windows = pd.read_parquet(out / "data" / "windows.parquet")
    scaler = joblib.load(out / "artifacts" / "window_scaler.joblib")
    order = json.loads((out / "artifacts" / "feature_order.json").read_text(encoding="utf-8"))
    train_normal = windows[(windows["split"] == "train") & (windows["label"] == 0)]
    assert train_normal[order["scaled_columns"]["window"]].mean().abs().max() < 1e-6     # centred on train-normal
    assert set(windows["device_type_gateway"].unique()) == {0.0, 1.0}                     # one-hot untouched
    assert scaler.n_features_in_ == 24


def test_zero_day_and_bad_manual_split(exported, tmp_path):
    conn, _, _ = exported
    summary = build_dataset(conn, tmp_path / "d", tmp_path / "a", zero_day="mqtt_spoofing")
    assert "mqtt_spoofing" not in summary["splits"]["train"]["scenarios"]
    assert summary["splits"]["test"]["captures"] == ["cap-demo-03", "cap-demo-06"]
    bad = tmp_path / "splits.json"
    bad.write_text(json.dumps({"train": ["cap-demo-01", "cap-demo-02"], "val": ["cap-demo-06"],
                               "test": ["cap-demo-05"]}), encoding="utf-8")
    with pytest.raises(DatasetError, match="has no bruteforce"):
        build_dataset(conn, tmp_path / "d2", tmp_path / "a2", splits_file=str(bad))


def test_export_is_repeatable(exported, tmp_path):
    conn, out, _ = exported
    build_dataset(conn, tmp_path / "d", tmp_path / "a")
    first, second = np.load(out / "data" / "sequences_test.npz"), np.load(tmp_path / "d" / "sequences_test.npz")
    assert np.array_equal(first["X"], second["X"]) and np.array_equal(first["y"], second["y"])
