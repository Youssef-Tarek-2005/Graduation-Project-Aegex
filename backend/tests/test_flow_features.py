"""Step 7 tests: 41 flow features, exactly as the contract defines them.

The first tests need no database. The last ones use the throw-away `aegex_test` database (see conftest.py).
"""
from __future__ import annotations

import math
from dataclasses import asdict
from pathlib import Path

import pytest

from features import flow as F
from features.build import build_flow_features, check_flow_features, feature_table, write_csv
from ingest.event import CONTRACT
from ingest.flows import ZeekConnParser, load_conn_log

SAMPLES = Path(__file__).resolve().parents[1] / "samples"
CONN_LOG = SAMPLES / "zeek" / "conn.log"
CAP = "cap-2026-11-20-a"

# A port scan probe: SYN sent, never answered. Zeek doesn't know duration or bytes.
SCAN = {"proto": "tcp", "service": None, "conn_state": "S0", "dst_port": 23,
        "duration_s": None, "orig_bytes": None, "resp_bytes": None, "orig_pkts": 1, "resp_pkts": 0}


def hot(features: dict, group: str) -> list[str]:
    return [v for v in F.VOCAB[group] if features[f"{group}_{v}"] == 1.0]


# ------------------------------------------------------------------------------------------- the list itself
def test_41_features_in_contract_order():
    assert len(F.FEATURE_NAMES) == 41 == CONTRACT["flow_features"]["dimension"]
    assert F.FEATURE_NAMES[:9] == [f["name"] for f in CONTRACT["flow_features"]["numeric"]]
    assert F.FEATURE_NAMES[9:13] == ["proto_tcp", "proto_udp", "proto_icmp", "proto_other"]
    assert F.FEATURE_NAMES[-3:] == ["dst_port_class_well_known", "dst_port_class_registered", "dst_port_class_dynamic"]
    assert len(set(F.FEATURE_NAMES)) == 41


def test_no_identifier_is_a_feature():
    forbidden = set(CONTRACT["forbidden_as_features"]["fields"]) | {"dst_port"}
    assert not forbidden & set(F.FEATURE_NAMES)


# ------------------------------------------------------------------------------------------- the numbers
def test_numbers_for_the_sample_dns_flow():
    raw = F.raw_numeric(0.02, 30, 58, 1, 1)
    assert raw["bytes_per_sec"] == pytest.approx(88 / 0.02)
    assert raw["pkts_per_sec"] == pytest.approx(2 / 0.02)
    assert raw["bytes_ratio_out"] == pytest.approx(30 / 89)
    assert raw["mean_pkt_size_orig"] == 30
    feats = F.flow_features({"proto": "udp", "service": "dns", "conn_state": "SF", "dst_port": 53,
                             "duration_s": 0.02, "orig_bytes": 30, "resp_bytes": 58, "orig_pkts": 1, "resp_pkts": 1})
    assert feats["orig_bytes"] == pytest.approx(math.log1p(30))                   # log1p applied
    assert feats["bytes_ratio_out"] == pytest.approx(30 / 89)                     # transform "none"
    assert (hot(feats, "proto"), hot(feats, "service"), hot(feats, "conn_state"), hot(feats, "dst_port_class")) == \
           (["udp"], ["dns"], ["SF"], ["well_known"])


def test_missing_values_become_0_not_nan():
    feats = F.flow_features(SCAN)
    assert all(math.isfinite(v) for v in feats.values())
    assert feats["duration_s"] == feats["orig_bytes"] == feats["bytes_per_sec"] == 0
    assert feats["orig_pkts"] == pytest.approx(math.log1p(1))
    assert feats["pkts_per_sec"] == pytest.approx(math.log1p(1 / 0.001))         # duration 0 -> divide by 0.001
    assert hot(feats, "service") == ["none"] and hot(feats, "conn_state") == ["S0"]


def test_nan_and_negative_become_0():
    feats = F.flow_features({**SCAN, "duration_s": float("nan"), "orig_pkts": -5})
    assert feats["duration_s"] == 0 and feats["orig_pkts"] == 0


@pytest.mark.parametrize("service, port, expected", [
    ("http", 554, "rtsp"),           # Zeek calls the camera stream http
    (None, 554, "rtsp"),
    ("http", 8554, "rtsp"),
    ("http", 80, "http"),
    ("ssl,http", 443, "ssl"),        # several services: the first counts
    ("SSH", 22, "ssh"),
    ("-http", 8080, "none"),         # "-" = Zeek's http analyzer failed: not really http
    ("quic", 443, "other"),          # not in the vocabulary
    (None, 23, "none"),              # unknown service stays unknown; we don't guess from the port
])
def test_service_mapping(service, port, expected):
    assert F.categories("tcp", service, "SF", port)["service"] == expected


@pytest.mark.parametrize("port, expected", [(0, "well_known"), (1023, "well_known"), (1024, "registered"),
                                            (49151, "registered"), (49152, "dynamic"), (65535, "dynamic")])
def test_port_class(port, expected):
    assert F.categories("tcp", None, "SF", port)["dst_port_class"] == expected


def test_unknown_categories_go_to_other():
    cats = F.categories("sctp", None, "WEIRD", None)
    assert cats == {"proto": "other", "service": "none", "conn_state": "other", "dst_port_class": None}
    feats = F.flow_features({**SCAN, "proto": None, "conn_state": None, "dst_port": None})
    assert hot(feats, "proto") == ["other"] and hot(feats, "conn_state") == ["other"]
    assert hot(feats, "dst_port_class") == []                                    # no port: all three 0


def test_every_sample_flow_has_one_value_per_group():
    for flow in ZeekConnParser().parse_file(CONN_LOG):
        feats = F.flow_features(asdict(flow))
        assert list(feats) == F.FEATURE_NAMES
        assert len(F.to_vector(feats)) == 41
        for group in F.ONE_HOT:
            assert len(hot(feats, group)) == 1, (flow.flow_id, group)


# ------------------------------------------------------------------------------------------- database
@pytest.fixture
def flows_db(db):
    load_conn_log(db, CONN_LOG, CAP)
    return db


def test_build_fills_every_flow_and_passes_the_check(flows_db):
    assert check_flow_features(flows_db, CAP).missing == 9
    result = build_flow_features(flows_db, CAP)
    assert (result.computed, result.already_done) == (9, 0)
    check = check_flow_features(flows_db, CAP)
    assert check.ok and check.rows == 9
    versions = flows_db.execute("SELECT DISTINCT feature_version FROM flows").fetchall()
    assert versions == [(F.FEATURE_VERSION,)]


def test_stored_features_equal_freshly_computed_ones(flows_db):
    build_flow_features(flows_db)
    stored = {row["flow_id"]: row for row in feature_table(flows_db, CAP)}
    for flow in ZeekConnParser().parse_file(CONN_LOG):
        expected = F.flow_features(asdict(flow))
        assert [stored[flow.flow_id][n] for n in F.FEATURE_NAMES] == pytest.approx(F.to_vector(expected))


def test_running_again_only_computes_what_is_missing(flows_db):
    build_flow_features(flows_db, CAP)
    assert build_flow_features(flows_db, CAP).computed == 0
    flows_db.execute("UPDATE flows SET feature_version = '0.9.0' WHERE dst_port = 53")     # older contract version
    assert build_flow_features(flows_db, CAP).computed == 1
    assert build_flow_features(flows_db, CAP, recompute=True).computed == 9


def test_check_catches_a_broken_vector(flows_db):
    build_flow_features(flows_db, CAP)
    flows_db.execute("""UPDATE flows SET features = features - 'proto_tcp' WHERE dst_port = 1883""")
    flows_db.execute("""UPDATE flows SET features = jsonb_set(features, '{service_dns}', '0') WHERE dst_port = 53""")
    check = check_flow_features(flows_db, CAP)
    assert not check.ok
    assert any("has 40 features" in p for p in check.problems)
    assert any("one-hot service has 0 ones" in p for p in check.problems)


def test_feature_table_and_csv(flows_db, tmp_path):
    build_flow_features(flows_db, CAP)
    table = feature_table(flows_db, CAP)
    assert len(table) == 9
    rtsp = next(r for r in table if r["dst_port"] == 554)
    assert rtsp["service"] == "http" and rtsp["service_rtsp"] == 1.0          # raw column keeps Zeek's value
    write_csv(table, tmp_path / "f.csv")
    header = (tmp_path / "f.csv").read_text(encoding="utf-8").splitlines()[0].split(",")
    assert header[-41:] == F.FEATURE_NAMES
