"""Step 2 unified schema: new flow columns, Zeek TCP flags, and public dataset rows -> the flows table."""
import json

import pandas as pd
import pytest

from datasets import to_unified as tu
from ingest.flows import ACK, FIN, PSH, RST, SYN, ZeekConnParser, history_flags, load_flows


# ----------------------------------------------------------------------------- Zeek flags
def test_history_flags_split_originator_and_responder():
    assert history_flags("Sr", "tcp") == (SYN, RST)                       # a port scan: SYN, answered by RST
    assert history_flags("ShADadFf", "tcp") == (SYN | ACK | PSH | FIN, SYN | ACK | PSH | FIN)
    assert history_flags("Dd", "udp") == (None, None)                      # not TCP: no flags
    assert history_flags(None, "tcp") == (None, None)


ZEEK_LINE = json.dumps({"ts": 1764500000.0, "uid": "Cx1", "id.orig_h": "192.168.137.50", "id.orig_p": 40000,
                        "id.resp_h": "192.168.137.57", "id.resp_p": 23, "proto": "tcp", "history": "Sr",
                        "duration": 0.01, "orig_pkts": 1, "resp_pkts": 1, "orig_bytes": 0, "resp_bytes": 0})


def test_zeek_flows_are_saved_with_their_tcp_flags(db):
    load_flows(db, ZeekConnParser(), [ZEEK_LINE])
    assert db.execute("SELECT fwd_flags, bwd_flags, attack_class, label_info FROM flows").fetchone() == \
        (SYN, RST, None, None)


# ----------------------------------------------------------------------------- schema
def test_schema_has_the_unified_columns(db):
    cols = {r[0] for r in db.execute("SELECT column_name FROM information_schema.columns WHERE table_name = 'flows'")}
    assert {"fwd_flags", "bwd_flags", "attack_class", "label_info"} <= cols
    assert db.execute("SELECT 1 FROM information_schema.columns "
                      "WHERE table_name = 'captures' AND column_name = 'dataset'").fetchone()


# ----------------------------------------------------------------------------- convert
def ai_flows():
    """Three rows in the AI team's FLOW_COLUMNS layout (+ one bad IP)."""
    return pd.DataFrame({
        "ts": [1540446000.0, 1540446010.0, 1540446020.0, 1540446030.0],
        "ts_end": [1540446001.5, 1540446010.0, 1540446019.0, 1540446031.0],
        "src_ip": ["192.168.2.110", "192.168.2.5", "192.168.2.110", "not-an-ip"],
        "src_port": [40000, 5353, 0, 1], "dst_ip": ["192.168.2.1", "224.0.0.251", "192.168.2.200", "1.1.1.1"],
        "dst_port": [23, 5353, 0, 80], "proto": ["tcp", "udp", "arp", "tcp"],
        "duration": [1.5, 0.0, 0.0, 1.0], "fwd_pkts": [2, 1, 1, 1], "bwd_pkts": [1, 0, 0, 0],
        "fwd_bytes": [120, 90, 42, 60], "bwd_bytes": [60, 0, 0, 0], "fwd_flags": [SYN, 0, 0, SYN],
        "bwd_flags": [RST, 0, 0, 0], "mal_frac": [0.5, 0.0, 1.0, 1.0], "is_attack": [1, 0, 1, 1],
        "attack_class": ["mirai", "benign", "mirai", "mirai"], "campaign": ["mirai", "", "mirai", ""],
        "original_label": ["malicious", "benign", "malicious", ""], "label_note": ["relabel R2", "", "relabel R1", ""],
        "dataset": "kitsune", "capture": "mirai",
    })


def test_capture_ids_are_safe_and_stable():
    assert tu.capture_id("kitsune", "mirai") == "ds-kitsune-mirai"
    assert tu.capture_id("iot23", "CTU-IoT-Malware-Capture-34-1") == "ds-iot23-ctu-iot-malware-capture-34-1"
    assert tu.capture_id("gotham", "Mirai DoS / part 1") == "ds-gotham-mirai-dos-part-1"


def test_to_rows_maps_the_ai_flow_table_to_our_columns():
    rows, dropped = tu.to_rows(ai_flows(), "ds-kitsune-mirai")
    assert dropped == {"bad_ip": 1, "bad_time": 0, "duplicate": 0}
    first = dict(zip(tu.COLUMNS, rows[0]))
    assert first["src_ip"] == "192.168.2.110" and first["dst_port"] == 23 and first["proto"] == "tcp"
    assert first["ts_start"].isoformat() == "2018-10-25T05:40:00+00:00"
    assert first["orig_bytes"] == 120 and first["resp_pkts"] == 1 and first["duration_s"] == 1.5
    assert (first["fwd_flags"], first["bwd_flags"]) == (SYN, RST)
    assert (first["label"], first["attack_class"], first["scenario"]) == (1, "mirai", "mirai_botnet")
    assert json.loads(first["label_info"]) == {"original_label": "malicious", "label_note": "relabel R2",
                                               "campaign": "mirai", "mal_frac": 0.5}
    benign = dict(zip(tu.COLUMNS, rows[1]))
    assert (benign["label"], benign["attack_class"], benign["scenario"]) == (0, "benign", None)
    assert dict(zip(tu.COLUMNS, rows[2]))["ts_end"] is None           # end before start: unknown, not wrong


def test_the_same_connection_twice_is_kept_once():
    df = pd.concat([ai_flows().head(1)] * 2, ignore_index=True)
    rows, dropped = tu.to_rows(df, "ds-x")
    assert len(rows) == 1 and dropped["duplicate"] == 1


def test_every_ai_class_has_one_of_our_scenarios():
    assert set(tu.SCENARIO) == {"benign", "scanning", "ddos", "mirai", "ransomware", "other"}
    assert tu.SCENARIO["ddos"] == "dos" and tu.SCENARIO["scanning"] == "vulnerability_scanning"


# ----------------------------------------------------------------------------- save
def test_dataset_capture_is_saved_and_a_rerun_replaces_it(db):
    rows, _ = tu.to_rows(ai_flows(), "ds-test-mirai")
    assert tu.save(db, "kitsune", "ds-test-mirai", rows, "test") == 3
    assert tu.save(db, "kitsune", "ds-test-mirai", rows, "test again") == 3     # no duplicates
    assert db.execute("SELECT count(*), sum(label) FROM flows WHERE capture_id = 'ds-test-mirai'").fetchone() == (3, 2)
    cap = db.execute("SELECT dataset, kind, notes, start_ts < end_ts FROM captures "
                     "WHERE capture_id = 'ds-test-mirai'").fetchone()
    assert cap == ("kitsune", "mixed", "test again", True)
    row = db.execute("SELECT host(src_ip), fwd_flags, bwd_flags, attack_class, scenario, label_info->>'label_note' "
                     "FROM flows WHERE capture_id = 'ds-test-mirai' ORDER BY ts_start LIMIT 1").fetchone()
    assert row == ("192.168.2.110", SYN, RST, "mirai", "mirai_botnet", "relabel R2")
    shown = [r for r in tu.show(db) if r[1] == "ds-test-mirai"]
    assert shown[0][:4] == ("kitsune", "ds-test-mirai", 3, 2)


class Adapter:
    TITLE = "Fake"

    def captures(self):
        return ["big", "gone"]

    def build(self, cap):
        if cap == "gone":
            raise FileNotFoundError("original 'gone.zip' not found in AEGEX_DATA=x")
        return ai_flows(), {}


class Registry:
    def get(self, name):
        return Adapter()


def test_load_dataset_respects_max_rows_and_skips_missing_files(db):
    out = tu.load_dataset(db, Registry(), "fake", max_rows=2, log=lambda m: None)
    assert list(out) == ["ds-fake-big"]
    assert out["ds-fake-big"] == {"connections": 4, "loaded": 2, "attacks": 1, "bad_ip": 0, "bad_time": 0,
                                  "duplicate": 0}
    notes = db.execute("SELECT notes FROM captures WHERE capture_id = 'ds-fake-big'").fetchone()[0]
    assert "first 2 of 4 connections" in notes
