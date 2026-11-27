"""Step 1 dataset analysis: catalogue, file checks, measuring and the report. No database, no real datasets."""
import hashlib

import pandas as pd
import pytest

from datasets import analyze as an


def test_catalogue_lists_the_eight_datasets_with_download_info():
    cat = an.load_catalogue()
    ids = [d["id"] for d in cat["datasets"]]
    assert ids == ["edge", "kitsune", "iot23", "iot23x", "xiiotid", "gotham", "aci", "nf_toniot"]
    for d in cat["datasets"]:
        assert d["url"].startswith("https://") and d["labelling"]["method"] and an.used_files(d)
    assert len(cat["rejected_datasets"]) == 5


def test_every_catalogue_dataset_has_an_adapter_in_the_ai_folder(tmp_path):
    reg = an.load_adapters(tmp_path)
    assert {d["id"] for d in an.load_catalogue()["datasets"]} <= set(reg.names())


def test_unused_files_are_not_expected():
    kitsune = next(d for d in an.load_catalogue()["datasets"] if d["id"] == "kitsune")
    names = [f["file"] for f in an.used_files(kitsune)]
    assert "Mirai_pcap.pcap.zip" in names and "SYN_DoS_pcap.pcap.zip" not in names


def entry(name, data):
    return {"file": name, "size_bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}


def test_file_check_verified_size_checksum_missing_and_unpacked(tmp_path):
    data = b"pcap bytes"
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "a.pcap.zip").write_bytes(data)            # found in a sub-folder
    assert an.check_file(tmp_path, entry("a.pcap.zip", data))["status"] == "verified"
    assert an.check_file(tmp_path, entry("a.pcap.zip", data), quick=True)["status"] == "present"

    (tmp_path / "b.zip").write_bytes(b"PCAP BYTES")                 # same size, other content
    assert an.check_file(tmp_path, entry("b.zip", data))["status"] == "checksum mismatch"
    (tmp_path / "c.zip").write_bytes(b"short")
    assert an.check_file(tmp_path, entry("c.zip", data))["status"] == "size mismatch"

    assert an.check_file(tmp_path, entry("gone.zip", data))["status"] == "missing"
    (tmp_path / "d.pcap").write_bytes(b"unpacked")                  # Kaggle-style unpacked copy of d.pcap.zip
    assert an.check_file(tmp_path, entry("d.pcap.zip", data))["status"] == "unpacked"


def flows():
    return pd.DataFrame({
        "ts": [100.0, 110.0, 3700.0], "ts_end": [105.0, 111.0, 3701.0],
        "src_ip": ["192.168.2.110", "192.168.2.110", "192.168.2.5"],
        "dst_ip": ["192.168.2.1", "8.8.8.8", "192.168.2.1"],
        "proto": ["tcp", "udp", "tcp"],
        "fwd_pkts": [3, 1, 2], "bwd_pkts": [2, 1, 0], "fwd_bytes": [180, 60, 120], "bwd_bytes": [120, 90, 0],
        "is_attack": [1, 1, 0], "attack_class": ["mirai", "mirai", "benign"],
        "label_note": ["behaviour relabel", "behaviour relabel", ""],
    })


def test_summarize_counts_one_capture():
    s = an.summarize(flows())
    assert s["flows"] == 3 and s["attack_flows"] == 2 and s["attack_share"] == pytest.approx(0.6667)
    assert s["classes"] == {"mirai": 2, "benign": 1}
    assert s["hosts"] == 4 and s["lan_hosts"] == 3                  # 8.8.8.8 is not on the LAN
    assert s["attack_sources"] == ["192.168.2.110"] and s["n_attack_sources"] == 1
    assert s["protocols"] == {"tcp": 2, "udp": 1}
    assert s["packets"] == 9 and s["bytes"] == 570
    assert s["start_utc"] == "1970-01-01 00:01:40" and s["span_hours"] == pytest.approx(1.0, abs=0.01)
    assert s["relabelled_flows"] == 2 and s["missing_values"] == {}


def test_combine_sums_flows_but_unions_hosts():
    a, b = an.summarize(flows()), an.summarize(flows())
    t = an.combine({"x": a, "y": b, "z": {"status": "files missing"}})
    assert t["captures"] == 2 and t["flows"] == 6 and t["classes"] == {"mirai": 4, "benign": 2}
    assert t["hosts"] == 4                                          # same 4 hosts, not 8


class FakeAdapter:
    def captures(self):
        return ["ok", "missing", "broken"]

    def build(self, cap):
        if cap == "missing":
            raise FileNotFoundError("original 'x.zip' not found in AEGEX_DATA=...")
        if cap == "broken":
            raise ValueError("bad file")
        return flows(), {}


class FakeRegistry:
    def get(self, name):
        return FakeAdapter()


def test_measure_skips_missing_and_broken_captures():
    out = an.measure(FakeRegistry(), "fake", log=lambda m: None)
    assert out["ok"]["status"] == "measured" and out["ok"]["flows"] == 3
    assert out["missing"] == {"status": "files missing", "detail": "original 'x.zip'"}
    assert out["broken"]["status"] == "error"


def test_report_keeps_measured_numbers_and_download_list(tmp_path):
    cat = an.load_catalogue()
    report = an.analyze(tmp_path, ["kitsune"], log=lambda m: None)   # empty folder: nothing here
    md = an.render(report)
    assert "Nothing measured yet" in md and "Kitsune" in md
    assert "kaggle datasets download -d ymirsky/network-attack-dataset-kitsune" in md
    assert len(report["rejected"]) == len(cat["rejected_datasets"])

    report["datasets"][0]["captures"] = {"mirai": {"status": "measured", **an.summarize(flows())}}
    md = an.render(report)
    assert "| Kitsune Network Attack Dataset | mirai | 3 | 2 (66.7%) | mirai 2, benign 1 |" in md
    assert "_ips" not in str(an.to_json(report))
