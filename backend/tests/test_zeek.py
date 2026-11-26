"""Step 5 tests: Zeek conn.log -> Flow objects -> flows table.

samples/zeek/conn.log is Zeek 8.0's real output for samples/cap-2026-11-20-a.pcap, saved so that most tests
don't need Docker. One test runs Zeek itself and is skipped if Docker isn't available.
"""
from __future__ import annotations

import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path

import pytest

from ingest.flows import ZeekConnParser, load_conn_log, load_flows, make_flow_id
from ingest.loader import LoadError, label_capture
from ingest.zeek import run_zeek

SAMPLES = Path(__file__).resolve().parents[1] / "samples"
CONN_LOG = SAMPLES / "zeek" / "conn.log"
PCAP = SAMPLES / "cap-2026-11-20-a.pcap"
CAP = "cap-2026-11-20-a"
UTC = timezone.utc


# ------------------------------------------------------------------------------------------ parsing
def test_conn_log_has_the_nine_connections_of_the_story():
    flows = ZeekConnParser().parse_file(CONN_LOG)
    summary = [(f.src_ip, f.dst_ip, f.dst_port, f.proto, f.service) for f in flows]
    assert summary == [
        ("192.168.56.20", "192.168.56.10", 53,   "udp",  "dns"),
        ("192.168.56.20", "192.168.56.10", 1883, "tcp",  "mqtt"),
        ("192.168.56.1",  "192.168.56.30", 554,  "tcp",  "http"),     # RTSP looks like HTTP to Zeek
        ("192.168.56.99", "192.168.56.10", 22,   "tcp",  "ssh"),
        ("192.168.56.99", "192.168.56.10", 22,   "tcp",  "ssh"),
        ("192.168.56.10", "192.168.56.99", 80,   "tcp",  "http"),     # honeypot downloads from the attacker
        ("192.168.56.99", "192.168.56.10", 22,   "tcp",  "ssh"),
        ("192.168.56.1",  "192.168.56.20", 0,    "icmp", None),       # ICMP: no service, "port" is the ICMP code
        ("192.168.56.1",  "192.168.56.10", 22,   "tcp",  "ssh"),
    ]


def test_flow_values_are_read_correctly():
    mqtt = ZeekConnParser().parse_file(CONN_LOG)[1]
    assert mqtt.ts_start == datetime(2026, 11, 20, 14, 5, 0, tzinfo=UTC)
    assert mqtt.conn_state == "SF" and mqtt.history == "ShADadFf"
    assert (mqtt.orig_bytes, mqtt.resp_bytes, mqtt.orig_pkts, mqtt.resp_pkts) == (104, 4, 8, 6)
    assert mqtt.ts_end > mqtt.ts_start and round(mqtt.duration_s, 2) == 0.34
    assert mqtt.zeek_uid and mqtt.flow_id.startswith("F")


def test_flow_id_ignores_zeeks_random_uid():
    # Same connection, two different Zeek runs (different uid) -> same flow_id.
    line = CONN_LOG.read_text(encoding="utf-8").splitlines()[1]
    other_run = line.replace('"uid":"', '"uid":"Xdifferent')
    a, b = ZeekConnParser().parse_lines([line, other_run])
    assert a.zeek_uid != b.zeek_uid and a.flow_id == b.flow_id


def test_flow_id_changes_when_the_connection_changes():
    ts = datetime(2026, 11, 20, 14, 5, tzinfo=UTC)
    base = make_flow_id(ts, "tcp", "10.0.0.1", 1000, "10.0.0.2", 22)
    assert base != make_flow_id(ts, "tcp", "10.0.0.1", 1001, "10.0.0.2", 22)        # other port
    assert base != make_flow_id(ts.replace(microsecond=1), "tcp", "10.0.0.1", 1000, "10.0.0.2", 22)  # 1 µs later


TSV = """\
#separator \\x09
#set_separator\t,
#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tservice\tduration\torig_bytes\tresp_bytes\tconn_state\thistory\torig_pkts\tresp_pkts
#types\ttime\tstring\taddr\tport\taddr\tport\tenum\tstring\tinterval\tcount\tcount\tstring\tstring\tcount\tcount
1795183800.500000\tCabc\t192.168.56.99\t40500\t192.168.56.10\t23\ttcp\t-\t-\t-\t-\tS0\tS\t1\t0
#close\t2026-11-20-15-00-00
"""


def test_zeeks_default_tab_separated_format_also_works():
    p = ZeekConnParser()
    (f,) = p.parse_lines(TSV.splitlines())
    assert (f.src_ip, f.dst_port, f.conn_state, f.service) == ("192.168.56.99", 23, "S0", None)
    assert f.duration_s is None and f.orig_bytes is None      # "-" means unknown, not 0
    assert (p.stats.events, p.stats.ignored) == (1, 5)


def test_bad_lines_are_skipped():
    p = ZeekConnParser()
    assert p.parse_lines(["{not json", '{"ts": 1}', "a\tb\tc"]) == []
    assert p.stats.skipped == 3


# ------------------------------------------------------------------------------------------ loading
def flow_count(db, where: str = "TRUE") -> int:
    return db.execute(f"SELECT count(*) FROM flows WHERE {where}").fetchone()[0]


def test_flows_are_saved_with_their_device(db):
    r = load_conn_log(db, CONN_LOG, CAP)
    assert (r.inserted, r.duplicates, r.with_device) == (9, 0, 9)
    devices = dict(db.execute("SELECT host(dst_ip) || ':' || dst_port, device_id FROM flows "
                              "WHERE proto <> 'icmp' AND dst_port IN (53, 554, 80)").fetchall())
    assert devices == {"192.168.56.10:53": "gw-01", "192.168.56.30:554": "cam-01",
                       "192.168.56.99:80": "gw-01"}           # attacker isn't a device -> the other end is


def test_loading_the_same_conn_log_twice_adds_nothing(db):
    load_conn_log(db, CONN_LOG, CAP)
    again = load_conn_log(db, CONN_LOG, CAP)
    assert (again.inserted, again.duplicates) == (0, 9) and flow_count(db) == 9


def test_labeling_flows(db):
    load_conn_log(db, CONN_LOG, CAP)
    label_capture(db, CAP)
    attack = db.execute("SELECT host(src_ip), host(dst_ip), dst_port FROM flows WHERE label = 1 ORDER BY ts_start").fetchall()
    assert attack == [("192.168.56.99", "192.168.56.10", 22),       # 14:10:02 failed login
                      ("192.168.56.99", "192.168.56.10", 22),       # 14:10:05 failed login
                      ("192.168.56.99", "192.168.56.10", 22),       # 14:12:39 successful session
                      ("192.168.56.10", "192.168.56.99", 80)]       # 14:13:20 download: attacker is the DESTINATION, still caught
    assert flow_count(db, "label = 0") == 5                          # incl. the admin's SSH on the same port 22
    summary = dict(db.execute("SELECT scenario, n_flows FROM v_label_summary").fetchall())
    assert summary == {"bruteforce": 4, "normal": 5}


def test_flows_outside_the_capture_are_refused(db):
    line = CONN_LOG.read_text(encoding="utf-8").splitlines()[0].replace('"ts":1795183490.0', '"ts":1795100000.0')
    with pytest.raises(LoadError, match="outside capture"):
        load_flows(db, ZeekConnParser(), [line], CAP)
    assert flow_count(db) == 0


def test_unknown_capture_is_refused(db):
    with pytest.raises(LoadError, match="capture"):
        load_conn_log(db, CONN_LOG, "cap-nope")


# ------------------------------------------------------------------------------- real Zeek (Docker)
def _docker_ok() -> bool:
    return shutil.which("docker") is not None and subprocess.run(["docker", "info"], capture_output=True).returncode == 0


@pytest.mark.skipif(not _docker_ok(), reason="Docker is not running")
def test_running_zeek_on_the_pcap_gives_the_same_flows(tmp_path):
    conn_log = run_zeek(PCAP, tmp_path)
    fresh = ZeekConnParser().parse_file(conn_log)
    saved = ZeekConnParser().parse_file(CONN_LOG)
    assert [f.flow_id for f in fresh] == [f.flow_id for f in saved]      # stable across Zeek runs
    assert [f.zeek_uid for f in fresh] != [f.zeek_uid for f in saved]    # ...even though Zeek's uids changed
