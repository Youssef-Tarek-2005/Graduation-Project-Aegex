"""Step 6 replay harness: stored flows -> Zeek conn.log lines -> the real ingest endpoint, on time, unchanged."""
import json
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from api.main import app
from datasets import to_unified as tu
from demo import replay as rp
from ingest.flows import ACK, FIN, PSH, RST, SYN, ZeekConnParser, history_flags

from test_datasets_unified import ai_flows


@pytest.mark.parametrize("fwd,bwd", [(SYN, RST | ACK), (SYN | ACK | PSH | FIN, SYN | ACK | PSH | FIN), (SYN, 0),
                                     (0, RST), (None, None)])
def test_flags_survive_the_trip_through_zeeks_history(fwd, bwd):
    history = rp.flags_to_history(fwd, bwd)
    if fwd is None:
        assert history is None
    else:
        assert history_flags(history, "tcp") == (fwd or 0, bwd or 0)


def row(**kw):
    base = {"ts_start": datetime(2018, 10, 25, 7, 0, 0, tzinfo=timezone.utc), "src_ip": "192.168.2.110",
            "src_port": 40000, "dst_ip": "192.168.2.1", "dst_port": 23, "proto": "tcp", "duration_s": 1.5,
            "orig_bytes": 120, "resp_bytes": 60, "orig_pkts": 2, "resp_pkts": 1, "service": None, "conn_state": None,
            "history": None, "fwd_flags": SYN, "bwd_flags": RST | ACK, "label": 1, "attack_class": "mirai",
            "scenario": "mirai_botnet"}
    return {**base, **kw}


def test_a_replayed_line_reads_back_as_the_same_flow_with_mapped_ips():
    line = rp.conn_line(row(), 1795000000.25, {"192.168.2.110": "192.168.137.50"})
    [flow] = ZeekConnParser().parse_line(json.dumps(line))
    assert (flow.src_ip, flow.dst_ip, flow.dst_port, flow.proto) == ("192.168.137.50", "192.168.2.1", 23, "tcp")
    assert (flow.orig_bytes, flow.resp_pkts, flow.duration_s) == (120, 1, 1.5)
    assert (flow.fwd_flags, flow.bwd_flags) == (SYN, RST | ACK)
    assert flow.ts_start == datetime.fromtimestamp(1795000000.25, timezone.utc)
    assert rp.replayed_flow_id(line) == flow.flow_id                  # the ground truth points at the saved row


def test_schedule_compresses_time_by_the_speed():
    rows = [row(), row(ts_start=row()["ts_start"] + timedelta(seconds=60)),
            row(ts_start=row()["ts_start"] + timedelta(seconds=600))]
    assert rp.schedule(rows, 1000.0, speed=10) == [1000.0, 1006.0, 1060.0]
    p = rp.plan(rows, speed=10)
    assert p["flows"] == 3 and p["attack_flows"] == 3 and p["source_minutes"] == 10.0 and p["replay_minutes"] == 1.0


def test_ip_map_and_time_options_are_checked():
    assert rp.parse_map(["192.168.2.110=192.168.137.57"]) == {"192.168.2.110": "192.168.137.57"}
    with pytest.raises(ValueError):
        rp.parse_map(["192.168.2.110"])
    with pytest.raises(ValueError):
        rp.utc("2018-10-25T07:00:00")                                   # no time zone


class FakeClock:
    def __init__(self, t=1000.0):
        self.t = t

    def __call__(self):
        return self.t

    def sleep(self, s):
        self.t += max(s, 0.01)


def test_flows_are_sent_when_their_time_comes(db, test_db_url, monkeypatch):
    """End to end: stored dataset flows -> Replayer -> the real API -> flows in the database, same values."""
    monkeypatch.setenv("AEGEX_DB_URL", test_db_url)
    src_rows, _ = tu.to_rows(ai_flows(), "ds-replay-src")
    tu.save(db, "kitsune", "ds-replay-src", src_rows, "replay source")
    rows = rp.read_flows(db, "ds-replay-src")
    assert len(rows) == 3
    clock = FakeClock(1795000000.0)
    times = rp.schedule(rows, clock() + 1, speed=10)
    with TestClient(app) as client:
        r = client.post("/api/v1/captures", json={"capture_id": "cap-replay-test", "kind": "live",
                                                   "start_ts": "2026-11-15T00:00:00Z"})
        assert r.status_code == 201, r.text
        rep = rp.Replayer("http://testserver", "cap-replay-test", http=client, log=lambda m: None)
        truth = rep.run(rows, times, {"192.168.2.110": "192.168.137.50"}, clock=clock, sleep=clock.sleep)
    assert rep.sent == rep.saved == 3 and rep.attacks == 2
    assert clock() >= times[-1]                                         # waited for the last flow's time
    saved = db.execute("SELECT flow_id, host(src_ip), fwd_flags, bwd_flags, label FROM flows "
                       "WHERE capture_id = 'cap-replay-test' ORDER BY ts_start").fetchall()
    assert [s[0] for s in saved] == [t["flow_id"] for t in truth]       # truth matches the saved rows 1:1
    assert saved[0][1:] == ("192.168.137.50", SYN, RST, None)           # mapped, flags kept, live = unlabelled
    assert [t["label"] for t in truth] == [1, 0, 1]
    for table in ("flows", "captures"):
        db.execute(f"DELETE FROM {table} WHERE capture_id IN ('cap-replay-test', 'ds-replay-src')")
