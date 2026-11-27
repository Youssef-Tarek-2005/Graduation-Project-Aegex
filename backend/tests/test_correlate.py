"""Step 7 correlation baseline: each rule just above / just below its threshold, merging into incidents, saving."""
from datetime import datetime, timedelta, timezone

import pandas as pd

from correlate import rules as R
from correlate import store

T0 = datetime(2026, 11, 27, 10, 0, 0, tzinfo=timezone.utc)
COLS = ["flow_id", "ts", "src_ip", "dst_ip", "dst_port", "proto", "resp_pkts", "conn_state", "bwd_flags", "device_id"]


def flow(i, sec, src, dst, port, proto="tcp", resp_pkts=1, bwd_flags=R.RST | 16, device=None):
    return (f"F{i}", T0 + timedelta(seconds=sec), src, dst, port, proto, resp_pkts, None, bwd_flags, device)


def frame(rows):
    return pd.DataFrame(rows, columns=COLS)


def port_scan(src="10.0.0.66", ports=25, start=0, dst="10.0.0.5"):
    return [flow(f"{src}{start}{p}", start + p * 0.5, src, dst, 1000 + p) for p in range(ports)]


def test_a_port_scan_above_the_line_is_one_incident():
    [inc] = R.correlate(frame(port_scan(ports=30)))
    assert inc.src_ip == "10.0.0.66" and inc.rules == {"port_scan": 30}
    assert inc.scenario == "vulnerability_scanning" and inc.score == 1.5 and inc.severity == "medium"
    assert inc.flows == 30 and inc.failed_share == 1.0 and inc.targets == ["10.0.0.5"]


def test_just_below_every_line_nothing_fires():
    rows = port_scan(ports=19)                                                     # 19 < 20 ports
    rows += [flow(f"s{h}", h, "10.0.0.67", f"10.0.1.{h}", 80, resp_pkts=0) for h in range(19)]   # 19 hosts
    rows += [flow(f"t{h}", h, "10.0.0.68", f"10.0.2.{h}", 23, resp_pkts=0) for h in range(4)]    # 4 Telnet hosts
    rows += [flow(f"f{n}", n * 0.5, "10.0.0.69", "10.0.0.5", 80) for n in range(99)]            # 99 connections
    assert R.correlate(frame(rows)) == []


def test_many_answered_hosts_are_not_a_sweep():
    rows = [flow(f"n{h}", h, "10.0.0.70", f"10.0.3.{h}", 443, resp_pkts=5, bwd_flags=16) for h in range(40)]
    assert R.correlate(frame(rows)) == []                                          # a busy client, not a scan


def test_an_arp_sweep_then_telnet_scans_merge_into_one_mirai_incident():
    rows = [flow(f"a{h}", h, "192.168.2.110", f"192.168.2.{h}", 0, proto="arp", resp_pkts=None, bwd_flags=None)
            for h in range(30)]
    rows += [flow(f"t{h}", 90 + h, "192.168.2.110", f"192.168.2.{200 + h}", 23, resp_pkts=0) for h in range(6)]
    [inc] = R.correlate(frame(rows))
    assert set(inc.rules) == {"host_sweep", "telnet_scan"} and inc.scenario == "mirai_botnet"
    assert inc.rules["host_sweep"] == 30 and inc.rules["telnet_scan"] == 6


def test_a_big_port_scan_is_not_mistaken_for_a_flood():
    rows = [flow(f"p{p}", p * 0.1, "10.0.0.66", "10.0.0.5", 1000 + p) for p in range(300)]   # 300 ports in 30 s
    [inc] = R.correlate(frame(rows))
    assert inc.rules == {"port_scan": 300} and inc.scenario == "vulnerability_scanning"


def test_a_flood_is_dos_and_reaches_our_device():
    rows = [flow(f"f{n}", n * 0.3, "192.168.137.50", "192.168.137.57", 80, device="esp32s3-01") for n in range(150)]
    [inc] = R.correlate(frame(rows))
    assert inc.scenario == "dos" and inc.rules == {"flood": 150} and inc.devices == ["esp32s3-01"]


def test_two_bursts_far_apart_are_two_incidents():
    rows = port_scan(start=0) + port_scan(start=600)                               # 10 minutes apart
    assert len(R.correlate(frame(rows))) == 2
    rows = port_scan(start=0) + port_scan(start=100)                               # next minute: one incident
    assert len(R.correlate(frame(rows))) == 1


def events(n, every_s, src="192.168.56.99", kind="login_failed"):
    return pd.DataFrame([{"ts": T0 + timedelta(seconds=i * every_s), "src_ip": src, "event_type": kind,
                          "device_id": "gw-01"} for i in range(n)])


def test_five_failed_logins_in_ten_minutes_is_a_brute_force():
    [inc] = R.correlate(frame([]), events(5, every_s=120))                         # 5 in 8 minutes
    assert inc.scenario == "bruteforce" and inc.rules == {"brute_force": 5} and inc.devices == ["gw-01"]
    assert R.correlate(frame([]), events(4, every_s=60)) == []                    # only 4
    assert R.correlate(frame([]), events(5, every_s=180)) == []                   # 5, but over 12 minutes


def test_an_incident_collects_the_sources_other_events():
    ev = pd.concat([events(3, 10, src="10.0.0.66", kind="http_request"), events(2, 5, src="10.9.9.9")])
    [inc] = R.correlate(frame(port_scan()), ev)
    assert inc.events == {"http_request": 3}                                       # only the same source


def test_incidents_are_saved_as_rule_alerts_and_a_rerun_replaces_them(db):
    db.execute("INSERT INTO captures (capture_id, start_ts, end_ts, kind) VALUES ('cap-rules-test', %s, %s, 'attack') "
               "ON CONFLICT DO NOTHING", (T0 - timedelta(hours=1), T0 + timedelta(hours=1)))
    rows = port_scan(ports=40) + [flow(f"f{n}", 300 + n * 0.2, "192.168.56.99", "192.168.56.10", 80) for n in range(120)]
    with db.cursor() as cur:
        for r in rows:
            cur.execute("INSERT INTO flows (flow_id, ts_start, capture_id, src_ip, dst_ip, dst_port, proto, resp_pkts, "
                        "bwd_flags) VALUES (%s, %s, 'cap-rules-test', %s, %s, %s, %s, %s, %s)",
                        (r[0], r[1], r[2], r[3], r[4], r[5], r[6], r[8]))
    incidents = store.run(db, "cap-rules-test")
    assert store.save(db, "cap-rules-test", incidents) == 2
    assert store.save(db, "cap-rules-test", incidents) == 2                       # replaced, not doubled
    saved = db.execute("SELECT entity_id, predicted_scenario, severity, score, evidence->'rules' FROM alerts "
                       "WHERE model_name = 'rules' AND evidence->>'capture' = 'cap-rules-test' ORDER BY entity_id"
                       ).fetchall()
    assert [(s[0], s[1]) for s in saved] == [("10.0.0.66", "vulnerability_scanning"), ("192.168.56.99", "dos")]
    assert saved[0][4]["port_scan"] == {"value": 40, "threshold": 20, "means": "ports tried on one host"}
    assert db.execute("SELECT metrics->'thresholds'->>'flood' FROM model_versions WHERE model_name = 'rules'"
                      ).fetchone()[0] == "100"
    db.execute("DELETE FROM alerts WHERE evidence->>'capture' = 'cap-rules-test'")
