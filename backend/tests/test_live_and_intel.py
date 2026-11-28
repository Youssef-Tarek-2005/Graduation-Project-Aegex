"""Live demo pieces (packets, events, labels) and the grounded threat-intelligence report."""
import random
from datetime import datetime, timedelta, timezone

from psycopg.types.json import Jsonb

from demo import live_demo as L
from intel import report as R

T0 = datetime(2026, 11, 27, 12, 0, tzinfo=timezone.utc)


# ----------------------------------------------------------------------------- live demo generators
def test_normal_traffic_matches_the_calibration_rates():
    rng = random.Random(1)
    packets, events = L.normal_traffic(rng, 0.0, 60.0)
    sensor = [p for p in packets if p["IP"].dst == L.LAPTOP and p["TCP"].flags == "S"]
    page = [p for p in packets if p["IP"].src == L.PHONE and p["TCP"].flags == "S"]
    assert 11 <= len(sensor) <= 13 and 4 <= len(page) <= 10              # every ~5 s and every ~10 s
    assert len(events) == len(page) and all(e["severity"] == "low" for e in events)


def test_every_attack_fits_in_one_15_second_slice_and_logs_honeypot_events():
    for kind, gen in L.GENERATORS.items():
        for seed in range(20):
            packets, events, end, what = gen(random.Random(seed), "192.168.137.50", 100.0)
            assert packets and what and end - 100.0 <= 12.5, kind    # starts <= 2 s in, so it ends inside 15 s
            assert max(float(p.time) for p in packets) <= end + 2, kind
            assert any(e["event_type"] == "device_log" for e in events), kind
    kinds = set()
    for seed in range(10):
        _, events, _, _ = L.telnet_brute(random.Random(seed), "192.168.137.66", 0.0)
        failed = [e for e in events if e["event_type"] == "login_failed"]
        assert len(failed) >= 8 and all(e["payload"]["username"] and e["severity"] == "medium" for e in failed)
        kinds |= {e["event_type"] for e in events}
    assert {"login_success", "command"} <= kinds                       # sometimes the honeypot lets it in
    _, events, _, _ = L.mirai(random.Random(1), "192.168.137.88", 0.0)
    assert any(e["event_type"] == "command" and "mirai" in e["payload"]["input"] for e in events)
    p = L.telnet_brute(random.Random(1), "192.168.137.66", 0.0)[0]
    assert b"Login incorrect" in bytes(p[5]["TCP"].payload) and b"\r\n" in bytes(p[3]["TCP"].payload)


def test_device_events_add_heartbeats_and_history_readings():
    ev = L.device_events(random.Random(2), 0.0, 600.0, sensors=True)
    kinds = [e["event_type"] for e in ev]
    assert kinds.count("sensor_reading") == 60 and 9 <= kinds.count("device_log") <= 10
    assert all(e["severity"] == "info" for e in ev)
    assert all(e["event_type"] == "device_log" for e in L.device_events(random.Random(2), 0.0, 600.0, sensors=False))


def test_label_period_uses_task_as_rule_for_one_slice(db):
    db.execute("INSERT INTO captures (capture_id, start_ts, kind) VALUES (%s, %s, 'live') ON CONFLICT DO NOTHING",
               (L.CAPTURE, T0 - timedelta(hours=1)))
    with db.cursor() as cur:
        for i, (src, s) in enumerate([("192.168.137.50", 10), ("192.168.137.20", 20), ("192.168.137.50", 200)]):
            cur.execute("INSERT INTO flows (flow_id, ts_start, capture_id, src_ip, dst_ip, proto) VALUES "
                        "(%s, %s, %s, %s, '192.168.137.57', 'tcp')", (f"LV{i}", T0 + timedelta(seconds=s), L.CAPTURE, src))
    run = {"run_id": "demo-x", "scenario": "vulnerability_scanning", "attacker_ip": "192.168.137.50",
           "start_ts": (T0 + timedelta(seconds=5)).isoformat(), "end_ts": (T0 + timedelta(seconds=30)).isoformat()}
    L.label_period(db, T0.timestamp(), T0.timestamp() + 60, [run])
    labels = dict(db.execute("SELECT flow_id, label FROM flows WHERE capture_id = %s", (L.CAPTURE,)).fetchall())
    assert labels == {"LV0": 1, "LV1": 0, "LV2": None}                   # the third flow is outside this slice
    db.execute("DELETE FROM flows WHERE capture_id = %s", (L.CAPTURE,))
    db.execute("DELETE FROM captures WHERE capture_id = %s", (L.CAPTURE,))


# ----------------------------------------------------------------------------- threat intelligence
def test_every_scenario_gets_cited_knowledge():
    for scen in R.SCENARIOS:
        i = R.intel_for(scen)
        assert i["attack_techniques"] and all(t["url"].startswith("https://attack.mitre.org/") for t in i["attack_techniques"])
        assert i["owasp_iot"] and i["mitigations"] and i["cwe"]
        assert all(x["id"].startswith(("IOT-", "CWE-", "CAPEC-", "M1")) for x in i["owasp_iot"] + i["cwe"] + i["mitigations"])
    assert R.intel_for("bruteforce")["owasp_iot"][0]["id"] == "IOT-I1"          # weak / default passwords
    assert all(c["url"].startswith("https://nvd.nist.gov/") for c in R.intel_for("dos")["cves"])


def alert(db, model, entity, scenario, minute, evidence):
    db.execute("INSERT INTO model_versions (model_name, version, feature_version) VALUES (%s, 'v', 'x') "
               "ON CONFLICT DO NOTHING", (model,))
    db.execute("INSERT INTO alerts (model_name, model_version, feature_version, entity_type, entity_id, window_start, "
               "window_end, score, is_anomaly, predicted_scenario, severity, evidence) VALUES "
               "(%s, 'v', 'x', 'src_ip', %s, %s, %s, 3, TRUE, %s, 'high', %s)",
               (model, entity, T0 + timedelta(minutes=minute), T0 + timedelta(minutes=minute + 1), scenario,
                Jsonb({"capture": "cap-intel-test", **evidence})))


def test_report_groups_detectors_per_attacker_with_the_rules_type_first(db):
    alert(db, "rules", "192.168.137.66", "bruteforce", 0, {"summary": "brute force: 20 failed logins in 10 minutes"})
    alert(db, "temporal_gat", "192.168.137.66", "mirai_botnet", 0, {})          # same attacker, same time
    alert(db, "vae", "192.168.137.66", None, 0, {"closest_known_class": "mirai"})
    alert(db, "vae", "192.168.137.91", None, 30, {"closest_known_class": "scanning"})   # AI only
    db.execute("INSERT INTO events (ts, source, event_type, layer, src_ip, payload) VALUES (%s, 'esp32', "
               "'login_failed', 'session_interaction', '192.168.137.66', %s)",
               (T0 + timedelta(seconds=20), Jsonb({"username": "root", "password": "xc3511"})))
    r = R.build(db, 60, now=T0 + timedelta(minutes=40))
    by = {(i["attacker"], i["scenario"]): i for i in r["incidents"]}
    assert set(by) == {("192.168.137.66", "bruteforce"), ("192.168.137.91", "vulnerability_scanning")}
    brute = by[("192.168.137.66", "bruteforce")]
    assert brute["detectors"] == {"Rule baseline": 1, "Temporal GAT": 1, "VAE": 1} and brute["alerts"] == 3
    assert brute["credentials_tried"] == [{"username": "root", "password": "xc3511", "times": 1}]
    md = R.markdown(r)
    assert "Password brute force from 192.168.137.66" in md and "T1110.001" in md and "IOT-I1" in md
    db.execute("DELETE FROM alerts WHERE evidence->>'capture' = 'cap-intel-test'")
    db.execute("DELETE FROM events")
