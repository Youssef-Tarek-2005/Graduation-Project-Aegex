"""Step 8 evaluation harness: alerts -> covered flows -> flow and attacker metrics, per detector."""
from datetime import datetime, timedelta, timezone

import pandas as pd
import pytest
from psycopg.types.json import Jsonb

from correlate import store
from correlate.rules import Incident
from evaluate import run as ev
from evaluate import score as sc

T0 = datetime(2026, 11, 25, 11, 0, tzinfo=timezone.utc)


def flows():
    """.50 attacks .57 at 11:05 (3 flows); normal: phone .20 -> .57, .57 -> outside, an external visitor."""
    rows = [(T0 + timedelta(minutes=5, seconds=s), "192.168.137.50", "192.168.137.57", 1) for s in range(3)]
    rows += [(T0 + timedelta(minutes=m), "192.168.137.20", "192.168.137.57", 0) for m in range(4)]
    rows += [(T0 + timedelta(minutes=m), "192.168.137.57", "8.8.8.8", 0) for m in range(3)]
    rows += [(T0 + timedelta(minutes=6), "203.0.113.9", "192.168.137.57", 0)]
    return pd.DataFrame(rows, columns=["ts", "src_ip", "dst_ip", "label"])


def alert(ip, start_min, end_min, entity_type="src_ip"):
    return {"entity_type": entity_type, "ip": ip, "window_start": T0 + timedelta(minutes=start_min),
            "window_end": T0 + timedelta(minutes=end_min)}


def test_flows_belong_to_devices_by_the_ai_teams_rule():
    dev = sc.device_of(flows())
    assert list(dev[:3]) == ["192.168.137.50"] * 3                      # local originator
    assert dev[-1] == "192.168.137.57"                                  # outside visitor -> the local responder


def test_an_ip_alert_covers_only_what_that_host_sent_in_its_window():
    hit = sc.covered(flows(), pd.DataFrame([alert("192.168.137.50", 5, 5 + 1 / 60)]))   # window 11:05:00-11:05:01
    assert hit.tolist() == [True, True, True] + [False] * 8              # the 11:05:02 flow: inside the 1 s slack
    assert sc.covered(flows(), pd.DataFrame([alert("192.168.137.50", 5, 5)])).sum() == 2   # 11:05:02 is 2 s past


def test_a_device_alert_covers_the_flows_of_that_device():
    hit = sc.covered(flows(), pd.DataFrame([alert("192.168.137.57", 0, 10, entity_type="device")]))
    assert hit.sum() == 4                                                # its 3 outgoing + the outside visitor's


def test_flow_metrics():
    m = sc.flow_metrics([1, 1, 0, 0, 0], [1, 0, 1, 0, 0])
    assert (m["tp"], m["fp"], m["fn"], m["tn"]) == (1, 1, 1, 2)
    assert m["precision"] == 0.5 and m["recall"] == 0.5 and m["f1"] == 0.5 and m["false_alarm_rate"] == 0.3333
    assert sc.flow_metrics([0, 0], [0, 0])["recall"] is None             # no attacks: recall undefined, not 0


def test_attacker_level_found_missed_and_time_to_detect():
    a = sc.attacker_metrics(flows(), pd.DataFrame([alert("192.168.137.50", 5.5, 6), alert("192.168.137.20", 1, 2)]))
    assert a["attackers"] == 1 and a["attackers_found"] == 1 and a["attackers_missed"] == []
    assert a["time_to_detect_s"] == {"192.168.137.50": 30.0}             # first alert 30 s after the first attack flow
    assert a["normal_hosts_flagged"] == 1 and a["flagged_normal"] == ["192.168.137.20"]
    none = sc.attacker_metrics(flows(), pd.DataFrame(columns=["ip", "window_start"]))
    assert none["attackers_missed"] == ["192.168.137.50"]


def test_ai_windows_are_split_into_lstm_and_vae_by_their_own_scores():
    alerts = pd.DataFrame([
        {"model_name": "lstm_ae", "evidence": {"lstm_score": 2.0, "vae_score": 0.5}},
        {"model_name": "vae", "evidence": {"lstm_score": 0.4, "vae_score": 3.0}},
        {"model_name": "rules", "evidence": {}}, {"model_name": "temporal_gat", "evidence": {}}])
    d = ev.detector_alerts(alerts)
    assert (len(d["LSTM-AE"]), len(d["VAE"]), len(d["LSTM-AE + VAE"])) == (1, 1, 2)
    assert (len(d["Rule baseline"]), len(d["Temporal GAT"]), len(d["Any detector"])) == (1, 1, 4)


def test_a_capture_is_scored_per_detector_from_the_database(db):
    cap = "cap-eval-test"
    db.execute("INSERT INTO captures (capture_id, start_ts, end_ts, kind) VALUES (%s, %s, %s, 'attack') "
               "ON CONFLICT DO NOTHING", (cap, T0, T0 + timedelta(hours=1)))
    with db.cursor() as cur:
        for i, r in enumerate(flows().itertuples(index=False)):
            cur.execute("INSERT INTO flows (flow_id, ts_start, capture_id, src_ip, dst_ip, proto, label) "
                        "VALUES (%s, %s, %s, %s, %s, 'tcp', %s)", (f"E{i}", r.ts, cap, r.src_ip, r.dst_ip, r.label))
    store.save(db, cap, [Incident("192.168.137.50", T0 + timedelta(minutes=5), T0 + timedelta(minutes=5, seconds=2),
                                  {"port_scan": 40})])
    db.execute("INSERT INTO model_versions (model_name, version, feature_version) VALUES ('vae', 'vae_v5', 'x') "
               "ON CONFLICT DO NOTHING")
    db.execute("INSERT INTO alerts (model_name, model_version, feature_version, entity_type, entity_id, window_start, "
               "window_end, score, is_anomaly, evidence) VALUES ('vae', 'vae_v5', 'x', 'device', '192.168.137.20', %s, "
               "%s, 2, TRUE, %s)", (T0, T0 + timedelta(minutes=10),
                                    Jsonb({"capture": cap, "lstm_score": 0.2, "vae_score": 2.0})))
    r = ev.score_capture(db, cap)
    assert r["flows"] == 11 and r["attack_flows"] == 3
    rules, vae = r["detectors"]["Rule baseline"], r["detectors"]["VAE"]
    assert rules["flow"]["recall"] == 1.0 and rules["flow"]["precision"] == 1.0 and rules["attacker"]["attackers_found"] == 1
    assert vae["flow"]["tp"] == 0 and vae["flow"]["fp"] == 4 and vae["attacker"]["flagged_normal"] == ["192.168.137.20"]
    later = ev.score_capture(db, cap, since=T0 + timedelta(minutes=5))   # only flows from 11:05 on
    assert later["flows"] == 4 and later["scored_from"].startswith("2026-11-25T11:05")
    assert "| Rule baseline | 1 | 100.0 % | 100.0 % |" in ev.render([r])
    db.execute("DELETE FROM alerts WHERE evidence->>'capture' = %s", (cap,))


def test_unlabelled_live_data_is_refused(db):
    cap = "cap-eval-live"
    db.execute("INSERT INTO captures (capture_id, start_ts, kind) VALUES (%s, %s, 'live') ON CONFLICT DO NOTHING",
               (cap, T0))
    db.execute("INSERT INTO flows (flow_id, ts_start, capture_id, src_ip, dst_ip, proto) "
               "VALUES ('L1', %s, %s, '10.0.0.1', '10.0.0.2', 'tcp')", (T0, cap))
    with pytest.raises(ValueError, match="no labels"):
        ev.score_capture(db, cap)
