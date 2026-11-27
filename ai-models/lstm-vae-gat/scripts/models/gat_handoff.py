"""
GAT -> team back end + LLM/RAG hand-off (Graduation-Project-Aegex on GitHub).

Runs a trained temporal GAT bundle exactly as trained and evaluated (same inputs, normalisation, thresholds; the
model is NOT changed or retrained) on 60 s graph snapshots, groups its alerts into incidents and writes them in
the two formats the team's code reads:

  detections.json       the LLM/RAG contract (ai-models/threat-intel/llm-rag/examples/detections.json):
                        {"detections": [{id, attack_type, source, target, detected_at, evidence{...}}]}
                        -> python report.py --detections detections.json
  attack_analyses.json  rows for the back end's PostgreSQL table `attack_analyses` (aegex/storage/postgres_store.py:
                        batch_id, ts, category, severity, confidence, src_ips, entry_vector, honeypot, signals,
                        mitre, ground_truth). Rows there feed GET /api/v1/attacks, /attacks/summary and the
                        blue-team report (/api/v1/reports). --postgres-url inserts them directly (idempotent on
                        batch_id, like the back end's own writes).
  alerts.json           rows for the newer back end's `alerts` table (backend/, database/schema_v2.sql, contract
                        alert_format): model_name temporal_gat, entity = attack source host, score = P(source),
                        predicted_scenario in the contract's names, attention_edges = the flagged links.
                        `python -m detect <pcap> --normal <pcap> --gat` in backend/ saves them.
  incidents.csv         one row per incident for people

What the GAT gives and what it does not
  GAT          P(host is an attack source), P(host is an attack target), P(link carries attack) per snapshot.
               An incident = a source host flagged in consecutive snapshots (gap <= --merge-gap) + its flagged links.
  attack type  the GAT does NOT classify attack types. `category` / `attack_type` come from a transparent
               behaviour rule on the incident's links (telnet fan-out -> mirai_botnet, many new ports / targets
               -> vulnerability_scanning, very high flow volume to few targets -> ddos, else anomalous_traffic).
               evidence.attack_type_from says so, so the report never presents it as a model output.
  severity     base severity of the category in the back end's CATEGORY_PROFILE (copied below).

Inputs (pick one)
  --capture-dir DIR     output folder of score_traffic.py (graph_edges.parquet, graph_nodes.parquet, run.json);
                        score_traffic.py --gat <bundle> calls this automatically
  --dataset DS          preprocessed graphs of a dataset (offline test; same code path as train_gat.py)

Usage:
    python gat_handoff.py --gat ..\\..\\models\\gat\\gat_v5 --dataset gotham --split test --out ..\\..\\handoff\\gotham
    python gat_handoff.py --gat ..\\..\\models\\gat\\gat_v5 --capture-dir ..\\..\\live_results\\my_capture --network gotham
"""
import argparse
import hashlib
import ipaddress
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import numpy as np
import pandas as pd

import aegex_gat as ag
import aegex_models as am
from aegex_models import ap
import train_gat as tg

# back end: aegex/intel/knowledge_base.py CATEGORY_PROFILE (severity + MITRE ATT&CK per category)
CATEGORY = {
    "vulnerability_scanning": {"severity": "low", "mitre": ["T1595.002"], "rag_label": "Port_Scanning"},
    "ddos": {"severity": "high", "mitre": ["T1498"], "rag_label": "DDoS"},
    "mirai_botnet": {"severity": "high", "mitre": ["T1110.001", "T1078.001", "T1105", "T1059.004"], "rag_label": "Mirai"},
    "ransomware": {"severity": "critical", "mitre": ["T1486", "T1490", "T1059.004"], "rag_label": "Ransomware"},
    "anomalous_traffic": {"severity": "medium", "mitre": [], "rag_label": "Suspicious_traffic"},
}
# backend/ (database/schema_v2.sql `alerts`, contracts/TASK_B_CONTRACT.md) scenario names
CONTRACT_SCENARIO = {"vulnerability_scanning": "vulnerability_scanning", "ddos": "dos", "mirai_botnet": "mirai_botnet",
                     "ransomware": "ransomware", "anomalous_traffic": "other"}
FEATURE_VERSION = "lstm-vae-gat"          # what backend/detect.py registers for the AI team's models
# our dataset attack classes -> back-end categories (ground_truth column, evaluation only)
TRUTH = {"scanning": "vulnerability_scanning", "mirai": "mirai_botnet", "ddos": "ddos", "ransomware": "ransomware"}
TYPE_COLS = ["svc_telnet", "log_dev_new_ports_60s", "log_dev_new_peers_60s", "fwd_syn", "log_fwd_pkts", "n_flows"]


def log(*a):
    print(time.strftime("%H:%M:%S"), *a, flush=True)


# ------------------------------------------------------------------------------------------ model
def load_gat(gdir, dev):
    b = am.ModelBundle.load(gdir, device=dev)
    meta = b.meta
    if meta.get("relative_inputs"):
        raise SystemExit("this bundle uses --relative-inputs; the hand-off supports the quoted bundles (gat_v5 and "
                         "earlier). Re-run with such a bundle.")
    norm = tuple(np.asarray(meta["norm"][k], np.float32) for k in ("node_mean", "node_std", "edge_mean", "edge_std"))
    b.model.eval()
    return b.model, meta, norm


def thresholds_for(meta, network, node_thr=None, edge_thr=None):
    known = network in meta.get("per_dataset_thresholds", {})
    t = node_thr if node_thr is not None else float(meta["per_dataset_thresholds"][network] if known else meta["threshold"])
    et = meta["edge_thresholds"]
    e = edge_thr if edge_thr is not None else float(et.get(network, et["_all"]))
    return t, e, known or node_thr is not None


def mask(seqs, meta):
    tg.mask_edge_features({"x": seqs}, meta.get("dropped_edge_features", []))


# ------------------------------------------------------------------------------------------ inputs
def dataset_inputs(meta, ds, split, dev):
    up = meta["upstream_per_dataset"].get(ds) if meta.get("upstream_per_dataset") else meta["upstream"]
    if up is None:
        raise SystemExit(f"bundle has no LSTM/VAE chain for '{ds}' (chains: {list(meta['upstream_per_dataset'])})")
    ch = tg.Chain(up["lstm_run"], up["vae_run"], dev, {})
    seqs = tg.dataset_sequences(ds, ch.lstm_run, ch.vae_run, int(meta["vae_latent"]),
                                ch if meta.get("relative_scores") else None)[split]
    gdir = os.path.join(am.PREPROCESSED, "graphs", ds)
    caps = {s["meta"]["capture"] for s in seqs}
    edges = pd.concat([pd.read_parquet(os.path.join(gdir, f"{c}_edges.parquet")).assign(capture=c) for c in caps])
    nodes = pd.concat([pd.read_parquet(os.path.join(gdir, f"{c}_nodes.parquet"), columns=["snapshot", "node", "t_start"])
                       .assign(capture=c) for c in caps])
    return seqs, edges, nodes


def capture_inputs(meta, cdir):
    """score_traffic.py output -> one GAT sequence. Stage scores are divided by the alarm lines that run used
    (= --relative-scores of the training), so the GAT sees exactly the inputs it was trained on."""
    run = json.load(open(os.path.join(cdir, "run.json")))
    E = pd.read_parquet(os.path.join(cdir, "graph_edges.parquet"))
    N = pd.read_parquet(os.path.join(cdir, "graph_nodes.parquet"))
    if meta.get("relative_scores"):
        for c, t in (("lstm_max_score", run["threshold"]), ("lstm_mean_score", run["threshold"]),
                     ("vae_max_score", run.get("vae_threshold")), ("vae_mean_score", run.get("vae_threshold"))):
            if c in N and t:
                N[c] = N[c] / float(t)
    for c in ("out_attack", "in_attack"):          # live traffic has no labels
        if c not in N:
            N[c] = 0
    if "n_attack" not in E:
        E["n_attack"] = 0
    name = os.path.basename(os.path.normpath(cdir))
    seq = ag.snapshot_sequence(E, N, None, int(meta["vae_latent"]), name,
                               {"dataset": "live", "source": "capture", "capture": name})
    return [seq], E.assign(capture=name), N[["snapshot", "node", "t_start"]].assign(capture=name)


# ------------------------------------------------------------------------------------------ incidents
def attack_type(L):
    """Behaviour rule on an incident's links (NOT a model output)."""
    w = L.n_flows.to_numpy(float)
    wm = lambda c: float(np.average(L[c], weights=w)) if c in L and w.sum() else 0.0  # noqa: E731
    n_tgt, flows = L.dst.nunique(), float(w.sum())
    per_snap = flows / max(L.snapshot.nunique(), 1)
    n_snap = L.snapshot.nunique()
    sig = []
    if wm("svc_telnet") >= 0.3:
        sig = ["telnet_fan_out" if n_tgt >= 3 else "telnet_traffic"]; cat = "mirai_botnet"
    elif n_tgt >= 10 or wm("log_dev_new_ports_60s") >= np.log1p(10):
        sig = ["many_targets_or_new_ports"]; cat = "vulnerability_scanning"
    elif per_snap >= 300 and n_tgt <= 3:
        sig = ["high_flow_volume_to_few_targets"]; cat = "ddos"
    elif n_tgt <= 2 and n_snap >= 5 and per_snap < 50:
        sig = ["persistent_low_volume_beaconing"]; cat = "mirai_botnet"   # bot -> C2 heartbeat
    else:
        cat = "anomalous_traffic"
    return cat, sig, {"targets": int(n_tgt), "flows": int(flows), "flows_per_snapshot": round(per_snap, 1),
                      "telnet_share": round(wm("svc_telnet"), 3), "syn_share": round(wm("fwd_syn"), 3)}


def incidents(Nn, Ee, links, times, thr, ethr, merge_gap, snap_s):
    """Flagged source hosts -> incidents (consecutive snapshots merged) with their flagged links as targets."""
    Nn = Nn.merge(times, on=["capture", "snapshot", "node"], how="left")
    src = Nn[Nn.p_source >= thr].sort_values(["capture", "node", "snapshot"])
    out = []
    for (cap, host), g in src.groupby(["capture", "node"], sort=False):
        brk = (g.snapshot.diff().fillna(0) > merge_gap + 1).cumsum()
        for _, run in g.groupby(brk):
            s0, s1 = int(run.snapshot.min()), int(run.snapshot.max())
            e = Ee[(Ee.capture == cap) & (Ee.src == host) & Ee.snapshot.between(s0, s1)]
            fe = e[e.p_edge >= ethr]
            if not len(fe):
                fe = e.sort_values("p_edge", ascending=False).head(3)
            L = links[(links.capture == cap) & (links.src == host) & links.snapshot.between(s0, s1)]
            L = L.merge(fe[["snapshot", "dst"]], on=["snapshot", "dst"]) if len(fe) else L.iloc[:0]
            tgt = (fe.groupby("dst").p_edge.max().sort_values(ascending=False) if len(fe) else pd.Series(dtype=float))
            tn = Nn[(Nn.capture == cap) & Nn.snapshot.between(s0, s1) & Nn.node.isin(tgt.index)]
            cat, sig, beh = attack_type(L)
            truth = None
            if "edge_class" in L and (L.edge_class != "benign").any():
                truth = TRUTH.get(L[L.edge_class != "benign"].edge_class.mode().iat[0])
            t_start = run.t_start.min()
            out.append({"capture": cap, "source": host, "snapshot_first": s0, "snapshot_last": s1,
                        "first_seen": t_start, "last_seen": run.t_start.max() + snap_s,
                        "p_source": float(run.p_source.max()), "p_target": float(tn.p_target.max()) if len(tn) else None,
                        "p_link": float(tgt.max()) if len(tgt) else None, "targets": list(tgt.index[:20]),
                        "target_links": [[str(d), round(float(pv), 4)] for d, pv in tgt.head(20).items()],
                        "n_flagged_links": int((e.p_edge >= ethr).sum()), "category": cat, "type_signals": sig,
                        "behaviour": beh, "lstm_max": float(run.lstm_max_score.max()) if "lstm_max_score" in run else None,
                        "vae_max": float(run.vae_max_score.max()) if "vae_max_score" in run else None,
                        "stage12": bool(run.baseline.max()) if "baseline" in run else None, "ground_truth": truth})
    return out


def is_ip(x):
    try:
        ipaddress.ip_address(str(x))
        return True
    except ValueError:                   # e.g. the EXTERNAL node (merged one-peer public hosts)
        return False


def iso(t):
    return pd.to_datetime(t, unit="s", utc=True).strftime("%Y-%m-%dT%H:%M:%SZ") if t is not None and np.isfinite(t) else None


def to_outputs(incs, run_name, thr, ethr, calibrated, relative, snap_s=60.0):
    dets, rows, alerts = [], [], []
    for i in incs:
        key = f"{run_name}|{i['capture']}|{i['source']}|{i['snapshot_first']}"
        bid = "gat-" + hashlib.sha1(key.encode()).hexdigest()[:16]
        prof = CATEGORY[i["category"]]
        conf = round(min(0.99, i["p_source"]), 2)
        signals = ["gat_attack_source"] + (["gat_attack_link"] if i["n_flagged_links"] else []) + \
                  (["lstm_or_vae_anomaly"] if i["stage12"] else []) + i["type_signals"]
        target = i["targets"][0] if i["targets"] else "unknown"
        ev = {"graph_probability": round(i["p_source"], 4), "source_probability": round(i["p_source"], 4),
              "target_probability": None if i["p_target"] is None else round(i["p_target"], 4),
              "link_probability": None if i["p_link"] is None else round(i["p_link"], 4),
              "graph_threshold": round(thr, 4), "link_threshold": round(ethr, 4),
              "verdict": "both layers agree" if i["stage12"] else "graph layer only (LSTM-AE / VAE did not flag the source)",
              "threshold_calibrated_for_network": calibrated,
              "targets": i["targets"], "flagged_links": i["n_flagged_links"],
              "first_seen": iso(i["first_seen"]), "last_seen": iso(i["last_seen"]),
              "snapshots": i["snapshot_last"] - i["snapshot_first"] + 1, "capture": i["capture"],
              "category": i["category"], "attack_type_from": "behaviour rule on the flagged links (the GAT does not classify attack types)",
              "behaviour": i["behaviour"], "model": run_name}
        if i["lstm_max"] is not None and relative:
            # stage-1 score as score / alarm line (1.0 = on the line). The RAG question builder quotes
            # reconstruction_error vs threshold when both exist, so they are only set when stage 1 flagged the
            # source; otherwise it quotes the GAT probability.
            ev["lstm_score_vs_alarm_line"] = round(i["lstm_max"], 4)
            if i["vae_max"] is not None:
                ev["vae_score_vs_alarm_line"] = round(i["vae_max"], 4)
            if i["lstm_max"] >= 1.0:
                ev["reconstruction_error"], ev["threshold"] = round(i["lstm_max"], 4), 1.0
        dets.append({"id": bid, "attack_type": prof["rag_label"], "source": i["source"], "target": target,
                     "detected_at": iso(i["first_seen"]), "evidence": ev})
        rows.append({"batch_id": bid, "ts": iso(i["first_seen"]), "category": i["category"], "severity": prof["severity"],
                     "confidence": conf, "src_ips": [i["source"]], "entry_vector": "unknown",
                     "honeypot": str(target)[:32], "signals": signals, "mitre": prof["mitre"],
                     "ground_truth": i["ground_truth"]})
        # backend/ `alerts` table (contracts/feature_contract.json -> alert_format); one row per incident
        alerts.append({"alert_key": bid, "model_name": "temporal_gat", "model_version": run_name,
                       "feature_version": FEATURE_VERSION, "entity_type": "device", "entity_id": i["source"],
                       "device_id": None, "src_ips": [i["source"]] if is_ip(i["source"]) else [], "window_start": iso(i["first_seen"]),
                       "window_end": iso(i["last_seen"]), "score": round(i["p_source"], 4), "threshold": round(thr, 4),
                       "is_anomaly": True, "predicted_scenario": CONTRACT_SCENARIO[i["category"]],
                       "severity": prof["severity"],
                       "evidence": {**ev, "capture": i["capture"], "rag_attack_type": prof["rag_label"],
                                    "mitre": prof["mitre"], "signals": signals,
                                    "attention_edges": [{"src": i["source"], "dst": d, "p_link": pv}
                                                        for d, pv in i["target_links"]],
                                    "predicted_scenario_from": "behaviour rule on the flagged links (not the GAT)"}})
    return dets, rows, alerts


def write_postgres(rows, url):
    from sqlalchemy import create_engine, text   # same driver stack as the back end
    sql = text("""INSERT INTO attack_analyses (batch_id, ts, category, severity, confidence, src_ips, entry_vector,
                  honeypot, signals, mitre, ground_truth) VALUES (:batch_id, :ts, :category, :severity, :confidence,
                  CAST(:src_ips AS jsonb), :entry_vector, :honeypot, CAST(:signals AS jsonb), CAST(:mitre AS jsonb),
                  :ground_truth) ON CONFLICT (batch_id) DO NOTHING""")
    eng = create_engine(url, future=True)
    with eng.begin() as c:
        for r in rows:
            c.execute(sql, {**r, **{k: json.dumps(r[k]) for k in ("src_ips", "signals", "mitre")}})
    log(f"inserted up to {len(rows)} rows into attack_analyses")


# ------------------------------------------------------------------------------------------ main
def run_handoff(gdir, out, dataset=None, split="test", capture_dir=None, network=None, node_thr=None, edge_thr=None,
                merge_gap=2, postgres_url=None, device="auto"):
    dev = am.pick_device(device)
    model, meta, norm = load_gat(gdir, dev)
    if dataset:
        seqs, links, times = dataset_inputs(meta, dataset, split, dev)
        network = network or dataset
    else:
        seqs, links, times = capture_inputs(meta, capture_dir)
    mask(seqs, meta)
    thr, ethr, calibrated = thresholds_for(meta, network, node_thr, edge_thr)
    if not calibrated:
        log(f"WARNING: '{network}' is not a network {meta['run']} trained on -> pooled threshold {thr:.4f}. The GAT "
            "does not transfer to unseen networks (results page); expect many false alarms.")
    Nn, Ee = tg.collect(model, seqs, norm, dev, meta["node_blocks"], int(meta["vae_latent"]))
    Nn["capture"] = Nn.seq.map({s["name"]: s["meta"].get("capture") for s in seqs})
    Ee["capture"] = Ee.seq.map({s["name"]: s["meta"].get("capture") for s in seqs})
    # stage-1/2 scores of each host for the evidence
    st = []
    for s in seqs:
        fc = s["feat_cols"]
        li, vi = fc.index("lstm_max_score"), fc.index("vae_max_score")
        for sn in s["snaps"]:
            st.append(pd.DataFrame({"capture": s["meta"].get("capture"), "snapshot": sn["snapshot"],
                                    "node": np.array(s["hosts"], dtype=object)[sn["nid"]],
                                    "lstm_max_score": np.expm1(sn["x"][:, li]), "vae_max_score": np.expm1(sn["x"][:, vi])}))
    Nn = Nn.merge(pd.concat(st).drop_duplicates(["capture", "snapshot", "node"]), on=["capture", "snapshot", "node"], how="left")
    snap_s = float(meta.get("snapshot_seconds", 60))
    incs = incidents(Nn, Ee, links, times, thr, ethr, merge_gap, snap_s)
    dets, rows, alerts = to_outputs(incs, meta["run"], thr, ethr, calibrated, bool(meta.get("relative_scores")), snap_s)
    os.makedirs(out, exist_ok=True)
    json.dump({"_comment": f"Written by gat_handoff.py from GAT bundle {meta['run']} (LLM/RAG contract: "
                           "ai-models/threat-intel/llm-rag/examples/detections.json).", "detections": dets},
              open(os.path.join(out, "detections.json"), "w"), indent=1)
    json.dump(rows, open(os.path.join(out, "attack_analyses.json"), "w"), indent=1)
    json.dump(alerts, open(os.path.join(out, "alerts.json"), "w"), indent=1)
    if incs:
        pd.DataFrame([{**{k: v for k, v in i.items() if k not in ("behaviour", "targets", "type_signals")},
                       "targets": " ".join(map(str, i["targets"][:5])), "first_seen": iso(i["first_seen"]),
                       "last_seen": iso(i["last_seen"])} for i in incs]).to_csv(os.path.join(out, "incidents.csv"), index=False)
    host_flag = (Nn.p_involved >= thr)
    summary = {"gat_run": meta["run"], "network": network, "threshold": thr, "edge_threshold": ethr,
               "threshold_calibrated_for_network": calibrated, "snapshots": int(Nn.snapshot.nunique()),
               "host_snapshots": int(len(Nn)), "flagged_host_snapshots": int(host_flag.sum()), "incidents": len(incs),
               "by_category": pd.Series([i["category"] for i in incs]).value_counts().to_dict() if incs else {}}
    if dataset:   # labelled data: the same detection / false-alarm numbers as train_gat.py's dataset test split
        inv = Nn.y_involved == 1
        summary.update({"host_detection": tg.rate(host_flag[inv]), "host_false_alarms": tg.rate(host_flag[~inv]),
                        "incidents_with_true_source": int(sum(i["ground_truth"] is not None for i in incs)),
                        "attack_type_rule_matches_truth": tg.rate([i["category"] == i["ground_truth"] for i in incs
                                                                   if i["ground_truth"]])})
    json.dump(summary, open(os.path.join(out, "handoff_summary.json"), "w"), indent=1, default=float)
    log(json.dumps(summary, default=float))
    if postgres_url:
        write_postgres(rows, postgres_url)
    return summary


def main():
    a = argparse.ArgumentParser()
    a.add_argument("--gat", required=True, help="GAT bundle directory (e.g. models/gat/gat_v5)")
    src = a.add_mutually_exclusive_group(required=True)
    src.add_argument("--dataset", help="preprocessed dataset (offline test)")
    src.add_argument("--capture-dir", help="score_traffic.py output folder")
    a.add_argument("--split", default="test", choices=["train", "val", "test"])
    a.add_argument("--network", help="which training network this traffic is from (selects its GAT threshold)")
    a.add_argument("--threshold", type=float, help="override the node threshold (e.g. calibrated on this network)")
    a.add_argument("--edge-threshold", type=float)
    a.add_argument("--merge-gap", type=int, default=2, help="snapshots without an alert that still join one incident")
    a.add_argument("--out", default=os.path.join(am.DATA_ROOT, "handoff"))
    a.add_argument("--postgres-url", help="also insert into the back end's attack_analyses table")
    a.add_argument("--device", default="auto")
    args = a.parse_args()
    run_handoff(args.gat, args.out, args.dataset, args.split, args.capture_dir, args.network, args.threshold,
                args.edge_threshold, args.merge_gap, args.postgres_url, args.device)


if __name__ == "__main__":
    main()
