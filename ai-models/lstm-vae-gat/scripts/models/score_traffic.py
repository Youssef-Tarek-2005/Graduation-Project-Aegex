"""
Score REAL traffic (e.g. a pcap captured on the Aegex honeypot network) with a trained LSTM-AE.

The capture goes through exactly the same code as the training datasets:
    pcap -> FlowBuilder flows -> 45 features -> robust scaling -> per-device windows -> LSTM-AE
         -> also: 60 s graph snapshots (same builder as step 3) with the LSTM scores attached per node,
            ready for the GAT stage

Scaling - pick ONE:
    --calibrate normal.pcap     fit the scaler on a capture of THIS network's normal traffic (recommended
                                for a new network; this is what the training data had: every dataset was
                                scaled on its own benign traffic). Add --recalibrate-threshold to also set
                                the alarm threshold from that normal capture.
    --reference-scaler edge     reuse a training dataset's scaler stored in the model bundle

Outputs (in --out/<capture name>/):
    flows.parquet               unified flow table (same schema as preprocessed/flows)
    windows.parquet             one row per window: LSTM-AE columns (+ VAE columns with --vae)
    lstm_node_snapshots.parquet, vae_node_snapshots.parquet   stage outputs per device per snapshot
    graph_edges.parquet, graph_nodes.parquet   GAT snapshots; graph_nodes already joined with every stage
    alerts.csv                  windows flagged by any stage: device, time, scores, worst features,
                                VAE confidence, closest known class, zero-day candidate
    run.json                    what was used (bundles, scaler, thresholds, counts)
    handoff/                    with --gat: GAT incidents as detections.json (LLM/RAG) + attack_analyses.json
                                (back end table), see gat_handoff.py

Usage:
    python score_traffic.py <capture.pcap|.pcapng|.zip> --model ..\\..\\models\\lstm_ae\\lstm_ae_v8
                            [--vae ..\\..\\models\\vae\\vae_v3]
                            (--calibrate normal.pcap [--recalibrate-threshold [--per-device]] | --reference-scaler edge)
                            [--member "path inside zip"] [--out ..\\..\\live_results]
"""
import argparse
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import numpy as np
import pandas as pd

import aegex_models as am
from aegex_models import ap, s3


def log(*a):
    print(time.strftime("%H:%M:%S"), *a, flush=True)


def main():
    a = argparse.ArgumentParser()
    a.add_argument("capture")
    a.add_argument("--model", required=True, help="LSTM-AE bundle directory")
    a.add_argument("--vae", help="VAE bundle directory (trained on this LSTM-AE); adds stage-2 outputs")
    g = a.add_mutually_exclusive_group(required=True)
    g.add_argument("--calibrate", help="pcap of this network's normal traffic")
    g.add_argument("--reference-scaler", help="dataset name whose scaler (stored in the bundle) to use")
    a.add_argument("--recalibrate-threshold", action="store_true")
    a.add_argument("--per-device", action="store_true",
                   help="with --calibrate --recalibrate-threshold: also give each device with >= "
                        f"{am.MIN_DEVICE_WINDOWS} calibration windows its own threshold (never below the network one)")
    a.add_argument("--member", help="file inside a zip archive")
    a.add_argument("--calibrate-member")
    a.add_argument("--name", help="capture name (default: file name)")
    a.add_argument("--out", default=os.path.join(am.DATA_ROOT, "live_results"))
    a.add_argument("--device", default="auto")
    a.add_argument("--gat", help="GAT bundle directory: also run the GAT and write the team hand-off files "
                                 "(detections.json for the LLM/RAG, attack_analyses.json for the back end)")
    a.add_argument("--gat-network", help="training network this traffic is from (selects the GAT threshold)")
    a.add_argument("--postgres-url", help="with --gat: insert the GAT incidents into the back end's attack_analyses")
    args = a.parse_args()
    if args.per_device and not (args.calibrate and args.recalibrate_threshold):
        a.error("--per-device needs --calibrate <normal capture> and --recalibrate-threshold")
    dev_thr = {}

    dev = am.pick_device(args.device)
    bundle = am.ModelBundle.load(args.model, device=dev)
    meta, T = bundle.meta, int(bundle.meta["window"])
    thr = bundle.threshold
    name = args.name or os.path.splitext(os.path.basename(args.member or args.capture))[0].replace(" ", "_")
    out = os.path.join(args.out, name)
    os.makedirs(out, exist_ok=True)
    run = {"capture": args.capture, "member": args.member, "model": os.path.abspath(args.model),
           "model_run": meta["run"], "started": am.now_iso()}
    vb = vmeta = None
    if args.vae:
        vb = am.ModelBundle.load(args.vae, device=dev)
        am.check_vae_matches_lstm(vb.meta, args.model)
        vmeta = dict(vb.meta)                     # may be recalibrated below
        run["vae_run"] = vmeta["run"]

    # ---------------------------------------------------------------- scaler
    if args.calibrate:
        log(f"calibrating scaler on normal traffic: {args.calibrate}")
        _, cal_feat, cal_st = am.traffic_to_inputs(args.calibrate, "calibration", None, member=args.calibrate_member, log=log)
        scaler = am.fit_scaler_on(cal_feat)
        run["scaler"] = {"source": "calibration capture", "file": args.calibrate, "flows": cal_st["flows"]}
        if args.recalibrate_threshold:
            cal_feat = scaler.transform(cal_feat).sort_values(["device", "ts"], kind="stable").reset_index(drop=True)
            cw = s3.windows_for(cal_feat, "calibration", T, int(meta["stride"]))
            Fc = cal_feat[ap.FEATURES].to_numpy(np.float32)
            ce = am.score_windows(bundle.model, Fc, cw, T, dev, score_agg=am.score_agg_of(bundle.meta))
            thr = float(np.quantile(ce.lstm_error, 0.99))
            run["threshold_source"] = f"99th pct of {len(cw):,} calibration windows"
            if args.per_device:
                dev_thr["lstm"] = am.device_thresholds(ce.device, ce.lstm_error, thr)
            if vb is not None:   # recalibrate the VAE threshold + confidence reference on the same normal traffic
                verr, _ = am.vae_score_windows(vb, ce, Fc, cw, dev, vmeta)
                vmeta["threshold"] = float(np.quantile(verr, 0.99))
                vmeta["benign_reference_scores"] = [float(v) for v in np.quantile(verr, np.linspace(0, 1, min(len(verr), 5000)))]
                run["vae_threshold_source"] = f"99th pct of {len(cw):,} calibration windows"
                if args.per_device:
                    dev_thr["vae"] = am.device_thresholds(ce.device, verr, vmeta["threshold"])
            if args.per_device:
                run["per_device_thresholds"] = dev_thr
                log(f"per-device thresholds for {len(dev_thr['lstm'])} devices "
                    f"(>= {am.MIN_DEVICE_WINDOWS} calibration windows); raised above the network threshold: "
                    f"LSTM {sum(t > thr for t in dev_thr['lstm'].values())}"
                    + (f", VAE {sum(t > vmeta['threshold'] for t in dev_thr['vae'].values())}" if vb is not None else ""))
    else:
        if args.reference_scaler not in meta["scalers"]:
            raise SystemExit(f"bundle has scalers for {list(meta['scalers'])}")
        scaler = ap.RobustScaler.from_dict(meta["scalers"][args.reference_scaler])
        run["scaler"] = {"source": "bundle", "dataset": args.reference_scaler}
    run["threshold"] = thr

    # ---------------------------------------------------------------- traffic -> model inputs
    log(f"reading {args.capture}" + (f" [{args.member}]" if args.member else ""))
    flows, feat, st = am.traffic_to_inputs(args.capture, name, scaler, member=args.member, log=log)
    run["capture_stats"] = st
    am.write_output(flows, os.path.join(out, "flows.parquet"))
    W = s3.windows_for(feat, name, T, int(meta["stride"]))
    F = feat[ap.FEATURES].to_numpy(np.float32)
    S = am.score_windows(bundle.model, F, W, T, dev, threshold=thr, score_agg=am.score_agg_of(bundle.meta))
    S = S.drop(columns=[c for c in ("label", "window_class", "attack_frac", "n_attack", "split", "split_pure",
                                    "device_compromised") if c in S.columns])
    if dev_thr:
        S = am.apply_device_thresholds(S, dev_thr)
    t0 = feat.ts.min()
    node_tables = [am.node_snapshot_table(S, t0, meta["snapshot_seconds"], stage="lstm")]
    if vb is not None:
        verr, vmu = am.vae_score_windows(vb, S, F, W, dev, vmeta)
        S = pd.concat([S, am.vae_outputs(vmeta, verr, vmu)], axis=1)
        if dev_thr:
            S = am.apply_device_thresholds(S, dev_thr)
        node_tables.append(am.node_snapshot_table(S, t0, meta["snapshot_seconds"], stage="vae", latent_prefix="mu_",
                                                  extra_max=("zero_day_candidate", "vae_confidence")))
    am.write_output(S, os.path.join(out, "windows.parquet"))
    for t, stage in zip(node_tables, ["lstm", "vae"]):
        am.write_output(t, os.path.join(out, f"{stage}_node_snapshots.parquet"))

    # ---------------------------------------------------------------- GAT snapshots + stage outputs on the nodes
    edges, nodes = s3.graphs_for(feat, meta["snapshot_seconds"])
    nodes = am.attach_to_graph_nodes(nodes, *node_tables)
    am.write_output(edges, os.path.join(out, "graph_edges.parquet"))
    am.write_output(nodes, os.path.join(out, "graph_nodes.parquet"))

    # ---------------------------------------------------------------- alerts (any stage)
    flag = S.lstm_anomaly == 1
    if vb is not None:
        flag |= S.vae_anomaly == 1
    al = S[flag].sort_values("t_start")
    alerts = pd.DataFrame({
        "device": al.device, "start_utc": pd.to_datetime(al.t_start, unit="s").dt.strftime("%Y-%m-%d %H:%M:%S"),
        "end_utc": pd.to_datetime(al.t_end, unit="s").dt.strftime("%Y-%m-%d %H:%M:%S"),
        "lstm_score": al.lstm_score.round(2), "flows_in_window": al.n_flows, "worst_features": al.lstm_top_features})
    if vb is not None:
        alerts["vae_score"] = al.vae_score.round(2)
        alerts["vae_confidence"] = al.vae_confidence.round(4)
        alerts["closest_known_class"] = al.vae_class_hint
        alerts["zero_day_candidate"] = al.zero_day_candidate
    alerts.to_csv(os.path.join(out, "alerts.csv"), index=False)
    run.update({"flows": len(flows), "devices": int(feat.device.nunique()), "windows": len(S),
                "anomalous_windows": int(flag.sum()), "lstm_anomalous": int(S.lstm_anomaly.sum()),
                "vae_anomalous": int(S.vae_anomaly.sum()) if vb is not None else None,
                "zero_day_candidates": int(S.zero_day_candidate.sum()) if vb is not None else None,
                "vae_threshold": vmeta["threshold"] if vb is not None else None,
                "devices_with_alerts": al.device.value_counts().head(20).to_dict(),
                "snapshots": int(edges.snapshot.nunique()) if len(edges) else 0, "finished": am.now_iso()})
    json.dump(run, open(os.path.join(out, "run.json"), "w"), indent=1, default=str)
    if args.gat:                                   # stage 3 + hand-off to the back end / LLM-RAG
        import gat_handoff
        gat_handoff.run_handoff(args.gat, os.path.join(out, "handoff"), capture_dir=out, network=args.gat_network,
                                postgres_url=args.postgres_url, device=args.device)
    log(f"{len(flows):,} flows | {len(S):,} windows | {run['anomalous_windows']:,} anomalous "
        f"({run['anomalous_windows'] / max(len(S), 1):.1%}) | results -> {out}")
    if len(al):
        log("devices with most anomalous windows: " + str(run["devices_with_alerts"]))


if __name__ == "__main__":
    main()
