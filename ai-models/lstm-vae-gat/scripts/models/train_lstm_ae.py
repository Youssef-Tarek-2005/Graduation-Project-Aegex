"""
Train + evaluate the stage-1 LSTM autoencoder, then export its outputs for the VAE / GAT stages.

  training data   BENIGN windows of the train split (split_pure only), every active dataset
                  sampled equally per epoch so one large dataset does not dominate
  early stopping  on BENIGN windows of the val split
  window score    --score-agg (default topk:4): mean of the 4 most unusual flows of the window, so a
                  few attack flows hidden among normal ones are not averaged away (v1-v7: mean)
  threshold       the 99th percentile (--fpr 0.01) of val-benign window scores
                  -> by construction ~1 % false alarms on normal traffic; no test data is used
  evaluation      TEST split windows (split_pure), per dataset: ROC-AUC, PR-AUC, detection rate
                  per attack class and false-alarm rate at the threshold
  export          every window of every split, scored, with latent vectors
                  -> preprocessed/model_outputs/lstm_ae/<run>/<dataset>_windows.parquet
                  -> preprocessed/model_outputs/lstm_ae/<run>/<dataset>_node_snapshots.parquet

Usage:
    python train_lstm_ae.py [--datasets kitsune edge iot23] [--run lstm_ae_v1] [--epochs 40]
                            [--hidden 64] [--latent 16] [--device auto|cpu|cuda]
"""
import argparse
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import numpy as np
import pandas as pd
import torch
from sklearn.metrics import average_precision_score, roc_auc_score

import aegex_models as am
from aegex_models import ap


def log(*a):
    print(time.strftime("%H:%M:%S"), *a, flush=True)


def load_capture_matrix(ds, cap):
    return pd.read_parquet(os.path.join(am.PREPROCESSED, "features", ds, f"{cap}.parquet"),
                           columns=ap.FEATURES).to_numpy(np.float32)


def collect(ds, W, window):
    """Materialise the given windows of one dataset as (X [n,T,F], M [n,T], capture [n])."""
    Xs, Ms, Cs = [], [], []
    for cap, wc in W.groupby("capture", sort=False):
        F = load_capture_matrix(ds, cap)
        for _, X, M in am.window_batches(F, wc.row_start.to_numpy(), wc.row_end.to_numpy(), window, 4096):
            Xs.append(X); Ms.append(M); Cs.append(np.full(len(X), cap, dtype=object))
        del F
    if not Xs:
        return (np.zeros((0, window, len(ap.FEATURES)), np.float32), np.zeros((0, window), bool),
                np.zeros(0, dtype=object))
    return np.concatenate(Xs), np.concatenate(Ms), np.concatenate(Cs)


def balanced_pick(caps, n, rng):
    """Sample n indices so every capture gets an equal share (captures = different networks / devices;
    without this the largest capture of a dataset dominates what 'normal' means)."""
    _, inv, counts = np.unique(caps, return_inverse=True, return_counts=True)
    p = 1.0 / counts[inv]
    return rng.choice(len(caps), min(n, len(caps)), replace=False, p=p / p.sum())


def batch_errors(model, X, M, device, how="mean", bs=2048):
    out = []
    with torch.no_grad():
        for b in range(0, len(X), bs):
            x, m = torch.from_numpy(X[b:b + bs]).to(device), torch.from_numpy(M[b:b + bs]).to(device)
            r, _ = model(x, m)
            out.append(am.aggregate_flow_errors(am.flow_errors(r, x, m), m, how).cpu().numpy())
    return np.concatenate(out) if out else np.zeros(0, np.float32)


def main():
    a = argparse.ArgumentParser()
    a.add_argument("--datasets", nargs="+", default=ap.ACTIVE_DATASETS)
    a.add_argument("--run", default="lstm_ae_v8")
    a.add_argument("--score-agg", default="topk:8", choices=am.SCORE_AGGS,
                   help="how per-flow errors become the window score (mean dilutes a few attack flows); "
                        "topk:8 was chosen on VAL-phase benchmark scenarios (select_score_agg.py)")
    a.add_argument("--threshold-mode", choices=["per_dataset", "global"], default="per_dataset",
                   help="per_dataset: each network gets the 99th pct of its OWN val normal traffic (what a "
                        "deployment does when it calibrates); global: one pooled threshold for all")
    a.add_argument("--epochs", type=int, default=40)
    a.add_argument("--patience", type=int, default=5)
    a.add_argument("--hidden", type=int, default=64)
    a.add_argument("--latent", type=int, default=16)
    a.add_argument("--layers", type=int, default=1)
    a.add_argument("--dropout", type=float, default=0.0)
    a.add_argument("--lr", type=float, default=1e-3)
    a.add_argument("--batch", type=int, default=256)
    a.add_argument("--per-dataset", type=int, default=20000, help="benign train windows per dataset per epoch")
    a.add_argument("--fpr", type=float, default=0.01, help="target false-alarm rate on val benign")
    a.add_argument("--threshold-weighting", choices=["window", "capture"], default="window",
                   help="window: every validation window counts once (robust); capture: every capture counts "
                        "equally (tiny captures with few windows can then dominate the threshold)")
    a.add_argument("--device", default="auto")
    a.add_argument("--seed", type=int, default=0)
    a.add_argument("--holdout", nargs="*", default=[], metavar="DATASET/CAPTURE",
                   help="captures removed from training+validation entirely; reported separately as "
                        "UNSEEN traffic (measures over-flagging of new normal traffic)")
    args = a.parse_args()
    holdout = {tuple(h.split("/", 1)) for h in args.holdout}
    torch.manual_seed(args.seed); rng = np.random.default_rng(args.seed)
    dev = am.pick_device(args.device)
    cfg = json.load(open(os.path.join(am.PREPROCESSED, "windows", "_config.json")))
    T = int(cfg["window"])
    log(f"device {dev} | datasets {args.datasets} | window {T}")

    # ---------------------------------------------------------------- data
    Wall = {ds: pd.read_parquet(os.path.join(am.PREPROCESSED, "windows", f"{ds}.parquet")) for ds in args.datasets}
    train, val = {}, {}
    for ds, W in Wall.items():
        seen = ~W.capture.isin([c for d, c in holdout if d == ds])
        pure_benign = W[seen & W.split_pure & (W.label == 0) & (W.device_compromised == 0)]   # clean benign only
        train[ds] = collect(ds, pure_benign[pure_benign.split == "train"], T)
        val[ds] = collect(ds, pure_benign[pure_benign.split == "val"], T)
        log(f"[{ds}] benign windows: train {len(train[ds][0]):,} | val {len(val[ds][0]):,}")
    Xv = np.concatenate([v[0] for v in val.values()]); Mv = np.concatenate([v[1] for v in val.values()])
    val_caps = np.concatenate([np.char.add(f"{ds}/", v[2].astype(str)) for ds, v in val.items()])

    # ---------------------------------------------------------------- model
    model = am.LSTMAutoencoder(len(ap.FEATURES), args.hidden, args.latent, args.layers, args.dropout).to(dev)
    opt = torch.optim.Adam(model.parameters(), lr=args.lr)
    best, best_state, bad, history = np.inf, None, 0, []
    for ep in range(1, args.epochs + 1):
        t0 = time.time()
        # equal share per dataset each epoch, and inside a dataset equal share per capture
        idx = [(ds, balanced_pick(train[ds][2], args.per_dataset, rng)) for ds in args.datasets if len(train[ds][0])]
        X = np.concatenate([train[ds][0][i] for ds, i in idx]); M = np.concatenate([train[ds][1][i] for ds, i in idx])
        perm = rng.permutation(len(X))
        model.train(); tot = 0.0
        for b in range(0, len(perm), args.batch):
            j = perm[b:b + args.batch]
            x, m = torch.from_numpy(X[j]).to(dev), torch.from_numpy(M[j]).to(dev)
            r, _ = model(x, m)
            loss = am.masked_errors(r, x, m)[0].mean()
            opt.zero_grad(); loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            opt.step(); tot += loss.item() * len(j)
        model.eval()
        ve = batch_errors(model, Xv, Mv, dev)
        vloss = float(pd.Series(ve).groupby(val_caps).mean().mean())   # every capture counts equally
        history.append({"epoch": ep, "train_loss": tot / len(perm), "val_loss": vloss, "seconds": round(time.time() - t0, 1)})
        log(f"epoch {ep:3d}  train {tot / len(perm):.4f}  val {vloss:.4f}  ({time.time() - t0:.0f}s)")
        if vloss < best - 1e-5:
            best, bad = vloss, 0
            best_state = {k: v.detach().cpu().clone() for k, v in model.state_dict().items()}
        else:
            bad += 1
            if bad >= args.patience:
                log("early stop"); break
    model.load_state_dict(best_state); model.eval()

    # ---------------------------------------------------------------- threshold (val benign only)
    ev = batch_errors(model, Xv, Mv, dev, args.score_agg)
    q = (lambda v, g, p: am.balanced_quantile(v, g, p)) if args.threshold_weighting == "capture" else \
        (lambda v, g, p: float(np.quantile(v, p)))
    thr = q(ev, val_caps, 1 - args.fpr)
    per_ds_thr, thr_src = {}, {}
    for ds in args.datasets:
        if len(val[ds][0]) >= am.MIN_CALIBRATION_WINDOWS:
            per_ds_thr[ds] = q(batch_errors(model, val[ds][0], val[ds][1], dev, args.score_agg), val[ds][2], 1 - args.fpr)
            thr_src[ds] = f"val clean normal ({len(val[ds][0])} windows)"
        elif len(val[ds][0]) + len(train[ds][0]):
            # too little val normal traffic: use train + val (train windows score slightly low -> conservative)
            e = np.r_[batch_errors(model, train[ds][0], train[ds][1], dev, args.score_agg),
                      batch_errors(model, val[ds][0], val[ds][1], dev, args.score_agg)]
            per_ds_thr[ds] = float(np.quantile(e, 1 - args.fpr))
            thr_src[ds] = f"LOW CONFIDENCE: train+val clean normal ({len(e)} windows)"
    log(f"threshold {thr:.4f} (val-benign {100 * (1 - args.fpr):.0f}th percentile of {args.score_agg} window scores) "
        f"| per dataset {({k: round(v, 4) for k, v in per_ds_thr.items()})} | mode {args.threshold_mode}")
    del train, Xv, Mv

    # ---------------------------------------------------------------- bundle
    scalers = {ds: json.load(open(os.path.join(am.PREPROCESSED, "features", ds, "_scaler.json"))) for ds in args.datasets}
    meta = {"bundle_format": am.BUNDLE_FORMAT, "model_type": "lstm_autoencoder", "run": args.run,
            "created": am.now_iso(), "torch": torch.__version__, "train_datasets": args.datasets,
            "init": {"n_features": len(ap.FEATURES), "hidden": args.hidden, "latent": args.latent,
                     "layers": args.layers, "dropout": args.dropout},
            "window": T, "stride": int(cfg["stride"]), "snapshot_seconds": float(cfg["snapshot_seconds"]),
            "hparams": {"hidden": args.hidden, "latent": args.latent, "layers": args.layers, "dropout": args.dropout,
                        "lr": args.lr, "batch": args.batch, "per_dataset": args.per_dataset, "seed": args.seed},
            "score_agg": args.score_agg, "threshold_mode": args.threshold_mode, "per_dataset_threshold_source": thr_src,
            "threshold": thr, "threshold_rule": f"{args.threshold_weighting}-weighted quantile {1 - args.fpr} "
                                                f"of val clean-benign window scores ({args.score_agg} of per-flow errors)",
            "per_dataset_thresholds": per_ds_thr, "history": history,
            "pipeline": am.pipeline_fingerprint(), "scalers": scalers,
            "scaler_note": "inputs were scaled per dataset on its own benign traffic; for new traffic "
                           "calibrate on that network's benign traffic (score_traffic.py --calibrate)"}
    bdir = os.path.join(am.MODELS_DIR, "lstm_ae", args.run)
    am.ModelBundle(model, meta).save(bdir)
    log(f"saved bundle -> {bdir}")

    # ---------------------------------------------------------------- evaluate + export
    odir = os.path.join(am.PREPROCESSED, "model_outputs", "lstm_ae", args.run)
    rdir = os.path.join(am.DATA_ROOT, "model_results", "lstm_ae", args.run)
    os.makedirs(odir, exist_ok=True); os.makedirs(rdir, exist_ok=True)
    results, lines = {}, [f"LSTM autoencoder '{args.run}' - test-split evaluation", f"threshold {thr:.4f} "
                          f"(val-benign {100 * (1 - args.fpr):.0f}th pct; no test data used to set it)", ""]
    for ds, W in Wall.items():
        parts = []
        for cap, wc in W.groupby("capture", sort=False):
            F = load_capture_matrix(ds, cap)
            sc = am.score_windows(model, F, wc, T, dev, threshold=am.threshold_for(meta, ds), score_agg=args.score_agg)
            del F
            t0 = pd.read_parquet(os.path.join(am.PREPROCESSED, "features", ds, f"{cap}.parquet"), columns=["ts"]).ts.min()
            ns = am.node_snapshot_table(sc, t0, meta["snapshot_seconds"])
            parts.append((sc, ns))
        S = pd.concat([p[0] for p in parts], ignore_index=True)
        NS = pd.concat([p[1] for p in parts], ignore_index=True)
        am.write_output(S, os.path.join(odir, f"{ds}_windows.parquet"))
        am.write_output(NS, os.path.join(odir, f"{ds}_node_snapshots.parquet"))

        held = S.capture.isin([c for d, c in holdout if d == ds])
        if held.any():   # unseen captures: ALL their windows count (none were used in training)
            H = S[held]
            hb, ha = H[(H.label == 0) & (H.device_compromised == 0)], H[H.label == 1]
            results[f"{ds}_HELDOUT"] = {
                "captures": sorted(H.capture.unique()), "benign_windows": int(len(hb)),
                "false_alarm_rate_unseen_benign": float(hb.lstm_anomaly.mean()) if len(hb) else None,
                "attack_windows": int(len(ha)), "detection_rate_unseen": float(ha.lstm_anomaly.mean()) if len(ha) else None,
                "per_capture_false_alarms": {c: float(g.lstm_anomaly.mean()) for c, g in hb.groupby("capture")}}
            r = results[f"{ds}_HELDOUT"]
            lines += [f"== {ds} HELD-OUT (never seen in training): {', '.join(r['captures'])}",
                      f"   false alarms on unseen NORMAL traffic: {r['false_alarm_rate_unseen_benign']} "
                      f"({r['benign_windows']:,} windows) per capture {r['per_capture_false_alarms']}",
                      f"   detection on unseen attacks: {r['detection_rate_unseen']} ({r['attack_windows']:,} windows)", ""]
            log(f"[{ds}] HELD-OUT false alarms {r['false_alarm_rate_unseen_benign']} | detection {r['detection_rate_unseen']}")
        S = S[~held]
        te_all = S[(S.split == "test") & S.split_pure]
        # benign-labelled windows of compromised devices are neither clean normal nor labelled attack:
        # reported separately, excluded from ROC / false-alarm figures
        comp = te_all[(te_all.label == 0) & (te_all.device_compromised == 1)]
        te = te_all.drop(comp.index)
        y, s = te.label.to_numpy(), te.lstm_error.to_numpy()
        r = {"test_windows": int(len(te)), "attack_windows": int(y.sum()),
             "benign_on_compromised_windows": int(len(comp)),
             "benign_on_compromised_flagged": float(comp.lstm_anomaly.mean()) if len(comp) else None}
        if 0 < y.sum() < len(y):
            r["roc_auc"] = float(roc_auc_score(y, s)); r["pr_auc"] = float(average_precision_score(y, s))
        ben = te[te.label == 0]
        r["false_alarm_rate"] = float(ben.lstm_anomaly.mean()) if len(ben) else None
        r["detection_rate"] = float(te[te.label == 1].lstm_anomaly.mean()) if y.sum() else None
        r["per_class_detection"] = {c: {"windows": int(len(g)), "detected": float(g.lstm_anomaly.mean())}
                                    for c, g in te[te.label == 1].groupby("window_class")}
        r["false_alarms_per_capture"] = {c: {"windows": int(len(g)), "false_alarm_rate": float(g.lstm_anomaly.mean())}
                                         for c, g in ben.groupby("capture")}
        results[ds] = r
        lines += [f"== {ds}: {r['test_windows']:,} test windows ({r['attack_windows']:,} attack)",
                  f"   ROC-AUC {r.get('roc_auc', float('nan')):.4f} | PR-AUC {r.get('pr_auc', float('nan')):.4f}",
                  f"   detection rate {r['detection_rate'] if r['detection_rate'] is not None else float('nan'):.4f} | "
                  f"false-alarm rate {r['false_alarm_rate'] if r['false_alarm_rate'] is not None else float('nan'):.4f}"]
        lines += [f"   {c:11s} {v['windows']:>8,} windows  detected {v['detected']:.4f}"
                  for c, v in r["per_class_detection"].items()]
        lines += [f"   false alarms in capture {c}: {v['false_alarm_rate']:.4f} ({v['windows']:,} clean benign windows)"
                  for c, v in r["false_alarms_per_capture"].items()]
        if len(comp):
            lines.append(f"   (benign-labelled windows on COMPROMISED devices: {len(comp):,}, flagged "
                         f"{r['benign_on_compromised_flagged']:.4f} - not counted as false alarms)")
        lines.append("")
        log(f"[{ds}] ROC-AUC {r.get('roc_auc', float('nan')):.4f} | detection {r['detection_rate']} | "
            f"false alarms {r['false_alarm_rate']}")
    json.dump({"threshold": thr, "per_dataset": results, "history": history}, open(os.path.join(rdir, "metrics.json"), "w"), indent=1)
    open(os.path.join(rdir, "evaluation.txt"), "w").write("\n".join(lines) + "\n")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
