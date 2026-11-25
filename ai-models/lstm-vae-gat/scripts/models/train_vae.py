"""
Train + evaluate the stage-2 VAE on top of a trained LSTM-AE run, then export outputs for the GAT.

Input per window (all derived from the CURRENT feature list, so dataset / feature changes need no code
change - just rerun the LSTM-AE, then this):
    z_*            LSTM-AE latent vector of the window          (block "lstm_latent")
    log_lstm_error LSTM-AE reconstruction error                 (block "lstm_error")
    log_lstm_error_peak  error of the most unusual flow     (block "lstm_peak")
    mean_* / std_* window statistics of the flow features       (block "window_stats")
    max_* / min_*  most extreme flow per feature (not diluted)  (block "window_max")

  training       CLEAN benign windows of the train split (split_pure, not on a compromised device),
                 inputs standardised with statistics of those same windows
  threshold      99th percentile (--fpr) of val clean-benign scores; the full val-benign score
                 distribution is stored as the reference for the calibrated confidence
  prototypes     Gaussian per KNOWN class (benign + each attack class) in the latent space, fitted on
                 train windows; --unknown-class X leaves X out to simulate a zero-day
  evaluation     test split: ROC-AUC, detection / false alarms (VAE alone and LSTM OR VAE), confidence
                 calibration, class-hint accuracy, zero-day candidate rate per class
  export         preprocessed/model_outputs/vae/<run>/<dataset>_windows.parquet
                 preprocessed/model_outputs/vae/<run>/<dataset>_node_snapshots.parquet

Usage:
    python train_vae.py [--lstm-run lstm_ae_v8] [--run vae_v5] [--unknown-class mirai] [--holdout ds/capture ...]
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
from sklearn.metrics import roc_auc_score

import aegex_models as am
from aegex_models import ap


def log(*a):
    print(time.strftime("%H:%M:%S"), *a, flush=True)


def balanced_pick(caps, n, rng):
    """n indices with an equal share per capture (see train_lstm_ae.balanced_pick)."""
    _, inv, counts = np.unique(np.asarray(caps).astype(str), return_inverse=True, return_counts=True)
    p = 1.0 / counts[inv]
    return rng.choice(len(caps), min(n, len(caps)), replace=False, p=p / p.sum())


def main():
    a = argparse.ArgumentParser()
    a.add_argument("--lstm-run", default="lstm_ae_v8")
    a.add_argument("--run", default="vae_v5")
    a.add_argument("--datasets", nargs="+", default=None, help="default: the LSTM run's training datasets")
    a.add_argument("--inputs", nargs="+", default=list(am.VAE_INPUT_BLOCKS), choices=am.VAE_INPUT_BLOCKS)
    a.add_argument("--min-std", type=float, default=0.1, help="floor of the per-input std used for standardising")
    a.add_argument("--clip", type=float, default=5.0, help="standardised inputs are clipped to +-clip")
    a.add_argument("--latent", type=int, default=8)
    a.add_argument("--hidden", type=int, nargs=2, default=[128, 64])
    a.add_argument("--epochs", type=int, default=80)
    a.add_argument("--patience", type=int, default=8)
    a.add_argument("--lr", type=float, default=1e-3)
    a.add_argument("--batch", type=int, default=512)
    a.add_argument("--per-dataset", type=int, default=20000)
    a.add_argument("--fpr", type=float, default=0.01)
    a.add_argument("--threshold-weighting", choices=["window", "capture"], default="window")
    a.add_argument("--threshold-mode", choices=["per_dataset", "global"], default="per_dataset",
                   help="per_dataset: each network's own val normal 99th pct (see train_lstm_ae.py)")
    a.add_argument("--unknown-class", nargs="*", default=[], help="attack classes hidden from the prototypes (zero-day test)")
    a.add_argument("--holdout", nargs="*", default=[], metavar="DATASET/CAPTURE")
    a.add_argument("--device", default="auto")
    a.add_argument("--seed", type=int, default=0)
    args = a.parse_args()
    torch.manual_seed(args.seed); rng = np.random.default_rng(args.seed)
    dev = am.pick_device(args.device)
    holdout = {tuple(h.split("/", 1)) for h in args.holdout}

    lstm_dir = os.path.join(am.MODELS_DIR, "lstm_ae", args.lstm_run)
    lstm = am.ModelBundle.load(lstm_dir, device="cpu")          # also checks pipeline compatibility
    lmeta = lstm.meta
    datasets = args.datasets or lmeta["train_datasets"]
    T = int(lmeta["window"])
    lstm_out = os.path.join(am.PREPROCESSED, "model_outputs", "lstm_ae", args.lstm_run)
    log(f"device {dev} | LSTM run {args.lstm_run} | datasets {datasets} | inputs {args.inputs}")

    # ------------------------------------------------------------------ inputs for every window
    tables, X = {}, {}
    for ds in datasets:
        L = pd.read_parquet(os.path.join(lstm_out, f"{ds}_windows.parquet"))
        parts = []
        for cap, wc in L.groupby("capture", sort=False):
            F = pd.read_parquet(os.path.join(am.PREPROCESSED, "features", ds, f"{cap}.parquet"),
                                columns=ap.FEATURES).to_numpy(np.float32)
            parts.append((wc.index.to_numpy(), am.window_stats(F, wc, T, args.inputs)))
            del F
        stats = np.zeros((len(L), len(am.window_stat_names(args.inputs))), np.float32)
        for idx, s in parts:
            stats[idx] = s
        X[ds] = am.build_vae_inputs(L, stats, args.inputs)
        tables[ds] = L
        log(f"[{ds}] {len(L):,} windows -> {X[ds].shape[1]} VAE inputs")
    names = am.vae_input_names(args.inputs, int(lmeta["hparams"]["latent"]))
    assert len(names) == X[datasets[0]].shape[1], "input names / matrix mismatch"

    def mask(ds, split, clean_benign=True):
        L = tables[ds]
        m = (L.split == split) & L.split_pure & ~L.capture.isin([c for d, c in holdout if d == ds])
        if clean_benign:
            m &= (L.label == 0) & (L.device_compromised == 0)
        return m.to_numpy()

    tr = {ds: X[ds][mask(ds, "train")] for ds in datasets}
    tr_caps = {ds: tables[ds].capture.to_numpy()[mask(ds, "train")] for ds in datasets}
    va = np.concatenate([X[ds][mask(ds, "val")] for ds in datasets])
    va_caps = np.concatenate([np.char.add(f"{ds}/", tables[ds].capture.to_numpy()[mask(ds, "val")].astype(str))
                              for ds in datasets])
    allb = np.concatenate(list(tr.values()))
    mean, std = allb.mean(0), allb.std(0)
    # Bounded standardisation. Without it, an input that is ~always 0 in normal traffic (mean_svc_telnet,
    # std 4e-4) turns ONE telnet flow into a 20-sigma input that alone exceeds the threshold: the VAE then
    # acts as a "this port / flag never occurs here" rule (shortcut_checks.py). The std floor + clip bound
    # what one input can contribute, so a window is flagged only when its overall behaviour is unusual.
    std = np.maximum(std, args.min_std)
    norm = lambda M: np.clip((M - mean) / std, -args.clip, args.clip).astype(np.float32)
    for ds in datasets:
        log(f"[{ds}] clean benign windows: train {len(tr[ds]):,}")

    # ------------------------------------------------------------------ train
    model = am.WindowVAE(len(names), tuple(args.hidden), args.latent).to(dev)
    opt = torch.optim.Adam(model.parameters(), lr=args.lr)
    vaN = norm(va)
    best, best_state, bad, hist = np.inf, None, 0, []
    for ep in range(1, args.epochs + 1):
        t0 = time.time()
        Xe = np.concatenate([norm(tr[ds][balanced_pick(tr_caps[ds], args.per_dataset, rng)])
                             for ds in datasets if len(tr[ds])])
        perm = rng.permutation(len(Xe)); model.train(); tot = 0.0
        for b in range(0, len(perm), args.batch):
            x = torch.from_numpy(Xe[perm[b:b + args.batch]]).to(dev)
            recon, mu, logvar = model(x)
            rec, kl = model.elbo_terms(x, recon, mu, logvar)
            loss = (rec + kl).mean()
            opt.zero_grad(); loss.backward(); torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0); opt.step()
            tot += loss.item() * len(x)
        vloss = float(pd.Series(am.vae_score_matrix(model, vaN, dev)[0]).groupby(va_caps).mean().mean())
        hist.append({"epoch": ep, "train_loss": tot / len(perm), "val_loss": vloss})
        if ep % 5 == 0 or ep == 1:
            log(f"epoch {ep:3d}  train {tot / len(perm):.4f}  val {vloss:.4f}  ({time.time() - t0:.1f}s)")
        if vloss < best - 1e-5:
            best, bad, best_state = vloss, 0, {k: v.detach().cpu().clone() for k, v in model.state_dict().items()}
        else:
            bad += 1
            if bad >= args.patience:
                log(f"early stop at epoch {ep}"); break
    model.load_state_dict(best_state); model.eval()

    # ------------------------------------------------------------------ threshold, confidence reference, prototypes
    verr, _ = am.vae_score_matrix(model, vaN, dev)
    qs = np.linspace(0, 1, min(len(verr), 5000))
    if args.threshold_weighting == "capture":
        thr = am.balanced_quantile(verr, va_caps, 1 - args.fpr)
        ref = am.balanced_quantile(verr, va_caps, qs)
    else:
        thr, ref = float(np.quantile(verr, 1 - args.fpr)), np.quantile(verr, qs)
    va_ds = np.array([c.split("/", 1)[0] for c in va_caps])
    per_ds_thr, per_ds_ref, thr_src = {}, {}, {}
    for ds in datasets:
        e = verr[va_ds == ds]
        if len(e) >= am.MIN_CALIBRATION_WINDOWS:
            thr_src[ds] = f"val clean normal ({len(e)} windows)"
        elif len(e) + len(tr[ds]):        # too little val normal traffic -> train + val (see train_lstm_ae.py)
            e = np.r_[am.vae_score_matrix(model, norm(tr[ds]), dev)[0], e]
            thr_src[ds] = f"LOW CONFIDENCE: train+val clean normal ({len(e)} windows)"
        else:
            continue
        per_ds_thr[ds] = float(np.quantile(e, 1 - args.fpr))
        per_ds_ref[ds] = [float(v) for v in np.quantile(e, np.linspace(0, 1, min(len(e), 5000)))]
    mus, labs = [], []
    for ds in datasets:
        L = tables[ds]
        m = mask(ds, "train", clean_benign=False) & ~((L.label == 0) & (L.device_compromised == 1)).to_numpy()
        _, mu = am.vae_score_matrix(model, norm(X[ds][m]), dev)
        mus.append(mu); labs.append(L.window_class.to_numpy()[m])
    mus, labs = np.concatenate(mus), np.concatenate(labs)
    keep = ~np.isin(labs, args.unknown_class)
    protos = am.LatentPrototypes().fit(mus[keep], labs[keep], rng=rng)
    log(f"threshold {thr:.4f} | prototypes for known classes {protos.classes} | hidden (zero-day test): {args.unknown_class or 'none'}")

    meta = {"bundle_format": am.BUNDLE_FORMAT, "model_type": "window_vae", "run": args.run, "created": am.now_iso(),
            "torch": torch.__version__, "init": {"n_in": len(names), "hidden": list(args.hidden), "latent": args.latent},
            "train_datasets": datasets, "input_blocks": args.inputs, "input_names": names,
            "input_mean": mean.tolist(), "input_std": std.tolist(), "input_clip": float(args.clip),
            "input_min_std": float(args.min_std),
            "window": T, "stride": int(lmeta["stride"]), "snapshot_seconds": float(lmeta["snapshot_seconds"]),
            "threshold": thr, "threshold_rule": f"{args.threshold_weighting}-weighted quantile {1 - args.fpr} "
                                                f"of val clean-benign VAE scores",
            "benign_reference_scores": [float(v) for v in ref], "prototypes": protos.to_dict(),
            "threshold_mode": args.threshold_mode, "per_dataset_thresholds": per_ds_thr,
            "per_dataset_reference_scores": per_ds_ref, "per_dataset_threshold_source": thr_src,
            "unknown_classes_hidden": args.unknown_class, "holdout": args.holdout,
            "upstream": {"lstm_run": args.lstm_run, "lstm_model_sha256": am.file_sha256(os.path.join(lstm_dir, "model.pt"))},
            "pipeline": am.pipeline_fingerprint(), "scalers": lmeta["scalers"], "history": hist,
            "hparams": {"lr": args.lr, "batch": args.batch, "per_dataset": args.per_dataset, "seed": args.seed, "fpr": args.fpr}}
    bdir = os.path.join(am.MODELS_DIR, "vae", args.run)
    am.ModelBundle(model, meta).save(bdir)
    log(f"saved bundle -> {bdir}")

    # ------------------------------------------------------------------ score everything, export, evaluate
    odir = os.path.join(am.PREPROCESSED, "model_outputs", "vae", args.run)
    rdir = os.path.join(am.DATA_ROOT, "model_results", "vae", args.run)
    os.makedirs(odir, exist_ok=True); os.makedirs(rdir, exist_ok=True)
    keys = ["capture", "device", "row_start", "row_end", "n_flows", "t_start", "t_end", "split", "split_pure",
            "label", "window_class", "attack_frac", "device_compromised", "lstm_score", "lstm_anomaly"]
    lines = [f"VAE '{args.run}' on LSTM-AE '{args.lstm_run}' - test-split evaluation",
             f"threshold {thr:.4f} (val clean-benign {100 * (1 - args.fpr):.0f}th pct) | inputs {args.inputs} ({len(names)})",
             f"known classes (prototypes): {protos.classes} | hidden as zero-day: {args.unknown_class or 'none'}", ""]
    results = {}
    for ds in datasets:
        L = tables[ds]
        err, mu = am.vae_score_matrix(model, norm(X[ds]), dev)
        extra = [c for c in ("lstm_error_peak", "lstm_peak_row", "lstm_top_features") if c in L.columns]
        V = pd.concat([L[keys + extra].reset_index(drop=True), am.vae_outputs(meta, err, mu, dataset=ds)], axis=1)
        am.write_output(V, os.path.join(odir, f"{ds}_windows.parquet"))
        NS = []
        for cap, g in V.groupby("capture", sort=False):
            t0 = pd.read_parquet(os.path.join(am.PREPROCESSED, "features", ds, f"{cap}.parquet"), columns=["ts"]).ts.min()
            NS.append(am.node_snapshot_table(g, t0, meta["snapshot_seconds"], stage="vae", latent_prefix="mu_",
                                             extra_max=("zero_day_candidate", "vae_confidence")))
        am.write_output(pd.concat(NS, ignore_index=True), os.path.join(odir, f"{ds}_node_snapshots.parquet"))

        held = V.capture.isin([c for d, c in holdout if d == ds])
        te = V[(V.split == "test") & V.split_pure & ~held]
        te = te[~((te.label == 0) & (te.device_compromised == 1))]
        ben, att = te[te.label == 0], te[te.label == 1]
        both = (te.lstm_anomaly == 1) | (te.vae_anomaly == 1)
        r = {"test_windows": int(len(te)), "attack_windows": int(len(att)), "clean_benign_windows": int(len(ben)),
             "vae_roc_auc": float(roc_auc_score(te.label, te.vae_error)) if 0 < len(att) < len(te) else None,
             "vae_detection": float(att.vae_anomaly.mean()) if len(att) else None,
             "vae_false_alarms": float(ben.vae_anomaly.mean()) if len(ben) else None,
             "lstm_or_vae_detection": float(both[te.label == 1].mean()) if len(att) else None,
             "lstm_or_vae_false_alarms": float(both[te.label == 0].mean()) if len(ben) else None,
             "benign_confidence_ge_0.99": float((ben.vae_confidence >= 0.99).mean()) if len(ben) else None,
             "false_alarms_per_capture": {c: {"windows": int(len(g)), "vae": float(g.vae_anomaly.mean()),
                                              "lstm_or_vae": float(((g.lstm_anomaly == 1) | (g.vae_anomaly == 1)).mean())}
                                          for c, g in ben.groupby("capture")},
             "per_class": {}}
        for c, g in te.groupby("window_class"):
            r["per_class"][c] = {"windows": int(len(g)), "vae_flagged": float(g.vae_anomaly.mean()),
                                 "lstm_or_vae": float(((g.lstm_anomaly == 1) | (g.vae_anomaly == 1)).mean()),
                                 "class_hint_correct": float((g.vae_class_hint == c).mean()),
                                 "zero_day_candidate": float(g.zero_day_candidate.mean()),
                                 "hidden_as_zero_day": c in args.unknown_class}
        results[ds] = r
        f = lambda v: "n/a" if v is None else f"{v:.4f}"
        lines += [f"== {ds}: {r['test_windows']:,} test windows ({r['attack_windows']:,} attack, {r['clean_benign_windows']:,} clean benign)",
                  f"   VAE ROC-AUC {f(r['vae_roc_auc'])} | VAE detection {f(r['vae_detection'])} false alarms {f(r['vae_false_alarms'])}",
                  f"   LSTM OR VAE: detection {f(r['lstm_or_vae_detection'])} false alarms {f(r['lstm_or_vae_false_alarms'])}",
                  f"   calibration: share of clean benign test windows with confidence >= 0.99: "
                  f"{f(r['benign_confidence_ge_0.99'])} (ideal ~0.01)",
                  *[f"   false alarms in capture {c}: VAE {v['vae']:.4f} | LSTM or VAE {v['lstm_or_vae']:.4f} ({v['windows']:,} windows)"
                    for c, v in r["false_alarms_per_capture"].items()],
                  "   class        windows  VAE-flag  LSTM|VAE  hint-correct  zero-day-cand"]
        lines += [f"   {c:11s} {v['windows']:>8,}  {v['vae_flagged']:8.4f}  {v['lstm_or_vae']:8.4f}  "
                  f"{v['class_hint_correct']:12.4f}  {v['zero_day_candidate']:13.4f}{'   <- HIDDEN (simulated zero-day)' if v['hidden_as_zero_day'] else ''}"
                  for c, v in r["per_class"].items()]
        lines.append("")
        log(f"[{ds}] VAE ROC-AUC {f(r['vae_roc_auc'])} | det {f(r['vae_detection'])} | FA {f(r['vae_false_alarms'])}")
    json.dump({"threshold": thr, "per_dataset": results, "history": hist}, open(os.path.join(rdir, "metrics.json"), "w"), indent=1)
    open(os.path.join(rdir, "evaluation.txt"), "w").write("\n".join(lines) + "\n")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
