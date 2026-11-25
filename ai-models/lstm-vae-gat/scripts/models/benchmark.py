"""
Realistic benchmark of the LSTM-AE + VAE (the numbers to quote - see aegex_bench.py for how scenarios
are built). Everything here is TEST data only: normal traffic from the test periods of normal captures,
attack flows from the test splits of attack captures, thresholds from the val split. No model has seen
any of it.

Reported per dataset
  false alarms        on the CLEAN test periods (no injection): share of normal windows flagged and
                      alerts per hour of normal traffic
  window detection    share of windows containing >= 1 attack flow that are flagged, per attack type and
                      speed (x1 original, x10 / x100 slower); also for windows that are < 50 % attack
  incidents detected  share of injected attacks with at least one alert, and median time to the first alert
  macro detection     window detection averaged over attack types (each type counts once), with a 95 %
                      bootstrap interval over scenarios
  'rule'              a one-line rule on the single best window statistic (chosen on the val split):
                      the no-model reference; a model has to beat it to be worth anything

Usage:
    python benchmark.py [--lstm-run lstm_ae_v8] [--vae-run vae_v5] [--datasets edge kitsune iot23]
                        [--slowdowns 1 10 100] [--reps 2] [--n-attack 300]
Writes model_results/benchmark/<lstm>__<vae>/{report.txt, metrics.json, scenarios.csv}
"""
import argparse
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import numpy as np
import pandas as pd

import aegex_bench as ab
import aegex_models as am
from aegex_models import ap

METHOD_NAMES = {"lstm": "LSTM-AE", "vae": "VAE", "either": "LSTM or VAE", "rule": "one-line rule"}


def log(*a):
    print(time.strftime("%H:%M:%S"), *a, flush=True)


def pooled(df, num, den):
    d = df[den].sum()
    return float(df[num].sum() / d) if d else float("nan")


def macro_with_ci(df, n_boot=1000, seed=0):
    """Window detection averaged over attack types; 95 % bootstrap CI (scenarios resampled per type)."""
    groups = [g[["detected_windows", "attack_windows"]].to_numpy(float) for _, g in df.groupby("attack")
              if g.attack_windows.sum() > 0]
    if not groups:
        return float("nan"), float("nan"), float("nan")
    point = float(np.mean([g[:, 0].sum() / g[:, 1].sum() for g in groups]))
    rng = np.random.default_rng(seed)
    boots = []
    for _ in range(n_boot):
        vals = []
        for g in groups:
            s = g[rng.integers(0, len(g), len(g))]
            vals.append(s[:, 0].sum() / s[:, 1].sum() if s[:, 1].sum() else np.nan)
        boots.append(np.nanmean(vals))
    lo, hi = np.nanquantile(boots, [0.025, 0.975])
    return point, float(lo), float(hi)


MIN_DEVICE_WINDOWS = am.MIN_DEVICE_WINDOWS     # clean val windows a device needs for its own threshold


def recalibrate(lstm, vae, datasets, T, S_, snap, dev, q=0.99, per_device=False):
    """Per dataset: thresholds = q-quantile of LSTM / VAE window errors on the clean val-period base(s).
    per_device: also a threshold per device = max(network threshold, that device's own q-quantile), for
    devices with >= MIN_DEVICE_WINDOWS clean val windows (only ever RAISES a device's bar, so a noisy
    estimate on a quiet device cannot create a hair trigger).
    Changes the loaded bundles' meta in memory only (files on disk are untouched)."""
    out = {}
    for ds in datasets:
        if ds not in lstm.meta["scalers"]:
            continue
        scaler = ap.RobustScaler.from_dict(lstm.meta["scalers"][ds])
        S = []
        for spec in ab.scenario_specs("val", [ds], attacks=False):
            if spec["attack_capture"] is None:
                S.append(ab.score_scenario(ab.build_scenario(spec, scaler, T, S_, snap), lstm, vae, dev))
        if not S:
            continue
        S = pd.concat(S, ignore_index=True)
        r = {"windows": len(S), "lstm_old": am.threshold_for(lstm.meta, ds), "vae_old": am.threshold_for(vae.meta, ds)}
        r["lstm_new"] = float(np.quantile(S.lstm_error, q))
        r["vae_new"] = float(np.quantile(S.vae_error, q))
        for b, key in ((lstm, "lstm_new"), (vae, "vae_new")):
            b.meta["threshold_mode"] = "per_dataset"
            b.meta.setdefault("per_dataset_thresholds", {})[ds] = r[key]
        vae.meta.setdefault("per_dataset_reference_scores", {})[ds] = [
            float(v) for v in np.quantile(S.vae_error, np.linspace(0, 1, min(len(S), 5000)))]
        if per_device:
            n = S.device.value_counts()
            r["per_device"] = {
                "lstm": am.device_thresholds(S.device, S.lstm_error, r["lstm_new"], q),
                "vae": am.device_thresholds(S.device, S.vae_error, r["vae_new"], q),
                "val_windows": {d: int(c) for d, c in n.items() if c >= MIN_DEVICE_WINDOWS}}
        out[ds] = r
    return out


def main():
    a = argparse.ArgumentParser()
    a.add_argument("--lstm-run", default="lstm_ae_v8")
    a.add_argument("--vae-run", default="vae_v5")
    a.add_argument("--datasets", nargs="+", default=ap.ACTIVE_DATASETS)
    a.add_argument("--slowdowns", type=float, nargs="+", default=[1, 10, 100])
    a.add_argument("--reps", type=int, default=2)
    a.add_argument("--n-attack", type=int, default=300)
    a.add_argument("--limit", type=int, default=0, help="debug: only the first N scenarios")
    a.add_argument("--device", default="auto")
    a.add_argument("--recalibrate", action="store_true",
                   help="reset each dataset's LSTM and VAE thresholds to the 99th pct of the clean VAL-period "
                        "benchmark base (the network's own recent normal traffic, as score_traffic --calibrate "
                        "does); test data is never used")
    a.add_argument("--per-device", action="store_true",
                   help="with --recalibrate: also per-device thresholds (never below the network threshold)")
    args = a.parse_args()
    if args.per_device and not args.recalibrate:
        a.error("--per-device needs --recalibrate")
    dev = am.pick_device(args.device)
    ldir = os.path.join(am.MODELS_DIR, "lstm_ae", args.lstm_run)
    lstm = am.ModelBundle.load(ldir, device=dev)
    vae = am.ModelBundle.load(os.path.join(am.MODELS_DIR, "vae", args.vae_run), device=dev)
    am.check_vae_matches_lstm(vae.meta, ldir)
    T, S_, snap = int(lstm.meta["window"]), int(lstm.meta["stride"]), float(lstm.meta["snapshot_seconds"])
    out_dir = os.path.join(am.DATA_ROOT, "model_results", "benchmark",
                           f"{args.lstm_run}__{args.vae_run}" + ("__recal" if args.recalibrate else "")
                           + ("_dev" if args.per_device else ""))
    os.makedirs(out_dir, exist_ok=True)
    recal = {}
    if args.recalibrate:
        recal = recalibrate(lstm, vae, args.datasets, T, S_, snap, dev, per_device=args.per_device)
        for ds, r in recal.items():
            log(f"[{ds}] recalibrated on {r['windows']:,} clean val windows: LSTM thr {r['lstm_old']:.4f} -> "
                f"{r['lstm_new']:.4f} | VAE thr {r['vae_old']:.4f} -> {r['vae_new']:.4f}")
            if "per_device" in r:
                pd_ = r["per_device"]
                raised = {d: round(t, 3) for d, t in pd_["vae"].items() if t > r["vae_new"]}
                log(f"[{ds}] per-device thresholds for {len(pd_['vae'])} devices; VAE raised on {len(raised)}: {raised}")

    rules = ab.trivial_rules(args.datasets, T)
    for ds, r in rules.items():
        log(f"[{ds}] one-line rule: {r['stat']} {'>' if r['higher'] else '<'} {r['threshold']:.3f} (val ROC-AUC {r['val_auc']:.3f})")

    specs = ab.scenario_specs("test", args.datasets, args.slowdowns, args.reps, args.n_attack, controls=ab.CONTROL_KINDS)
    if args.limit:
        specs = specs[:args.limit]
    log(f"{len(specs)} test scenarios | LSTM {args.lstm_run} ({am.score_agg_of(lstm.meta)}, thr {lstm.threshold:.4f}) "
        f"| VAE {args.vae_run} (thr {vae.threshold:.4f})")
    rows, infos = [], []
    for i, spec in enumerate(specs, 1):
        scaler = ap.RobustScaler.from_dict(lstm.meta["scalers"][spec["dataset"]])
        sc = ab.build_scenario(spec, scaler, T, S_, snap)
        scored = ab.score_scenario(sc, lstm, vae, dev, rules,
                                   device_thr=recal.get(spec["dataset"], {}).get("per_device"))
        rows += ab.scenario_metrics(scored, sc["info"])
        infos.append(sc["info"])
        if i % 10 == 0 or i == len(specs):
            log(f"  {i}/{len(specs)} scenarios")
    R = pd.DataFrame(rows)
    R.to_csv(os.path.join(out_dir, "scenarios.csv"), index=False)
    pd.DataFrame(infos).to_csv(os.path.join(out_dir, "scenario_info.csv"), index=False)

    # ------------------------------------------------------------------ report
    L = [f"REALISTIC BENCHMARK  |  LSTM-AE {args.lstm_run} (window score: {am.score_agg_of(lstm.meta)})  |  VAE {args.vae_run}",
         "attacks injected into real normal traffic of a busy device; test data only (no model saw it);",
         f"thresholds from the val split; {args.n_attack} attack flows per scenario; speeds x{', x'.join(str(int(s)) for s in args.slowdowns)}"]
    for ds, r in recal.items():
        L.append(f"RECALIBRATED [{ds}]: thresholds = 99th pct of {r['windows']:,} clean VAL-period benchmark windows "
                 f"(LSTM {r['lstm_old']:.4f} -> {r['lstm_new']:.4f}, VAE {r['vae_old']:.4f} -> {r['vae_new']:.4f})")
        if "per_device" in r:
            v = r["per_device"]["vae"]
            L.append(f"  + PER-DEVICE thresholds for {len(v)} devices with >= {MIN_DEVICE_WINDOWS} val windows "
                     f"(never below the network threshold); VAE raised: "
                     + ", ".join(f"{d} {t:.3f}" for d, t in sorted(v.items(), key=lambda x: -x[1]) if t > r["vae_new"]))
    L.append("")
    metrics = {"lstm_run": args.lstm_run, "vae_run": args.vae_run, "score_agg": am.score_agg_of(lstm.meta),
               "recalibration": recal,
               "rules": rules, "datasets": {}}
    methods = [m for m in ("lstm", "vae", "either", "rule") if m in set(R.method)]
    for ds in args.datasets:
        D = R[R.dataset == ds]
        if D.empty:
            continue
        md = metrics["datasets"][ds] = {"false_alarms": {}, "detection": {}, "macro": {}}
        L += ["=" * 100, f"{ds.upper()}" + (f"   (one-line rule: {rules[ds]['stat']})" if ds in rules else ""), "=" * 100]
        C = D[D.attack.isna()]
        L.append("False alarms on CLEAN normal test traffic (no attack injected):")
        L.append(f"  {'normal capture':34s} {'hours':>6s} {'windows':>8s}  " + "  ".join(f"{METHOD_NAMES[m]:>20s}" for m in methods))
        for base, g in C.groupby("base"):
            cells = []
            for m in methods:
                x = g[g.method == m]
                rate = pooled(x, "false_alarm_windows", "benign_windows")
                per_h = x.false_alarm_windows.sum() / max(x.base_hours.sum(), 1e-9)
                cells.append(f"{rate:6.2%} ({per_h:6.1f}/h)")
                md["false_alarms"].setdefault(m, {})[base] = {"rate": rate, "alerts_per_hour": float(per_h)}
            x0 = g[g.method == methods[0]]
            L.append(f"  {base:34s} {x0.base_hours.sum():6.1f} {int(x0.benign_windows.sum()):8,}  " + "  ".join(f"{c:>20s}" for c in cells))
        for m in methods:
            x = C[C.method == m]
            md["false_alarms"].setdefault(m, {})["_all"] = {"rate": pooled(x, "false_alarm_windows", "benign_windows"),
                                             "alerts_per_hour": float(x.false_alarm_windows.sum() / max(x.base_hours.sum(), 1e-9))}
        K = D[D.attack.fillna("").str.startswith("control_")]
        if len(K):
            L += ["", "INJECTION NOISE FLOOR: NORMAL traffic injected exactly like an attack (should be flagged at the",
                  "false-alarm rate; detection of a real attack only counts as far as it is ABOVE this line):",
                  f"  {'injected normal traffic':42s} {'win.':>7s}  " + "  ".join(f"{METHOD_NAMES[m]:>13s}" for m in methods)]
            for k, g in K.groupby("attack"):
                L.append(f"  {k:42s} {int(g[g.method == methods[0]].attack_windows.sum()):7d}  " +
                         "  ".join(f"{pooled(g[g.method == m], 'detected_windows', 'attack_windows'):13.1%}" for m in methods))
                for m in methods:
                    md.setdefault("noise_floor", {}).setdefault(m, {})[k] = pooled(g[g.method == m], "detected_windows", "attack_windows")
        A = D[D.attack.notna() & ~D.attack.fillna("").str.startswith("control_")]
        A = A.assign(case=A.attack_capture + ":" + A.attack)
        L += ["", "Window detection (share of windows with >= 1 attack flow that are flagged)",
              f"  {'attack (capture:class)':42s} {'speed':>5s} {'att.win':>7s} {'mixed':>6s}  " +
              "  ".join(f"{METHOD_NAMES[m]:>13s}" for m in methods) + f"  {'<50% att.':>9s}  {'incidents':>9s}  {'1st alert':>9s}"]
        for (case, slow), g in A.groupby(["case", "slowdown"]):
            e = g[g.method == "either"]
            cells = [f"{pooled(g[g.method == m], 'detected_windows', 'attack_windows'):13.1%}" for m in methods]
            ttd = e.time_to_detect_s.dropna()
            L.append(f"  {case[:42]:42s} {'x' + format(e.speed.median(), '.3g'):>5s} {int(e.attack_windows.sum()):7d} "
                     f"{e.attack_windows_mixed.sum() / max(e.attack_windows.sum(), 1):6.0%}  " + "  ".join(cells) +
                     f"  {pooled(e, 'low_share_detected', 'low_share_windows'):9.1%}  "
                     f"{int(e.incident_detected.sum())}/{len(e):<7d}  {(f'{ttd.median() / 60:7.1f} m' if len(ttd) else '      -  '):>9s}")
            for m in methods:
                md["detection"].setdefault(m, {})[f"{case} x{int(slow)}"] = pooled(g[g.method == m], "detected_windows", "attack_windows")
        L += ["", "Macro window detection (attack types weighted equally) [95 % bootstrap interval]  |  incidents detected"]
        for m in methods:
            parts = []
            for slow in sorted(A.slowdown.unique()):
                p, lo, hi = macro_with_ci(A[(A.method == m) & (A.slowdown == slow)])
                parts.append(f"x{int(slow)} {p:6.1%} [{lo:5.1%}-{hi:5.1%}]")
                md["macro"].setdefault(m, {})[f"x{int(slow)}"] = {"value": p, "ci95": [lo, hi]}
            p, lo, hi = macro_with_ci(A[A.method == m])
            md["macro"][m]["all"] = {"value": p, "ci95": [lo, hi]}
            inc = A[A.method == m].incident_detected
            md["macro"][m]["incidents_detected"] = float(inc.mean())
            L.append(f"  {METHOD_NAMES[m]:14s} all {p:6.1%} [{lo:5.1%}-{hi:5.1%}]  |  " + "  ".join(parts) +
                     f"  |  incidents {int(inc.sum())}/{len(inc)}")
        L.append("")
    L += ["How to read: 'mixed' = share of attack windows that also contain normal flows (realism check);",
          "'<50% att.' = detection on windows where attacks are a minority (the hard, realistic case);",
          "'incidents' = injected attacks with >= 1 alert; '1st alert' = median minutes from attack start to first alert.",
          "False alarms are measured on devices that carry no attack flow."]
    text = "\n".join(L) + "\n"
    open(os.path.join(out_dir, "report.txt"), "w", encoding="utf-8").write(text)
    json.dump(metrics, open(os.path.join(out_dir, "metrics.json"), "w"), indent=1, default=float)
    print(text)


if __name__ == "__main__":
    main()
