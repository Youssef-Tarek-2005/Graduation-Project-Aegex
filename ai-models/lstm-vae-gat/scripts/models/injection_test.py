"""
SUPERSEDED by benchmark.py (+ aegex_bench.py), which uses only TEST-split attack flows, many more
scenarios, clean-traffic false alarms, incident-level numbers and a no-model reference rule. Kept for the
record of the first investigation (lstm_ae_v7 / vae_v3).

Realistic attack-injection test: blend real attack flows into a real NORMAL capture's timeline, as if one
normal device had been compromised, then run the UNCHANGED pipeline (features incl. device context are
recomputed from the merged traffic) and the trained LSTM-AE + VAE.

  base      the last 15 % (test period) of a normal capture's clean benign flows
  attack    the first --n attack flows of an attack capture, keeping their relative timing but stretched
            by a SLOWDOWN factor (1 = original speed, 10 / 100 = stealthier), and moved into the base period
  identity  the attacker's IP is replaced by a busy normal device of the base capture (compromised device)
  measured  detection = share of windows that contain >= 1 injected flow and are flagged
            false alarms = share of windows without injected flows that are flagged (same merged capture)

Usage:
    python injection_test.py [--lstm-run lstm_ae_v7] [--vae-run vae_v3] [--n 300] [--slowdowns 1 10 100]
"""
import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import numpy as np
import pandas as pd

import aegex_models as am
from aegex_models import ap, s3

CASES = [  # (dataset, normal capture, attack capture)
    ("edge", "normal_water_level", "port_scanning"),
    ("edge", "normal_water_level", "vulnerability_scanner"),
    ("edge", "normal_water_level", "ransomware"),
    ("edge", "normal_water_level", "ddos_http"),
    ("edge", "normal_temperature_and_humidity", "port_scanning"),
    ("edge", "normal_temperature_and_humidity", "ransomware"),
    ("kitsune", "ssdp_flood", "os_scan"),
    ("kitsune", "ssdp_flood", "mirai"),
]
out = []


def say(s):
    print(s, flush=True); out.append(s)


def flows(ds, cap):
    return pd.read_parquet(os.path.join(am.PREPROCESSED, "flows", ds, f"{cap}.parquet"))


def main():
    a = argparse.ArgumentParser()
    a.add_argument("--lstm-run", default="lstm_ae_v7")
    a.add_argument("--vae-run", default="vae_v3")
    a.add_argument("--n", type=int, default=300)
    a.add_argument("--slowdowns", type=float, nargs="+", default=[1, 10, 100])
    args = a.parse_args()
    dev = am.pick_device("auto")
    ldir = os.path.join(am.MODELS_DIR, "lstm_ae", args.lstm_run)
    lstm = am.ModelBundle.load(ldir, device=dev)
    vae = am.ModelBundle.load(os.path.join(am.MODELS_DIR, "vae", args.vae_run), device=dev)
    am.check_vae_matches_lstm(vae.meta, ldir)
    T, S_ = int(lstm.meta["window"]), int(lstm.meta["stride"])
    say(f"Injection test | LSTM {args.lstm_run} (thr {lstm.threshold:.3f}) | VAE {args.vae_run} (thr {vae.threshold:.3f}) | "
        f"{args.n} attack flows per case\n")
    say(f"{'dataset':8s} {'normal capture':32s} {'attack':22s} {'slow':>5s} {'attack span':>12s} "
        f"{'att.win':>7s} {'LSTM det':>8s} {'VAE det':>8s} {'either':>7s} {'FA either':>9s}")
    for ds, base_cap, att_cap in CASES:
        B = flows(ds, base_cap)
        attackers = set(B.loc[B.is_attack == 1, "src_ip"])
        B = B[(B.is_attack == 0) & ~B.src_ip.isin(attackers) & ~B.dst_ip.isin(attackers)]
        B = B[B.ts >= B.ts.quantile(0.85)].copy()                 # test period of the normal capture
        Araw = flows(ds, att_cap)
        A0 = Araw[Araw.is_attack == 1].sort_values("ts").head(args.n).copy()
        attacker = A0.src_ip.value_counts().index[0]
        victim_dev = B.src_ip.value_counts().index[0]             # busiest normal device -> "compromised"
        scaler = ap.RobustScaler.from_dict(lstm.meta["scalers"][ds])
        for slow in args.slowdowns:
            A = A0.copy()
            rel = (A.ts - A.ts.min()) * slow
            start = B.ts.min() + 0.25 * (B.ts.max() - B.ts.min())
            A["ts"] = start + rel
            A["ts_end"] = A.ts + A.duration
            for col in ("src_ip", "dst_ip"):
                A.loc[A[col] == attacker, col] = victim_dev
            M = ap.to_schema(pd.concat([B, A], ignore_index=True))
            M["capture"] = f"{base_cap}+{att_cap}"
            feat = ap.engineer_features(M)
            feat = scaler.transform(feat)
            feat["split"] = "live"
            feat = feat.sort_values(["device", "ts"], kind="stable").reset_index(drop=True)
            F = feat[ap.FEATURES].to_numpy(np.float32)
            W = s3.windows_for(feat, "inj", T, S_)
            Sc = am.score_windows(lstm.model, F, W, T, dev, threshold=am.threshold_for(lstm.meta, ds), score_agg=am.score_agg_of(lstm.meta))
            err, mu = am.vae_score_windows(vae, Sc, F, W, dev)
            V = am.vae_outputs(vae.meta, err, mu, dataset=ds)
            either = (Sc.lstm_anomaly.to_numpy() == 1) | (V.vae_anomaly.to_numpy() == 1)
            att = W.n_attack.to_numpy() > 0
            span = (A.ts.max() - A.ts.min())
            frac = W.attack_frac.to_numpy()
            comp_dev = W.device.to_numpy() == victim_dev
            low, high = att & (frac < 0.5), att & (frac >= 0.5)
            rate = lambda m: f"{either[m].mean():.2f} ({int(m.sum())})" if m.any() else "   -    "
            say(f"{ds:8s} {base_cap:32s} {att_cap:22s} {slow:5.0f} {span / 60:10.1f} m {int(att.sum()):7d} "
                f"{Sc.lstm_anomaly.to_numpy()[att].mean():8.3f} {V.vae_anomaly.to_numpy()[att].mean():8.3f} "
                f"{either[att].mean():7.3f} {either[~att].mean():9.3f}   "
                f"compromised-dev {rate(att & comp_dev):>11s} other-dev {rate(att & ~comp_dev):>11s} "
                f"| <50% attack {rate(low):>11s} >=50% {rate(high):>11s}")
    say("\natt.win = windows containing >= 1 injected attack flow; FA either = flagged share of the other windows")
    say("compromised-dev / other-dev: detection (either model) on windows of the compromised device vs of the "
        "devices it contacts (victims); <50% / >=50%: by share of attack flows in the window; (n windows)")
    p = os.path.join(am.DATA_ROOT, "model_results", "investigation")
    os.makedirs(p, exist_ok=True)
    open(os.path.join(p, f"injection__{args.lstm_run}__{args.vae_run}.txt"), "w", encoding="utf-8").write("\n".join(out) + "\n")


if __name__ == "__main__":
    main()
