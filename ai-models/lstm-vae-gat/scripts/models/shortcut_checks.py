"""
Shortcut checks for the window detectors (LSTM-AE, VAE) on the realistic benchmark.

Question: when the VAE flags ~100 % of benchmark windows that contain even a few attack flows, is it
detecting the ATTACK, or something the injection procedure itself leaves behind?

  A  control injections   NORMAL flows injected exactly like an attack (aegex_bench.CONTROL_KINDS).
                          Flag rate on those "injected" windows vs the clean false-alarm rate.
  B  what drives the VAE  for VAE-flagged attack windows with < 50 % attack flows (and for flagged control
                          windows): which VAE inputs carry the reconstruction error, and how often the top
                          input is a value never seen in normal training data (standardised |x| >= 10).
  C  near-constant inputs VAE inputs whose normal-training std is tiny -> any deviation explodes the score.

Usage:
    python shortcut_checks.py [--lstm-run lstm_ae_v8] [--vae-run vae_v5] [--datasets edge kitsune iot23]
Writes model_results/shortcut_checks/<lstm>__<vae>.txt
"""
import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import numpy as np
import pandas as pd
import torch

import aegex_bench as ab
import aegex_models as am
from aegex_models import ap

out = []


def say(*a):
    s = " ".join(str(x) for x in a)
    print(s, flush=True); out.append(s)


def block_of(name):
    for p, b in (("z_", "lstm_latent"), ("log_lstm_error_peak", "lstm_peak"), ("log_lstm_error", "lstm_error"),
                 ("mean_", "window mean"), ("std_", "window std"), ("max_", "window max"), ("min_", "window min")):
        if name.startswith(p):
            return b
    return "?"


@torch.no_grad()
def vae_contrib(vae, F, scored, W):
    """Per-window, per-input squared reconstruction error (standardised space) + standardised inputs."""
    meta = vae.meta
    stats = am.window_stats(F, W, int(meta["window"]), meta["input_blocks"])
    Xn = am.vae_normalise(meta, am.build_vae_inputs(scored, stats, meta["input_blocks"]))
    vae.model.eval()
    x = torch.from_numpy(Xn).to(next(vae.model.parameters()).device)
    recon, _, _ = vae.model(x)
    return ((recon - x) ** 2).cpu().numpy(), Xn


def main():
    a = argparse.ArgumentParser()
    a.add_argument("--lstm-run", default="lstm_ae_v8")
    a.add_argument("--vae-run", default="vae_v5")
    a.add_argument("--datasets", nargs="+", default=ap.ACTIVE_DATASETS)
    a.add_argument("--n-attack", type=int, default=300)
    args = a.parse_args()
    dev = am.pick_device("auto")
    lstm = am.ModelBundle.load(os.path.join(am.MODELS_DIR, "lstm_ae", args.lstm_run), device=dev)
    vae = am.ModelBundle.load(os.path.join(am.MODELS_DIR, "vae", args.vae_run), device=dev)
    T, S_, snap = int(lstm.meta["window"]), int(lstm.meta["stride"]), float(lstm.meta["snapshot_seconds"])
    names = vae.meta["input_names"]
    rules = ab.trivial_rules(args.datasets, T)
    say(f"SHORTCUT CHECKS  LSTM-AE {args.lstm_run} | VAE {args.vae_run} | test phase only")

    # ---------------------------------------------------------------- C near-constant inputs
    std = np.asarray(vae.meta["input_std"])
    say("\n[C] VAE inputs with near-constant normal training values (std < 0.01, standardised x is clipped at +-20):")
    small = [(names[i], std[i]) for i in np.argsort(std) if std[i] < 0.01]
    say(f"    {len(small)} of {len(names)} inputs: " + ", ".join(f"{n} ({s:.1e})" for n, s in small[:25]))

    # ---------------------------------------------------------------- A + B
    specs = ab.scenario_specs("test", args.datasets, (1,), 2, args.n_attack, controls=ab.CONTROL_KINDS)
    rows, contrib = [], []
    for i, spec in enumerate(specs, 1):
        if spec["attack_capture"] is None:
            continue
        sc = ab.build_scenario(spec, ap.RobustScaler.from_dict(lstm.meta["scalers"][spec["dataset"]]), T, S_, snap)
        S = ab.score_scenario(sc, lstm, vae, dev, rules)
        F = sc["feat"][ap.FEATURES].to_numpy(np.float32)
        inj = S.n_attack.to_numpy() > 0
        involved = S.device.isin(set(S.device[inj])).to_numpy()
        other = ~inj & ~involved
        kind = "attack" if not spec["attack_class"].startswith("control_") else spec["attack_class"]
        r = {"dataset": spec["dataset"], "kind": kind, "attack": spec["attack_class"], "base": spec["base"],
             "inj_windows": int(inj.sum()), "other_windows": int(other.sum())}
        for m in ("lstm", "vae", "either", "rule"):
            f = ab.flags(S, m)
            if f is None:
                continue
            r[f"{m}_inj"] = float(f[inj].mean()) if inj.any() else np.nan
            r[f"{m}_inj_low"] = float(f[inj & (S.attack_frac.to_numpy() < 0.5)].mean()) if (inj & (S.attack_frac.to_numpy() < 0.5)).any() else np.nan
            r[f"{m}_other"] = float(f[other].mean()) if other.any() else np.nan
        rows.append(r)
        # B: contributions on VAE-flagged injected windows with < 50 % injected flows
        sel = inj & (S.vae_anomaly.to_numpy() == 1) & (S.attack_frac.to_numpy() < 0.5)
        if sel.any():
            Wsel = sc["windows"][sel].reset_index(drop=True)
            C, Xn = vae_contrib(vae, F, S[sel].reset_index(drop=True), Wsel)
            top = C.argmax(1)
            for j in range(len(C)):
                contrib.append({"dataset": spec["dataset"], "kind": kind, "top_input": names[top[j]],
                                "top_block": block_of(names[top[j]]), "top_share": float(C[j, top[j]] / C[j].sum()),
                                "never_seen": bool(abs(Xn[j, top[j]]) >= 10)})
        if i % 20 == 0:
            print(f"  {i}/{len(specs)}", flush=True)
    R, Cb = pd.DataFrame(rows), pd.DataFrame(contrib)

    say("\n[A] flag rate on INJECTED windows: real attacks vs NORMAL traffic injected the same way (controls)")
    say("    a control flag rate far above the 'other windows' false-alarm rate = the detector reacts to the injection")
    say(f"    {'dataset':8s} {'injected':20s} {'scen':>4s} {'windows':>8s} | {'LSTM inj':>8s} {'VAE inj':>8s} {'VAE <50%':>8s} "
        f"{'rule inj':>8s} | {'LSTM FA':>7s} {'VAE FA':>7s} {'rule FA':>7s}")
    for (ds, k), g in R.groupby(["dataset", "kind"]):
        say(f"    {ds:8s} {k:20s} {len(g):4d} {int(g.inj_windows.sum()):8,} | {g.lstm_inj.mean():8.1%} {g.vae_inj.mean():8.1%} "
            f"{g.vae_inj_low.mean():8.1%} {g.get('rule_inj', pd.Series([np.nan])).mean():8.1%} | {g.lstm_other.mean():7.2%} "
            f"{g.vae_other.mean():7.2%} {g.get('rule_other', pd.Series([np.nan])).mean():7.2%}")

    say("\n[B] what makes the VAE flag injected windows with < 50 % injected flows (top error input per window)")
    if len(Cb):
        for (ds, k), g in Cb.groupby(["dataset", "kind"]):
            blk = g.top_block.value_counts(normalize=True)
            inp = g.top_input.value_counts(normalize=True).head(5)
            say(f"    {ds:8s} {k:20s} {len(g):6,} windows | top input never seen in normal training: {g.never_seen.mean():5.1%} "
                f"| median share of error in top input {g.top_share.median():.0%}")
            say("        blocks: " + ", ".join(f"{b} {v:.0%}" for b, v in blk.items()))
            say("        inputs: " + ", ".join(f"{n} {v:.0%}" for n, v in inp.items()))

    d = os.path.join(am.DATA_ROOT, "model_results", "shortcut_checks")
    os.makedirs(d, exist_ok=True)
    R.to_csv(os.path.join(d, f"{args.lstm_run}__{args.vae_run}_scenarios.csv"), index=False)
    Cb.to_csv(os.path.join(d, f"{args.lstm_run}__{args.vae_run}_vae_drivers.csv"), index=False)
    open(os.path.join(d, f"{args.lstm_run}__{args.vae_run}.txt"), "w", encoding="utf-8").write("\n".join(out) + "\n")


if __name__ == "__main__":
    main()
