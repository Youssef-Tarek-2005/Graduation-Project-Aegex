"""
Why do the LSTM-AE / VAE reach ~100 % on some datasets? Five read-only checks on the trained models.

  1 single-feature test   ROC-AUC of every window statistic alone, and a one-threshold rule on the best one
                          (threshold from VAL benign only). If one number separates the classes, the task
                          is trivial and a perfect model score says little about the model.
  2 attack purity         share of attack flows inside test attack windows; detection by purity bin
  3 near-duplicates       share of test windows whose (rounded) statistics also occur in the train split
  4 composition           which attack class / capture makes up the test attack windows
  5 stress test           hide k = 1..32 attack flows inside real normal test windows (replacing the
                          window's last k flows) and measure detection; k = 0 gives the false-alarm rate

Usage:
    python investigate_results.py [--lstm-run lstm_ae_v8] [--vae-run vae_v5] [--datasets edge kitsune]
Writes model_results/investigation/<lstm-run>__<vae-run>.txt
"""
import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import numpy as np
import pandas as pd
import torch
from sklearn.metrics import roc_auc_score

import aegex_models as am
from aegex_models import ap

out_lines = []


def say(*a):
    s = " ".join(str(x) for x in a)
    print(s, flush=True); out_lines.append(s)


def load_F(ds, cap):
    return pd.read_parquet(os.path.join(am.PREPROCESSED, "features", ds, f"{cap}.parquet"),
                           columns=ap.FEATURES + ["is_attack", "split"])


@torch.no_grad()
def score_X(lstm, vae, X, M, dev, vmeta):
    """Score raw window tensors with LSTM-AE and VAE -> (lstm_error, vae_error)."""
    le, ve = [], []
    for b in range(0, len(X), 2048):
        x, m = torch.from_numpy(X[b:b + 2048]).to(dev), torch.from_numpy(M[b:b + 2048]).to(dev)
        r = am.lstm_batch_scores(lstm.model, x, m, am.score_agg_of(lstm.meta))
        e, z = r["error"], r["z"]
        stats = am.batch_window_stats(X[b:b + 2048], M[b:b + 2048], vmeta["input_blocks"])
        L = pd.DataFrame(z, columns=[f"z_{i}" for i in range(z.shape[1])])
        L["lstm_error"], L["lstm_error_peak"] = e, r["error_peak"]
        Xv = am.build_vae_inputs(L, stats, vmeta["input_blocks"])
        verr, _ = am.vae_score_matrix(vae.model, am.vae_normalise(vmeta, Xv), dev)
        le.append(e); ve.append(verr)
    return np.concatenate(le), np.concatenate(ve)


def main():
    a = argparse.ArgumentParser()
    a.add_argument("--lstm-run", default="lstm_ae_v8")
    a.add_argument("--vae-run", default="vae_v5")
    a.add_argument("--datasets", nargs="+", default=["edge", "kitsune"])
    a.add_argument("--stress-windows", type=int, default=2000)
    args = a.parse_args()
    dev = am.pick_device("auto")
    rng = np.random.default_rng(0)
    lstm = am.ModelBundle.load(os.path.join(am.MODELS_DIR, "lstm_ae", args.lstm_run), device=dev)
    vae = am.ModelBundle.load(os.path.join(am.MODELS_DIR, "vae", args.vae_run), device=dev)
    am.check_vae_matches_lstm(vae.meta, os.path.join(am.MODELS_DIR, "lstm_ae", args.lstm_run))
    T, lthr, vthr = int(lstm.meta["window"]), lstm.threshold, vae.threshold
    names = am.window_stat_names()

    for ds in args.datasets:
        lthr, vthr = am.threshold_for(lstm.meta, ds), am.threshold_for(vae.meta, ds)
        V = pd.read_parquet(os.path.join(am.PREPROCESSED, "model_outputs", "vae", args.vae_run, f"{ds}_windows.parquet"))
        V = V[V.split_pure & ~((V.label == 0) & (V.device_compromised == 1))].reset_index(drop=True)
        say("\n" + "=" * 90 + f"\n{ds.upper()}\n" + "=" * 90)
        stats = np.zeros((len(V), len(names)), np.float32)
        for cap, g in V.groupby("capture", sort=False):
            F = load_F(ds, cap)[ap.FEATURES].to_numpy(np.float32)
            stats[g.index.to_numpy()] = am.window_stats(F, g, T)
        te, va, tr = (V.split == "test").to_numpy(), (V.split == "val").to_numpy(), (V.split == "train").to_numpy()
        ben, att = (V.label == 0).to_numpy(), (V.label == 1).to_numpy()

        # ---- 4 composition
        say("\n[4] TEST attack windows by class / capture:")
        comp = V[te & att].groupby(["window_class", "capture"]).size().sort_values(ascending=False)
        for (c, cap), n in comp.items():
            say(f"    {c:11s} {cap:28s} {n:>8,}  ({n / comp.sum():.1%})")
        say(f"    clean benign test windows: {int((te & ben).sum()):,} from captures "
            f"{sorted(V[te & ben].capture.unique())}")

        # ---- 1 single-feature separability
        say("\n[1] single window statistic alone (test ROC-AUC, best 6):")
        y = att[te].astype(int)
        aucs = []
        for j, n in enumerate(names):
            s = stats[te, j]
            if np.std(s) < 1e-9:
                continue
            auc = roc_auc_score(y, s)
            aucs.append((max(auc, 1 - auc), n, auc >= 0.5))
        aucs.sort(reverse=True)
        for auc, n, up in aucs[:6]:
            say(f"    {n:34s} ROC-AUC {auc:.4f}  (attack {'higher' if up else 'lower'})")
        best_auc, best, up = aucs[0]
        j = names.index(best)
        vb = stats[va & ben, j]
        thr = np.quantile(vb, 0.99) if up else np.quantile(vb, 0.01)
        flag = stats[:, j] > thr if up else stats[:, j] < thr
        say(f"    ONE-LINE RULE on '{best}' (threshold from val benign): detection {flag[te & att].mean():.4f} | "
            f"false alarms {flag[te & ben].mean():.4f}")
        say(f"    for comparison  LSTM-AE: detection {V.lstm_anomaly[te & att].mean():.4f} false alarms "
            f"{V.lstm_anomaly[te & ben].mean():.4f} | VAE: detection {V.vae_anomaly[te & att].mean():.4f} "
            f"false alarms {V.vae_anomaly[te & ben].mean():.4f}")
        n95 = sum(1 for x in aucs if x[0] >= 0.95)
        say(f"    window statistics that alone reach ROC-AUC >= 0.95: {n95} of {len(aucs)}")

        # ---- 2 attack purity
        say("\n[2] attack purity of TEST attack windows (share of attack flows in the window):")
        af = V.attack_frac[te & att]
        bins = [0, .25, .5, .75, .9999, 1.0001]
        lab = ["<25 %", "25-50 %", "50-75 %", "75-<100 %", "100 % (pure attack)"]
        cut = pd.cut(af, bins, labels=lab, include_lowest=True)
        g = V[te & att].assign(bin=cut.values).groupby("bin", observed=False)
        for b, gg in g:
            if len(gg):
                say(f"    {b:20s} {len(gg):>8,} windows ({len(gg) / len(af):6.1%}) | LSTM det {gg.lstm_anomaly.mean():.3f} "
                    f"| VAE det {gg.vae_anomaly.mean():.3f}")

        # ---- 3 near-duplicates
        say("\n[3] near-duplicates (window statistics rounded to 2 decimals):")
        key = pd.util.hash_pandas_object(pd.DataFrame(np.round(stats, 2)), index=False).to_numpy()
        for nm, m in [("benign", ben), ("attack", att)]:
            trk = set(key[tr & m])
            tk = key[te & m]
            say(f"    test {nm:6s} windows identical to a TRAIN {nm} window: {np.isin(tk, list(trk)).mean():6.1%} "
                f"| distinct test {nm} windows: {len(set(tk)):,} of {len(tk):,}")

        # ---- 5 stress test: hide k attack flows inside normal windows
        say(f"\n[5] stress test: k attack flows hidden at the end of a real normal test window "
            f"({args.stress_windows} windows; global thresholds)")
        Bw = V[te & ben & (V.n_flows == T)]
        Bw = Bw.sample(min(len(Bw), args.stress_windows), random_state=0)
        pool = []
        for cap, gcap in V[te & att].groupby("capture"):
            F = load_F(ds, cap)
            rows = F[(F.split == "test") & (F.is_attack == 1)][ap.FEATURES].to_numpy(np.float32)
            if len(rows):
                pool.append((cap, rows))
        if not pool or not len(Bw):
            say("    (not enough data)"); continue
        base = np.zeros((len(Bw), T, len(ap.FEATURES)), np.float32)
        for cap, g in Bw.reset_index(drop=True).groupby("capture"):
            F = load_F(ds, cap)[ap.FEATURES].to_numpy(np.float32)
            for i, (s, e) in zip(g.index, zip(g.row_start, g.row_end)):
                base[i] = F[s:e]
        M = np.ones((len(Bw), T), bool)
        say("    k  attack share   " + "  ".join(f"{cap[:18]:>18s}" for cap, _ in pool))
        for k in [0, 1, 2, 4, 8, 16, 32]:
            cells = []
            for cap, rows in pool:
                X = base.copy()
                if k:
                    X[:, T - k:, :] = rows[rng.integers(0, len(rows), size=(len(X), k))]
                le, ve = score_X(lstm, vae, X, M, dev, vae.meta)
                either = ((le >= lthr) | (ve >= vthr)).mean()
                cells.append(f"L{(le >= lthr).mean():.2f} V{(ve >= vthr).mean():.2f}")
                if k == 0:
                    break
            label = "false alarms" if k == 0 else f"{k / T:5.0%} attack"
            say(f"   {k:2d}  {label:13s}  " + "  ".join(f"{c:>18s}" for c in cells))
        say("    (L = LSTM-AE flagged share, V = VAE flagged share; columns = which attack capture the flows came from)")

    path = os.path.join(am.DATA_ROOT, "model_results", "investigation")
    os.makedirs(path, exist_ok=True)
    open(os.path.join(path, f"{args.lstm_run}__{args.vae_run}.txt"), "w", encoding="utf-8").write("\n".join(out_lines) + "\n")


if __name__ == "__main__":
    main()
