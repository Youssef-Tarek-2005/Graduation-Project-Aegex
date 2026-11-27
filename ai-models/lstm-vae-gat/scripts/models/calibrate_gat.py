"""
Benign-calibration test for networks the GAT never trained on (default: gat_v5 on kitsune + edge).

The GAT itself is NOT retrained. Only what a real deployment can do on a new network with a short
attack-free warm-up recording (no attack labels) is changed:

  pooled        what the bundle does today: the pooled threshold from the training networks
  thr           GAT threshold = 99th pct of host scores in the network's own ATTACK-FREE val snapshots
  thr+norm      also re-standardise the GAT's node / edge inputs with mean / std from the network's own
                attack-free TRAIN snapshots (adaptive normalisation, like AdaBN)

The LSTM-AE / VAE stages for these networks (lstm_ae_v8 / vae_v5) already use alarm lines from each
network's own normal traffic, so the GAT threshold + input scale are the parts left uncalibrated.
Attack-free = no host in the snapshot is an attack source or target. Only test data is scored.

Usage:
    python calibrate_gat.py [--run gat_v5] [--datasets kitsune edge] [--out gat_v5_calibrated]
"""
import argparse
import json
import os
import pickle
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import numpy as np
import pandas as pd

import aegex_bench as ab
import aegex_gat as ag
import aegex_models as am
from aegex_models import ap
import train_gat as tg


def snaps_attack_free(seqs):
    """Keep only snapshots with no involved host (an attack-free warm-up recording)."""
    out = []
    for s in seqs:
        keep = [sn for sn in s["snaps"] if not sn["y_node"].any()]
        if keep:
            out.append({**s, "snaps": keep})
    return out


def adapted_norm(seqs, base, blocks, vae_latent, drop_idx):
    nm, ns, em, es = base
    X = np.concatenate([ag.select_blocks(sn["x"], s["feat_cols"], blocks, vae_latent) for s in seqs for sn in s["snaps"]])
    Ef = np.concatenate([sn["e"] for s in seqs for sn in s["snaps"] if len(sn["e"])])
    Ef = np.concatenate([Ef, np.zeros((len(Ef), 1), np.float32)], 1)
    nmean, nstd = X.mean(0), X.std(0)
    emean, estd = Ef.mean(0), Ef.std(0)
    # inputs that never vary in the warm-up (std ~0) keep the training scale, so they do not blow up
    nstd = np.where(nstd < 1e-6, ns, nstd); nmean = np.where(X.std(0) < 1e-6, nm, nmean)
    bad = estd < 1e-6
    estd = np.where(bad, es, estd); emean = np.where(bad, em, emean)
    emean[-1], estd[-1] = 0.0, 1.0
    return (nmean.astype(np.float32), nstd.astype(np.float32), emean.astype(np.float32), estd.astype(np.float32))


def main():
    a = argparse.ArgumentParser()
    a.add_argument("--run", default="gat_v5")
    a.add_argument("--datasets", nargs="+", default=["kitsune", "edge"])
    a.add_argument("--out", default=None)
    a.add_argument("--fpr", type=float, default=0.01)
    a.add_argument("--device", default="auto")
    a.add_argument("--rebuild", action="store_true")
    args = a.parse_args()
    out = args.out or f"{args.run}_calibrated"
    dev = am.pick_device(args.device)
    bdir = os.path.join(am.MODELS_DIR, "gat", args.run)
    b = am.ModelBundle.load(bdir, device=dev)
    model, meta = b.model, b.meta
    model.eval()
    blocks, vae_latent = meta["node_blocks"], int(meta["vae_latent"])
    rel = bool(meta.get("relative_scores"))
    drop = meta.get("dropped_edge_features", [])
    base_norm = tuple(np.asarray(meta["norm"][k], np.float32) for k in ("node_mean", "node_std", "edge_mean", "edge_std"))
    pooled = float(meta["threshold"])
    up = meta["upstream_per_dataset"]
    loaded = {}
    chains = {ds: tg.Chain(up[ds]["lstm_run"], up[ds]["vae_run"], dev, loaded) for ds in args.datasets}
    tg.log(f"{args.run}: trained on {meta['train_datasets']} | calibrating {args.datasets} | pooled threshold {pooled:.4f}")

    cache = os.path.join(am.PREPROCESSED, "gat_inputs", f"calib__{'_'.join(args.datasets)}.pkl")
    if os.path.exists(cache) and not args.rebuild:
        data = pickle.load(open(cache, "rb")); tg.log(f"loaded {cache}")
    else:
        data = {}
        for ds in args.datasets:
            ch = chains[ds]
            data[ds] = tg.dataset_sequences(ds, ch.lstm_run, ch.vae_run, vae_latent, ch if rel else None)
            tg.log(f"[{ds}] dataset sequences " + ", ".join(f"{k} {len(v)}" for k, v in data[ds].items()))
        data["bench"] = tg.scenario_sequences("test", args.datasets, chains, dev, 2, [1, 10, 100], 300, vae_latent, rel)
        cargs = argparse.Namespace(datasets=args.datasets, test_datasets=[], n_attack=300, rebuild=True, relative_scores=rel)
        data["control"] = tg.control_inputs(cargs, chains, dev, vae_latent, cache.replace(".pkl", "__controls.pkl"))
        os.makedirs(os.path.dirname(cache), exist_ok=True)
        pickle.dump(data, open(cache, "wb"), protocol=4)
    # same edge inputs as the bundle
    allseq = {"x": [s for ds in args.datasets for k in ("train", "val", "test") for s in data[ds][k]] + data["bench"] + data["control"]}
    names = tg.mask_edge_features(allseq, drop)
    assert names == meta["edge_features"][:-1] or names == meta["edge_features"], "edge inputs differ from the bundle"

    rows, lines = {}, []
    lines += [f"BENIGN-CALIBRATION TEST: GAT '{args.run}' (not retrained) on networks it never trained on: {args.datasets}",
              f"trained on {meta['train_datasets']}; LSTM-AE / VAE per network: " +
              ", ".join(f"{ds}={chains[ds].lstm_run}/{chains[ds].vae_run}" for ds in args.datasets),
              "warm-up = attack-free snapshots (no involved host) of the network's own TRAIN (input scale) and VAL",
              f"(threshold = {1 - args.fpr:.0%} pct of host scores) splits - no attack labels needed in a deployment.",
              "Scored on TEST only: realistic benchmark (attacks injected into normal traffic), the dataset test split,",
              "and CONTROL injections (normal traffic injected like an attack; should be flagged at about the FA rate).",
              "Benchmark scenarios are built for these networks only, so absolute numbers can differ slightly from",
              f"{args.run}'s own evaluation; the three columns are compared on the same scenarios.", ""]
    for ds in args.datasets:
        warm_tr, warm_va = snaps_attack_free(data[ds]["train"]), snaps_attack_free(data[ds]["val"])
        nwt = sum(len(s["snaps"]) for s in warm_tr); nwv = sum(len(s["snaps"]) for s in warm_va)
        variants = {"pooled": base_norm, "thr": base_norm}
        if nwt:
            variants["thr+norm"] = adapted_norm(warm_tr, base_norm, blocks, vae_latent, None)
        bench = [s for s in data["bench"] if s["meta"]["dataset"] == ds]
        ctrl = [s for s in data["control"] if s["meta"]["dataset"] == ds]
        res = {}
        for v, norm in variants.items():
            if v == "pooled":
                t = pooled
            else:
                Nw, _ = tg.collect(model, warm_va, norm, dev, blocks, vae_latent)
                t = float(np.quantile(Nw.p_involved, 1 - args.fpr))
            thr = {"_all": t}
            _, rb = tg.node_report(tg.collect(model, bench, norm, dev, blocks, vae_latent)[0], thr, "")
            _, rt = tg.node_report(tg.collect(model, data[ds]["test"], norm, dev, blocks, vae_latent)[0], thr, "")
            r = {"threshold": t, "benchmark": rb.get(ds, {}), "dataset_test": rt.get(ds, {})}
            if ctrl:
                Nc, _ = tg.collect(model, ctrl, norm, dev, blocks, vae_latent)
                r["controls"] = {att: {"injected": tg.rate(g[g.y_involved == 1].p_involved >= t),
                                       "other": tg.rate(g[g.y_involved == 0].p_involved >= t)}
                                 for att, g in Nc.groupby("attack")}
            res[v] = r
            tg.log(f"[{ds}] {v:8s} thr {t:.4f} | bench det {r['benchmark'].get('gat_detection', float('nan')):.1%} "
                   f"FA {r['benchmark'].get('gat_false_alarms', float('nan')):.2%}")
        rows[ds] = {"warmup_train_snapshots": nwt, "warmup_val_snapshots": nwv, **res}
        lines.append(f"{ds}: warm-up {nwt:,} train + {nwv:,} val attack-free snapshots")
        lines.append(f"  {'variant':9s} {'thresh':>7s} | {'bench det':>9s} {'bench FA':>8s} {'ROC-AUC':>7s} {'top-1':>6s} | "
                     f"{'split det':>9s} {'split FA':>8s} | {'ctrl inj':>8s} {'ctrl oth':>8s}")
        for v, r in res.items():
            B, T = r["benchmark"], r["dataset_test"]
            c = r.get("controls", {})
            ci = np.nanmean([x["injected"] for x in c.values()]) if c else float("nan")
            co = np.nanmean([x["other"] for x in c.values()]) if c else float("nan")
            lines.append(f"  {v:9s} {r['threshold']:7.4f} | {B.get('gat_detection', np.nan):9.1%} {B.get('gat_false_alarms', np.nan):8.2%} "
                         f"{B.get('roc_auc', np.nan):7.4f} {B.get('top1_source_attribution', np.nan):6.1%} | "
                         f"{T.get('gat_detection', np.nan):9.1%} {T.get('gat_false_alarms', np.nan):8.2%} | {ci:8.1%} {co:8.2%}")
        B = res["pooled"]["benchmark"]
        lines.append(f"  stage-1/2 baseline (LSTM or VAE flag): bench det {B.get('baseline_detection', np.nan):.1%} "
                     f"FA {B.get('baseline_false_alarms', np.nan):.2%}")
        lines.append("")
    text = "\n".join(lines) + "\n"
    rdir = os.path.join(am.DATA_ROOT, "model_results", "gat", out)
    os.makedirs(rdir, exist_ok=True)
    open(os.path.join(rdir, "evaluation.txt"), "w", encoding="utf-8").write(text)
    json.dump({"run": args.run, "datasets": args.datasets, "results": rows}, open(os.path.join(rdir, "metrics.json"), "w"),
              indent=1, default=float)
    print(text)


if __name__ == "__main__":
    main()
