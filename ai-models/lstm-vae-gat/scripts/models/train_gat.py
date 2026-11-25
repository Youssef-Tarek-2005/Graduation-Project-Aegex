"""
Train + evaluate the stage-3 temporal GAT on top of an LSTM-AE run and its VAE run.

Data (graph snapshot sequences, 60 s snapshots, host memory carried through each sequence)
  dataset graphs     step-3 graphs of every capture, cut into train / val / test runs of snapshots
                     (snapshot split = majority split of its edges)
  benchmark graphs   mixed scenarios from aegex_bench (attacks injected into normal traffic):
                     train-phase scenarios -> training, val-phase -> early stopping + thresholds,
                     test-phase (same scenarios as benchmark.py) -> the realistic evaluation
  node inputs        traffic aggregates + LSTM-AE / VAE outputs of the host's windows in that snapshot
                     (computed with the given LSTM / VAE bundles, so the GAT sees exactly what the
                     deployed stages output)
Thresholds          per dataset, 99th pct of NON-involved node scores in val data (~1 % false alarms
                     per host-snapshot); edge threshold likewise on benign val edges
Evaluation (test only)
  node level         involved host = attack source or target in the snapshot; detection / false alarms
                     vs the stage-1/2 baseline "host has a flagged LSTM or VAE window in the snapshot"
  roles              source vs target: share of detected attack hosts given the right role; top-1
                     attribution = the host ranked most likely source is the true source
  incidents          scenarios with >= 1 alert on an involved host during the attack
  edges              detection of attack-carrying host pairs

Usage:
    python train_gat.py [--lstm-run lstm_ae_v8] [--vae-run vae_v5] [--run gat_v1] [--epochs 20]
                        [--node-blocks traffic stage latent] [--rebuild]
"""
import argparse
import json
import os
import pickle
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import numpy as np
import pandas as pd
import torch
import torch.nn.functional as Fn
from sklearn.metrics import average_precision_score, roc_auc_score

import aegex_bench as ab
import aegex_gat as ag
import aegex_models as am
from aegex_models import ap


def log(*a):
    print(time.strftime("%H:%M:%S"), *a, flush=True)


# ------------------------------------------------------------------------------------------ data
def dataset_sequences(ds, lstm_run, vae_run, vae_latent):
    """Step-3 graphs of a dataset -> {split: [sequence, ...]} with stage outputs attached."""
    gdir = os.path.join(am.PREPROCESSED, "graphs", ds)
    ln = pd.read_parquet(os.path.join(am.PREPROCESSED, "model_outputs", "lstm_ae", lstm_run, f"{ds}_node_snapshots.parquet"))
    vn = pd.read_parquet(os.path.join(am.PREPROCESSED, "model_outputs", "vae", vae_run, f"{ds}_node_snapshots.parquet"))
    ln = ln[["capture", "snapshot", "node", "lstm_max_score", "lstm_mean_score", "lstm_n_windows", "lstm_any_anomaly"]]
    st = ln.merge(vn, on=["capture", "snapshot", "node"], how="outer")
    out = {"train": [], "val": [], "test": []}
    for cap in json.load(open(os.path.join(gdir, "_summary.json"))):
        E = pd.read_parquet(os.path.join(gdir, f"{cap}_edges.parquet"))
        N = pd.read_parquet(os.path.join(gdir, f"{cap}_nodes.parquet"))
        sq = ag.snapshot_sequence(E, N, st[st.capture == cap], vae_latent, f"{ds}/{cap}",
                                  {"dataset": ds, "source": "dataset", "capture": cap})
        run, cur = [], None                       # cut into consecutive runs of one split; splits only move
        order = {"train": 0, "val": 1, "test": 2}  # forward in time (train -> val -> test), so snapshots near
        for s in sq["snaps"]:                     # a boundary with mixed edges do not flip back and forth
            sp = s["split"] or cur or "train"
            if cur is not None and order.get(sp, 0) < order[cur]:
                sp = cur
            if cur is not None and sp != cur and run:
                out[cur].append({**sq, "snaps": run, "meta": {**sq["meta"], "split": cur}}); run = []
            cur = sp; run.append(s)
        if run:
            out[cur].append({**sq, "snaps": run, "meta": {**sq["meta"], "split": cur}})
    return out


def scenario_sequences(phase, datasets, lstm, vae, dev, reps, slowdowns, n_attack, vae_latent):
    T, S_, snap = int(lstm.meta["window"]), int(lstm.meta["stride"]), float(lstm.meta["snapshot_seconds"])
    specs = ab.scenario_specs(phase, datasets, slowdowns, reps, n_attack)
    seqs = []
    for i, spec in enumerate(specs, 1):
        sc = ab.build_scenario(spec, ap.RobustScaler.from_dict(lstm.meta["scalers"][spec["dataset"]]), T, S_, snap)
        scored = ab.score_scenario(sc, lstm, vae, dev)
        stage = ag.node_stage_table(scored, sc["info"]["t0"], snap)
        info = {k: v for k, v in sc["info"].items()}
        info.update(source="benchmark", split=phase)
        seqs.append(ag.snapshot_sequence(sc["edges"], sc["nodes"], stage, vae_latent, spec["id"], info))
        if i % 25 == 0 or i == len(specs):
            log(f"  [{phase}] {i}/{len(specs)} scenarios")
    return seqs


def build_inputs(args, lstm, vae, dev, vae_latent, cache):
    if os.path.exists(cache) and not args.rebuild:
        log(f"loading cached graph inputs {cache}")
        return pickle.load(open(cache, "rb"))
    data = {"train": [], "val": [], "test": [], "test_bench": []}
    for ds in args.datasets:
        d = dataset_sequences(ds, args.lstm_run, args.vae_run, vae_latent)
        for k in ("train", "val", "test"):
            data[k] += d[k]
        log(f"[{ds}] dataset graph sequences: " + ", ".join(f"{k} {len(v)}" for k, v in d.items()))
    data["train"] += scenario_sequences("train", args.datasets, lstm, vae, dev, 2, args.slowdowns, args.n_attack, vae_latent)
    data["val"] += scenario_sequences("val", args.datasets, lstm, vae, dev, 1, args.slowdowns, args.n_attack, vae_latent)
    data["test_bench"] = scenario_sequences("test", args.datasets, lstm, vae, dev, 2, args.slowdowns, args.n_attack, vae_latent)
    os.makedirs(os.path.dirname(cache), exist_ok=True)
    pickle.dump(data, open(cache, "wb"), protocol=4)
    return data


def control_inputs(args, lstm, vae, dev, vae_latent, cache):
    """Test-phase CONTROL scenarios: normal traffic injected exactly like an attack (aegex_bench.CONTROL_KINDS).
    Its 'involved' hosts did nothing abnormal, so the GAT should flag them only at its false-alarm rate."""
    if os.path.exists(cache) and not args.rebuild:
        return pickle.load(open(cache, "rb"))
    T, S_, snap = int(lstm.meta["window"]), int(lstm.meta["stride"]), float(lstm.meta["snapshot_seconds"])
    seqs = []
    for spec in ab.scenario_specs("test", args.datasets, (1,), 2, args.n_attack, controls=ab.CONTROL_KINDS, attacks=False):
        if spec["attack_capture"] is None:
            continue
        sc = ab.build_scenario(spec, ap.RobustScaler.from_dict(lstm.meta["scalers"][spec["dataset"]]), T, S_, snap)
        scored = ab.score_scenario(sc, lstm, vae, dev)
        info = dict(sc["info"]); info.update(source="control", split="test")
        seqs.append(ag.snapshot_sequence(sc["edges"], sc["nodes"], ag.node_stage_table(scored, sc["info"]["t0"], snap),
                                         vae_latent, spec["id"], info))
    log(f"control scenarios: {len(seqs)}")
    pickle.dump(seqs, open(cache, "wb"), protocol=4)
    return seqs


def capture_classes(datasets):
    """{(dataset, capture): set of attack classes in the capture} from the step-3 window tables."""
    out = {}
    for ds in datasets:
        W = pd.read_parquet(os.path.join(am.PREPROCESSED, "windows", f"{ds}.parquet"), columns=["capture", "window_class"])
        for cap, g in W.groupby("capture"):
            out[(ds, cap)] = set(g.window_class.unique()) - {"benign", None}
    return out


def drop_holdout(data, holdout, datasets):
    """Remove every train / val sequence that contains the held-out attack class (benchmark scenarios of that
    class and dataset captures that contain it). Test data is untouched: the class is then UNSEEN."""
    cc = capture_classes(datasets)
    for k in ("train", "val"):
        keep = []
        for sq in data[k]:
            m = sq["meta"]
            if m.get("source") == "benchmark" and m.get("attack_class") == holdout:
                continue
            if m.get("source") == "dataset" and holdout in cc.get((m["dataset"], m.get("capture")), set()):
                continue
            keep.append(sq)
        log(f"holdout '{holdout}': {k} {len(data[k])} -> {len(keep)} sequences")
        data[k] = keep
    return data


# ------------------------------------------------------------------------------------------ eval helpers
def collect(model, seqs, norm, dev, blocks, vae_latent):
    """Run sequences -> node table + edge table (scores, labels, baseline flags, ids)."""
    nrows, erows = [], []
    model.eval()
    with torch.no_grad():
        for sq in seqs:
            outs = ag.run_sequence(model, sq, norm, dev, train=False, blocks=blocks, vae_latent=vae_latent)
            fc = sq["feat_cols"]
            li, vi = fc.index("lstm_any_anomaly"), fc.index("vae_any_anomaly")
            m = sq["meta"]
            for s, (pn, pe) in zip(sq["snaps"], outs):
                n = len(s["nid"])
                nrows.append(pd.DataFrame({
                    "seq": sq["name"], "dataset": m["dataset"], "source": m["source"], "split": m.get("split"),
                    "attack": m.get("attack_class"), "slowdown": m.get("slowdown"), "snapshot": s["snapshot"],
                    "node": np.array(sq["hosts"], dtype=object)[s["nid"]],
                    "p_source": pn[:, 0], "p_target": pn[:, 1],
                    "y_source": s["y_node"][:, 0], "y_target": s["y_node"][:, 1],
                    "baseline": ((s["x"][:, li] > 0) | (s["x"][:, vi] > 0)).astype(np.int8)}))
                if len(s["src"]):
                    erows.append(pd.DataFrame({"seq": sq["name"], "dataset": m["dataset"], "source": m["source"],
                                               "snapshot": s["snapshot"], "p_edge": pe, "y_edge": s["y_edge"]}))
    N = pd.concat(nrows, ignore_index=True)
    N["p_involved"] = N[["p_source", "p_target"]].max(axis=1)
    N["y_involved"] = ((N.y_source + N.y_target) > 0).astype(np.int8)
    E = pd.concat(erows, ignore_index=True) if erows else pd.DataFrame(columns=["p_edge", "y_edge", "dataset"])
    return N, E


def rate(x):
    return float(np.mean(x)) if len(x) else float("nan")


def node_report(N, thr, title):
    """Lines + dict comparing GAT vs stage-1/2 baseline on a node table."""
    L, res = [title], {}
    L.append(f"  {'dataset':8s} {'involved':>9s} {'other':>9s} | {'GAT det':>8s} {'GAT FA':>7s} {'base det':>8s} {'base FA':>8s} | "
             f"{'src det':>7s} {'tgt det':>7s} {'role ok':>7s} {'top-1 src':>9s} | {'ROC-AUC':>7s} {'PR-AUC':>7s}")
    for ds, D in N.groupby("dataset"):
        t = thr.get(ds, thr["_all"])
        flag = (D.p_involved >= t).to_numpy()
        inv, oth = D.y_involved.to_numpy() == 1, D.y_involved.to_numpy() == 0
        src, tgt = D.y_source.to_numpy() == 1, D.y_target.to_numpy() == 1
        role_pred_src = (D.p_source >= D.p_target).to_numpy()
        det_inv = flag & inv
        role_ok = rate(np.where(src[det_inv] & ~tgt[det_inv], role_pred_src[det_inv],
                                np.where(tgt[det_inv] & ~src[det_inv], ~role_pred_src[det_inv], True)))
        top1 = []
        for _, g in D.groupby(["seq", "snapshot"]):
            if g.y_source.max() == 1:
                top1.append(g.y_source.to_numpy()[g.p_source.to_numpy().argmax()] == 1)
        auc = roc_auc_score(inv, D.p_involved) if 0 < inv.sum() < len(inv) else float("nan")
        ap_ = average_precision_score(inv, D.p_involved) if inv.any() else float("nan")
        r = {"involved": int(inv.sum()), "other": int(oth.sum()), "gat_detection": rate(flag[inv]), "gat_false_alarms": rate(flag[oth]),
             "baseline_detection": rate(D.baseline.to_numpy()[inv] == 1), "baseline_false_alarms": rate(D.baseline.to_numpy()[oth] == 1),
             "source_detection": rate(flag[src]), "target_detection": rate(flag[tgt]), "role_correct": role_ok,
             "top1_source_attribution": rate(top1), "roc_auc": float(auc), "pr_auc": float(ap_), "threshold": t}
        res[ds] = r
        L.append(f"  {ds:8s} {r['involved']:9,} {r['other']:9,} | {r['gat_detection']:8.1%} {r['gat_false_alarms']:7.2%} "
                 f"{r['baseline_detection']:8.1%} {r['baseline_false_alarms']:8.2%} | {r['source_detection']:7.1%} "
                 f"{r['target_detection']:7.1%} {r['role_correct']:7.1%} {r['top1_source_attribution']:9.1%} | "
                 f"{r['roc_auc']:7.4f} {r['pr_auc']:7.4f}")
    return L, res


# ------------------------------------------------------------------------------------------ main
def main():
    a = argparse.ArgumentParser()
    a.add_argument("--lstm-run", default="lstm_ae_v8")
    a.add_argument("--vae-run", default="vae_v5")
    a.add_argument("--run", default="gat_v1")
    a.add_argument("--datasets", nargs="+", default=ap.ACTIVE_DATASETS)
    a.add_argument("--node-blocks", nargs="+", default=list(ag.NODE_BLOCKS), choices=ag.NODE_BLOCKS)
    a.add_argument("--hidden", type=int, default=64)
    a.add_argument("--heads", type=int, default=4)
    a.add_argument("--layers", type=int, default=2)
    a.add_argument("--dropout", type=float, default=0.1)
    a.add_argument("--epochs", type=int, default=20)
    a.add_argument("--patience", type=int, default=4)
    a.add_argument("--lr", type=float, default=1e-3)
    a.add_argument("--chunk", type=int, default=32, help="snapshots per truncated-BPTT step")
    a.add_argument("--fpr", type=float, default=0.01)
    a.add_argument("--slowdowns", type=float, nargs="+", default=[1, 10, 100])
    a.add_argument("--n-attack", type=int, default=300)
    a.add_argument("--rebuild", action="store_true", help="rebuild the cached graph inputs")
    a.add_argument("--holdout", default=None, help="attack class left out of train + val (unseen-attack test)")
    a.add_argument("--eval-only", action="store_true", help="load models/gat/<run> and only evaluate")
    a.add_argument("--device", default="auto")
    a.add_argument("--seed", type=int, default=0)
    args = a.parse_args()
    torch.manual_seed(args.seed); rng = np.random.default_rng(args.seed)
    dev = am.pick_device(args.device)
    ldir = os.path.join(am.MODELS_DIR, "lstm_ae", args.lstm_run)
    vdir = os.path.join(am.MODELS_DIR, "vae", args.vae_run)
    lstm, vae = am.ModelBundle.load(ldir, device=dev), am.ModelBundle.load(vdir, device=dev)
    am.check_vae_matches_lstm(vae.meta, ldir)
    vae_latent = int(vae.meta["init"]["latent"])
    cache = os.path.join(am.PREPROCESSED, "gat_inputs", f"{args.lstm_run}__{args.vae_run}.pkl")
    data = build_inputs(args, lstm, vae, dev, vae_latent, cache)
    data["test_control"] = control_inputs(args, lstm, vae, dev, vae_latent, cache.replace(".pkl", "__controls.pkl"))
    if args.holdout:
        data = drop_holdout(data, args.holdout, args.datasets)
    for k, v in data.items():
        log(f"{k:10s} {len(v):4d} sequences, {sum(len(s['snaps']) for s in v):7,} snapshots, "
            f"{sum(int(sum(sn['y_node'][:, 0].sum() for sn in s['snaps'])) for s in v):7,} source host-snapshots")
    blocks = args.node_blocks
    bdir = os.path.join(am.MODELS_DIR, "gat", args.run)
    if args.eval_only:
        b = am.ModelBundle.load(bdir, device=dev)
        model, meta = b.model, b.meta
        model.eval()
        blocks = meta["node_blocks"]
        nm_ = meta["norm"]
        norm = tuple(np.asarray(nm_[k], np.float32) for k in ("node_mean", "node_std", "edge_mean", "edge_std"))
        thr = {"_all": meta["threshold"], **meta["per_dataset_thresholds"]}
        ethr, hist = meta["edge_thresholds"], meta["history"]
        log(f"eval-only: loaded {bdir}")
    else:
        model, meta, norm, thr, ethr, hist = train(args, data, blocks, vae_latent, dev, rng, ldir, vdir, lstm, bdir)
    evaluate(args, model, data, norm, thr, ethr, hist, blocks, vae_latent, dev)


def train(args, data, blocks, vae_latent, dev, rng, ldir, vdir, lstm, bdir):
    # ---------------------------------------------------------------- normalisation (train only)
    X = np.concatenate([ag.select_blocks(sn["x"], s["feat_cols"], blocks, vae_latent) for s in data["train"] for sn in s["snaps"]])
    Ef = np.concatenate([sn["e"] for s in data["train"] for sn in s["snaps"] if len(sn["e"])])
    Ef = np.concatenate([Ef, np.zeros((len(Ef), 1), np.float32)], 1)
    nmean, nstd = X.mean(0), X.std(0); nstd[nstd < 1e-6] = 1
    emean, estd = Ef.mean(0), Ef.std(0); estd[estd < 1e-6] = 1; emean[-1], estd[-1] = 0.0, 1.0
    norm = (nmean, nstd, emean, estd)
    Yn = np.concatenate([sn["y_node"] for s in data["train"] for sn in s["snaps"]])
    Ye = np.concatenate([sn["y_edge"] for s in data["train"] for sn in s["snaps"]])
    pw_n = torch.tensor(np.clip((1 - Yn.mean(0)) / np.maximum(Yn.mean(0), 1e-6), 1, 50), dtype=torch.float32, device=dev)
    pw_e = torch.tensor(float(np.clip((1 - Ye.mean()) / max(Ye.mean(), 1e-6), 1, 50)), device=dev)
    log(f"node inputs {X.shape[1]} ({blocks}) | edge inputs {Ef.shape[1]} | pos-weights node {pw_n.tolist()} edge {pw_e.item():.1f}")
    del X, Ef

    def loss_fn(logits, el, s):
        y = torch.from_numpy(s["y_node"]).to(dev)
        l = Fn.binary_cross_entropy_with_logits(logits, y, pos_weight=pw_n)
        if len(el):
            l = l + 0.5 * Fn.binary_cross_entropy_with_logits(el, torch.from_numpy(s["y_edge"]).to(dev), pos_weight=pw_e)
        return l

    # ---------------------------------------------------------------- train
    model = ag.TemporalGAT(len(ag.node_feature_names(blocks, vae_latent)), len(ag.EDGE_FEATURES), args.hidden,
                           args.heads, args.layers, args.dropout).to(dev)
    opt = torch.optim.Adam(model.parameters(), lr=args.lr, weight_decay=1e-5)
    best, best_state, bad, hist = -np.inf, None, 0, []
    for ep in range(1, args.epochs + 1):
        t0 = time.time(); model.train(); tot = 0.0; ns = 0
        for i in rng.permutation(len(data["train"])):
            sq = data["train"][i]
            tot += ag.run_sequence(model, sq, norm, dev, train=True, chunk=args.chunk, loss_fn=loss_fn, opt=opt,
                                   blocks=blocks, vae_latent=vae_latent)
            ns += len(sq["snaps"])
        Nv, _ = collect(model, data["val"], norm, dev, blocks, vae_latent)
        vap = average_precision_score(Nv.y_involved, Nv.p_involved) if Nv.y_involved.any() else 0.0
        hist.append({"epoch": ep, "train_loss": tot / max(ns, 1), "val_pr_auc": float(vap), "seconds": round(time.time() - t0, 1)})
        log(f"epoch {ep:3d} train loss {tot / max(ns, 1):.4f} | val node PR-AUC {vap:.4f} ({time.time() - t0:.0f}s)")
        if vap > best + 1e-4:
            best, bad, best_state = vap, 0, {k: v.detach().cpu().clone() for k, v in model.state_dict().items()}
        else:
            bad += 1
            if bad >= args.patience:
                log("early stop"); break
    model.load_state_dict(best_state); model.eval()

    # ---------------------------------------------------------------- thresholds (val only)
    Nv, Ev = collect(model, data["val"], norm, dev, blocks, vae_latent)
    neg = Nv[Nv.y_involved == 0]
    thr = {"_all": float(np.quantile(neg.p_involved, 1 - args.fpr))}
    thr.update({ds: float(np.quantile(g.p_involved, 1 - args.fpr)) for ds, g in neg.groupby("dataset") if len(g) >= 50})
    eneg = Ev[Ev.y_edge == 0]
    ethr = {"_all": float(np.quantile(eneg.p_edge, 1 - args.fpr))} if len(eneg) else {"_all": 0.5}
    ethr.update({ds: float(np.quantile(g.p_edge, 1 - args.fpr)) for ds, g in eneg.groupby("dataset") if len(g) >= 50})
    log(f"node thresholds {thr} | edge thresholds {ethr}")

    meta = {"bundle_format": am.BUNDLE_FORMAT, "model_type": "temporal_gat", "run": args.run, "created": am.now_iso(),
            "torch": torch.__version__,
            "init": {"n_node": len(ag.node_feature_names(blocks, vae_latent)), "n_edge": len(ag.EDGE_FEATURES),
                     "hidden": args.hidden, "heads": args.heads, "layers": args.layers, "dropout": args.dropout},
            "node_blocks": blocks, "node_features": ag.node_feature_names(blocks, vae_latent), "edge_features": ag.EDGE_FEATURES,
            "vae_latent": vae_latent, "norm": {"node_mean": nmean.tolist(), "node_std": nstd.tolist(),
                                               "edge_mean": emean.tolist(), "edge_std": estd.tolist()},
            "threshold": thr["_all"], "threshold_mode": "per_dataset", "per_dataset_thresholds": {k: v for k, v in thr.items() if k != "_all"},
            "edge_thresholds": ethr, "snapshot_seconds": float(lstm.meta["snapshot_seconds"]),
            "upstream": {"lstm_run": args.lstm_run, "lstm_model_sha256": am.file_sha256(os.path.join(ldir, "model.pt")),
                         "vae_run": args.vae_run, "vae_model_sha256": am.file_sha256(os.path.join(vdir, "model.pt"))},
            "pipeline": am.pipeline_fingerprint(), "history": hist, "train_datasets": args.datasets,
            "hparams": {"lr": args.lr, "chunk": args.chunk, "seed": args.seed, "fpr": args.fpr},
            "holdout_attack": args.holdout}
    am.ModelBundle(model, meta).save(bdir)
    log(f"saved bundle -> {bdir}")
    return model, meta, norm, thr, ethr, hist


def evaluate(args, model, data, norm, thr, ethr, hist, blocks, vae_latent, dev):
    # ---------------------------------------------------------------- evaluate (test only) + export
    rdir = os.path.join(am.DATA_ROOT, "model_results", "gat", args.run)
    odir = os.path.join(am.PREPROCESSED, "model_outputs", "gat", args.run)
    os.makedirs(rdir, exist_ok=True); os.makedirs(odir, exist_ok=True)
    Nb, Eb = collect(model, data["test_bench"], norm, dev, blocks, vae_latent)
    Nt, Et = collect(model, data["test"], norm, dev, blocks, vae_latent)
    for nm, Nx in (("benchmark_test", Nb), ("dataset_test", Nt)):
        ap.write_parquet(Nx, os.path.join(odir, f"{nm}_nodes.parquet"))
    lines = [f"Temporal GAT '{args.run}' on LSTM-AE '{args.lstm_run}' + VAE '{args.vae_run}' | node inputs {blocks}",
             "threshold per dataset = 99th pct of NON-involved host scores on VAL data (no test data used)",
             "involved = host is attack source or target in the 60 s snapshot; 'base' = stage-1/2 baseline: host has",
             "a flagged LSTM-AE or VAE window in the snapshot. FA = flagged share of non-involved host-snapshots.", ""]
    L1, r1 = node_report(Nb, thr, "REALISTIC BENCHMARK (test scenarios: attacks injected into normal traffic)")
    L2, r2 = node_report(Nt, thr, "DATASET TEST SPLITS (original captures; Edge attacks are separate attack-only files)")
    lines += L1 + [""] + L2 + [""]
    # incidents (benchmark): any alert on an involved host during the attack
    inc = []
    for seq, g in Nb[Nb.attack.notna()].groupby("seq"):
        t = thr.get(g.dataset.iat[0], thr["_all"])
        inv = g[g.y_involved == 1]
        inc.append({"dataset": g.dataset.iat[0], "attack": g.attack.iat[0], "gat": bool((inv.p_involved >= t).any()),
                    "baseline": bool((inv.baseline == 1).any()), "has_involved": len(inv) > 0})
    I = pd.DataFrame(inc)
    lines.append("Incidents (benchmark scenarios with >= 1 alert on an involved host):")
    for ds, g in I.groupby("dataset"):
        lines.append(f"  {ds:8s} GAT {int(g.gat.sum())}/{len(g)}   baseline {int(g.baseline.sum())}/{len(g)}")
    lines.append("")
    lines.append("Benchmark node detection per attack type (GAT | baseline):")
    for (ds, att), g in Nb[Nb.y_involved == 1].groupby(["dataset", "attack"]):
        t = thr.get(ds, thr["_all"])
        lines.append(f"  {ds:8s} {att:11s} {len(g):7,} involved host-snapshots | GAT {rate(g.p_involved >= t):6.1%} | "
                     f"baseline {rate(g.baseline == 1):6.1%}")
    lines.append("")
    for nm, Ex in (("benchmark", Eb), ("dataset test", Et)):
        if len(Ex):
            lines.append(f"Edges ({nm}): " + " | ".join(
                f"{ds} attack edges {int((g.y_edge == 1).sum()):,} detected {rate(g.p_edge[g.y_edge == 1] >= ethr.get(ds, ethr['_all'])):.1%}, "
                f"benign edges flagged {rate(g.p_edge[g.y_edge == 0] >= ethr.get(ds, ethr['_all'])):.2%}"
                for ds, g in Ex.groupby("dataset")))
    ctrl = {}
    if data.get("test_control"):
        Nc, _ = collect(model, data["test_control"], norm, dev, blocks, vae_latent)
        ap.write_parquet(Nc, os.path.join(odir, "control_test_nodes.parquet"))
        lines += ["", "CONTROL injections (NORMAL traffic injected exactly like an attack - the 'injected' hosts did nothing",
                  "abnormal, so their flag rate should be close to the false-alarm rate; higher = the model detects the",
                  "injection procedure, not attacks):"]
        for (ds, att), g in Nc.groupby(["dataset", "attack"]):
            t = thr.get(ds, thr["_all"])
            inv, oth = g[g.y_involved == 1], g[g.y_involved == 0]
            ctrl[f"{ds}/{att}"] = {"gat_injected": rate(inv.p_involved >= t), "gat_other": rate(oth.p_involved >= t),
                                   "baseline_injected": rate(inv.baseline == 1), "baseline_other": rate(oth.baseline == 1)}
            lines.append(f"  {ds:8s} {att:20s} {len(inv):6,} injected host-snapshots | GAT {rate(inv.p_involved >= t):6.1%} "
                         f"(other hosts {rate(oth.p_involved >= t):5.2%}) | baseline {rate(inv.baseline == 1):6.1%} "
                         f"(other hosts {rate(oth.baseline == 1):5.2%})")
    if args.holdout:
        lines.insert(0, f"HOLDOUT RUN: attack class '{args.holdout}' was removed from train + val -> its test rows are UNSEEN attacks")
    text = "\n".join(lines) + "\n"
    open(os.path.join(rdir, "evaluation.txt"), "w", encoding="utf-8").write(text)
    json.dump({"thresholds": thr, "edge_thresholds": ethr, "benchmark": r1, "dataset_test": r2, "history": hist,
               "controls": ctrl, "holdout": args.holdout,
               "incidents": I.groupby("dataset")[["gat", "baseline"]].mean().to_dict() if len(I) else {}},
              open(os.path.join(rdir, "metrics.json"), "w"), indent=1, default=float)
    print(text)


if __name__ == "__main__":
    main()
