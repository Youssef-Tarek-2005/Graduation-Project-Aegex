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


# ------------------------------------------------------------------------------------------ chains
class Chain:
    """The LSTM-AE + VAE pair that feeds the GAT for ONE dataset (network). gat_v1/v2 used one pair for all
    datasets; from gat_v3 each dataset can use its own pair (--chain ds=lstm_run:vae_run)."""

    def __init__(self, lstm_run, vae_run, dev, cache):
        key = (lstm_run, vae_run)
        if key not in cache:
            ldir = os.path.join(am.MODELS_DIR, "lstm_ae", lstm_run)
            vdir = os.path.join(am.MODELS_DIR, "vae", vae_run)
            l, v = am.ModelBundle.load(ldir, device=dev), am.ModelBundle.load(vdir, device=dev)
            am.check_vae_matches_lstm(v.meta, ldir)
            cache[key] = (l, v, ldir, vdir)
        self.lstm_run, self.vae_run = key
        self.lstm, self.vae, self.ldir, self.vdir = cache[key]

    def upstream(self):
        return {"lstm_run": self.lstm_run, "lstm_model_sha256": am.file_sha256(os.path.join(self.ldir, "model.pt")),
                "vae_run": self.vae_run, "vae_model_sha256": am.file_sha256(os.path.join(self.vdir, "model.pt"))}


SCORE_COLS = {"lstm": ("lstm_max_score", "lstm_mean_score"), "vae": ("vae_max_score", "vae_mean_score")}


def relative_scores(st, chain, ds):
    """Divide the stage scores by that stage's alarm line for this dataset (1.0 = on the line), so scores from
    different LSTM / VAE models mean the same to the GAT."""
    st = st.copy()
    for stage, b in (("lstm", chain.lstm), ("vae", chain.vae)):
        t = am.threshold_for(b.meta, ds)
        for c in SCORE_COLS[stage]:
            if c in st:
                st[c] = st[c] / t
    return st


def ordered(datasets):
    """Datasets in ACTIVE order first (so benchmark scenario seeds match earlier GAT runs), then the rest."""
    act = [d for d in ap.ACTIVE_DATASETS if d in datasets]
    return act + [d for d in datasets if d not in act]


# ------------------------------------------------------------------------------------------ data
def dataset_sequences(ds, lstm_run, vae_run, vae_latent, rel_chain=None):
    """Step-3 graphs of a dataset -> {split: [sequence, ...]} with stage outputs attached."""
    gdir = os.path.join(am.PREPROCESSED, "graphs", ds)
    ln = pd.read_parquet(os.path.join(am.PREPROCESSED, "model_outputs", "lstm_ae", lstm_run, f"{ds}_node_snapshots.parquet"))
    vn = pd.read_parquet(os.path.join(am.PREPROCESSED, "model_outputs", "vae", vae_run, f"{ds}_node_snapshots.parquet"))
    ln = ln[["capture", "snapshot", "node", "lstm_max_score", "lstm_mean_score", "lstm_n_windows", "lstm_any_anomaly"]]
    st = ln.merge(vn, on=["capture", "snapshot", "node"], how="outer")
    if rel_chain is not None:
        st = relative_scores(st, rel_chain, ds)
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


def scenario_stage(sc, chain, ds, dev, snap, rel):
    scored = ab.score_scenario(sc, chain.lstm, chain.vae, dev)
    stage = ag.node_stage_table(scored, sc["info"]["t0"], snap)
    return relative_scores(stage, chain, ds) if rel else stage


def scenario_sequences(phase, datasets, chains, dev, reps, slowdowns, n_attack, vae_latent, rel=False):
    specs = ab.scenario_specs(phase, ordered(datasets), slowdowns, reps, n_attack)
    seqs = []
    for i, spec in enumerate(specs, 1):
        ch = chains[spec["dataset"]]
        T, S_, snap = int(ch.lstm.meta["window"]), int(ch.lstm.meta["stride"]), float(ch.lstm.meta["snapshot_seconds"])
        sc = ab.build_scenario(spec, ap.RobustScaler.from_dict(ch.lstm.meta["scalers"][spec["dataset"]]), T, S_, snap)
        stage = scenario_stage(sc, ch, spec["dataset"], dev, snap, rel)
        info = {k: v for k, v in sc["info"].items()}
        info.update(source="benchmark", split=phase)
        seqs.append(ag.snapshot_sequence(sc["edges"], sc["nodes"], stage, vae_latent, spec["id"], info))
        if i % 25 == 0 or i == len(specs):
            log(f"  [{phase}] {i}/{len(specs)} scenarios")
    return seqs


def build_inputs(args, chains, dev, vae_latent, cache):
    """Training datasets -> train / val / test; --test-datasets (networks never trained on) -> test only."""
    if os.path.exists(cache) and not args.rebuild:
        log(f"loading cached graph inputs {cache}")
        return pickle.load(open(cache, "rb"))
    data = {"train": [], "val": [], "test": [], "test_bench": []}
    rel = args.relative_scores
    for ds in args.datasets + args.test_datasets:
        ch = chains[ds]
        d = dataset_sequences(ds, ch.lstm_run, ch.vae_run, vae_latent, ch if rel else None)
        for k in (("train", "val", "test") if ds in args.datasets else ("test",)):
            data[k] += d[k]
        if ds not in args.datasets:              # unlabelled warm-up of a new network: only its attack-free
            data.setdefault("warm_train", []).extend(d["train"])   # snapshots are used (input scale / threshold)
            data.setdefault("warm_val", []).extend(d["val"])
        log(f"[{ds}] dataset graph sequences: " + ", ".join(f"{k} {len(v)}" for k, v in d.items())
            + ("" if ds in args.datasets else "  (test only: network never trained on)"))
    data["train"] += scenario_sequences("train", args.datasets, chains, dev, 2, args.slowdowns, args.n_attack, vae_latent, rel)
    data["val"] += scenario_sequences("val", args.datasets, chains, dev, 1, args.slowdowns, args.n_attack, vae_latent, rel)
    data["test_bench"] = scenario_sequences("test", args.datasets + args.test_datasets, chains, dev, 2, args.slowdowns,
                                            args.n_attack, vae_latent, rel)
    os.makedirs(os.path.dirname(cache), exist_ok=True)
    pickle.dump(data, open(cache, "wb"), protocol=4)
    return data


def control_inputs(args, chains, dev, vae_latent, cache):
    """Test-phase CONTROL scenarios: normal traffic injected exactly like an attack (aegex_bench.CONTROL_KINDS).
    Its 'involved' hosts did nothing abnormal, so the GAT should flag them only at its false-alarm rate."""
    if os.path.exists(cache) and not args.rebuild:
        return pickle.load(open(cache, "rb"))
    seqs = []
    for spec in ab.scenario_specs("test", ordered(args.datasets + args.test_datasets), (1,), 2, args.n_attack,
                                  controls=ab.CONTROL_KINDS, attacks=False):
        if spec["attack_capture"] is None:
            continue
        ch = chains[spec["dataset"]]
        T, S_, snap = int(ch.lstm.meta["window"]), int(ch.lstm.meta["stride"]), float(ch.lstm.meta["snapshot_seconds"])
        sc = ab.build_scenario(spec, ap.RobustScaler.from_dict(ch.lstm.meta["scalers"][spec["dataset"]]), T, S_, snap)
        info = dict(sc["info"]); info.update(source="control", split="test")
        seqs.append(ag.snapshot_sequence(sc["edges"], sc["nodes"], scenario_stage(sc, ch, spec["dataset"], dev, snap,
                                                                                  args.relative_scores),
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


def mask_edge_features(data, drop):
    """Remove edge inputs whose name starts with one of the `drop` prefixes from every snapshot (in place).
    Returns the edge input names the GAT sees (incl. the is_reverse flag added at run time)."""
    base = ag.EDGE_FEATURES[:-1]                       # stored columns; is_reverse is appended by add_reverse
    keep = [i for i, n in enumerate(base) if not any(n.startswith(p) for p in drop)]
    if len(keep) < len(base):
        seen = set()
        for seqs in data.values():
            for sq in seqs:
                for s in sq["snaps"]:
                    if id(s) not in seen and s["e"].shape[1] == len(base):
                        s["e"] = s["e"][:, keep]; seen.add(id(s))
        log(f"edge inputs: dropped {len(base) - len(keep)} ({sorted(set(base) - {base[i] for i in keep})})")
    return [base[i] for i in keep] + ["is_reverse"]


def _rule_candidates(seqs, blocks, vae_latent, edge_names):
    """Per host-snapshot: the node inputs plus, for every edge input, its max and min over the host's links.
    Returns {dataset: (matrix, y_involved)} and the candidate names."""
    names = None
    out = {}
    for sq in seqs:
        ds = sq["meta"]["dataset"]
        for s in sq["snaps"]:
            x = ag.select_blocks(s["x"], sq["feat_cols"], blocks, vae_latent)
            n, ne = len(x), s["e"].shape[1]
            mx = np.full((n, ne), -np.inf, np.float32); mn = np.full((n, ne), np.inf, np.float32)
            if len(s["src"]):
                for idx in (s["src"], s["dst"]):
                    np.maximum.at(mx, idx, s["e"]); np.minimum.at(mn, idx, s["e"])
            mx[~np.isfinite(mx)] = 0; mn[~np.isfinite(mn)] = 0
            out.setdefault(ds, ([], []))
            out[ds][0].append(np.concatenate([x, mx, mn], 1))
            out[ds][1].append((s["y_node"].sum(1) > 0).astype(np.int8))
        if names is None:
            en = edge_names[:-1]
            names = ag.node_feature_names(blocks, vae_latent) + [f"max link {c}" for c in en] + [f"min link {c}" for c in en]
    return {k: (np.concatenate(v[0]), np.concatenate(v[1])) for k, v in out.items()}, names


def rule_baseline(data, blocks, vae_latent, edge_names, fpr):
    """The 'no model' reference for the GAT: ONE input (a host input, or the max / min of one link input over the
    host's links), chosen per network by VAL ROC-AUC and thresholded at the val non-involved (1 - fpr) quantile,
    then applied to the benchmark TEST. Networks without val data (test-only) use the rule chosen on all val data."""
    V, names = _rule_candidates(data["val"], blocks, vae_latent, edge_names)
    T, _ = _rule_candidates(data["test_bench"], blocks, vae_latent, edge_names)
    pooled = (np.concatenate([v[0] for v in V.values()]), np.concatenate([v[1] for v in V.values()]))

    def choose(X, y):
        best = (-1, 0, 1, 0.0)
        for j in range(X.shape[1]):
            v = X[:, j]
            if v.std() == 0 or y.min() == y.max():
                continue
            a = roc_auc_score(y, v)
            sg = 1 if a >= 0.5 else -1
            if max(a, 1 - a) > best[0]:
                best = (max(a, 1 - a), j, sg, float(np.quantile(sg * v[y == 0], 1 - fpr)))
        return best
    res = {}
    for ds, (X, y) in T.items():
        src = V.get(ds) if ds in V and V[ds][1].any() else pooled
        auc, j, sg, t = choose(*src)
        f = sg * X[:, j] > t
        res[ds] = {"rule": f"{'high' if sg > 0 else 'low'} {names[j]}", "val_auc": auc,
                   "chosen_on": "own val" if src is not pooled else "all val (test-only network)",
                   "detection": rate(f[y == 1]), "false_alarms": rate(f[y == 0])}
    return res


# ------------------------------------------------------------------------------------------ relative inputs
REL_EDGE = list(ap.CONT_FEATURES) + ["log_n_flows"]      # continuous link inputs (flags / 0-1 shares kept raw)
DEV_ALPHA, DEV_FLOOR = 0.2, 0.5


def attack_free(seqs):
    out = []
    for s in seqs:
        keep = [sn for sn in s["snaps"] if not sn["y_node"].any()]
        if keep:
            out.append({**s, "snaps": keep})
    return out


def relative_inputs(data):
    """--relative-inputs (in place, once per sequence):
      1. per-network scale: continuous host traffic + link inputs -> z-score with mean / std of THAT network's
         attack-free train snapshots (training networks: their train split; test-only networks: their unlabelled
         warm-up = own train split). Uses no test data.
      2. deviation block: each host's traffic vs its own history in the sequence (EWMA mean / var, alpha 0.2,
         std floor 0.5 in log units); 0 when the host has no history yet.
    Returns the per-network stats (stored in the bundle)."""
    ecols = list(ap.FEATURES) + ["log_n_flows"]
    eidx = [ecols.index(c) for c in REL_EDGE]
    seqs = list({id(s): s for v in data.values() for s in v}.values())
    warm = {}
    for s in seqs:
        m = s["meta"]
        if m.get("source") == "dataset" and m.get("split") == "train":
            warm.setdefault(m["dataset"], []).append(s)
    stats = {}
    for ds, ws in warm.items():
        ws = attack_free(ws)
        if not ws:
            continue
        fc = ws[0]["feat_cols"]
        nidx = [fc.index(c) for c in ag.NODE_DEV_BASE]
        X = np.concatenate([sn["x"][:, nidx] for s in ws for sn in s["snaps"]])
        E = np.concatenate([sn["e"][:, eidx] for s in ws for sn in s["snaps"] if len(sn["e"])])
        stats[ds] = {"node_mean": X.mean(0).tolist(), "node_std": np.maximum(X.std(0), 0.1).tolist(),
                     "edge_mean": E.mean(0).tolist(), "edge_std": np.maximum(E.std(0), 0.1).tolist(),
                     "warmup_snapshots": int(sum(len(s["snaps"]) for s in ws))}
        log(f"[{ds}] relative inputs: scale from {stats[ds]['warmup_snapshots']:,} attack-free train snapshots")
    for s in seqs:
        if s.get("relative"):
            continue
        ds = s["meta"]["dataset"]
        if ds not in stats:
            raise SystemExit(f"--relative-inputs: no attack-free train snapshots for network '{ds}'")
        st = stats[ds]
        nm, ns = np.asarray(st["node_mean"], np.float32), np.asarray(st["node_std"], np.float32)
        em, es = np.asarray(st["edge_mean"], np.float32), np.asarray(st["edge_std"], np.float32)
        fc = s["feat_cols"]
        nidx = [fc.index(c) for c in ag.NODE_DEV_BASE]
        H = len(s["hosts"])
        mu, var = np.zeros((H, len(nidx)), np.float32), np.zeros((H, len(nidx)), np.float32)
        seen = np.zeros(H, bool)
        for sn in s["snaps"]:
            raw = sn["x"][:, nidx].astype(np.float32)
            h = sn["nid"]
            old = seen[h][:, None]
            dev = np.where(old, (raw - mu[h]) / np.sqrt(var[h] + DEV_FLOOR ** 2), 0.0).astype(np.float32)
            d = raw - mu[h]
            new_mu = np.where(old, mu[h] + DEV_ALPHA * d, raw)
            new_var = np.where(old, (1 - DEV_ALPHA) * (var[h] + DEV_ALPHA * d * d), 0.0)
            mu[h], var[h], seen[h] = new_mu, new_var, True
            x = sn["x"].copy()
            x[:, nidx] = (raw - nm) / ns
            sn["x"] = np.concatenate([x, np.clip(dev, -10, 10)], 1).astype(np.float32)
            if len(sn["e"]):
                e = sn["e"].copy()
                e[:, eidx] = (e[:, eidx] - em) / es
                sn["e"] = e
        s["feat_cols"] = list(fc) + ag.NODE_DEV
        s["relative"] = True
    return stats


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
                    hn = np.array(sq["hosts"], dtype=object)[s["nid"]]   # host names (used by gat_handoff.py)
                    erows.append(pd.DataFrame({"seq": sq["name"], "dataset": m["dataset"], "source": m["source"],
                                               "snapshot": s["snapshot"], "p_edge": pe, "y_edge": s["y_edge"],
                                               "src": hn[s["src"]], "dst": hn[s["dst"]]}))
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
    a.add_argument("--node-blocks", nargs="+", default=list(ag.NODE_BLOCKS), choices=ag.ALL_NODE_BLOCKS)
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
    a.add_argument("--drop-edge-features", nargs="*", default=[], metavar="PREFIX",
                   help="leave these edge inputs out (name prefixes, e.g. svc_ = port/service identity)")
    a.add_argument("--chain", nargs="*", default=[], metavar="DS=LSTM_RUN:VAE_RUN",
                   help="per-dataset LSTM-AE + VAE runs (others use --lstm-run / --vae-run)")
    a.add_argument("--test-datasets", nargs="*", default=[],
                   help="networks used ONLY for testing (never trained on; they get the pooled threshold)")
    a.add_argument("--relative-scores", action="store_true",
                   help="feed stage scores as score / that stage's alarm line (needed when chains differ)")
    a.add_argument("--relative-inputs", action="store_true",
                   help="per-network standardised traffic / link inputs (stats from the network's own attack-free "
                        "train snapshots) + 'deviation' node block (each host vs its own history)")
    a.add_argument("--inputs-tag", default=None, help="cache name for the graph inputs (default <lstm>__<vae>)")
    args = a.parse_args()
    torch.manual_seed(args.seed); rng = np.random.default_rng(args.seed)
    dev = am.pick_device(args.device)
    pairs = {ds: (args.lstm_run, args.vae_run) for ds in args.datasets + args.test_datasets}
    for c in args.chain:
        ds, _, runs = c.partition("=")
        pairs[ds] = tuple(runs.split(":"))
    loaded = {}
    chains = {ds: Chain(l, v, dev, loaded) for ds, (l, v) in pairs.items()}
    lat = {int(ch.vae.meta["init"]["latent"]) for ch in chains.values()}
    if len(lat) != 1:
        raise SystemExit(f"all VAEs must have the same latent size, got {lat}")
    vae_latent = lat.pop()
    if len(loaded) > 1 and "latent" in args.node_blocks:
        log("WARNING: VAE latents of different VAEs are not comparable; consider --node-blocks traffic stage")
    args.lstm_run = "+".join(sorted({c.lstm_run for c in chains.values()})) if len(loaded) > 1 else args.lstm_run
    args.vae_run = "+".join(sorted({c.vae_run for c in chains.values()})) if len(loaded) > 1 else args.vae_run
    tag = args.inputs_tag or f"{args.lstm_run}__{args.vae_run}"
    cache = os.path.join(am.PREPROCESSED, "gat_inputs", f"{tag}.pkl")
    data = build_inputs(args, chains, dev, vae_latent, cache)
    data["test_control"] = control_inputs(args, chains, dev, vae_latent, cache.replace(".pkl", "__controls.pkl"))
    args.chains = chains
    if "deviation" in args.node_blocks and not args.relative_inputs:
        raise SystemExit("--node-blocks deviation needs --relative-inputs")
    args.rel_stats = relative_inputs(data) if args.relative_inputs else None
    if args.eval_only:       # an evaluated bundle decides which edge inputs exist
        args.drop_edge_features = am.ModelBundle.load(os.path.join(am.MODELS_DIR, "gat", args.run), device="cpu") \
            .meta.get("dropped_edge_features", [])
    args.edge_names = mask_edge_features(data, args.drop_edge_features)
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
        model, meta, norm, thr, ethr, hist = train(args, data, blocks, vae_latent, dev, rng, bdir)
    evaluate(args, model, data, norm, thr, ethr, hist, blocks, vae_latent, dev)


def train(args, data, blocks, vae_latent, dev, rng, bdir):
    lstm = next(iter(args.chains.values())).lstm
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
    model = ag.TemporalGAT(len(ag.node_feature_names(blocks, vae_latent)), len(args.edge_names), args.hidden,
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
            "init": {"n_node": len(ag.node_feature_names(blocks, vae_latent)), "n_edge": len(args.edge_names),
                     "hidden": args.hidden, "heads": args.heads, "layers": args.layers, "dropout": args.dropout},
            "node_blocks": blocks, "node_features": ag.node_feature_names(blocks, vae_latent), "edge_features": args.edge_names, "dropped_edge_features": args.drop_edge_features,
            "vae_latent": vae_latent, "norm": {"node_mean": nmean.tolist(), "node_std": nstd.tolist(),
                                               "edge_mean": emean.tolist(), "edge_std": estd.tolist()},
            "threshold": thr["_all"], "threshold_mode": "per_dataset", "per_dataset_thresholds": {k: v for k, v in thr.items() if k != "_all"},
            "edge_thresholds": ethr, "snapshot_seconds": float(lstm.meta["snapshot_seconds"]),
            "upstream": ({**next(iter(args.chains.values())).upstream()}
                         if len({(c.lstm_run, c.vae_run) for c in args.chains.values()}) == 1 else
                         {"lstm_run": args.lstm_run, "vae_run": args.vae_run, "per_dataset": True}),
            "upstream_per_dataset": {ds: c.upstream() for ds, c in args.chains.items()},
            "relative_scores": bool(args.relative_scores), "test_only_datasets": args.test_datasets,
            "relative_inputs": args.rel_stats,
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
             f"trained on {args.datasets}; test-only networks (never trained on, pooled threshold): {args.test_datasets or 'none'}",
             "stage scores fed as score / alarm line" if args.relative_scores else "stage scores fed raw",
             "involved = host is attack source or target in the 60 s snapshot; 'base' = stage-1/2 baseline: host has",
             "a flagged LSTM-AE or VAE window in the snapshot. FA = flagged share of non-involved host-snapshots.", ""]
    L1, r1 = node_report(Nb, thr, "REALISTIC BENCHMARK (test scenarios: attacks injected into normal traffic)")
    L2, r2 = node_report(Nt, thr, "DATASET TEST SPLITS (original captures; Edge attacks are separate attack-only files)")
    lines += L1 + [""]
    rules = rule_baseline(data, blocks, vae_latent, args.edge_names, args.fpr)
    lines.append("ONE-INPUT RULE vs GAT (benchmark test; rule = best single GAT input, chosen + thresholded on VAL only).")
    lines.append("The GAT only counts for what it adds above this rule.")
    if args.drop_edge_features:
        lines.append(f"edge inputs left out of the GAT and the rule: {args.drop_edge_features}")
    for ds, r in rules.items():
        g = r1.get(ds, {})
        lines.append(f"  {ds:9s} rule det {r['detection']:6.1%} FA {r['false_alarms']:6.2%} | GAT det "
                     f"{g.get('gat_detection', float('nan')):6.1%} FA {g.get('gat_false_alarms', float('nan')):6.2%} | "
                     f"rule = {r['rule']} (val AUC {r['val_auc']:.3f}, {r['chosen_on']})")
    lines += [""] + L2 + [""]
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
    warm_rows = {}
    if args.test_datasets and data.get("warm_val"):
        lines += ["", "TEST-ONLY NETWORKS, OWN WARM-UP THRESHOLD (99th pct of host scores in the network's attack-free",
                  "val snapshots; no attack labels needed in a deployment) instead of the pooled threshold above:"]
        Nw, _ = collect(model, attack_free(data["warm_val"]), norm, dev, blocks, vae_latent)
        for ds in args.test_datasets:
            w = Nw[Nw.dataset == ds]
            if len(w) < 20:
                lines.append(f"  {ds:8s} too few warm-up host-snapshots ({len(w)})")
                continue
            t = float(np.quantile(w.p_involved, 1 - args.fpr))
            _, rr = node_report(Nb[Nb.dataset == ds], {"_all": t}, "")
            _, rt = node_report(Nt[Nt.dataset == ds], {"_all": t}, "")
            B, T = rr.get(ds, {}), rt.get(ds, {})
            ci = co = float("nan")
            if data.get("test_control") and (Nc.dataset == ds).any():
                g = Nc[Nc.dataset == ds]
                ci, co = rate(g[g.y_involved == 1].p_involved >= t), rate(g[g.y_involved == 0].p_involved >= t)
            warm_rows[ds] = {"threshold": t, "warmup_host_snapshots": int(len(w)), "benchmark": B, "dataset_test": T,
                             "control_injected": ci, "control_other": co}
            lines.append(f"  {ds:8s} thr {t:.4f} ({len(w):,} warm-up host-snapshots) | bench det "
                         f"{B.get('gat_detection', np.nan):6.1%} FA {B.get('gat_false_alarms', np.nan):6.2%} "
                         f"ROC-AUC {B.get('roc_auc', np.nan):.4f} | split det {T.get('gat_detection', np.nan):6.1%} "
                         f"FA {T.get('gat_false_alarms', np.nan):6.2%} | controls injected {ci:6.1%} other {co:6.2%}")
    if args.holdout:
        lines.insert(0, f"HOLDOUT RUN: attack class '{args.holdout}' was removed from train + val -> its test rows are UNSEEN attacks")
    text = "\n".join(lines) + "\n"
    open(os.path.join(rdir, "evaluation.txt"), "w", encoding="utf-8").write(text)
    json.dump({"thresholds": thr, "edge_thresholds": ethr, "benchmark": r1, "dataset_test": r2, "history": hist,
               "one_input_rule": rules, "dropped_edge_features": args.drop_edge_features,
               "controls": ctrl, "holdout": args.holdout,
               "test_only_own_threshold": warm_rows, "relative_inputs": bool(args.relative_inputs),
               "incidents": I.groupby("dataset")[["gat", "baseline"]].mean().to_dict() if len(I) else {}},
              open(os.path.join(rdir, "metrics.json"), "w"), indent=1, default=float)
    print(text)


if __name__ == "__main__":
    main()
