"""
Export GAT results for the visual dashboard (model_results/gat/<run>/viz_data.json):
  scenarios   a few realistic-benchmark TEST scenarios (one per dataset x attack type, plus controls),
              replayed through the trained GAT: per 60 s snapshot the hosts (P(source), P(target),
              truth, stage-1/2 baseline flag) and host-to-host edges (P(attack edge), truth, flows)
  metrics     the evaluation numbers of the main run, the unseen-attack holdout runs and the controls

Usage:
    python gat_viz_export.py [--run gat_v2] [--lstm-run lstm_ae_v8] [--vae-run vae_v5] [--max-nodes 45]
"""
import argparse
import json
import os
import pickle
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import numpy as np
import torch

import aegex_gat as ag
import aegex_models as am


def pick(seqs, per_key=1):
    """One scenario per (dataset, attack class): original speed, first repetition."""
    out, seen = [], {}
    for sq in seqs:
        m = sq["meta"]
        key = (m["dataset"], m.get("attack_class"))
        if m.get("rep", 0) != 0 or (m.get("slowdown") not in (1, 1.0, None) and not str(m.get("attack_class")).startswith("control")):
            continue
        if seen.get(key, 0) >= per_key:
            continue
        seen[key] = seen.get(key, 0) + 1
        out.append(sq)
    return out


def main():
    a = argparse.ArgumentParser()
    a.add_argument("--run", default="gat_v2")
    a.add_argument("--lstm-run", default="lstm_ae_v8")
    a.add_argument("--vae-run", default="vae_v5")
    a.add_argument("--max-nodes", type=int, default=45, help="hosts kept per snapshot (highest score / involved first)")
    a.add_argument("--context", type=int, default=6, help="snapshots kept before / after the attack")
    args = a.parse_args()
    dev = am.pick_device("auto")
    b = am.ModelBundle.load(os.path.join(am.MODELS_DIR, "gat", args.run), device=dev)
    model, meta = b.model, b.meta
    model.eval()
    norm = tuple(np.asarray(meta["norm"][k], np.float32) for k in ("node_mean", "node_std", "edge_mean", "edge_std"))
    thr = {"_all": meta["threshold"], **meta["per_dataset_thresholds"]}
    ethr = meta["edge_thresholds"]
    cache = os.path.join(am.PREPROCESSED, "gat_inputs", f"{args.lstm_run}__{args.vae_run}.pkl")
    data = pickle.load(open(cache, "rb"))
    ctrl = pickle.load(open(cache.replace(".pkl", "__controls.pkl"), "rb"))
    chosen = pick(data["test_bench"]) + pick([s for s in ctrl if s["meta"].get("attack_class") in ("control_self", "control_other")])

    scenarios = []
    for sq in chosen:
        m = sq["meta"]
        with torch.no_grad():
            outs = ag.run_sequence(model, sq, norm, dev, train=False, blocks=meta["node_blocks"], vae_latent=meta["vae_latent"])
        fc = sq["feat_cols"]
        li, vi = fc.index("lstm_any_anomaly"), fc.index("vae_any_anomaly")
        att = [i for i, s in enumerate(sq["snaps"]) if s["y_node"].any()]
        if not att:
            continue
        lo, hi = max(0, att[0] - args.context), min(len(sq["snaps"]), att[-1] + args.context + 1)
        if hi - lo > 60:                                   # keep the page light: attack start + some of it
            hi = lo + 60
        host_ids, snaps = {}, []
        for s, (pn, pe) in list(zip(sq["snaps"], outs))[lo:hi]:
            hosts = np.array(sq["hosts"], dtype=object)[s["nid"]]
            inv = s["y_node"].max(1) > 0
            score = np.maximum(pn[:, 0], pn[:, 1])
            order = np.lexsort((-score, ~inv))[:args.max_nodes]
            keep = set(order.tolist())
            nodes = []
            for i in order:
                hid = host_ids.setdefault(hosts[i], len(host_ids))
                nodes.append([hid, round(float(pn[i, 0]), 4), round(float(pn[i, 1]), 4), int(s["y_node"][i, 0]),
                              int(s["y_node"][i, 1]), int((s["x"][i, li] > 0) or (s["x"][i, vi] > 0))])
            edges = []
            nfl = s["e"][:, -1] if len(s["e"]) else []
            for k in range(len(s["src"])):
                u, v = int(s["src"][k]), int(s["dst"][k])
                if u in keep and v in keep:
                    edges.append([host_ids[hosts[u]], host_ids[hosts[v]], round(float(pe[k]), 4), int(s["y_edge"][k]),
                                  round(float(np.expm1(nfl[k])), 1) if len(nfl) else 0])
            snaps.append({"t": int(s["snapshot"]), "nodes": nodes, "edges": edges})
        names = [None] * len(host_ids)
        for h, i in host_ids.items():
            names[i] = str(h)
        scenarios.append({"id": sq["name"], "dataset": m["dataset"], "attack": m.get("attack_class"),
                          "base": m.get("base"), "attack_capture": m.get("attack_capture"),
                          "victim": m.get("victim"), "target": m.get("target"),
                          "threshold": thr.get(m["dataset"], thr["_all"]),
                          "edge_threshold": ethr.get(m["dataset"], ethr["_all"]), "hosts": names, "snaps": snaps})
        print(f"{sq['name']}: {len(snaps)} snapshots, {len(names)} hosts", flush=True)

    res = os.path.join(am.DATA_ROOT, "model_results", "gat")
    metrics = {}
    for r in sorted(os.listdir(res)):
        p = os.path.join(res, r, "metrics.json")
        if os.path.exists(p) and r.startswith(args.run):
            metrics[r] = json.load(open(p))
    out = {"run": args.run, "upstream": meta["upstream"], "scenarios": scenarios, "metrics": metrics}
    path = os.path.join(res, args.run, "viz_data.json")
    json.dump(out, open(path, "w"), default=float)
    print(f"-> {path} ({os.path.getsize(path) / 1e6:.2f} MB)")


if __name__ == "__main__":
    main()
