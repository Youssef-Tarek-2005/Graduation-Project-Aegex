"""
Build the GAT dashboard page (model_results/gat/<run>/gat_dashboard.html): an interactive replay of
benchmark scenarios (hosts + connections per 60 s snapshot, coloured by the GAT's scores) and the
evaluation numbers (GAT vs stage-1/2 baseline, unseen-attack holdouts, control injections).

Run gat_viz_export.py first (it writes viz_data.json). Rerun this after new holdout runs finish.

Usage:
    python gat_dashboard.py [--run gat_v5]
"""
import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import numpy as np
import pandas as pd

import aegex_models as am

HERE = os.path.dirname(os.path.abspath(__file__))


def per_attack(run, metrics):
    p = os.path.join(am.PREPROCESSED, "model_outputs", "gat", run, "benchmark_test_nodes.parquet")
    if not os.path.exists(p):
        return {}
    N = pd.read_parquet(p, columns=["dataset", "attack", "p_involved", "y_involved", "baseline"])
    thr = metrics["thresholds"]
    out = {}
    for (ds, att), g in N[N.y_involved == 1].groupby(["dataset", "attack"]):
        t = thr.get(ds, thr["_all"])
        out[f"{ds}/{att}"] = {"n": int(len(g)), "gat": float((g.p_involved >= t).mean()), "baseline": float((g.baseline == 1).mean())}
    return out


def main():
    a = argparse.ArgumentParser()
    a.add_argument("--run", default="gat_v5")
    args = a.parse_args()
    rdir = os.path.join(am.DATA_ROOT, "model_results", "gat")
    viz = json.load(open(os.path.join(rdir, args.run, "viz_data.json")))
    runs = {}
    for r in sorted(os.listdir(rdir)):
        mp = os.path.join(rdir, r, "metrics.json")
        if r.startswith(args.run) and os.path.exists(mp):
            m = json.load(open(mp))
            if "benchmark" not in m or "dataset_test" not in m:     # e.g. gat_v5_calibrated: a different report
                continue
            runs[r] = {"holdout": m.get("holdout"), "benchmark": m["benchmark"], "dataset_test": m["dataset_test"],
                       "controls": m.get("controls", {}), "per_attack": per_attack(r, m)}
    data = {"run": args.run, "upstream": viz["upstream"], "scenarios": viz["scenarios"], "runs": runs}
    tpl = open(os.path.join(HERE, "gat_dashboard_template.html"), encoding="utf-8").read()
    html = tpl.replace("/*__DATA__*/null", json.dumps(data, separators=(",", ":"), default=float))
    out = os.path.join(rdir, args.run, "gat_dashboard.html")
    open(out, "w", encoding="utf-8").write(html)
    print(f"-> {out} ({os.path.getsize(out) / 1e3:.0f} KB) | runs: {list(runs)}")


if __name__ == "__main__":
    main()
