"""
Choose the LSTM-AE window-score aggregation (mean / max / topk:K) WITHOUT touching test data:
thresholds from the original val split's clean benign windows, detection measured on VAL-phase benchmark
scenarios (attack flows from the val splits injected into val-period normal traffic).

Usage:  python select_score_agg.py [--lstm-run lstm_ae_v7]
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

AGGS = ["mean", "topk:8", "topk:4", "topk:2", "max"]


@torch.no_grad()
def errors(model, F, W, T, dev):
    out = {g: [] for g in AGGS}
    for _, X, M in am.window_batches(F, W.row_start.to_numpy(), W.row_end.to_numpy(), T, 2048):
        x, m = torch.from_numpy(X).to(dev), torch.from_numpy(M).to(dev)
        r, _ = model(x, m)
        fe = am.flow_errors(r, x, m)
        for g in AGGS:
            out[g].append(am.aggregate_flow_errors(fe, m, g).cpu().numpy())
    return {g: np.concatenate(v) for g, v in out.items()}


def main():
    a = argparse.ArgumentParser()
    a.add_argument("--lstm-run", default="lstm_ae_v7")
    a.add_argument("mode", nargs="?", default="per-dataset", choices=["pooled", "per-dataset"])
    args = a.parse_args()
    dev = am.pick_device("auto")
    lstm = am.ModelBundle.load(os.path.join(am.MODELS_DIR, "lstm_ae", args.lstm_run), device=dev)
    T, S_, snap = int(lstm.meta["window"]), int(lstm.meta["stride"]), float(lstm.meta["snapshot_seconds"])
    # thresholds: original val split, clean benign, all datasets pooled (as in training)
    val = {g: [] for g in AGGS}
    vds = []
    for ds in lstm.meta["train_datasets"]:
        W = pd.read_parquet(os.path.join(am.PREPROCESSED, "windows", f"{ds}.parquet"))
        W = W[(W.split == "val") & W.split_pure & (W.label == 0) & (W.device_compromised == 0)]
        for cap, g in W.groupby("capture"):
            F = pd.read_parquet(os.path.join(am.PREPROCESSED, "features", ds, f"{cap}.parquet"), columns=ap.FEATURES).to_numpy(np.float32)
            for k, v in errors(lstm.model, F, g, T, dev).items():
                val[k].append(v)
            vds.append(np.full(len(g), ds))
    vds = np.concatenate(vds)
    pooled = {g: float(np.quantile(np.concatenate(v), 0.99)) for g, v in val.items()}
    perds = {g: {ds: float(np.quantile(np.concatenate(v)[vds == ds], 0.99)) for ds in set(vds)} for g, v in val.items()}
    mode = sys.argv[-1] if sys.argv[-1] in ("pooled", "per-dataset") else "per-dataset"
    thr_of = (lambda g, ds: pooled[g]) if mode == "pooled" else (lambda g, ds: perds[g][ds])
    rows = []
    specs = ab.scenario_specs("val", lstm.meta["train_datasets"], reps=1)
    for spec in specs:
        sc = ab.build_scenario(spec, ap.RobustScaler.from_dict(lstm.meta["scalers"][spec["dataset"]]), T, S_, snap)
        W = sc["windows"]
        E = errors(lstm.model, sc["feat"][ap.FEATURES].to_numpy(np.float32), W, T, dev)
        att = W.n_attack.to_numpy() > 0
        ben = ~att & ~W.device.isin(set(W.device[att])).to_numpy()
        low = att & (W.attack_frac.to_numpy() < 0.5)
        for g in AGGS:
            f = E[g] >= thr_of(g, spec["dataset"])
            rows.append({"dataset": spec["dataset"], "case": f"{spec['attack_capture']}:{spec['attack_class']}",
                         "agg": g, "att": att.sum(), "det": f[att].sum(), "low": low.sum(), "low_det": f[low].sum(),
                         "ben": ben.sum(), "fa": f[ben].sum(), "clean": spec["attack_capture"] is None})
    R = pd.DataFrame(rows)
    print(f"VAL-phase scenarios: {len(specs)} | thresholds = val clean-benign 99th pct per aggregation ({mode})")
    print(f"{'agg':8s} {'dataset':8s} {'macro det':>9s} {'<50% det':>9s} {'FA clean':>9s}")
    for g in AGGS:
        for ds, D in R[R["agg"] == g].groupby("dataset"):
            A = D[~D.clean]
            per = A.groupby("case").apply(lambda x: x.det.sum() / max(x.att.sum(), 1), include_groups=False)
            C = D[D.clean]
            print(f"{g:8s} {ds:8s} {per.mean():9.1%} {A.low_det.sum() / max(A.low.sum(), 1):9.1%} {C.fa.sum() / max(C.ben.sum(), 1):9.2%}")


if __name__ == "__main__":
    main()
