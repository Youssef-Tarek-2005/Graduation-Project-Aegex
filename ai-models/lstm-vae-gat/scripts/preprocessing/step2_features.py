"""
Step 2 - unified feature engineering, chronological splits and normalisation.

For every capture produced by step 1:
  1. engineer the SAME feature set for every dataset (aegex_prep.FEATURES)
     - IPs, ports and timestamps are kept as identity columns only, never as model features
  2. split chronologically per (capture, attack_class): first 70 % train, next 15 % val, last 15 % test
  3. fit a RobustScaler per dataset on TRAIN + BENIGN flows only (no test/attack leakage)
     and apply it to every split; binary features stay 0/1
  4. sort rows by (device, ts) so LSTM windows are contiguous row ranges

Outputs
    <out>/features/<dataset>/<capture>.parquet
    <out>/features/<dataset>/_scaler.json
    <out>/features/feature_spec.json

Usage:
    python step2_features.py [--datasets kitsune edge iot23 nf_toniot]
"""
import argparse
import glob
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import numpy as np
import pandas as pd

import aegex_prep as ap

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = ap.PREPROCESSED_DIR      # AEGEX_OUT/preprocessed (default: project folder)
SCALER_SAMPLE_PER_CAPTURE = 300_000
SCALER_SAMPLE_TOTAL = 3_000_000


def log(*a):
    print(time.strftime("%H:%M:%S"), *a, flush=True)


def captures(dataset):
    base = os.path.join(OUT, "flows", dataset)
    caps = {}
    for p in sorted(glob.glob(os.path.join(base, "*.parquet"))):
        caps[os.path.splitext(os.path.basename(p))[0]] = [p]
    for d in sorted(glob.glob(os.path.join(base, "*", ""))):
        parts = sorted(glob.glob(os.path.join(d, "part-*.parquet")))
        if parts:
            caps[os.path.basename(os.path.normpath(d))] = parts
    return caps


def run(dataset):
    caps = captures(dataset)
    if not caps:
        log(f"[{dataset}] no flows found - run step1 first"); return
    fdir = os.path.join(OUT, "features", dataset)
    os.makedirs(fdir, exist_ok=True)
    rng = np.random.default_rng(0)
    sample, summary = [], {}

    # ---- pass A: features + split (unscaled), collect train-benign sample for the scaler
    for cap, files in caps.items():
        flows = pd.concat([pd.read_parquet(f) for f in files], ignore_index=True)
        feat = ap.engineer_features(flows)
        del flows
        feat["split"] = ap.chronological_split(feat)
        tb = np.flatnonzero((feat.split.values == "train") & (feat.attack_class.values == "benign")
                            & (feat.device_compromised.values == 0))     # clean benign only
        if len(tb):
            pick = rng.choice(tb, min(len(tb), SCALER_SAMPLE_PER_CAPTURE), replace=False)
            sample.append(feat.loc[pick, ap.CONT_FEATURES])
        feat = feat.sort_values(["device", "ts"], kind="stable").reset_index(drop=True)
        ap.write_parquet(feat, os.path.join(fdir, f"{cap}.parquet"))
        summary[cap] = {"flows": len(feat), "devices": int(feat.device.nunique()),
                        "split_x_class": {f"{s}/{c}": int(n) for (s, c), n in
                                          feat.groupby(["split", "attack_class"]).size().items()}}
        log(f"[{dataset}/{cap}] {len(feat):,} flows, {summary[cap]['devices']:,} devices")
        del feat

    # ---- fit scaler on train+benign (per dataset)
    S = pd.concat(sample, ignore_index=True) if sample else None
    if S is None or not len(S):
        raise RuntimeError(f"{dataset}: no benign training flows to fit the scaler")
    if len(S) > SCALER_SAMPLE_TOTAL:
        S = S.sample(SCALER_SAMPLE_TOTAL, random_state=0)
    scaler = ap.RobustScaler().fit(S)
    meta = scaler.to_dict()
    meta["fit_rows"] = len(S)
    json.dump(meta, open(os.path.join(fdir, "_scaler.json"), "w"), indent=1)

    # ---- pass B: apply scaler
    for cap in caps:
        p = os.path.join(fdir, f"{cap}.parquet")
        feat = scaler.transform(pd.read_parquet(p))
        bad = int((~np.isfinite(feat[ap.FEATURES].to_numpy()).all(axis=1)).sum())
        summary[cap]["non_finite_rows"] = bad
        ap.write_parquet(feat, p)
        del feat
    json.dump(summary, open(os.path.join(fdir, "_summary.json"), "w"), indent=1)
    log(f"[{dataset}] scaled with {meta['fit_rows']:,} train-benign rows")


def main():
    a = argparse.ArgumentParser()
    a.add_argument("--datasets", nargs="+", default=ap.ACTIVE_DATASETS, choices=ap.ALL_DATASETS)
    args = a.parse_args()
    os.makedirs(os.path.join(OUT, "features"), exist_ok=True)
    json.dump({"continuous_features (robust-scaled)": ap.CONT_FEATURES,
               "binary_features (0/1)": ap.BIN_FEATURES,
               "feature_order": ap.FEATURES,
               "identity_columns (never model inputs)": ap.IDENTITY,
               "label_columns": ap.LABELS + ["split"],
               "attack_classes": ap.ATTACK_CLASSES,
               "service_ports": {k: sorted(v) for k, v in ap.SERVICE_PORTS.items()},
               "split": "chronological 70/15/15 per (capture, attack_class)"},
              open(os.path.join(OUT, "features", "feature_spec.json"), "w"), indent=1)
    for d in args.datasets:
        run(d)


if __name__ == "__main__":
    main()
