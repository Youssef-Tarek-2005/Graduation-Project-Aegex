"""
Step 4 - independent checks on everything the pipeline produced (read-only).

  * originals still match ORIGINALS_SHA256.txt
  * flow counts are preserved from step 1 to step 2
  * features: all present, float32, finite, binary features are 0/1, continuous within the clip
  * no identity column (IP, port, timestamp, device) is used as a model feature
  * splits are chronological per (capture, attack_class) and close to 70/15/15
  * scaler sanity: train-benign continuous features have median ~0
  * windows: row ranges are valid, one device per window, labels match the flows
  * graphs exist for every capture

Writes <out>/_verification.txt and exits with code 1 if any check fails.
"""
import glob
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import numpy as np
import pandas as pd

import aegex_prep as ap
import step1_flows as s1

OUT = s1.OUT
lines, failures = [], []


def check(ok, msg):
    (lines if ok else failures).append(("PASS  " if ok else "FAIL  ") + msg)
    if not ok:
        lines.append("FAIL  " + msg)


def main():
    names = s1.reg.originals(ap.ACTIVE_DATASETS)
    try:
        ap.check_originals(s1.DATA, names)
        check(True, f"{len(names)} original files byte-identical to ORIGINALS_SHA256.txt")
    except RuntimeError as e:
        check(False, str(e))

    assert not set(ap.FEATURES) & set(ap.IDENTITY), "identity column used as feature"
    check(True, f"{len(ap.FEATURES)} model features; none of them is an IP, port, timestamp or device id")

    win_cfg = json.load(open(os.path.join(OUT, "windows", "_config.json")))
    totals, pooled = [], {}
    for ds in ap.ACTIVE_DATASETS:
        rep_path = os.path.join(OUT, "flows", ds, "_report.json")
        if not os.path.exists(rep_path):
            check(False, f"{ds}: step 1 report missing"); continue
        rep = json.load(open(rep_path))
        W = pd.read_parquet(os.path.join(OUT, "windows", f"{ds}.parquet"))
        for cap, r in rep.items():
            p = os.path.join(OUT, "features", ds, f"{cap}.parquet")
            if not os.path.exists(p):
                check(False, f"{ds}/{cap}: features missing"); continue
            F = pd.read_parquet(p)
            tag = f"{ds}/{cap}"
            check(len(F) == r["flows"], f"{tag}: {len(F):,} feature rows == {r['flows']:,} flows")
            X = F[ap.FEATURES]
            check(all(X.dtypes == "float32"), f"{tag}: features float32")
            check(np.isfinite(X.to_numpy()).all(), f"{tag}: no NaN/inf")
            B = F[ap.BIN_FEATURES].to_numpy()
            check(np.isin(B, (0, 1)).all(), f"{tag}: binary features are 0/1")
            C = F[ap.CONT_FEATURES].to_numpy()
            check(np.abs(C).max() <= 10.0001, f"{tag}: continuous features within [-10, 10]")
            # chronological split per class
            bad = 0
            for _, g in F.groupby("attack_class"):
                tr, va, te = (g.ts[g.split == s] for s in ("train", "val", "test"))
                if len(tr) and len(va) and tr.max() > va.min(): bad += 1
                if len(va) and len(te) and va.max() > te.min(): bad += 1
            check(bad == 0, f"{tag}: splits chronological per class")
            share = F.split.value_counts(normalize=True)
            check(abs(share.get("train", 0) - 0.70) < 0.05 or len(F) < 100,
                  f"{tag}: split shares " + ", ".join(f"{k} {v:.2f}" for k, v in share.items()))
            # windows
            w = W[W.capture == cap]
            ok_rng = (w.row_start >= 0).all() and (w.row_end <= len(F)).all() and (w.row_end > w.row_start).all()
            dev = F.device.to_numpy()
            one_dev = (dev[w.row_start.to_numpy()] == dev[w.row_end.to_numpy() - 1]).all()
            att = np.r_[0, np.cumsum(F.is_attack.to_numpy())]
            lab_ok = ((att[w.row_end.to_numpy()] - att[w.row_start.to_numpy()]) == w.n_attack.to_numpy()).all()
            check(ok_rng and one_dev and lab_ok, f"{tag}: {len(w):,} windows valid (ranges, single device, labels)")
            g_ok = os.path.exists(os.path.join(OUT, "graphs", ds, f"{cap}_edges.parquet"))
            check(g_ok, f"{tag}: graph snapshots present")
            tb = F.loc[(F.split == "train") & (F.attack_class == "benign") & (F.device_compromised == 0),
                       ap.CONT_FEATURES]
            if len(tb):   # same capture-balanced sampling the scaler was fitted on
                pooled.setdefault(ds, []).append(tb.sample(min(len(tb), 300_000), random_state=0))
            totals.append({"dataset": ds, "capture": cap, "flows": len(F), "attack": int(F.is_attack.sum()),
                           **{c: int((F.attack_class == c).sum()) for c in ap.ATTACK_CLASSES},
                           "windows": len(w)})
            del F
    T = pd.DataFrame(totals)
    summary = T.groupby("dataset")[["flows", "attack"] + ap.ATTACK_CLASSES + ["windows"]].sum()
    summary.loc["TOTAL"] = summary.sum()
    # 0 must be a median of the scaled train-benign data: P(x<0) <= 0.5 <= P(x<=0) (+-5 %).
    # (This form is correct for discrete features too, e.g. 1-vs-2 packet flows split ~50/50.)
    worst = {}
    for ds, v in pooled.items():
        A = pd.concat(v).to_numpy()
        lo, le = (A < 0).mean(axis=0), (A <= 0).mean(axis=0)
        worst[ds] = float(max((lo - 0.5).max(), (0.5 - le).max(), 0))
    check(all(w <= 0.05 for w in worst.values()),
          "scaler sanity: 0 is the median of scaled train-benign features (max deviation "
          + str({k: round(x, 3) for k, x in worst.items()}) + ")")
    report = ["Aegex preprocessing verification", f"window/snapshot config: {win_cfg}", ""] + lines + \
             ["", "per-dataset totals:", summary.to_string(), "", f"FAILURES: {len(failures)}"] + failures
    open(os.path.join(OUT, "_verification.txt"), "w").write("\n".join(report) + "\n")
    print("\n".join(report[-(len(failures) + 15):]))
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
