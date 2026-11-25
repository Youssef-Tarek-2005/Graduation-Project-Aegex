"""
Step 5 - baseline results: a Random Forest per dataset on the 45 preprocessed features.

Purpose: show the preprocessed data is learnable and give a reference score that the
LSTM-AE / VAE / GAT models must beat. This is NOT one of the Aegex models.

  * trains on the TRAIN split, reports on the (later-in-time) TEST split - never mixed
  * training rows are capped per class (default 200k, random sample) so huge classes
    do not dominate; class_weight='balanced_subsample' handles the rest
  * the WHOLE test split is scored, streamed capture by capture (no sampling in evaluation)
  * reports per class (precision / recall / F1), macro F1, binary attack detection
    (detection rate, false-alarm rate) and the confusion matrix

Outputs
    <out>/baseline/<dataset>_report.txt
    <out>/baseline/results.json
    <out>/baseline/summary.txt

Usage:
    python step5_baseline.py [--datasets kitsune edge iot23 nf_toniot] [--per-class 200000] [--trees 100]
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
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix, f1_score

import aegex_prep as ap

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = ap.PREPROCESSED_DIR      # AEGEX_OUT/preprocessed (default: project folder)
import aegex_datasets as reg

# per-dataset notes and the leave-one-capture-out captures (train on all OTHER captures, score the
# whole held-out one) come from the dataset plug-ins (BASELINE_NOTE, CROSS_CAPTURE)
NOTES = reg.baseline_notes()
CROSS_CAPTURE = reg.cross_capture()


def log(*a):
    print(time.strftime("%H:%M:%S"), *a, flush=True)


def make_rf(trees):
    return RandomForestClassifier(n_estimators=trees, max_depth=24, min_samples_leaf=3,
                                  class_weight="balanced_subsample", n_jobs=-1, random_state=0)


def binary_scores(yt, yp):
    ta, pa = yt != "benign", yp != "benign"
    tp, fn = int((ta & pa).sum()), int((ta & ~pa).sum())
    fp, tn = int((~ta & pa).sum()), int((~ta & ~pa).sum())
    b = {"detection_rate": tp / max(tp + fn, 1), "false_alarm_rate": fp / max(fp + tn, 1),
         "precision": tp / max(tp + fp, 1), "tp": tp, "fn": fn, "fp": fp, "tn": tn}
    b["f1"] = 2 * b["precision"] * b["detection_rate"] / max(b["precision"] + b["detection_rate"], 1e-12)
    return b


def cross_capture(ds, held_out, per_class, trees, rng):
    """Train on every capture except `held_out` (all splits), score the entire held-out capture."""
    files = {os.path.splitext(os.path.basename(p))[0]: p
             for p in sorted(glob.glob(os.path.join(OUT, "features", ds, "*.parquet")))}
    Xs, ys = [], []
    for cap, p in files.items():
        if cap == held_out:
            continue
        d = pd.read_parquet(p, columns=ap.FEATURES + ["attack_class"])
        parts = [g.sample(min(len(g), per_class), random_state=0) for _, g in d.groupby("attack_class")]
        d = pd.concat(parts)
        Xs.append(d[ap.FEATURES].to_numpy(np.float32)); ys.append(d.attack_class.to_numpy())
    X, y = np.concatenate(Xs), np.concatenate(ys)
    # re-cap per class over all training captures
    keep = np.concatenate([rng.permutation(np.flatnonzero(y == c))[:per_class] for c in np.unique(y)])
    X, y = X[keep], y[keep]
    rf = make_rf(trees).fit(X, y)
    seen = set(y)
    d = pd.read_parquet(files[held_out], columns=ap.FEATURES + ["attack_class"])
    yp = np.concatenate([rf.predict(d[ap.FEATURES].iloc[a:a + 1_000_000].to_numpy(np.float32))
                         for a in range(0, len(d), 1_000_000)])
    yt = d.attack_class.to_numpy()
    labels = [c for c in ap.ATTACK_CLASSES if c in set(yt) and c in seen]
    unseen = sorted(set(yt) - seen)
    rep = classification_report(yt, yp, labels=labels, digits=4, zero_division=0)
    return {"held_out": held_out, "test_flows": int(len(yt)),
            "train_classes": pd.Series(y).value_counts().to_dict(),
            "macro_f1": f1_score(yt, yp, labels=labels, average="macro", zero_division=0),
            "binary_attack_detection": binary_scores(yt, yp), "classes_unseen_in_training": unseen,
            "report": rep}


def run(ds, per_class, trees, rng):
    files = sorted(glob.glob(os.path.join(OUT, "features", ds, "*.parquet")))
    lab = ["split", "attack_class"]
    # pass 1: training class counts -> per-class sampling probability
    counts = pd.Series(dtype="int64")
    for p in files:
        d = pd.read_parquet(p, columns=lab)
        counts = counts.add(d[d.split == "train"].attack_class.value_counts(), fill_value=0)
    prob = (per_class / counts).clip(upper=1.0)
    # pass 2: sample training rows
    Xs, ys = [], []
    for p in files:
        d = pd.read_parquet(p, columns=ap.FEATURES + lab)
        d = d[d.split == "train"]
        keep = rng.random(len(d)) < d.attack_class.map(prob).to_numpy()
        Xs.append(d.loc[keep, ap.FEATURES].to_numpy(np.float32)); ys.append(d.loc[keep, "attack_class"].to_numpy())
    X, y = np.concatenate(Xs), np.concatenate(ys)
    del Xs
    classes = [c for c in ap.ATTACK_CLASSES if c in set(y)]
    log(f"[{ds}] training on {len(y):,} rows " + str(pd.Series(y).value_counts().to_dict()))
    t = time.time()
    rf = make_rf(trees)
    rf.fit(X, y)
    fit_s = time.time() - t
    del X, y
    # pass 3: score the full test split
    yt, yp = [], []
    for p in files:
        d = pd.read_parquet(p, columns=ap.FEATURES + lab)
        d = d[d.split == "test"]
        if not len(d):
            continue
        for a in range(0, len(d), 1_000_000):
            part = d.iloc[a:a + 1_000_000]
            yp.append(rf.predict(part[ap.FEATURES].to_numpy(np.float32))); yt.append(part.attack_class.to_numpy())
    yt, yp = np.concatenate(yt), np.concatenate(yp)
    labels = [c for c in ap.ATTACK_CLASSES if c in set(yt) | set(yp)]
    rep = classification_report(yt, yp, labels=labels, digits=4, zero_division=0, output_dict=True)
    rep_txt = classification_report(yt, yp, labels=labels, digits=4, zero_division=0)
    cm = pd.DataFrame(confusion_matrix(yt, yp, labels=labels), index=[f"true {c}" for c in labels],
                      columns=[f"pred {c}" for c in labels])
    binary = binary_scores(yt, yp)
    imp = pd.Series(rf.feature_importances_, index=ap.FEATURES).sort_values(ascending=False)
    res = {"test_rows": int(len(yt)), "fit_seconds": round(fit_s, 1),
           "macro_f1": f1_score(yt, yp, labels=labels, average="macro", zero_division=0),
           "per_class": {c: {k: rep[c][k] for k in ("precision", "recall", "f1-score", "support")} for c in labels},
           "binary_attack_detection": binary, "top_features": imp.head(10).round(4).to_dict()}
    text = [f"Baseline Random Forest - {ds}", NOTES.get(ds, ""), "",
            f"train rows (capped {per_class:,}/class): see log | test rows: {len(yt):,} (full test split, later in time than train)",
            "", rep_txt,
            f"binary attack detection: detection rate {binary['detection_rate']:.4f} | false-alarm rate "
            f"{binary['false_alarm_rate']:.4f} | precision {binary['precision']:.4f} | F1 {binary['f1']:.4f}",
            "", "confusion matrix (rows = true, columns = predicted):", cm.to_string(), "",
            "top 10 features:", imp.head(10).round(4).to_string()]
    if ds in CROSS_CAPTURE:
        res["cross_capture"] = []
        text += ["", "=" * 70, "CROSS-CAPTURE TEST (leave one capture out: train on the other captures,",
                 "score the ENTIRE unseen capture) - measures generalisation, not memory", "=" * 70]
        for cap in CROSS_CAPTURE[ds]:
            r = cross_capture(ds, cap, per_class, trees, rng)
            b = r["binary_attack_detection"]
            text += ["", f"held out: {cap}  ({r['test_flows']:,} flows) | train classes {r['train_classes']}",
                     f"classes in this capture never seen in training: {r['classes_unseen_in_training'] or 'none'}",
                     r["report"], f"macro F1 {r['macro_f1']:.4f} | detection {b['detection_rate']:.4f} | "
                     f"false alarms {b['false_alarm_rate']:.4f}"]
            log(f"[{ds}] cross-capture {cap}: macro F1 {r['macro_f1']:.4f} | detection "
                f"{b['detection_rate']:.4f} | false alarms {b['false_alarm_rate']:.4f}")
            r.pop("report")
            res["cross_capture"].append(r)
    os.makedirs(os.path.join(OUT, "baseline"), exist_ok=True)
    open(os.path.join(OUT, "baseline", f"{ds}_report.txt"), "w").write("\n".join(text) + "\n")
    log(f"[{ds}] macro F1 {res['macro_f1']:.4f} | detection {binary['detection_rate']:.4f} | "
        f"false alarms {binary['false_alarm_rate']:.4f}")
    return res


def main():
    a = argparse.ArgumentParser()
    a.add_argument("--datasets", nargs="+", default=ap.ACTIVE_DATASETS, choices=ap.ALL_DATASETS)
    a.add_argument("--per-class", type=int, default=200_000)
    a.add_argument("--trees", type=int, default=100)
    args = a.parse_args()
    rng = np.random.default_rng(0)
    path = os.path.join(OUT, "baseline", "results.json")
    results = json.load(open(path)) if os.path.exists(path) else {}
    results = {k: v for k, v in results.items() if k in args.datasets}   # report only datasets in use
    for ds in args.datasets:
        results[ds] = run(ds, args.per_class, args.trees, rng)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    json.dump(results, open(path, "w"), indent=1)
    rows = []
    for ds, r in results.items():
        row = {"dataset": ds, "test_flows": r["test_rows"], "macro_F1": r["macro_f1"],
               "detection_rate": r["binary_attack_detection"]["detection_rate"],
               "false_alarm_rate": r["binary_attack_detection"]["false_alarm_rate"]}
        for c, m in r["per_class"].items():
            row[f"F1_{c}"] = m["f1-score"]
        rows.append(row)
    S = pd.DataFrame(rows).set_index("dataset")
    txt = "Baseline Random Forest (45 features, trained on train split, scored on full test split)\n\n" + \
          S.round(4).to_string(na_rep="-") + "\n"
    cc = [{"dataset": ds, "held_out_capture": c["held_out"], "flows": c["test_flows"], "macro_F1": c["macro_f1"],
           "detection_rate": c["binary_attack_detection"]["detection_rate"],
           "false_alarm_rate": c["binary_attack_detection"]["false_alarm_rate"]}
          for ds, r in results.items() for c in r.get("cross_capture", [])]
    if cc:
        txt += "\nCross-capture test (train on the other captures, score the whole unseen capture)\n\n" + \
               pd.DataFrame(cc).set_index(["dataset", "held_out_capture"]).round(4).to_string() + "\n"
    open(os.path.join(OUT, "baseline", "summary.txt"), "w").write(txt)
    print(txt)


if __name__ == "__main__":
    main()
