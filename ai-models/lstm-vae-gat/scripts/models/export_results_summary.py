"""
Write the RESULTS as a few small CSV tables (no per-window / per-flow rows) to <project>\\results_summary\\.

    headline_results.csv     one row per dataset, quoted numbers, LSTM-AE and VAE (and rule) side by side
    benchmark_summary.csv    one row per benchmark run x dataset x method: detection (macro, 95 % interval),
                             false alarms, noise floor (control injections)        <- the numbers to quote
    benchmark_by_attack.csv  detection per attack type and speed
    benchmark_false_alarms_by_capture.csv   false alarms per normal recording
    gat_summary.csv          GAT vs window alerts per dataset (benchmark + dataset test split), incl. holdout runs
    gat_by_attack.csv        GAT detection per attack type; holdout rows = attack type never seen in training
    gat_controls.csv         GAT on injected normal traffic (shortcut check)
    test_split_summary.csv   per model run x dataset x class on the datasets' OWN test split (optimistic; not quoted)
    README.txt               what each file and column means

Column `quoted` = yes for the runs whose numbers are on the results page.

Usage:
    python export_results_summary.py [--out <folder>]
"""
import argparse
import glob
import json
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import pandas as pd

import aegex_models as am

RESULTS = os.path.join(am.DATA_ROOT, "model_results")
# results-page runs: benchmark folder -> datasets quoted from it (each dataset plug-in's QUOTED_RUN,
# scripts/aegex_datasets/<name>.py)
import aegex_datasets as reg

QUOTED_BENCH = reg.quoted_runs()
QUOTED_GAT = {"gat_v2", "gat_v2_ho_scanning", "gat_v2_ho_mirai", "gat_v2_ho_ddos", "gat_v2_ho_ransomware"}
METHOD_NAME = {"lstm": "LSTM-AE", "vae": "VAE", "either": "LSTM or VAE", "rule": "one-line rule"}


def r4(x):
    return None if x is None else round(float(x), 4)


def benchmark_tables():
    summ, by_attack, fa_cap = [], [], []
    for mpath in sorted(glob.glob(os.path.join(RESULTS, "benchmark", "*", "metrics.json"))):
        folder = os.path.basename(os.path.dirname(mpath))
        m = json.load(open(mpath))
        recal = "per-device" if folder.endswith("_dev") else ("network" if "__recal" in folder else "none")
        for ds, d in m.get("datasets", {}).items():
            quoted = "yes" if ds in QUOTED_BENCH.get(folder, set()) else "no"
            for meth in d.get("macro", {}):
                mac = d["macro"][meth].get("all", {})
                fa = d.get("false_alarms", {}).get(meth, {}).get("_all", {})
                nf = d.get("noise_floor", {}).get(meth, {})
                summ.append({"benchmark_run": folder, "lstm_run": m.get("lstm_run"), "vae_run": m.get("vae_run"),
                             "threshold_calibration": recal, "dataset": ds, "method": METHOD_NAME.get(meth, meth),
                             "detection_macro": r4(mac.get("value")),
                             "detection_ci95_low": r4((mac.get("ci95") or [None, None])[0]),
                             "detection_ci95_high": r4((mac.get("ci95") or [None, None])[1]),
                             "false_alarm_rate": r4(fa.get("rate")), "false_alarms_per_hour": r4(fa.get("alerts_per_hour")),
                             "incidents_detected": r4(d["macro"][meth].get("incidents_detected")),
                             "noise_floor_self": r4(nf.get("control_self")),
                             "noise_floor_self_nomap": r4(nf.get("control_self_nomap")),
                             "noise_floor_other_device": r4(nf.get("control_other")), "quoted": quoted})
            for meth, caps in d.get("false_alarms", {}).items():
                for cap, v in caps.items():
                    if cap != "_all":
                        fa_cap.append({"benchmark_run": folder, "dataset": ds, "normal_capture": cap,
                                       "method": METHOD_NAME.get(meth, meth), "false_alarm_rate": r4(v.get("rate")),
                                       "false_alarms_per_hour": r4(v.get("alerts_per_hour")), "quoted": quoted})
            for meth, att in d.get("detection", {}).items():
                for key, v in att.items():
                    name, _, speed = key.rpartition(" x")
                    cap, _, cls = name.partition(":")
                    by_attack.append({"benchmark_run": folder, "dataset": ds, "attack_capture": cap, "attack_class": cls,
                                      "slowdown": f"x{speed}", "method": METHOD_NAME.get(meth, meth),
                                      "detection": r4(v), "quoted": quoted})
    return pd.DataFrame(summ), pd.DataFrame(by_attack), pd.DataFrame(fa_cap)


def headline_table(summ):
    """One row per dataset from the quoted benchmark runs: every method side by side."""
    q = summ[summ.quoted == "yes"]
    rows = []
    for ds, g in q.groupby("dataset", sort=False):
        r = {"dataset": ds, "benchmark_run": g.benchmark_run.iloc[0], "threshold_calibration": g.threshold_calibration.iloc[0]}
        for meth, key in (("LSTM-AE", "lstm"), ("VAE", "vae"), ("LSTM or VAE", "lstm_or_vae"), ("one-line rule", "rule")):
            x = g[g.method == meth]
            if x.empty:
                continue
            x = x.iloc[0]
            r[f"{key}_detection"] = x.detection_macro
            r[f"{key}_false_alarms"] = x.false_alarm_rate
            if key in ("lstm", "vae"):
                r[f"{key}_noise_floor_self"] = x.noise_floor_self
                r[f"{key}_noise_floor_other_device"] = x.noise_floor_other_device
        rows.append(r)
    return pd.DataFrame(rows)


def gat_tables():
    from gat_dashboard import per_attack
    summ, by_attack, controls = [], [], []
    for mpath in sorted(glob.glob(os.path.join(RESULTS, "gat", "*", "metrics.json"))):
        run = os.path.basename(os.path.dirname(mpath))
        m = json.load(open(mpath))
        ho = m.get("holdout") or ""
        quoted = "yes" if run in QUOTED_GAT else "no"
        for test in ("benchmark", "dataset_test"):
            for ds, d in (m.get(test) or {}).items():
                summ.append({"gat_run": run, "held_out_attack": ho, "test_set": test, "dataset": ds,
                             "gat_detection": r4(d.get("gat_detection")), "gat_false_alarms": r4(d.get("gat_false_alarms")),
                             "window_alerts_detection": r4(d.get("baseline_detection")),
                             "window_alerts_false_alarms": r4(d.get("baseline_false_alarms")),
                             "attacker_ranked_first": r4(d.get("top1_source_attribution")),
                             "role_correct": r4(d.get("role_correct")), "roc_auc": r4(d.get("roc_auc")),
                             "involved_host_minutes": d.get("involved"), "other_host_minutes": d.get("other"),
                             "quoted": quoted if test == "benchmark" else "no"})
        for key, v in per_attack(run, m).items():
            ds, att = key.split("/", 1)
            by_attack.append({"gat_run": run, "held_out_attack": ho, "dataset": ds, "attack": att,
                              "seen_in_training": "no" if ho and att == ho else "yes",
                              "host_minutes": v["n"], "gat_detection": r4(v["gat"]),
                              "window_alerts_detection": r4(v["baseline"]), "quoted": quoted})
        for key, v in (m.get("controls") or {}).items():
            ds, kind = key.split("/", 1)
            controls.append({"gat_run": run, "dataset": ds, "control": kind,
                             "gat_flags_injected_host": r4(v.get("gat_injected")),
                             "gat_flags_other_hosts": r4(v.get("gat_other")),
                             "window_alerts_flag_injected_host": r4(v.get("baseline_injected")),
                             "window_alerts_flag_other_hosts": r4(v.get("baseline_other")), "quoted": quoted})
    return pd.DataFrame(summ), pd.DataFrame(by_attack), pd.DataFrame(controls)


def test_split_table():
    rows = []
    cols = ["split", "window_class", "device_compromised", "lstm_anomaly", "vae_anomaly"]
    for p in sorted(glob.glob(os.path.join(am.PREPROCESSED, "model_outputs", "vae", "*", "*_windows.parquet"))):
        run = os.path.basename(os.path.dirname(p))
        ds = os.path.basename(p)[:-len("_windows.parquet")]
        try:
            W = pd.read_parquet(p, columns=cols)
        except Exception:
            continue
        W = W[W.split == "test"]
        W["class"] = W.window_class.where(W.window_class != "benign",
                                          W.device_compromised.map({0: "benign (clean)", 1: "benign (compromised device)"}))
        for c, g in W.groupby("class"):
            rows.append({"vae_run": run, "dataset": ds, "class": c, "test_windows": len(g),
                         "lstm_flagged": r4(g.lstm_anomaly.mean()), "vae_flagged": r4(g.vae_anomaly.mean()),
                         "meaning": "false-alarm rate" if c.startswith("benign") else "detection rate"})
    return pd.DataFrame(rows)


README = """Aegex results summary  (generated {when} by scripts\\models\\export_results_summary.py)

All rates are shares between 0 and 1 (0.907 = 90.7 %). Column `quoted` = yes for the numbers on the results page.

headline_results.csv     ONE ROW PER DATASET with the quoted numbers: LSTM-AE, VAE, LSTM or VAE and the one-line
                         rule side by side (detection, false alarms; noise floor for LSTM and VAE).
benchmark_summary.csv    MAIN RESULTS. Realistic benchmark: real attack traffic hidden in real normal traffic,
                         test data only. One row per benchmark run x dataset x method.
  detection_macro          share of attack windows flagged, every attack type weighted equally
  detection_ci95_low/high  95 % bootstrap interval of detection_macro
  false_alarm_rate         share of clean normal windows flagged (target about 0.01)
  false_alarms_per_hour    the same as alerts per hour of normal traffic
  noise_floor_*            share flagged when plain NORMAL traffic is injected like an attack (self = the
                           device's own traffic replayed, other_device = another device's traffic). Detection
                           only counts as far as it is above this.
  threshold_calibration    none = alarm lines saved in the model; network = reset on the network's own
                           validation-period normal traffic; per-device = network + one line per device
benchmark_by_attack.csv  detection per attack type and speed (x1 = original speed, x10 / x100 = slowed down)
benchmark_false_alarms_by_capture.csv
                         false alarms per normal recording (e.g. Kitsune's camera network vs its Mirai network)
gat_summary.csv          GAT (which host is attacking / attacked, per minute) vs window alerts alone.
                         test_set benchmark = realistic benchmark (quoted); dataset_test = datasets' own split.
                         held_out_attack = attack type removed from GAT training in that run.
gat_by_attack.csv        GAT detection per attack; seen_in_training = no -> the unseen-attack result
gat_controls.csv         GAT on hosts that only received injected NORMAL traffic (should be low)
test_split_summary.csv   datasets' OWN test split per class (optimistic: attacks come as pure blocks; not quoted).
                         For benign rows the flagged share is the false-alarm rate.

Which run is quoted for each dataset is set in that dataset's plug-in (scripts\\aegex_datasets\\<name>.py,
QUOTED_RUN). nf_toniot is quoted with the thresholds saved in the model: recalibrating collapses there,
because one device dominates the calibration slice.
"""


def main():
    a = argparse.ArgumentParser()
    a.add_argument("--out", default=os.path.join(am.DATA_ROOT, "results_summary"))
    args = a.parse_args()
    os.makedirs(args.out, exist_ok=True)
    tables = {}
    tables["benchmark_summary"], tables["benchmark_by_attack"], tables["benchmark_false_alarms_by_capture"] = benchmark_tables()
    tables = {"headline_results": headline_table(tables["benchmark_summary"]), **tables}
    tables["gat_summary"], tables["gat_by_attack"], tables["gat_controls"] = gat_tables()
    tables["test_split_summary"] = test_split_table()
    for name, df in tables.items():
        path = os.path.join(args.out, f"{name}.csv")
        df.to_csv(path, index=False)
        print(f"{len(df):5d} rows -> {path}")
    with open(os.path.join(args.out, "README.txt"), "w", encoding="utf-8") as f:
        f.write(README.format(when=time.strftime("%Y-%m-%d %H:%M")))


if __name__ == "__main__":
    main()
