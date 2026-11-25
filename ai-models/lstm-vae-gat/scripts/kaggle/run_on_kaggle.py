"""
Try a dataset on Kaggle without downloading it: preprocessing -> LSTM-AE -> VAE -> one-line-rule check ->
realistic benchmark (saved thresholds, then recalibrated + per-device) -> results summary.

Run inside a Kaggle notebook / script kernel that has two inputs attached:
    * the Aegex code (this repository's scripts\\ folder, uploaded as a private Kaggle dataset)
    * the candidate dataset (e.g. emilynack/aci-iot-network-traffic-dataset-2023)

Only small files are kept in /kaggle/working (reports, metrics, summary CSVs, model bundles, logs); the
large intermediate tables are deleted at the end so the notebook output stays small.

Usage (inside Kaggle):
    python run_on_kaggle.py --dataset aci
"""
import argparse
import glob
import json
import os
import shutil
import subprocess
import sys
import time

WORK = "/kaggle/working"


def find_code():
    here = os.path.dirname(os.path.abspath(__file__))
    for root in [os.path.join(here, ".."), "/kaggle/input"]:
        hits = glob.glob(os.path.join(root, "**", "preprocessing", "step1_flows.py"), recursive=True)
        if hits:
            return os.path.dirname(os.path.dirname(os.path.abspath(hits[0])))
    raise SystemExit("Aegex code not found: attach the code dataset (it must contain preprocessing/step1_flows.py)")


def main():
    a = argparse.ArgumentParser()
    a.add_argument("--dataset", required=True)
    a.add_argument("--tag", default="kaggle_v1", help="suffix of the model run names")
    a.add_argument("--keep-intermediate", action="store_true", help="do not delete preprocessed/ at the end")
    args = a.parse_args()

    code = find_code()
    os.environ.setdefault("AEGEX_DATA", "/kaggle/input")
    os.environ.setdefault("AEGEX_OUT", WORK)
    os.environ["PYTHONDONTWRITEBYTECODE"] = "1"          # code folder is read-only on Kaggle
    out = os.environ["AEGEX_OUT"]
    os.makedirs(out, exist_ok=True)
    log_path = os.path.join(out, f"run_{args.dataset}.log")
    ds, lstm, vae = args.dataset, f"lstm_ae_{args.dataset}_{args.tag}", f"vae_{args.dataset}_{args.tag}"
    prep, models = os.path.join(code, "preprocessing"), os.path.join(code, "models")

    steps = [
        ("preprocess 1/3 flows", [f"{prep}/step1_flows.py", "--datasets", ds, "--workers", "1", "--skip-checksums"]),
        ("preprocess 2/3 features", [f"{prep}/step2_features.py", "--datasets", ds]),
        ("preprocess 3/3 windows+graphs", [f"{prep}/step3_sequences_graphs.py", "--datasets", ds]),
        ("train LSTM-AE", [f"{models}/train_lstm_ae.py", "--datasets", ds, "--run", lstm]),
        ("train VAE", [f"{models}/train_vae.py", "--lstm-run", lstm, "--run", vae]),
        ("one-line-rule check", [f"{models}/investigate_results.py", "--lstm-run", lstm, "--vae-run", vae,
                                 "--datasets", ds]),
        ("benchmark (saved thresholds)", [f"{models}/benchmark.py", "--lstm-run", lstm, "--vae-run", vae,
                                          "--datasets", ds]),
        ("benchmark (recalibrated + per-device)", [f"{models}/benchmark.py", "--lstm-run", lstm, "--vae-run", vae,
                                                   "--datasets", ds, "--recalibrate", "--per-device"]),
        ("results summary", [f"{models}/export_results_summary.py"]),
    ]
    status = {}
    with open(log_path, "w", encoding="utf-8") as log:
        def say(msg):
            line = time.strftime("%H:%M:%S ") + msg
            print(line, flush=True)
            log.write(line + "\n")
            log.flush()
        say(f"code={code} data={os.environ['AEGEX_DATA']} out={out}")
        for name, cmd in steps:
            say(f"===== {name}")
            t0 = time.time()
            p = subprocess.Popen([sys.executable, "-u"] + cmd, cwd=os.path.dirname(cmd[0]),
                                 stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            for line in p.stdout:
                print(line, end="", flush=True)
                log.write(line)
            p.wait()
            status[name] = {"exit": p.returncode, "seconds": round(time.time() - t0, 1)}
            say(f"----- {name}: exit {p.returncode} ({status[name]['seconds']} s)")
            if p.returncode != 0:
                say("STOPPED: fix the error above and run again")
                break
    json.dump(status, open(os.path.join(out, f"run_{ds}_status.json"), "w"), indent=1)

    # keep the small preprocessing reports, drop the big tables
    pre = os.path.join(out, "preprocessed")
    keep = os.path.join(out, "preprocessing_reports")
    os.makedirs(keep, exist_ok=True)
    for f in glob.glob(os.path.join(pre, "**", "_*.json"), recursive=True) + \
            glob.glob(os.path.join(pre, "**", "*_spec.json"), recursive=True):
        dst = os.path.join(keep, os.path.relpath(f, pre).replace(os.sep, "__"))
        shutil.copy(f, dst)
    if not args.keep_intermediate and os.path.isdir(pre):
        shutil.rmtree(pre)
    print(f"done; results in {out} (see run_{ds}.log, model_results/, results_summary/)")


if __name__ == "__main__":
    main()
