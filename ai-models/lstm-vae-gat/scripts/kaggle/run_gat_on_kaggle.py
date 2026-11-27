"""
Train a temporal GAT on Kaggle across several networks, each scored by its own LSTM-AE + VAE.

Inputs attached to the kernel:
    * aegex-code        this repository's scripts\\ folder (private Kaggle dataset)
    * aegex-gat-data    already-preprocessed networks + their trained LSTM-AE / VAE bundles, uploaded from the
                        project PC (folders preprocessed\\ and models\\, private Kaggle dataset)
    * raw datasets for the networks preprocessed HERE (--new), e.g. ACI-IoT-2023 and IoT-23

Steps
    1. copy aegex-gat-data into /kaggle/working (so all networks sit in one preprocessed\\ + models\\ tree)
    2. for every --new dataset: preprocessing steps 1-3, train its own LSTM-AE + VAE
       (a dataset whose steps fail is dropped from the GAT run, the rest continue)
    3. train_gat.py with one chain per dataset, --relative-scores, node blocks traffic + stage
    4. keep reports, metrics and model bundles; delete the big preprocessed tables

Usage (inside Kaggle):
    python run_gat_on_kaggle.py --new aci iot23x --train gotham iot23 xiiotid aci iot23x \
        --test kitsune edge --chain gotham=lstm_ae_gotham_v1:vae_gotham_v1 ... --run gat_v4
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
    raise SystemExit("Aegex code not found")


def find_data():
    for p in glob.glob("/kaggle/input/**/aegex_gat_data_marker.txt", recursive=True):
        return os.path.dirname(p)
    raise SystemExit("aegex-gat-data not attached (marker file missing)")


def main():
    a = argparse.ArgumentParser()
    a.add_argument("--new", nargs="*", default=[], help="datasets to preprocess + train LSTM/VAE here")
    a.add_argument("--train", nargs="+", required=True, help="GAT training networks")
    a.add_argument("--test", nargs="*", default=[], help="GAT test-only networks")
    a.add_argument("--chain", nargs="*", default=[], help="ds=lstm_run:vae_run for uploaded networks")
    a.add_argument("--tag", default="kaggle_v2")
    a.add_argument("--run", default="gat_v4")
    a.add_argument("--gat-args", default="", help="extra arguments for train_gat.py")
    args = a.parse_args()

    code = find_code()
    os.environ.setdefault("AEGEX_DATA", "/kaggle/input")
    os.environ.setdefault("AEGEX_OUT", WORK)
    os.environ["PYTHONDONTWRITEBYTECODE"] = "1"
    out = os.environ["AEGEX_OUT"]
    os.makedirs(out, exist_ok=True)
    prep, models = os.path.join(code, "preprocessing"), os.path.join(code, "models")
    log = open(os.path.join(out, f"run_{args.run}.log"), "w", encoding="utf-8")
    status = {}

    def say(msg):
        line = time.strftime("%H:%M:%S ") + msg
        print(line, flush=True); log.write(line + "\n"); log.flush()

    def run(name, cmd):
        say(f"===== {name}")
        t0 = time.time()
        p = subprocess.Popen([sys.executable, "-u"] + cmd, cwd=os.path.dirname(cmd[0]),
                             stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        for line in p.stdout:
            print(line, end="", flush=True); log.write(line)
        p.wait()
        status[name] = {"exit": p.returncode, "seconds": round(time.time() - t0, 1)}
        say(f"----- {name}: exit {p.returncode} ({status[name]['seconds']} s)")
        return p.returncode == 0

    # 1. uploaded networks + models
    data = find_data()
    for sub in ("preprocessed", "models"):
        src = os.path.join(data, sub)
        if os.path.isdir(src):
            shutil.copytree(src, os.path.join(out, sub), dirs_exist_ok=True)
        elif os.path.exists(src + ".zip"):               # folder uploaded as a zip and not unpacked by Kaggle
            shutil.unpack_archive(src + ".zip", os.path.join(out, sub))
        else:
            raise SystemExit(f"{sub} missing in {data}: {os.listdir(data)}")
        if os.path.isdir(os.path.join(out, sub, sub)):     # zip held the folder itself -> flatten one level
            shutil.copytree(os.path.join(out, sub, sub), os.path.join(out, sub), dirs_exist_ok=True)
            shutil.rmtree(os.path.join(out, sub, sub))
    say(f"code={code} uploaded data={data} out={out}")

    # 2. new networks
    chains = list(args.chain)
    ok_new = []
    for ds in args.new:
        lstm, vae = f"lstm_ae_{ds}_{args.tag}", f"vae_{ds}_{args.tag}"
        steps = [(f"{ds} flows", [f"{prep}/step1_flows.py", "--datasets", ds, "--workers", "1", "--skip-checksums"]),
                 (f"{ds} features", [f"{prep}/step2_features.py", "--datasets", ds]),
                 (f"{ds} windows+graphs", [f"{prep}/step3_sequences_graphs.py", "--datasets", ds]),
                 (f"{ds} LSTM-AE", [f"{models}/train_lstm_ae.py", "--datasets", ds, "--run", lstm]),
                 (f"{ds} VAE", [f"{models}/train_vae.py", "--lstm-run", lstm, "--run", vae])]
        if all(run(n, c) for n, c in steps):
            ok_new.append(ds)
            chains.append(f"{ds}={lstm}:{vae}")
        else:
            say(f"DROPPED {ds}: a step failed, the GAT run continues without it")
    train = [d for d in args.train if d not in args.new or d in ok_new]
    test = [d for d in args.test if d not in args.new or d in ok_new]

    # 3. GAT
    cmd = [f"{models}/train_gat.py", "--run", args.run, "--inputs-tag", args.run, "--datasets", *train,
           "--node-blocks", "traffic", "stage", "--relative-scores"]
    if test:
        cmd += ["--test-datasets", *test]
    if chains:
        cmd += ["--chain", *chains]
    cmd += args.gat_args.split()
    run(f"train {args.run}", cmd)
    json.dump({"status": status, "train": train, "test": test, "chains": chains},
              open(os.path.join(out, f"run_{args.run}_status.json"), "w"), indent=1)

    # 4. keep small outputs only
    keep = os.path.join(out, "preprocessing_reports")
    os.makedirs(keep, exist_ok=True)
    pre = os.path.join(out, "preprocessed")
    for ds in ok_new:
        for f in glob.glob(os.path.join(pre, "**", ds, "_*.json"), recursive=True):
            shutil.copy(f, os.path.join(keep, os.path.relpath(f, pre).replace(os.sep, "__")))
    shutil.rmtree(pre, ignore_errors=True)
    for sub in ("lstm_ae", "vae"):                 # uploaded bundles are already on the PC
        for d in glob.glob(os.path.join(out, "models", sub, "*")):
            if not any(os.path.basename(d).endswith(f"_{args.tag}") for _ in [0]):
                shutil.rmtree(d, ignore_errors=True)
    say(f"done; see model_results/gat/{args.run}/evaluation.txt")


if __name__ == "__main__":
    main()
