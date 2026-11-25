"""
Write CSV copies of model outputs that already exist as parquet (no retraining needed).
New training / scoring runs write the CSV automatically (aegex_models.write_output).

Usage:
    python export_csv.py                         # lstm_ae_v8, vae_v5, gat_v2
    python export_csv.py --runs lstm_ae/lstm_ae_v8 vae/vae_v5
    python export_csv.py --path ..\\..\\live_results\\mycapture
Each <name>.parquet gets a <name>.csv next to it (existing CSVs are overwritten).
"""
import argparse
import glob
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import pandas as pd

import aegex_models as am


def main():
    a = argparse.ArgumentParser()
    a.add_argument("--runs", nargs="+", default=["lstm_ae/lstm_ae_v8", "vae/vae_v5", "gat/gat_v2"],
                   help="<stage>/<run> under preprocessed/model_outputs")
    a.add_argument("--path", nargs="*", default=[], help="extra folders with parquet files (e.g. live_results/<capture>)")
    args = a.parse_args()
    folders = [os.path.join(am.PREPROCESSED, "model_outputs", r) for r in args.runs] + args.path
    for d in folders:
        files = sorted(glob.glob(os.path.join(d, "*.parquet")))
        if not files:
            print(f"(no parquet files in {d})")
        for f in files:
            df = pd.read_parquet(f)
            out = os.path.splitext(f)[0] + ".csv"
            am.to_csv_safe(df, out)
            print(f"{len(df):>10,} rows -> {out} ({os.path.getsize(out) / 1e6:.1f} MB)", flush=True)


if __name__ == "__main__":
    main()
