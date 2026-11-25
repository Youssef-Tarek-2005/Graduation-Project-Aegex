"""
Step 1 - convert every raw dataset into the unified flow schema (aegex_prep.FLOW_COLUMNS).

The datasets themselves are plug-ins in scripts/aegex_datasets (one file each: originals, captures,
adapter). This script only runs them in parallel, saves the flows and verifies the originals.

Reads originals read-only (zips are streamed, never extracted or modified) and writes
    <out>/flows/<dataset>/<capture>.parquet          (streaming plug-ins, e.g. nf_toniot: <capture>/part-NNNN.parquet)
    <out>/flows/<dataset>/_report.json

Usage:
    python step1_flows.py [--datasets kitsune edge iot23 ...] [--workers 3]
    (default: the ACTIVE plug-ins; `python -m aegex_datasets` in the scripts folder lists them)
"""
import argparse
import json
import os
import sys
from concurrent.futures import ProcessPoolExecutor, as_completed

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import aegex_prep as ap
import aegex_datasets as reg

HERE = os.path.dirname(os.path.abspath(__file__))
DATA = ap.DATA_DIR             # originals (AEGEX_DATA, default: project folder); found via ap.locate()
OUT = ap.PREPROCESSED_DIR      # outputs (AEGEX_OUT/preprocessed)
log = ap.log


# kept for older callers: {dataset: [original files]} and the ones stored in a sub-folder
ORIGINALS = {n: list(reg.get(n).ORIGINALS) for n in reg.names()}
PATH_ORIGINALS = {f for fs in ORIGINALS.values() for f in fs if os.sep in f or "/" in f}


# ---------------------------------------------------------------------------- workers
def capture_job(dataset, capture):
    """One capture of one plug-in (runs in a worker process)."""
    mod = reg.get(dataset)
    df, st = mod.build(capture)
    name = mod.capture_name(capture) if hasattr(mod, "capture_name") else capture
    return dataset, name, df, st


def save(dataset, capture, df):
    df["dataset"], df["capture"] = dataset, capture
    df = ap.to_schema(df)
    ap.write_parquet(df, os.path.join(OUT, "flows", dataset, f"{capture}.parquet"))
    return {"flows": len(df), "attack_flows": int(df.is_attack.sum()),
            "classes": df.attack_class.value_counts().to_dict(),
            "time": [float(df.ts.min()), float(df.ts.max())] if len(df) else None}


def run_pool(jobs, workers, report):
    with ProcessPoolExecutor(max_workers=workers) as ex:
        futs = {ex.submit(capture_job, ds, cap): (ds, cap) for ds, cap in jobs}
        for fu in as_completed(futs):
            ds, cap, df, st = fu.result()
            st.update(save(ds, cap, df))
            report.setdefault(ds, {})[cap] = st
            log(f"[{ds}/{cap}] {st['flows']:,} flows, classes {st['classes']}")


def main():
    ap_ = argparse.ArgumentParser()
    ap_.add_argument("--datasets", nargs="+", default=reg.active(), choices=reg.names())
    ap_.add_argument("--workers", type=int, default=3)
    ap_.add_argument("--skip-checksums", action="store_true")
    a = ap_.parse_args()

    names = reg.originals(a.datasets)
    if not a.skip_checksums:
        log("verifying originals against ORIGINALS_SHA256.txt ...")
        ap.check_originals(DATA, names)
        log("originals OK")

    report = {}
    jobs = [(ds, cap) for ds in a.datasets if not hasattr(reg.get(ds), "run")
            for cap in reg.get(ds).captures()]
    if jobs:
        run_pool(jobs, a.workers, report)
    for ds in a.datasets:                       # streaming plug-ins (too big for one DataFrame)
        if hasattr(reg.get(ds), "run"):
            reg.get(ds).run(report, log)

    for ds, caps in report.items():
        path = os.path.join(OUT, "flows", ds, "_report.json")
        old = json.load(open(path)) if os.path.exists(path) else {}
        old.update(caps)
        json.dump(old, open(path, "w"), indent=1, default=str)
    if not a.skip_checksums:
        ap.check_originals(DATA, names)
        log("originals still byte-identical after processing")


if __name__ == "__main__":
    main()
