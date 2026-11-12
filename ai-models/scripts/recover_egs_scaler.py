"""
Recover the StandardScaler the E-GraphSAGE notebook fitted but never saved.

The notebook computed it, used it, and discarded it when the kernel closed.
Without it the trained weights cannot be applied to new data at all.

Nothing is retrained here. The scaler is only a mean and a standard deviation
per feature, measured on the training split — this script reproduces that split
exactly (same seed, same window size, same held-out families) and re-measures.

Writes into EGraphSAGE_results/:
    egs_scaler.pkl     the scaler
    egs_features.json  the feature columns, in order

Run:
    python recover_egs_scaler.py
"""
from __future__ import annotations

import gc
import json
import os
import pickle
import time
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler

# --------------------------------------------------------------------------
# Must match the notebook exactly — do not tune these
# --------------------------------------------------------------------------
# Where the data and trained artifacts live. Override without editing this
# file by setting AEGEX_POC_DIR; the default is one person's layout.
POC_DIR = Path(os.environ.get("AEGEX_POC_DIR",
                              r"C:\Users\KimoStore\Desktop\PoC"))
CSV_PATH = POC_DIR / "DNN-EdgeIIoT-dataset.csv"
OUT_DIR = POC_DIR / "EGraphSAGE_results"

SEED = 42
WINDOW = 100
HELDOUT_ATTACKS = ["XSS", "SQL_injection", "Backdoor"]

LABEL_COL, TYPE_COL = "Attack_label", "Attack_type"
SRC_COL, DST_COL = "ip.src_host", "ip.dst_host"

ID_LIKE = {
    "frame.time", "ip.src_host", "ip.dst_host", "arp.src.proto_ipv4",
    "arp.dst.proto_ipv4", "http.file_data", "http.request.full_uri",
    "http.request.version", "icmp.transmit_timestamp", "tcp.options",
    "tcp.payload", "mqtt.msg", "dns.qry.name", "http.referer", "mqtt.topic",
}


def main() -> None:
    assert CSV_PATH.exists(), f"CSV not found: {CSV_PATH}"
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    # 1 — column selection, exactly as the notebook did it -----------------
    print("1/5  choosing columns ...")
    peek = pd.read_csv(CSV_PATH, nrows=2000, low_memory=False)
    for col in (LABEL_COL, TYPE_COL, SRC_COL, DST_COL):
        assert col in peek.columns, f"missing column: {col}"
    numeric_cols = [c for c in peek.columns
                    if c not in (LABEL_COL, TYPE_COL) and c not in ID_LIKE
                    and pd.api.types.is_numeric_dtype(peek[c])]
    keep = numeric_cols + [LABEL_COL, TYPE_COL, SRC_COL, DST_COL]
    print(f"     {len(numeric_cols)} candidate numeric features")
    del peek
    gc.collect()

    # 2 — load every flow, leniently --------------------------------------
    print("2/5  loading every flow (slowest step) ...")
    t0 = time.time()
    parts, unparsable = [], {c: 0 for c in numeric_cols}
    for chunk in pd.read_csv(CSV_PATH, usecols=keep, chunksize=200_000,
                             low_memory=False):
        for c in numeric_cols:
            conv = pd.to_numeric(chunk[c], errors="coerce")
            unparsable[c] += int(conv.isna().sum() - chunk[c].isna().sum())
            chunk[c] = conv.astype(np.float32)
        chunk[LABEL_COL] = (pd.to_numeric(chunk[LABEL_COL], errors="coerce")
                            .fillna(0).astype(np.int8))
        parts.append(chunk)
    df = pd.concat(parts, ignore_index=True)
    del parts
    gc.collect()
    n = len(df)
    print(f"     {n:,} flows in {time.time() - t0:.0f}s")

    # same 1% text-tolerance rule
    dead = [c for c, v in unparsable.items() if v > 0.01 * n]
    if dead:
        print(f"     dropping {len(dead)} text columns: {dead}")
        numeric_cols = [c for c in numeric_cols if c not in dead]

    missing = [a for a in HELDOUT_ATTACKS if a not in set(df[TYPE_COL].unique())]
    assert not missing, f"held-out families not in the data: {missing}"

    # 3 — features, constant columns dropped ------------------------------
    print("3/5  building the feature matrix ...")
    X = df[numeric_cols].replace([np.inf, -np.inf], np.nan).fillna(0)
    const = [c for c in X.columns if X[c].nunique() <= 1]
    X = X.drop(columns=const)
    feature_cols = list(X.columns)
    print(f"     dropped {len(const)} constant columns -> {len(feature_cols)} features")
    Xv = X.values.astype(np.float32)
    atype = df[TYPE_COL].values.astype(str)
    del X
    gc.collect()

    # 4 — reproduce the window split --------------------------------------
    # build_windowed_graph() assigned win_id[i] = i // WINDOW; the node
    # renumbering it also did is irrelevant to the split, so it is skipped.
    print("4/5  reproducing the train / test / zero-day split ...")
    win_id = np.arange(n) // WINDOW
    n_win = int(win_id.max()) + 1

    rng = np.random.default_rng(SEED)
    heldout_flow = np.isin(atype, HELDOUT_ATTACKS)
    win_has_heldout = np.zeros(n_win, dtype=bool)
    win_has_heldout[np.unique(win_id[heldout_flow])] = True

    clean_wins = np.where(~win_has_heldout)[0]
    rng.shuffle(clean_wins)
    cut = int(0.7 * len(clean_wins))
    train_wins = np.sort(clean_wins[:cut])
    in_train = np.isin(win_id, train_wins)

    print(f"     windows {n_win:,} | clean windows {len(clean_wins):,} "
          f"| train windows {len(train_wins):,} | train flows {int(in_train.sum()):,}")
    if in_train.sum() == 0:
        raise SystemExit(
            "     No training flows. Every window contains a held-out family, "
            "so nothing is left to fit on. That means this CSV is not the one "
            "the notebook trained on, or WINDOW / HELDOUT_ATTACKS were changed."
        )
    assert not np.isin(atype[in_train], HELDOUT_ATTACKS).any(), \
        "LEAK: a held-out family reached training — split does not match"
    print("     no held-out family in training — split matches the notebook")

    # 5 — fit and save -----------------------------------------------------
    print("5/5  fitting and saving ...")
    scaler = StandardScaler().fit(Xv[in_train])

    with open(OUT_DIR / "egs_scaler.pkl", "wb") as fh:
        pickle.dump(scaler, fh)
    with open(OUT_DIR / "egs_features.json", "w") as fh:
        json.dump({"window": WINDOW, "seed": SEED,
                   "heldout_attacks": HELDOUT_ATTACKS,
                   "n_features": len(feature_cols),
                   "features": feature_cols}, fh, indent=2)

    # verification against the trained weights ----------------------------
    pt = OUT_DIR / "egraphsage.pt"
    if pt.exists():
        import torch
        sd = torch.load(pt, map_location="cpu")
        # l1.lin takes CONCAT(node, node, edge) -> edge_dim = in_features - 2*hidden
        w = sd["l1.lin.weight"]
        hidden = w.shape[0]
        edge_dim = w.shape[1] - 2 * hidden
        print()
        print(f"     model expects  {edge_dim} features")
        print(f"     scaler carries {scaler.n_features_in_} features")
        if edge_dim == scaler.n_features_in_:
            print("     MATCH — the scaler fits the trained model")
        else:
            print("     MISMATCH — do not use this scaler; tell Claude these numbers")
            return

    print(f"\ndone -> {OUT_DIR / 'egs_scaler.pkl'}")
    print(f"     -> {OUT_DIR / 'egs_features.json'}")


if __name__ == "__main__":
    main()
