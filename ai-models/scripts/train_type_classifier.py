"""
Train the missing third model: which KIND of attack is this flow?

The autoencoder answers "is this anomalous", E-GraphSAGE answers "is this an
attack". Neither names the attack, so the report has been borrowing the
dataset's own label. This trains a classifier over the 15 Attack_type classes
on the same 38 features, so the name comes from a model.

Writes into PoC_results/:
    type_classifier.keras   the trained network
    type_scaler.pkl         its scaler
    type_classes.json       class names, in model-output order
    type_report.csv         per-class recall on held-out data

Run:
    python train_type_classifier.py
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

os.environ.setdefault("TF_CPP_MIN_LOG_LEVEL", "3")

# Where the data and trained artifacts live. Override without editing this
# file by setting AEGEX_POC_DIR; the default is one person's layout.
POC_DIR = Path(os.environ.get("AEGEX_POC_DIR",
                              r"C:\Users\KimoStore\Desktop\PoC"))
CSV_PATH = POC_DIR / "DNN-EdgeIIoT-dataset.csv"
OUT_DIR = POC_DIR / "PoC_results"

SEED = 42
BLOCK = 500        # flows per block; blocks are split, never individual flows
TEST_FRAC = 0.30
EPOCHS = 12
BATCH = 2048

LABEL_COL, TYPE_COL = "Attack_label", "Attack_type"
ID_LIKE = {
    "frame.time", "ip.src_host", "ip.dst_host", "arp.src.proto_ipv4",
    "arp.dst.proto_ipv4", "http.file_data", "http.request.full_uri",
    "http.request.version", "icmp.transmit_timestamp", "tcp.options",
    "tcp.payload", "mqtt.msg", "dns.qry.name", "http.referer", "mqtt.topic",
}


def load() -> tuple[pd.DataFrame, list[str]]:
    peek = pd.read_csv(CSV_PATH, nrows=2000, low_memory=False)
    numeric_cols = [c for c in peek.columns
                    if c not in (LABEL_COL, TYPE_COL) and c not in ID_LIKE
                    and pd.api.types.is_numeric_dtype(peek[c])]
    keep = numeric_cols + [LABEL_COL, TYPE_COL]
    del peek
    gc.collect()

    parts, unparsable = [], {c: 0 for c in numeric_cols}
    for chunk in pd.read_csv(CSV_PATH, usecols=keep, chunksize=200_000,
                             low_memory=False):
        for c in numeric_cols:
            conv = pd.to_numeric(chunk[c], errors="coerce")
            unparsable[c] += int(conv.isna().sum() - chunk[c].isna().sum())
            chunk[c] = conv.astype(np.float32)
        parts.append(chunk)
    df = pd.concat(parts, ignore_index=True)
    del parts
    gc.collect()

    dead = [c for c, v in unparsable.items() if v > 0.01 * len(df)]
    if dead:
        print(f"     dropping {len(dead)} text columns: {dead}")
        numeric_cols = [c for c in numeric_cols if c not in dead]
    return df, numeric_cols


def main() -> None:
    assert CSV_PATH.exists(), f"CSV not found: {CSV_PATH}"
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    np.random.seed(SEED)

    print("1/6  loading ...")
    t0 = time.time()
    df, numeric_cols = load()
    n = len(df)
    print(f"     {n:,} flows in {time.time() - t0:.0f}s")

    print("2/6  features and labels ...")
    X = df[numeric_cols].replace([np.inf, -np.inf], np.nan).fillna(0)
    const = [c for c in X.columns if X[c].nunique() <= 1]
    X = X.drop(columns=const)
    feature_cols = list(X.columns)
    Xv = X.values.astype(np.float32)
    del X
    gc.collect()

    classes = sorted(df[TYPE_COL].astype(str).unique())
    code = {c: i for i, c in enumerate(classes)}
    y = df[TYPE_COL].astype(str).map(code).values.astype(np.int32)
    print(f"     {len(feature_cols)} features | {len(classes)} classes")
    for c in classes:
        k = int((y == code[c]).sum())
        print(f"       {c:<24} {k:>9,}  ({k / n:.2%})")
    del df
    gc.collect()

    # 3 — block split ------------------------------------------------------
    # Neighbouring flows belong to the same burst and are near-duplicates.
    # Splitting individual flows at random would put copies of the same burst
    # in both train and test, and the accuracy would be inflated. Whole blocks
    # are assigned to one side instead.
    print("3/6  splitting by blocks (not by single flows) ...")
    block_id = np.arange(n) // BLOCK
    n_blocks = int(block_id.max()) + 1
    rng = np.random.default_rng(SEED)

    # A rare family can occupy only a handful of blocks, so a plain shuffle can
    # drop all of them on one side and leave the class untested or untrained.
    # Blocks are grouped by the class that dominates them and split within each
    # group, which keeps every class on both sides.
    dom = np.zeros(n_blocks, dtype=np.int32)
    for b in range(n_blocks):
        seg = y[b * BLOCK:(b + 1) * BLOCK]
        dom[b] = np.bincount(seg, minlength=len(classes)).argmax()

    test_blocks = np.zeros(n_blocks, dtype=bool)
    for ci in range(len(classes)):
        own = np.where(dom == ci)[0]
        if len(own) == 0:
            continue
        own = own[rng.permutation(len(own))]
        k = max(1, int(round(TEST_FRAC * len(own)))) if len(own) > 1 else 0
        test_blocks[own[:k]] = True

    is_test = test_blocks[block_id]
    is_train = ~is_test
    print(f"     blocks {n_blocks:,} | train flows {int(is_train.sum()):,} "
          f"| test flows {int(is_test.sum()):,}")

    for name in classes:
        i = code[name]
        tr, te = int((y[is_train] == i).sum()), int((y[is_test] == i).sum())
        if tr == 0 or te == 0:
            print(f"     ! {name}: train {tr:,} / test {te:,} — too few blocks "
                  f"to appear on both sides")

    print("4/6  scaling ...")
    scaler = StandardScaler().fit(Xv[is_train])
    Xs = scaler.transform(Xv).astype(np.float32)
    del Xv
    gc.collect()

    # 5 — train ------------------------------------------------------------
    print("5/6  training ...")
    from tensorflow import keras

    counts = np.bincount(y[is_train], minlength=len(classes)).astype(np.float64)
    weights = {i: (len(y[is_train]) / (len(classes) * c)) if c > 0 else 0.0
               for i, c in enumerate(counts)}

    model = keras.Sequential([
        keras.layers.Input((Xs.shape[1],)),
        keras.layers.Dense(128, activation="relu"),
        keras.layers.Dropout(0.2),
        keras.layers.Dense(64, activation="relu"),
        keras.layers.Dropout(0.2),
        keras.layers.Dense(len(classes), activation="softmax"),
    ])
    model.compile(optimizer="adam",
                  loss="sparse_categorical_crossentropy",
                  metrics=["accuracy"])
    model.fit(Xs[is_train], y[is_train], epochs=EPOCHS, batch_size=BATCH,
              class_weight=weights, verbose=2, shuffle=True)

    # 6 — evaluate and save ------------------------------------------------
    print("6/6  evaluating on held-out blocks ...")
    pred = np.argmax(model.predict(Xs[is_test], batch_size=8192, verbose=0), axis=1)
    truth = y[is_test]
    overall = float((pred == truth).mean())

    rows = []
    for c in classes:
        i = code[c]
        m = truth == i
        rows.append({
            "attack_type": c,
            "test_flows": int(m.sum()),
            "recall": float((pred[m] == i).mean()) if m.sum() else float("nan"),
        })
    rep = pd.DataFrame(rows).sort_values("recall", ascending=False)

    print()
    print(f"     overall accuracy on unseen blocks: {overall:.2%}")
    print()
    print(rep.to_string(index=False))

    model.save(OUT_DIR / "type_classifier.keras")
    with open(OUT_DIR / "type_scaler.pkl", "wb") as fh:
        pickle.dump(scaler, fh)
    with open(OUT_DIR / "type_classes.json", "w") as fh:
        json.dump({"classes": classes, "features": feature_cols,
                   "overall_accuracy": overall, "block": BLOCK,
                   "seed": SEED}, fh, indent=2)
    rep.to_csv(OUT_DIR / "type_report.csv", index=False)

    print(f"\ndone -> {OUT_DIR / 'type_classifier.keras'}")


if __name__ == "__main__":
    main()
