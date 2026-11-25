"""
Step 3 - model-ready structures for the LSTM-AE / VAE / Temporal GAT stages.

A) LSTM sequence windows (index only - nothing is duplicated on disk)
   Rows in features/<dataset>/<capture>.parquet are sorted by (device, ts), so a window is a
   contiguous row range [row_start, row_end) of one device. Default: 32 flows, stride 16.
   Devices with fewer flows get one shorter window (pad when batching).
     window label   = 1 if any flow in the window is an attack
     window_class   = attack class with most attack flows in the window (else benign)
     split          = split of the window's LAST flow; split_pure = all flows share that split
   -> <out>/windows/<dataset>.parquet

B) Temporal graph snapshots (for the GAT)
   Flows are bucketed into fixed time snapshots (default 60 s) per capture.
   Edges  = directed (src -> dst) host pairs in the snapshot, attributes = mean of the flow
            features + log flow count, labels = attack fraction / majority class.
   Nodes  = hosts in the snapshot with traffic aggregates and attack-source / attack-target counts.
   Public IPs that talk to only one host in a snapshot are merged into one 'EXTERNAL' node, so
   spoofed-source floods do not create millions of one-edge nodes.
   -> <out>/graphs/<dataset>/<capture>_edges.parquet, <capture>_nodes.parquet

Usage:
    python step3_sequences_graphs.py [--datasets ...] [--window 32] [--stride 16] [--snapshot 60]
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
SPLITS = ["train", "val", "test"]


def log(*a):
    print(time.strftime("%H:%M:%S"), *a, flush=True)


# ------------------------------------------------------------------------------------- windows
def windows_for(feat, cap, W, S):
    dev = feat.device.to_numpy()
    n = len(feat)
    starts_dev = np.flatnonzero(np.r_[True, dev[1:] != dev[:-1]])
    ends_dev = np.r_[starts_dev[1:], n]
    rs, re_ = [], []
    for a, b in zip(starts_dev, ends_dev):
        L = b - a
        if L <= W:
            rs.append(np.array([a])); re_.append(np.array([b]))
        else:
            s = np.arange(a, b - W + 1, S)
            if s[-1] != b - W:
                s = np.r_[s, b - W]            # last window ends exactly at the device's last flow
            rs.append(s); re_.append(s + W)
    rs, re_ = np.concatenate(rs), np.concatenate(re_)

    def csum(x):
        return np.r_[0, np.cumsum(x, dtype=np.int64)]

    att = csum(feat.is_attack.to_numpy())
    cls_counts = np.stack([csum(((feat.attack_class == c) & (feat.is_attack == 1)).to_numpy())
                           for c in ap.ATTACK_CLASSES], axis=1)
    split_vals = feat.split.to_numpy() if "split" in feat else np.full(n, "live", dtype=object)
    sp_counts = np.stack([csum(split_vals == s) for s in pd.unique(split_vals)], axis=1)
    n_att = att[re_] - att[rs]
    cc = cls_counts[re_] - cls_counts[rs]
    sc = sp_counts[re_] - sp_counts[rs]
    last_split = split_vals[re_ - 1]
    ts = feat.ts.to_numpy()
    out = pd.DataFrame({
        "capture": cap, "device": dev[rs], "row_start": rs, "row_end": re_, "n_flows": re_ - rs,
        "t_start": ts[rs], "t_end": ts[re_ - 1], "n_attack": n_att,
        "attack_frac": (n_att / (re_ - rs)).astype("float32"),
        "label": (n_att > 0).astype("int8"),
        "window_class": np.where(n_att > 0, np.array(ap.ATTACK_CLASSES)[cc.argmax(axis=1)], "benign"),
        "split": last_split, "split_pure": (sc.max(axis=1) == (re_ - rs)),
        "device_compromised": (feat.device_compromised.to_numpy()[rs] if "device_compromised" in feat
                               else np.zeros(len(rs), np.int8)),
    })
    return out


# ------------------------------------------------------------------------------------- graphs
def majority(df, keys, col):
    """Most frequent value of `col` per group (vectorised)."""
    c = df.groupby(keys + [col], sort=False, observed=True).size().reset_index(name="_n")
    c = c.sort_values("_n", kind="stable").drop_duplicates(keys, keep="last")
    return c.set_index(keys)[col]


def graphs_for(feat, snap_len):
    t0 = feat.ts.min()
    g = pd.DataFrame({"snapshot": ((feat.ts - t0) // snap_len).astype("int64"),
                      "src": feat.src_ip.astype(str), "dst": feat.dst_ip.astype(str)})
    # merge one-peer public hosts into EXTERNAL (peers counted regardless of direction)
    a, b = np.minimum(g.src.to_numpy(object), g.dst.to_numpy(object)), np.maximum(g.src.to_numpy(object), g.dst.to_numpy(object))
    pairs = pd.DataFrame({"snapshot": g.snapshot.to_numpy(), "a": a, "b": b}).drop_duplicates()
    deg = pd.concat([pairs[["snapshot", "a"]].rename(columns={"a": "node"}),
                     pairs[["snapshot", "b"]].rename(columns={"b": "node"})]).value_counts()
    lone = deg[deg == 1].reset_index()[["snapshot", "node"]]
    priv = {ip: ap.is_private(ip) for ip in pd.unique(lone.node)}
    lone = lone[~lone.node.map(priv).astype(bool)]
    if len(lone):
        lone["lone"] = True
        for col in ("src", "dst"):
            m = g[["snapshot", col]].merge(lone.rename(columns={"node": col}), on=["snapshot", col], how="left")
            g.loc[m["lone"].fillna(False).to_numpy(dtype=bool), col] = "EXTERNAL"

    cols = ap.FEATURES
    E = pd.concat([g, feat[cols + ["is_attack", "attack_class", "split", "fwd_bytes", "bwd_bytes"]]
                   .rename(columns={"fwd_bytes": "fwd_bytes_raw", "bwd_bytes": "bwd_bytes_raw"})
                   .reset_index(drop=True)], axis=1)
    keys = ["snapshot", "src", "dst"]
    grp = E.groupby(keys, sort=True)
    edges = grp[cols].mean().astype("float32")
    edges["n_flows"] = grp.size()
    edges["log_n_flows"] = np.log1p(edges.n_flows).astype("float32")
    edges["n_attack"] = grp.is_attack.sum()
    edges["attack_frac"] = (edges.n_attack / edges.n_flows).astype("float32")
    edges["edge_class"] = majority(E[E.is_attack == 1], keys, "attack_class").reindex(edges.index).fillna("benign")
    edges["split"] = majority(E, keys, "split").reindex(edges.index)
    edges = edges.reset_index()

    out_ = E.groupby(["snapshot", "src"]).agg(out_flows=("is_attack", "size"), out_attack=("is_attack", "sum"),
                                              out_bytes=("fwd_bytes_raw", "sum"), out_peers=("dst", "nunique"))
    in_ = E.groupby(["snapshot", "dst"]).agg(in_flows=("is_attack", "size"), in_attack=("is_attack", "sum"),
                                             in_bytes=("bwd_bytes_raw", "sum"), in_peers=("src", "nunique"))
    out_.index.names = in_.index.names = ["snapshot", "node"]
    nodes = out_.join(in_, how="outer").fillna(0).reset_index()
    for c in ("out_flows", "in_flows", "out_peers", "in_peers", "out_bytes", "in_bytes"):
        nodes["log_" + c] = np.log1p(nodes[c]).astype("float32")
    nodes["is_private"] = nodes.node.map(lambda x: x != "EXTERNAL" and ap.is_private(x)).astype("int8")
    nodes["is_attack_source"] = (nodes.out_attack > 0).astype("int8")
    nodes["is_attack_target"] = (nodes.in_attack > 0).astype("int8")
    for df in (edges, nodes):
        df["t_start"] = t0 + df.snapshot * snap_len
    return edges, nodes


def main():
    a = argparse.ArgumentParser()
    a.add_argument("--datasets", nargs="+", default=ap.ACTIVE_DATASETS, choices=ap.ALL_DATASETS)
    a.add_argument("--window", type=int, default=32)
    a.add_argument("--stride", type=int, default=16)
    a.add_argument("--snapshot", type=float, default=60.0)
    a.add_argument("--no-graphs", action="store_true")
    args = a.parse_args()
    for ds in args.datasets:
        files = sorted(glob.glob(os.path.join(OUT, "features", ds, "*.parquet")))
        allw, gsum = [], {}
        for p in files:
            cap = os.path.splitext(os.path.basename(p))[0]
            feat = pd.read_parquet(p)
            w = windows_for(feat, cap, args.window, args.stride)
            allw.append(w)
            msg = f"[{ds}/{cap}] {len(w):,} windows ({int(w.label.sum()):,} attack)"
            if not args.no_graphs:
                edges, nodes = graphs_for(feat, args.snapshot)
                gdir = os.path.join(OUT, "graphs", ds)
                ap.write_parquet(edges, os.path.join(gdir, f"{cap}_edges.parquet"))
                ap.write_parquet(nodes, os.path.join(gdir, f"{cap}_nodes.parquet"))
                gsum[cap] = {"snapshots": int(edges.snapshot.nunique()), "edges": len(edges),
                             "nodes": len(nodes), "attack_edges": int((edges.n_attack > 0).sum()),
                             "max_nodes_per_snapshot": int(nodes.groupby("snapshot").size().max())}
                msg += f", {gsum[cap]['snapshots']:,} snapshots, {len(edges):,} edges"
                del edges, nodes
            log(msg)
            del feat
        W = pd.concat(allw, ignore_index=True)
        ap.write_parquet(W, os.path.join(OUT, "windows", f"{ds}.parquet"))
        if gsum:
            json.dump(gsum, open(os.path.join(OUT, "graphs", ds, "_summary.json"), "w"), indent=1)
        json.dump({"window": args.window, "stride": args.stride, "snapshot_seconds": args.snapshot},
                  open(os.path.join(OUT, "windows", "_config.json"), "w"), indent=1)


if __name__ == "__main__":
    main()
