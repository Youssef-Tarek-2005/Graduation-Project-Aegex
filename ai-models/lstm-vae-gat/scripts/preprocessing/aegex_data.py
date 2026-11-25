"""
Aegex data loaders - read the preprocessed outputs for the model stages.

    from aegex_data import AegexData
    data = AegexData(r"C:\\...\\preprocessed")

    # LSTM autoencoder / VAE: benign training sequences
    for X, mask, y, cls in data.windows("edge", split="train", benign_only=True, batch_size=256):
        ...   # X: float32 [B, 32, n_features] (zero-padded), mask: bool [B, 32], y: int8 [B], cls: str [B]

    # flat flow matrix (e.g. VAE on single flows, baselines)
    X, meta = data.flows("nf_toniot", split="test")

    # Temporal GAT: one graph per time snapshot
    for snap in data.snapshots("iot23", "CTU-IoT-Malware-Capture-34-1"):
        snap["edge_index"], snap["edge_attr"], snap["node_attr"], snap["edge_label"], snap["node_label"]

Pure numpy/pandas so it works with PyTorch (torch.from_numpy) or TensorFlow alike.
"""
import glob
import json
import os

import numpy as np
import pandas as pd

import aegex_prep as ap

NODE_ATTR = ["log_out_flows", "log_in_flows", "log_out_peers", "log_in_peers", "log_out_bytes",
             "log_in_bytes", "is_private"]


class AegexData:
    def __init__(self, root=None):
        root = root or ap.PREPROCESSED_DIR       # AEGEX_OUT/preprocessed by default
        self.root = root
        self.spec = json.load(open(os.path.join(root, "features", "feature_spec.json")))
        self.features = self.spec["feature_order"]
        self._cache = {}

    def captures(self, dataset):
        return [os.path.splitext(os.path.basename(p))[0]
                for p in sorted(glob.glob(os.path.join(self.root, "features", dataset, "*.parquet")))]

    def _feat(self, dataset, capture):
        key = (dataset, capture)
        if key not in self._cache:
            self._cache.clear()                       # keep one capture in memory at a time
            self._cache[key] = pd.read_parquet(os.path.join(self.root, "features", dataset, f"{capture}.parquet"))
        return self._cache[key]

    # ---------------------------------------------------------------- flat flows
    def flows(self, dataset, split=None, benign_only=False, captures=None):
        Xs, metas = [], []
        for cap in captures or self.captures(dataset):
            F = self._feat(dataset, cap)
            m = np.ones(len(F), bool)
            if split: m &= (F.split == split).to_numpy()
            if benign_only: m &= (F.is_attack == 0).to_numpy()
            Xs.append(F.loc[m, self.features].to_numpy(np.float32))
            metas.append(F.loc[m, ap.IDENTITY + ap.LABELS + ["split"]])
        return np.concatenate(Xs), pd.concat(metas, ignore_index=True)

    # ---------------------------------------------------------------- LSTM windows
    def windows(self, dataset, split=None, benign_only=False, pure_only=True, batch_size=256,
                shuffle=False, seed=0, captures=None):
        W = pd.read_parquet(os.path.join(self.root, "windows", f"{dataset}.parquet"))
        if captures: W = W[W.capture.isin(captures)]
        if split: W = W[W.split == split]
        if pure_only: W = W[W.split_pure]
        if benign_only: W = W[W.label == 0]
        L = int(json.load(open(os.path.join(self.root, "windows", "_config.json")))["window"])
        rng = np.random.default_rng(seed)
        for cap, wc in W.groupby("capture", sort=False):
            F = self._feat(dataset, cap)[self.features].to_numpy(np.float32)
            idx = rng.permutation(len(wc)) if shuffle else np.arange(len(wc))
            rs, re_ = wc.row_start.to_numpy()[idx], wc.row_end.to_numpy()[idx]
            y, cls = wc.label.to_numpy()[idx], wc.window_class.to_numpy()[idx]
            for b in range(0, len(idx), batch_size):
                sl = slice(b, b + batch_size)
                n = len(rs[sl])
                X = np.zeros((n, L, F.shape[1]), np.float32)
                M = np.zeros((n, L), bool)
                for i, (a, e) in enumerate(zip(rs[sl], re_[sl])):
                    X[i, :e - a], M[i, :e - a] = F[a:e], True
                yield X, M, y[sl], cls[sl]

    # ---------------------------------------------------------------- GAT snapshots
    def snapshots(self, dataset, capture, split=None):
        E = pd.read_parquet(os.path.join(self.root, "graphs", dataset, f"{capture}_edges.parquet"))
        N = pd.read_parquet(os.path.join(self.root, "graphs", dataset, f"{capture}_nodes.parquet"))
        if split: E = E[E.split == split]
        edge_attr_cols = self.features + ["log_n_flows"]
        for s, e in E.groupby("snapshot", sort=True):
            n = N[N.snapshot == s].reset_index(drop=True)
            pos = pd.Series(np.arange(len(n)), index=n.node)
            yield {
                "snapshot": int(s), "t_start": float(e.t_start.iloc[0]), "nodes": n.node.to_numpy(),
                "edge_index": np.vstack([pos[e.src].to_numpy(), pos[e.dst].to_numpy()]),
                "edge_attr": e[edge_attr_cols].to_numpy(np.float32),
                "node_attr": n[NODE_ATTR].to_numpy(np.float32),
                "edge_label": (e.n_attack > 0).to_numpy(np.int8), "edge_class": e.edge_class.to_numpy(),
                "node_label": n.is_attack_source.to_numpy(np.int8),
            }
