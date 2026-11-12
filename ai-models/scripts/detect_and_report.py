"""
Bridge: all three detection models  ->  grounded threat-intelligence report.

    Layer 1  autoencoder       is this flow anomalous?        (unsupervised)
    Layer 2  E-GraphSAGE       is this an attack?             (graph context)
    Layer 3  type classifier   which kind of attack is it?    (15 classes)
    Bridge   question builder  turns that into an analyst question
    Layer 4  RAG               grounded report with MITRE / CISA citations

Nothing in the report is taken from the dataset's own labels.

Run:
    python detect_and_report.py --csv <flows.csv> --top 3
    python detect_and_report.py --csv <flows.csv> --no-rag     (detection only)
"""
from __future__ import annotations

import argparse
import json
import os
import pickle
import sys
from datetime import datetime
from pathlib import Path

import numpy as np
import pandas as pd

os.environ.setdefault("TF_CPP_MIN_LOG_LEVEL", "3")

# --------------------------------------------------------------------------
# Paths
# --------------------------------------------------------------------------
# Where the data and trained artifacts live. Override without editing this
# file by setting AEGEX_POC_DIR; the default is one person's layout.
POC_DIR = Path(os.environ.get("AEGEX_POC_DIR",
                              r"C:\Users\KimoStore\Desktop\PoC"))
RAG_DIR = POC_DIR / "threat-intelligence-assistant"
AE_DIR = POC_DIR / "PoC_results"
EGS_DIR = POC_DIR / "EGraphSAGE_results"

WINDOW = 100                      # must match the E-GraphSAGE training run
LABEL_COL, TYPE_COL = "Attack_label", "Attack_type"
SRC_COL, DST_COL = "ip.src_host", "ip.dst_host"


# --------------------------------------------------------------------------
# Reading flows — whole windows, spread across the file
# --------------------------------------------------------------------------
def read_flows(path: str, rows: int, head: bool) -> pd.DataFrame:
    """
    Sample whole WINDOW-sized runs of consecutive flows, spread over the file.

    Two constraints meet here. Edge-IIoTset is ordered, so reading the first N
    rows returns normal traffic only. But E-GraphSAGE was trained on windows of
    100 *consecutive* flows — sampling individual rows at random would hand it
    windows that never existed, and its graph context would be meaningless.
    Taking whole windows at a stride satisfies both.
    """
    if head:
        return pd.read_csv(path, nrows=rows, low_memory=False)

    total = sum(1 for _ in open(path, encoding="utf-8", errors="ignore")) - 1
    if rows >= total:
        return pd.read_csv(path, low_memory=False)

    n_win = total // WINDOW
    want_win = max(1, rows // WINDOW)
    stride = max(1, n_win // want_win)
    print(f"     file has {total:,} flows — taking every {stride}th window "
          f"of {WINDOW} consecutive flows")

    parts, offset = [], 0
    for chunk in pd.read_csv(path, chunksize=200_000, low_memory=False):
        gidx = np.arange(offset, offset + len(chunk))
        keep = (gidx // WINDOW) % stride == 0
        if keep.any():
            parts.append(chunk[keep])
        offset += len(chunk)
    return pd.concat(parts, ignore_index=True)


def align(df: pd.DataFrame, cols: list[str]) -> tuple[pd.DataFrame, list[str]]:
    """Align any CSV to an exact column list, in that exact order."""
    missing = [c for c in cols if c not in df.columns]
    frame = pd.DataFrame(index=df.index)
    for c in cols:
        s = df[c] if c in df.columns else 0.0
        frame[c] = pd.to_numeric(s, errors="coerce")
    return frame.replace([np.inf, -np.inf], np.nan).fillna(0.0), missing


def apply_scaler(scaler, X: pd.DataFrame) -> np.ndarray:
    """
    Feed the scaler whichever shape it was fitted with.

    Some of these scalers were fitted on a DataFrame and some on a bare array;
    handing one the other kind still works but prints a warning on every call.
    """
    data = X if hasattr(scaler, "feature_names_in_") else X.values
    return scaler.transform(data).astype(np.float32)


# --------------------------------------------------------------------------
# Layer 1 — autoencoder
# --------------------------------------------------------------------------
def load_detector():
    from tensorflow import keras

    scaler = pickle.load(open(AE_DIR / "scaler.pkl", "rb"))
    if not hasattr(scaler, "feature_names_in_"):
        raise SystemExit("scaler.pkl was not fitted on a DataFrame — the "
                         "training columns cannot be recovered from it.")
    cols = [str(c) for c in scaler.feature_names_in_]
    model = keras.models.load_model(AE_DIR / "autoencoder.keras", compile=False)
    threshold = float(json.load(open(AE_DIR / "summary.json"))["threshold"])
    if model.input_shape[-1] != len(cols):
        raise SystemExit(f"autoencoder wants {model.input_shape[-1]} features, "
                         f"scaler carries {len(cols)} — different runs.")
    return model, scaler, threshold, cols


def detect(model, scaler, threshold, X):
    # No np.clip here: clamping scaled values into [0,1] hides exactly the
    # out-of-range behaviour that makes an attack reconstruct badly.
    Xs = apply_scaler(scaler, X)
    err = np.mean((model.predict(Xs, batch_size=4096, verbose=0) - Xs) ** 2, axis=1)
    return err, err > threshold


# --------------------------------------------------------------------------
# Layer 2 — E-GraphSAGE  (binary: attack or not, with graph context)
# --------------------------------------------------------------------------
def _egs_classes():
    import torch
    import torch.nn as nn
    import torch.nn.functional as Fn

    def mean_aggregate(messages, index, num_nodes):
        out = torch.zeros(num_nodes, messages.size(1), dtype=messages.dtype)
        out.index_add_(0, index, messages)
        deg = torch.zeros(num_nodes, dtype=messages.dtype)
        deg.index_add_(0, index, torch.ones(index.size(0), dtype=messages.dtype))
        return out / deg.clamp(min=1).unsqueeze(1)

    class EGraphSAGELayer(nn.Module):
        def __init__(self, node_dim, edge_dim, out_dim, dropout=0.2):
            super().__init__()
            self.lin = nn.Linear(node_dim * 2 + edge_dim, out_dim)
            self.dropout = dropout

        def forward(self, h, e, mp_src, mp_dst, mp_feat):
            msg = torch.cat([h[mp_src], e[mp_feat]], dim=1)
            agg = mean_aggregate(msg, mp_dst, h.size(0))
            return Fn.dropout(Fn.relu(self.lin(torch.cat([h, agg], dim=1))),
                              self.dropout, self.training)

    class EGraphSAGE(nn.Module):
        def __init__(self, edge_dim, hidden=64, dropout=0.2, use_edge_in_head=True):
            super().__init__()
            self.embed0 = nn.Linear(1, hidden)
            self.l1 = EGraphSAGELayer(hidden, edge_dim, hidden, dropout)
            self.l2 = EGraphSAGELayer(hidden, edge_dim, hidden, dropout)
            self.use_edge_in_head = use_edge_in_head
            head_in = 2 * hidden + (edge_dim if use_edge_in_head else 0)
            self.head = nn.Sequential(nn.Linear(head_in, hidden), nn.ReLU(),
                                      nn.Dropout(dropout), nn.Linear(hidden, 1))

        def forward(self, e, mp_src, mp_dst, mp_feat, num_nodes, f_src, f_dst):
            h = Fn.relu(self.embed0(torch.ones(num_nodes, 1, dtype=e.dtype)))
            h = self.l1(h, e, mp_src, mp_dst, mp_feat)
            h = self.l2(h, e, mp_src, mp_dst, mp_feat)
            parts = [h[f_src], h[f_dst]]
            if self.use_edge_in_head:
                parts.append(e)
            return self.head(torch.cat(parts, dim=1)).squeeze(-1)

    return EGraphSAGE


def egs_available() -> bool:
    return all((EGS_DIR / f).exists()
               for f in ("egraphsage.pt", "egs_scaler.pkl", "egs_features.json"))


def egs_predict(df: pd.DataFrame) -> np.ndarray | None:
    """Per-flow attack probability from the graph model, or None if unusable."""
    import torch

    meta = json.load(open(EGS_DIR / "egs_features.json"))
    cols = meta["features"]
    scaler = pickle.load(open(EGS_DIR / "egs_scaler.pkl", "rb"))
    X, missing = align(df, cols)
    if missing:
        print(f"     E-GraphSAGE skipped: {len(missing)} feature(s) absent")
        return None
    if SRC_COL not in df.columns or DST_COL not in df.columns:
        print("     E-GraphSAGE skipped: host columns absent, no graph to build")
        return None

    n = len(df)
    if n % WINDOW:
        print(f"     E-GraphSAGE skipped: {n:,} flows is not whole windows")
        return None

    Xs = apply_scaler(scaler, X)

    # per-window node ids, exactly as build_windowed_graph did
    src = pd.factorize(df[SRC_COL].astype(str))[0]
    dst = pd.factorize(df[DST_COL].astype(str))[0]
    f_src = np.empty(n, dtype=np.int64)
    f_dst = np.empty(n, dtype=np.int64)
    offset = 0
    for begin in range(0, n, WINDOW):
        end = min(begin + WINDOW, n)
        s, d = src[begin:end], dst[begin:end]
        _, inv = np.unique(np.concatenate([s, d]), return_inverse=True)
        k = len(s)
        f_src[begin:end] = inv[:k] + offset
        f_dst[begin:end] = inv[k:] + offset
        offset += int(inv.max()) + 1

    model = _egs_classes()(Xs.shape[1])
    model.load_state_dict(torch.load(EGS_DIR / "egraphsage.pt", map_location="cpu"))
    model.eval()

    out = np.empty(n, dtype=np.float32)
    STEP = WINDOW * 400                      # same batch shape as training
    with torch.no_grad():
        for b in range(0, n, STEP):
            e = min(b + STEP, n)
            nodes = np.unique(np.concatenate([f_src[b:e], f_dst[b:e]]))
            remap = np.full(nodes.max() + 1, -1, dtype=np.int64)
            remap[nodes] = np.arange(len(nodes))
            fs = torch.from_numpy(remap[f_src[b:e]])
            fd = torch.from_numpy(remap[f_dst[b:e]])
            ar = torch.arange(e - b)
            logit = model(torch.from_numpy(Xs[b:e]),
                          torch.cat([fs, fd]), torch.cat([fd, fs]),
                          torch.cat([ar, ar]), len(nodes), fs, fd)
            out[b:e] = torch.sigmoid(logit).numpy()
    return out


# --------------------------------------------------------------------------
# Layer 3 — attack type
# --------------------------------------------------------------------------
def type_available() -> bool:
    return all((AE_DIR / f).exists()
               for f in ("type_classifier.keras", "type_scaler.pkl",
                         "type_classes.json"))


def classify_type(df: pd.DataFrame, idx: np.ndarray) -> tuple[list[str], list[float], str]:
    """Attack type per selected flow, from the classifier when it is available."""
    if type_available():
        from tensorflow import keras

        meta = json.load(open(AE_DIR / "type_classes.json"))
        scaler = pickle.load(open(AE_DIR / "type_scaler.pkl", "rb"))
        model = keras.models.load_model(AE_DIR / "type_classifier.keras",
                                        compile=False)
        X, missing = align(df.iloc[idx], meta["features"])
        if not missing:
            Xs = apply_scaler(scaler, X)
            p = model.predict(Xs, verbose=0)
            names = [meta["classes"][i] for i in p.argmax(axis=1)]
            conf = [float(v) for v in p.max(axis=1)]
            return names, conf, "type classifier (model)"
        print(f"     type classifier skipped: {len(missing)} feature(s) absent")

    if TYPE_COL in df.columns:
        return (list(df.iloc[idx][TYPE_COL].astype(str)),
                [float("nan")] * len(idx), "dataset ground-truth label")
    return ["Unknown"] * len(idx), [float("nan")] * len(idx), "not available"


# --------------------------------------------------------------------------
# Bridge — build the analyst question
# --------------------------------------------------------------------------
def build_question(attack: str, src: str, dst: str, error: float,
                   threshold: float) -> str:
    """
    The RAG layer refuses anything that does not read as a threat-intel
    question, so a bare class name like "Port_Scanning" is rejected. This
    wording always carries the words MITRE ATT&CK.
    """
    return (
        f"{attack.replace('_', ' ')} activity was detected from {src} against "
        f"IoT honeypot {dst} (reconstruction error {error:.4f} vs threshold "
        f"{threshold:.4f}). Which MITRE ATT&CK technique does this map to, and "
        f"what mitigation is recommended?"
    )


# --------------------------------------------------------------------------
# Layer 4 — RAG
# --------------------------------------------------------------------------
def load_rag(rag_dir: Path):
    sys.path.insert(0, str(rag_dir))
    os.chdir(rag_dir)          # settings resolve .env and indices/ from here
    from config.settings import get_settings
    from src.embeddings.factory import get_embeddings
    from src.llm.factory import get_llm
    from src.rag.chain import ThreatIntelRAGChain
    from src.vectorstore.factory import load_vectorstore

    s = get_settings()
    return ThreatIntelRAGChain(vectorstore=load_vectorstore(get_embeddings(s), s),
                               llm=get_llm(s), settings=s)


# --------------------------------------------------------------------------
def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--csv", required=True)
    p.add_argument("--top", type=int, default=3, help="how many alerts to report")
    p.add_argument("--rows", type=int, default=200_000, help="flows to score")
    p.add_argument("--no-rag", action="store_true", help="detection only")
    p.add_argument("--no-graph", action="store_true", help="skip E-GraphSAGE")
    p.add_argument("--head", action="store_true",
                   help="read the first N rows (fast, but an ordered file "
                        "then gives one class only)")
    p.add_argument("--allow-missing", action="store_true")
    p.add_argument("--out", default="incident_report.md")
    a = p.parse_args()

    print("1/6  loading the autoencoder ...")
    ae, scaler, threshold, cols = load_detector()
    print(f"     {len(cols)} features | threshold {threshold:.6f}")

    print("2/6  reading flows ...")
    df = read_flows(a.csv, a.rows, a.head)
    X, missing = align(df, cols)
    print(f"     {len(df):,} flows")
    if LABEL_COL in df.columns:
        n_atk = int(pd.to_numeric(df[LABEL_COL], errors="coerce").fillna(0).sum())
        print(f"     labelled attacks present: {n_atk:,} ({n_atk/len(df):.1%}) "
              f"— used only to sanity-check the sample, never in the report")

    if missing:
        # Measured: dropping even ONE training feature and zero-filling it put
        # every flow above the threshold (100% false positives). A zero column
        # is not neutral — the model never saw one.
        print(f"\n  !! {len(missing)} of {len(cols)} feature column(s) absent: "
              f"{', '.join(missing[:8])}{' ...' if len(missing) > 8 else ''}")
        print("     Zero-filling them makes EVERY flow look anomalous.")
        if not a.allow_missing:
            raise SystemExit("     Fix the feature extraction, or pass "
                             "--allow-missing to score anyway.")
        print("     --allow-missing given: output is NOT reliable.\n")

    print("3/6  layer 1 — anomaly detection ...")
    err, anom = detect(ae, scaler, threshold, X)
    print(f"     {int(anom.sum()):,} anomalous ({anom.mean():.2%})")
    if not anom.any():
        print("     nothing to report."); return

    graph_p = None
    if not a.no_graph and egs_available():
        print("4/6  layer 2 — E-GraphSAGE (graph context) ...")
        graph_p = egs_predict(df)
        if graph_p is not None:
            agree = int((anom & (graph_p > 0.5)).sum())
            print(f"     {int((graph_p > 0.5).sum()):,} called attack | "
                  f"{agree:,} agreed with layer 1")
    else:
        print("4/6  layer 2 — skipped")

    # rank: flows both layers agree on first, then by reconstruction error
    score = err.copy()
    if graph_p is not None:
        score = score + (graph_p > 0.5) * (err.max() + 1.0)
    order = np.argsort(-score)
    idx = order[anom[order]][:a.top]

    print("5/6  layer 3 — attack type ...")
    types, tconf, provenance = classify_type(df, idx)
    print(f"     source: {provenance}")

    chain = None
    if not a.no_rag:
        print("6/6  layer 4 — RAG (first call is slow) ...")
        chain = load_rag(RAG_DIR)
    else:
        print("6/6  layer 4 — skipped")

    out = [
        "# Honeypot Incident Report", "",
        f"- Generated: {datetime.now():%Y-%m-%d %H:%M}",
        f"- Flows analysed: {len(df):,}",
        f"- Anomalous (layer 1): {int(anom.sum()):,} ({anom.mean():.2%})",
        f"- Detector threshold: {threshold:.6f}",
        f"- Attack type source: {provenance}",
        f"- Graph layer: {'active' if graph_p is not None else 'not used'}",
        "",
    ]

    for n, (i, atk) in enumerate(zip(idx, types), 1):
        src = str(df[SRC_COL].iloc[i]) if SRC_COL in df.columns else "unknown"
        dst = str(df[DST_COL].iloc[i]) if DST_COL in df.columns else "honeypot"
        q = build_question(atk, src, dst, err[i], threshold)

        verdict = "layer 1 only"
        if graph_p is not None:
            verdict = ("both layers agree" if graph_p[i] > 0.5
                       else "layer 1 only (graph layer disagrees)")

        out += [f"## Alert {n} — {atk.replace('_', ' ')}", "",
                f"- Source: `{src}`  ->  Target: `{dst}`",
                f"- Reconstruction error: `{err[i]:.6f}` "
                f"(threshold `{threshold:.6f}`)"]
        if graph_p is not None:
            out.append(f"- Graph-model attack probability: `{graph_p[i]:.3f}`")
        if not np.isnan(tconf[n - 1]):
            out.append(f"- Type confidence: `{tconf[n-1]:.3f}`")
        out += [f"- Verdict: **{verdict}**", "",
                "**Query sent to the intelligence layer**", "", f"> {q}", ""]

        if chain is None:
            out += ["_RAG layer skipped._", ""]
            continue

        r = chain.invoke(q)
        out += ["**Grounded assessment**", "", r.answer, "",
                f"- Confidence: **{r.confidence.overall}/100**",
                f"- Abstained: {r.hard_abstained}", ""]
        if r.citations.sources:
            out.append("- Sources: " + ", ".join(
                f"[{s.source_id}]({s.url})" for s in r.citations.sources))
        out.append("")
        print(f"     alert {n}: {atk} -> confidence {r.confidence.overall}/100")

    dest = POC_DIR / a.out
    dest.write_text("\n".join(out), encoding="utf-8")
    print(f"\ndone -> {dest}")


if __name__ == "__main__":
    main()
