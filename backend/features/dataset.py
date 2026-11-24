"""Step 9: split, scale, and export the dataset for Task C and Task D.

    cd backend
    .venv/Scripts/python -m features.dataset --dry-run            # only show the proposed split
    .venv/Scripts/python -m features.dataset                      # split + scalers + all export files
    .venv/Scripts/python -m features.dataset --zero-day mqtt_spoofing   # keep one scenario out of train/val entirely
    .venv/Scripts/python -m features.dataset --splits my_splits.json    # your own capture -> split assignment

What comes out (paths from the contract):

  artifacts/features/v1.0.0/           what C and D LOAD (never re-fit their own)
      flow_scaler.joblib               fitted on train, normal rows only
      window_scaler.joblib
      feature_order.json               the exact column order of every vector
      contract.json                    the contract as it was when the scalers were fitted
      splits.json                      which capture is in which split
  data/processed/v1.0.0/               the data, already scaled
      flows.parquet                    one row per flow: ids, labels, split, 41 features
      windows.parquet                  one row per (device, 10 s): labels, split, 24 features      (for C)
      sequences_{train,val,test}.npz   X [N, 30, 24]: 30 windows in a row = 5 minutes               (for C)
      edges_{train,val,test}.parquet   one row per flow, sorted by time, with graph node ids        (for D)
      nodes.parquet                    every IP / device seen                                        (for D)
      summary.json                     counts per split

The scaler
  StandardScaler: (value - mean) / std, so every feature is centred on 0 with a similar spread, and no feature
  dominates just because its numbers are bigger. It's fitted ONLY on train rows with label 0. Fitting on test
  data would leak the test set into training; fitting on attacks would teach the autoencoders that attacks are
  normal. Columns the contract marks scale = "none" (one-hots, ratios) pass through unchanged: the scaler is
  fitted on all columns, then those columns get mean 0 and std 1. So C and D can simply call
  scaler.transform(X) on the full vector, in the order from feature_order.json.
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import shutil
import sys
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import psycopg
from sklearn.preprocessing import StandardScaler

from ingest.event import CONTRACT

from . import flow as F
from . import split as S
from . import window as W

REPO = Path(__file__).resolve().parents[2]
VERSION = CONTRACT["feature_version"]
SEQ_LEN: int = CONTRACT["outputs"]["sequences_{split}.npz"]["sequence_length"]
STRIDE: int = CONTRACT["outputs"]["sequences_{split}.npz"]["stride"]
FLOW_SCALED = [f["name"] for f in CONTRACT["flow_features"]["numeric"] if f["scale"] == "standard"]
WINDOW_SCALED = [f["name"] for f in CONTRACT["window_features"]["numeric"] if f["scale"] == "standard"]


class DatasetError(Exception):
    pass


# ------------------------------------------------------------------------------------------- reading
def read_windows(conn: psycopg.Connection, capture_ids: list[str]) -> pd.DataFrame:
    rows = conn.execute("""
        SELECT entity_id, window_start, capture_id, label, scenario, run_id, features FROM feature_windows
         WHERE entity_type = 'device' AND feature_version = %s AND capture_id = ANY(%s)
         ORDER BY capture_id, entity_id, window_start""", (VERSION, capture_ids)).fetchall()
    meta = pd.DataFrame([r[:6] for r in rows], columns=["entity_id", "window_start", "capture_id", "label", "scenario", "run_id"])
    feats = pd.DataFrame([r[6] for r in rows], columns=W.FEATURE_NAMES, dtype="float64")
    return pd.concat([meta, feats], axis=1)


def read_flows(conn: psycopg.Connection, capture_ids: list[str]) -> pd.DataFrame:
    missing = conn.execute("SELECT count(*) FROM flows WHERE capture_id = ANY(%s) AND feature_version IS DISTINCT FROM %s",
                           (capture_ids, VERSION)).fetchone()[0]
    if missing:
        raise DatasetError(f"{missing} flows have no features of version {VERSION}. "
                           f"Run step 7 first: python -m features.build flows")
    rows = conn.execute("""
        SELECT flow_id, ts_start, capture_id, device_id, host(src_ip), host(dst_ip), dst_port, proto, service,
               label, scenario, run_id, features FROM flows
         WHERE capture_id = ANY(%s) ORDER BY ts_start, flow_id""", (capture_ids,)).fetchall()
    cols = ["flow_id", "ts_start", "capture_id", "device_id", "src_ip", "dst_ip", "dst_port", "proto", "service",
            "label", "scenario", "run_id"]
    meta = pd.DataFrame([r[:12] for r in rows], columns=cols)
    meta["dst_port"] = meta["dst_port"].astype("Int64")
    meta["label"] = meta["label"].astype("Int8")
    feats = pd.DataFrame([r[12] for r in rows], columns=F.FEATURE_NAMES, dtype="float64")
    return pd.concat([meta, feats], axis=1)


# ------------------------------------------------------------------------------------------- scaling
def fit_scaler(df: pd.DataFrame, names: list[str], scaled: list[str]) -> StandardScaler:
    """Fit on the train split's normal rows only; columns not in `scaled` pass through unchanged."""
    fit_rows = df[(df["split"] == "train") & (df["label"] == 0)]
    if fit_rows.empty:
        raise DatasetError("no normal rows in the train split to fit the scaler on")
    scaler = StandardScaler().fit(fit_rows[names])
    passthrough = np.array([n not in scaled for n in names])
    scaler.mean_[passthrough], scaler.scale_[passthrough], scaler.var_[passthrough] = 0.0, 1.0, 1.0
    return scaler


def apply_scaler(df: pd.DataFrame, names: list[str], scaler: StandardScaler) -> pd.DataFrame:
    out = df.copy()
    out[names] = scaler.transform(df[names])
    return out


# ------------------------------------------------------------------------------------------- sequences
def make_sequences(windows: pd.DataFrame) -> dict[str, np.ndarray]:
    """30 consecutive windows of ONE device inside ONE capture, stride 1. Never across captures, never across a gap."""
    X, y_win, ents, starts = [], [], [], []
    step = np.timedelta64(W.WINDOW_SECONDS, "s")
    for (_, entity), g in windows.groupby(["capture_id", "entity_id"], sort=True):
        g = g.sort_values("window_start")
        t = g["window_start"].dt.tz_convert("UTC").dt.tz_localize(None).to_numpy()
        # cut into runs of back-to-back windows (inside a capture every window exists, but be safe)
        cuts = np.flatnonzero(np.diff(t) != step) + 1
        for part in np.split(np.arange(len(g)), cuts):
            if len(part) < SEQ_LEN:
                continue
            feats = g[W.FEATURE_NAMES].to_numpy(np.float32)[part]
            labels = g["label"].to_numpy(np.int8)[part]
            idx = np.arange(0, len(part) - SEQ_LEN + 1, STRIDE)
            X.append(np.lib.stride_tricks.sliding_window_view(feats, (SEQ_LEN, feats.shape[1]))[idx, 0])
            y_win.append(np.lib.stride_tricks.sliding_window_view(labels, SEQ_LEN)[idx])
            ents.append(np.full(len(idx), entity))
            starts.append(t[part][idx])
    if not X:
        return {"X": np.zeros((0, SEQ_LEN, len(W.FEATURE_NAMES)), np.float32), "y": np.zeros(0, np.int8),
                "y_window": np.zeros((0, SEQ_LEN), np.int8), "entity_id": np.array([], dtype=str),
                "window_start": np.array([], dtype="datetime64[ns]")}
    y_window = np.concatenate(y_win).astype(np.int8)
    return {"X": np.concatenate(X).astype(np.float32), "y": y_window.max(axis=1).astype(np.int8), "y_window": y_window,
            "entity_id": np.concatenate(ents).astype(str), "window_start": np.concatenate(starts).astype("datetime64[ns]")}


# ------------------------------------------------------------------------------------------- graph
def node_ids(flows: pd.DataFrame, device_ip: dict[str, str]) -> tuple[pd.Series, pd.Series]:
    """Contract node_id_rule: 'dev:<device_id>' for our devices, else 'ip:<address>'."""
    def node(ip: str) -> str:
        return f"dev:{device_ip[ip]}" if ip in device_ip else f"ip:{ip}"
    return flows["src_ip"].map(node), flows["dst_ip"].map(node)


def make_nodes(edges: pd.DataFrame, devices: pd.DataFrame) -> pd.DataFrame:
    seen = pd.concat([edges[["src_node", "src_ip", "ts_start"]].set_axis(["node_id", "ip", "ts"], axis=1),
                      edges[["dst_node", "dst_ip", "ts_start"]].set_axis(["node_id", "ip", "ts"], axis=1)])
    nodes = seen.groupby("node_id").agg(ip=("ip", "first"), first_seen=("ts", "min"), last_seen=("ts", "max")).reset_index()
    dev_type = dict(zip("dev:" + devices["device_id"], devices["device_type"]))
    nodes["device_type"] = nodes["node_id"].map(dev_type)
    nodes["node_type"] = [
        "device" if nid in dev_type else ("internal_ip" if ipaddress.ip_address(ip).is_private else "external_ip")
        for nid, ip in zip(nodes["node_id"], nodes["ip"])]
    return nodes[["node_id", "node_type", "device_type", "first_seen", "last_seen"]]


# ------------------------------------------------------------------------------------------- the whole step
def build_dataset(conn: psycopg.Connection, data_dir: Path, artifacts_dir: Path, zero_day: str | None = None,
                  splits_file: str | None = None) -> dict:
    captures = S.capture_infos(conn)
    split = S.read_splits(splits_file) if splits_file else S.propose_split(captures, zero_day=zero_day)
    check = S.check_split(split, captures, zero_day)
    if not check.ok:
        raise DatasetError("the split can't be used:\n" + "\n".join(f"  - {p}" for p in check.problems))
    split_of = {cid: name for name in S.SPLITS for cid in split[name]}
    used = list(split_of)

    windows = read_windows(conn, used)
    windows["split"] = windows["capture_id"].map(split_of)
    flows = read_flows(conn, used)
    flows["split"] = flows["capture_id"].map(split_of)

    window_scaler = fit_scaler(windows, W.FEATURE_NAMES, WINDOW_SCALED)
    flow_scaler = fit_scaler(flows, F.FEATURE_NAMES, FLOW_SCALED)
    windows_s = apply_scaler(windows, W.FEATURE_NAMES, window_scaler)
    flows_s = apply_scaler(flows, F.FEATURE_NAMES, flow_scaler)

    data_dir.mkdir(parents=True, exist_ok=True)
    artifacts_dir.mkdir(parents=True, exist_ok=True)
    summary: dict = {"feature_version": VERSION, "zero_day": zero_day, "warnings": check.warnings, "splits": {}}

    # flows.parquet and windows.parquet: contract column lists
    flow_cols = ["flow_id", "ts_start", "capture_id", "device_id", "src_ip", "dst_ip", "dst_port", "proto", "service",
                 "label", "scenario", "run_id", "split", *F.FEATURE_NAMES]
    flows_s[flow_cols].to_parquet(data_dir / "flows.parquet", index=False)
    window_cols = ["entity_id", "window_start", "capture_id", "label", "scenario", "split", *W.FEATURE_NAMES]
    windows_s[window_cols].to_parquet(data_dir / "windows.parquet", index=False)

    # graph: edges per split, one nodes table
    devices = pd.DataFrame(conn.execute("SELECT device_id, device_type, host(ip) FROM devices").fetchall(),
                           columns=["device_id", "device_type", "ip"])
    device_ip = dict(zip(devices["ip"].dropna(), devices["device_id"]))
    edges = flows_s.copy()
    edges["src_node"], edges["dst_node"] = node_ids(edges, device_ip)
    edges["ts"] = edges["ts_start"].map(lambda t: t.timestamp())
    edge_cols = ["src_ip", "dst_ip", "dst_port", "proto", "src_node", "dst_node", "ts", "device_id", "label", "scenario",
                 *F.FEATURE_NAMES]
    make_nodes(edges, devices).to_parquet(data_dir / "nodes.parquet", index=False)

    for name in S.SPLITS:
        seq = make_sequences(windows_s[windows_s["split"] == name])
        np.savez_compressed(data_dir / f"sequences_{name}.npz", **seq)
        part = edges[edges["split"] == name].sort_values("ts", kind="stable")
        part[edge_cols].to_parquet(data_dir / f"edges_{name}.parquet", index=False)
        w = windows[windows["split"] == name]
        summary["splits"][name] = {
            "captures": split[name], "windows": len(w), "attack_windows": int((w["label"] == 1).sum()),
            "sequences": int(len(seq["y"])), "attack_sequences": int(seq["y"].sum()),
            "X_shape": list(seq["X"].shape), "flows": len(part), "attack_flows": int((part["label"] == 1).sum()),
            "scenarios": sorted(w["scenario"].dropna().unique().tolist())}

    joblib.dump(flow_scaler, artifacts_dir / "flow_scaler.joblib")
    joblib.dump(window_scaler, artifacts_dir / "window_scaler.joblib")
    order = {"flow": F.FEATURE_NAMES, "window": W.FEATURE_NAMES,
             "scaled_columns": {"flow": FLOW_SCALED, "window": WINDOW_SCALED},
             "usage": "X must be in exactly this column order; then scaler.transform(X). Unscaled columns pass through."}
    (artifacts_dir / "feature_order.json").write_text(json.dumps(order, indent=2), encoding="utf-8")
    shutil.copyfile(REPO / "contracts" / "feature_contract.json", artifacts_dir / "contract.json")
    (artifacts_dir / "splits.json").write_text(json.dumps(
        {"unit": "capture", "feature_version": VERSION, "zero_day": zero_day, **split}, indent=2), encoding="utf-8")
    (data_dir / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    return summary


def print_summary(summary: dict, data_dir: Path, artifacts_dir: Path) -> None:
    print(f"\n{'split':<6} {'windows':>8} {'attack':>7} {'sequences':>10} {'attack':>7} {'flows':>6} {'attack':>7}  X shape")
    for name, s in summary["splits"].items():
        print(f"{name:<6} {s['windows']:>8} {s['attack_windows']:>7} {s['sequences']:>10} {s['attack_sequences']:>7} "
              f"{s['flows']:>6} {s['attack_flows']:>7}  {s['X_shape']}")
    for w in summary["warnings"]:
        print(f"WARNING: {w}")
    print(f"\ndata:      {data_dir}\nartifacts: {artifacts_dir}")


def main() -> int:
    from ingest.db import connect, db_url

    ap = argparse.ArgumentParser(prog="python -m features.dataset", description="Split, scale and export the dataset.")
    ap.add_argument("--dry-run", action="store_true", help="only show the proposed split and its check")
    ap.add_argument("--zero-day", metavar="SCENARIO", help="keep this scenario out of train and val (test only)")
    ap.add_argument("--splits", metavar="FILE", help="use this splits.json instead of the automatic proposal")
    ap.add_argument("--data-dir", default=str(REPO / "data" / "processed" / f"v{VERSION}"))
    ap.add_argument("--artifacts-dir", default=str(REPO / "artifacts" / "features" / f"v{VERSION}"))
    a = ap.parse_args()

    try:
        with connect() as conn:
            captures = S.capture_infos(conn)
            split = S.read_splits(a.splits) if a.splits else S.propose_split(captures, zero_day=a.zero_day)
            print(S.describe(split, captures))
            check = S.check_split(split, captures, a.zero_day)
            for p in check.problems:
                print(f"PROBLEM: {p}", file=sys.stderr)
            if a.dry_run or not check.ok:
                for w in check.warnings:
                    print(f"WARNING: {w}")
                return 0 if check.ok else 1
            summary = build_dataset(conn, Path(a.data_dir), Path(a.artifacts_dir), a.zero_day, a.splits)
            print_summary(summary, Path(a.data_dir), Path(a.artifacts_dir))
    except DatasetError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    except psycopg.OperationalError as exc:
        print(f"ERROR: can't reach the database at {db_url()}. Is Docker running?\n{exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
