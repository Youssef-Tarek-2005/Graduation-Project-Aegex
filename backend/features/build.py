"""Compute features for what's already in the database.

    cd backend
    .venv/Scripts/python -m features.build flows --capture cap-2026-11-20-a           # fill flows.features
    .venv/Scripts/python -m features.build flows --capture cap-2026-11-20-a --show    # + print the feature table
    .venv/Scripts/python -m features.build flows --capture cap-2026-11-20-a --csv ../data/flow_features.csv

    .venv/Scripts/python -m features.build windows --capture cap-2026-11-20-a --show  # 24 numbers per device per 10 s

flows:   only flows without features (or from an older contract version) are computed; --recompute redoes all.
windows: a capture's windows are always rebuilt completely (they depend on the labels, which can change).
"""
from __future__ import annotations

import argparse
import csv
import math
import sys
from dataclasses import dataclass, field
from pathlib import Path

import psycopg
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from . import flow as F
from . import window as W

FLOW_COLUMNS = ("flow_id, ts_start, proto, service, conn_state, dst_port, "
                "duration_s, orig_bytes, resp_bytes, orig_pkts, resp_pkts")


@dataclass
class BuildResult:
    computed: int = 0
    already_done: int = 0

    def __str__(self) -> str:
        return (f"computed features for {self.computed} flows "
                f"({self.already_done} already had version {F.FEATURE_VERSION})")


def _scope(capture_id: str | None) -> tuple[str, dict]:
    if capture_id is None:
        return "TRUE", {}
    return "capture_id = %(cap)s", {"cap": capture_id}


def build_flow_features(conn: psycopg.Connection, capture_id: str | None = None, recompute: bool = False,
                        batch_size: int = 1000) -> BuildResult:
    """Fill flows.features and flows.feature_version. One transaction: all flows get them, or none do."""
    scope, params = _scope(capture_id)
    params["v"] = F.FEATURE_VERSION
    todo = scope if recompute else f"{scope} AND (features IS NULL OR feature_version IS DISTINCT FROM %(v)s)"

    result = BuildResult()
    total = conn.execute(f"SELECT count(*) FROM flows WHERE {scope}", params).fetchone()[0]
    with conn.transaction():
        # A named (server-side) cursor reads the flows in batches, so a million flows don't all sit in memory.
        with conn.cursor(name="flows_to_featurize", row_factory=dict_row) as read, conn.cursor() as write:
            read.execute(f"SELECT {FLOW_COLUMNS} FROM flows WHERE {todo}", params)
            while rows := read.fetchmany(batch_size):
                write.executemany(
                    "UPDATE flows SET features = %s, feature_version = %s WHERE flow_id = %s AND ts_start = %s",
                    [(Jsonb(F.flow_features(r)), F.FEATURE_VERSION, r["flow_id"], r["ts_start"]) for r in rows])
                result.computed += len(rows)
    result.already_done = total - result.computed
    return result


@dataclass
class FeatureCheck:
    unit: str = "flows"
    n_features: int = len(F.FEATURE_NAMES)
    rows: int = 0
    missing: int = 0                                     # rows not there, or from an old contract version
    problems: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.missing == 0 and not self.problems

    def __str__(self) -> str:
        if self.ok:
            return f"OK: {self.rows} {self.unit} x {self.n_features} features, nothing missing, no NaN"
        lines = []
        if self.missing:
            lines.append(f"{self.missing} {self.unit} missing or without features (version {F.FEATURE_VERSION})")
        return "\n".join(lines + [f"  - {p}" for p in self.problems[:20]])


def check_flow_features(conn: psycopg.Connection, capture_id: str | None = None) -> FeatureCheck:
    """The step 7 success check: every flow has exactly the 41 contract features, all real numbers, and each
    one-hot group has exactly one 1 (the port class may be all 0 when the flow has no port)."""
    scope, params = _scope(capture_id)
    check = FeatureCheck()
    for flow_id, version, feats in conn.execute(
            f"SELECT flow_id, feature_version, features FROM flows WHERE {scope}", params):
        check.rows += 1
        if feats is None or version != F.FEATURE_VERSION:
            check.missing += 1
            continue
        if set(feats) != set(F.FEATURE_NAMES):
            check.problems.append(f"{flow_id}: has {len(feats)} features, expected the {len(F.FEATURE_NAMES)} from the contract")
            continue
        bad = [n for n in F.FEATURE_NAMES if not isinstance(feats[n], (int, float)) or not math.isfinite(feats[n])]
        if bad:
            check.problems.append(f"{flow_id}: not a real number: {', '.join(bad)}")
        for group in F.ONE_HOT:
            ones = sum(feats[f"{group}_{v}"] for v in F.VOCAB[group])
            if ones != 1 and not (group == "dst_port_class" and ones == 0):
                check.problems.append(f"{flow_id}: one-hot {group} has {ones:g} ones, expected exactly 1")
    return check


def feature_table(conn: psycopg.Connection, capture_id: str | None = None) -> list[dict]:
    """One dict per flow: a few readable columns, the label, then the 41 features in contract order."""
    scope, params = _scope(capture_id)
    rows = conn.execute(f"""
        SELECT flow_id, ts_start, host(src_ip), host(dst_ip), dst_port, service, label, scenario, features
          FROM flows WHERE {scope} AND features IS NOT NULL ORDER BY ts_start""", params).fetchall()
    return [{"flow_id": flow_id, "ts_start": ts.isoformat(), "src_ip": src, "dst_ip": dst, "dst_port": port,
             "service": service, "label": label, "scenario": scenario, **{n: feats[n] for n in F.FEATURE_NAMES}}
            for flow_id, ts, src, dst, port, service, label, scenario, feats in rows]


SHORT = {"duration_s": "dur", "orig_bytes": "o_byt", "resp_bytes": "r_byt", "orig_pkts": "o_pkt",
         "resp_pkts": "r_pkt", "bytes_per_sec": "B/s", "pkts_per_sec": "pkt/s", "bytes_ratio_out": "out",
         "mean_pkt_size_orig": "o_size"}


def print_table(table: list[dict]) -> None:
    """The 9 numbers, plus which column is 1 in each one-hot group (41 columns don't fit on a screen)."""
    head = f"{'time':<8} {'to':<18} {'label':<5} " + " ".join(f"{SHORT[n]:>6}" for n in F.NUMERIC) + "   one-hot columns that are 1"
    print(head)
    print("-" * len(head))
    for row in table:
        hot = [next((v for v in F.VOCAB[g] if row[f"{g}_{v}"] == 1), "-") for g in F.ONE_HOT]
        label = "?" if row["label"] is None else str(row["label"])
        to = f"{row['dst_ip']}:{row['dst_port']}"
        print(f"{row['ts_start'][11:19]:<8} {to:<18} {label:<5} "
              + " ".join(f"{row[n]:>6.2f}" for n in F.NUMERIC) + "   " + " ".join(hot))
    print("(numbers are after log1p, except 'out'; one-hot = proto, service, conn_state, port class)")


def write_csv(table: list[dict], path: str | Path) -> None:
    fieldnames = list(table[0]) if table else ["flow_id", *F.FEATURE_NAMES]
    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(table)


# ------------------------------------------------------------------------------------------- windows
INSERT_WINDOW_SQL = """
INSERT INTO feature_windows (window_start, window_end, entity_type, entity_id, capture_id, feature_version,
                             features_raw, features, n_events, label, scenario, run_id)
VALUES (%s, %s, 'device', %s, %s, %s, %s, %s, %s, %s, %s, %s)
"""


@dataclass
class WindowResult:
    capture_id: str
    windows: int = 0
    devices: int = 0
    active: int = 0                 # windows where something touched the device
    attack: int = 0
    unlabeled: int = 0

    def __str__(self) -> str:
        per = self.windows // self.devices if self.devices else 0
        text = (f"capture {self.capture_id}: {self.windows} windows ({self.devices} devices x {per} windows of "
                f"{W.WINDOW_SECONDS} s); {self.active} with activity, {self.windows - self.active} silent; "
                f"{self.attack} attack")
        if self.unlabeled:
            text += (f"\nWARNING: {self.unlabeled} windows have no label, because the capture isn't fully labeled. "
                     f"Run: python -m ingest.attacks --report {self.capture_id}")
        return text


def build_window_features(conn: psycopg.Connection, capture_id: str) -> WindowResult:
    """Rebuild every window of one capture: delete the old ones and insert the new ones in one transaction."""
    windows = W.capture_window_features(conn, capture_id)
    with conn.transaction(), conn.cursor() as cur:
        cur.execute("DELETE FROM feature_windows WHERE capture_id = %s AND entity_type = 'device' "
                    "AND feature_version = %s", (capture_id, W.FEATURE_VERSION))
        cur.executemany(INSERT_WINDOW_SQL, [
            (w.window_start, w.window_end, w.device_id, capture_id, W.FEATURE_VERSION, Jsonb(w.features_raw),
             Jsonb(w.features), w.n_events, w.label, w.scenario, w.run_id) for w in windows])
    return WindowResult(capture_id, windows=len(windows), devices=len({w.device_id for w in windows}),
                        active=sum(w.n_events > 0 for w in windows), attack=sum(w.label == 1 for w in windows),
                        unlabeled=sum(w.label is None for w in windows))


def check_window_features(conn: psycopg.Connection, capture_id: str) -> FeatureCheck:
    """The step 8 check: one window per device per 10 s of the capture, each with the 24 contract features,
    all real numbers, exactly one device_type."""
    check = FeatureCheck(unit="windows", n_features=len(W.FEATURE_NAMES))
    start, end = conn.execute("SELECT start_ts, end_ts FROM captures WHERE capture_id = %s", (capture_id,)).fetchone()
    n_devices = conn.execute("SELECT count(*) FROM devices WHERE monitored").fetchone()[0]
    rows = conn.execute("SELECT entity_id, window_start, features FROM feature_windows WHERE capture_id = %s "
                        "AND entity_type = 'device' AND feature_version = %s",
                        (capture_id, W.FEATURE_VERSION)).fetchall()
    check.rows = len(rows)
    if end is not None:
        expected = n_devices * len(W.capture_windows(start, end))
        check.missing = max(expected - len(rows), 0)
        if len(rows) > expected:
            check.problems.append(f"{len(rows)} windows, expected {expected}")
    for device, ws, feats in rows:
        where = f"{device} {ws:%H:%M:%S}"
        if set(feats) != set(W.FEATURE_NAMES):
            check.problems.append(f"{where}: has {len(feats)} features, expected {len(W.FEATURE_NAMES)}")
            continue
        if any(not math.isfinite(feats[n]) for n in W.FEATURE_NAMES):
            check.problems.append(f"{where}: a feature is not a real number")
        if sum(feats[f"device_type_{t}"] for t in W.DEVICE_TYPES) != 1:
            check.problems.append(f"{where}: device_type one-hot doesn't have exactly one 1")
    return check


def window_table(conn: psycopg.Connection, capture_id: str, active_only: bool = False) -> list[dict]:
    active = "AND n_events > 0" if active_only else ""
    rows = conn.execute(f"""
        SELECT window_start, entity_id, label, scenario, run_id, n_events, features_raw, features
          FROM feature_windows WHERE capture_id = %s AND entity_type = 'device' AND feature_version = %s {active}
         ORDER BY window_start, entity_id""", (capture_id, W.FEATURE_VERSION)).fetchall()
    return [{"window_start": ws.isoformat(), "device_id": dev, "label": label, "scenario": scenario, "run_id": run,
             "n_events": n, "_raw": raw, **{name: feats[name] for name in W.FEATURE_NAMES}}
            for ws, dev, label, scenario, run, n, raw, feats in rows]


def print_window_table(table: list[dict]) -> None:
    """Only windows with activity, and only the counts that aren't 0 (24 columns don't fit on a screen)."""
    for row in table:
        raw = row["_raw"]
        label = {1: f"ATTACK {row['scenario']}", 0: "normal", None: "?"}[row["label"]]
        counts = "  ".join(f"{n}={raw[n]:g}" for n in W.NUMERIC if raw[n])
        print(f"{row['window_start'][11:19]}  {row['device_id']:<15} {label:<18} "
              f"{counts or '(touched, but nothing the features count)'}")


def main() -> int:
    from ingest.db import connect, db_url

    ap = argparse.ArgumentParser(prog="python -m features.build", description=__doc__.splitlines()[0])
    ap.add_argument("what", choices=["flows", "windows"])
    ap.add_argument("--capture", help="only this capture (default: all captures)")
    ap.add_argument("--recompute", action="store_true", help="flows: recompute even flows that already have features")
    ap.add_argument("--show", action="store_true", help="print the feature table (windows: only windows with activity)")
    ap.add_argument("--csv", help="also write the feature table to this CSV file (opens in Excel)")
    a = ap.parse_args()

    try:
        with connect() as conn:
            if a.what == "windows":
                return _windows_cli(conn, a)
            print(build_flow_features(conn, a.capture, a.recompute))
            check = check_flow_features(conn, a.capture)
            print(check)
            if a.show or a.csv:
                table = feature_table(conn, a.capture)
                if a.show:
                    print()
                    print_table(table)
                if a.csv:
                    write_csv(table, a.csv)
                    print(f"\nwrote {len(table)} rows x {len(table[0]) if table else 0} columns to {a.csv}")
            return 0 if check.ok else 1
    except psycopg.OperationalError as exc:
        print(f"ERROR: can't reach the database at {db_url()}. Is Docker running?\n{exc}", file=sys.stderr)
        return 1


def _windows_cli(conn: psycopg.Connection, a: argparse.Namespace) -> int:
    captures = [a.capture] if a.capture else [c for (c,) in conn.execute("SELECT capture_id FROM captures ORDER BY start_ts")]
    ok = True
    for cid in captures:
        try:
            print(build_window_features(conn, cid))
        except W.WindowError as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            return 1
        check = check_window_features(conn, cid)
        print(check)
        ok &= check.ok
        if a.show:
            print()
            print_window_table(window_table(conn, cid, active_only=True))
        if a.csv:
            table = [{k: v for k, v in r.items() if k != "_raw"} for r in window_table(conn, cid)]
            path = a.csv if len(captures) == 1 else str(Path(a.csv).with_stem(f"{Path(a.csv).stem}_{cid}"))
            write_csv(table, path)
            print(f"\nwrote {len(table)} rows x {len(table[0]) if table else 0} columns to {path}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
