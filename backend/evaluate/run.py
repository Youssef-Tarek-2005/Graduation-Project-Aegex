"""Step 8 - the evaluation harness: score every detector on a labelled capture, side by side.

    cd backend
    .venv\\Scripts\\python -m evaluate --capture ds-kitsune-mirai --db aegex_datasets
    .venv\\Scripts\\python -m evaluate --capture poc-attack --db aegex_poc
    .venv\\Scripts\\python -m evaluate --capture ds-kitsune-mirai --db aegex_datasets --capture poc-attack --db aegex_poc

Each --capture goes with the --db after it (or the last one given). The detectors are read from the alerts table:

    Rule baseline    model 'rules' (Step 7)
    LSTM-AE          AI windows whose LSTM-AE score passed its line (score >= 1)
    VAE              AI windows whose VAE score passed its line
    LSTM-AE + VAE    either of the two: how the AI team defines an alert
    Temporal GAT     model 'temporal_gat' (one alert per attack source)
    Any detector     all of the above together

Ground truth = flows.label. How alerts become covered flows, and the two levels (flow, attacker): evaluate/score.py.
Writes evaluate/report/evaluation.md (tables for the slides) and evaluation.json.
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd

from ingest.datastore import url_for
from ingest.db import connect

from .score import evaluate

REPORT_DIR = Path(__file__).resolve().parent / "report"
DETECTORS = ["Rule baseline", "LSTM-AE", "VAE", "LSTM-AE + VAE", "Temporal GAT", "Any detector"]


def load(conn, capture: str) -> tuple[pd.DataFrame, pd.DataFrame, dict]:
    cur = conn.execute("SELECT ts_start AS ts, host(src_ip) AS src_ip, host(dst_ip) AS dst_ip, label FROM flows "
                       "WHERE capture_id = %s", (capture,))
    flows = pd.DataFrame(cur.fetchall(), columns=[d.name for d in cur.description])
    ips = dict(conn.execute("SELECT device_id, host(ip) FROM devices WHERE ip IS NOT NULL").fetchall())
    cur = conn.execute("SELECT model_name, entity_type, entity_id, window_start, window_end, score, evidence FROM alerts "
                       "WHERE evidence->>'capture' = %s", (capture,))
    alerts = pd.DataFrame(cur.fetchall(), columns=[d.name for d in cur.description])
    if not alerts.empty:
        alerts["ip"] = alerts["entity_id"].map(lambda e: ips.get(e, e))     # our device ids -> their address
    info = dict(zip(("kind", "dataset", "notes"), conn.execute(
        "SELECT kind, dataset, notes FROM captures WHERE capture_id = %s", (capture,)).fetchone() or (None,) * 3))
    return flows, alerts, info


def detector_alerts(alerts: pd.DataFrame) -> dict[str, pd.DataFrame]:
    if alerts.empty:
        return {d: alerts for d in DETECTORS}
    ai = alerts[alerts["model_name"].isin(["lstm_ae", "vae"])]
    score = lambda key: ai["evidence"].map(lambda e: float((e or {}).get(key) or 0))
    out = {"Rule baseline": alerts[alerts["model_name"] == "rules"],
           "LSTM-AE": ai[score("lstm_score") >= 1.0] if not ai.empty else ai,
           "VAE": ai[score("vae_score") >= 1.0] if not ai.empty else ai,
           "LSTM-AE + VAE": ai,
           "Temporal GAT": alerts[alerts["model_name"] == "temporal_gat"]}
    out["Any detector"] = alerts[alerts["model_name"].isin(["rules", "lstm_ae", "vae", "temporal_gat"])]
    return out


def score_capture(conn, capture: str, since: datetime | None = None) -> dict:
    """since: score only flows from this time on (e.g. after the part the AI models calibrated on)."""
    flows, alerts, info = load(conn, capture)
    if since is not None:
        flows = flows[pd.to_datetime(flows["ts"], utc=True) >= pd.Timestamp(since)]
        if not alerts.empty:
            alerts = alerts[pd.to_datetime(alerts["window_end"], utc=True) >= pd.Timestamp(since)]
        info["scored_from"] = since.isoformat()
    if flows.empty:
        raise ValueError(f"capture {capture} has no flows in this database")
    if flows["label"].isna().all():
        raise ValueError(f"capture {capture} has no labels (live data): load an attack log or use a dataset")
    flows["label"] = flows["label"].fillna(0).astype(int)
    return {"capture": capture, **info, "flows": len(flows), "attack_flows": int(flows["label"].sum()),
            "detectors": {name: evaluate(flows, a) for name, a in detector_alerts(alerts).items()}}


def pct(x) -> str:
    return "-" if x is None else f"{100 * x:.1f} %"


def render(results: list[dict]) -> str:
    L = ["# Detection evaluation (Step 8)", "",
         f"Generated {datetime.now(timezone.utc):%Y-%m-%d %H:%M} UTC by `python -m evaluate`. Ground truth = flow labels.",
         "", "**Flow level**: recall = attack flows covered by an alert; precision = covered flows that really were "
         "attacks; false alarm rate = normal flows covered. **Attacker level**: hosts that sent attack traffic and "
         "were flagged; normal hosts flagged; time from a host's first attack flow to its first alert.", ""]
    for r in results:
        since = f" Scored from {r['scored_from']} on (after the calibration part)." if r.get("scored_from") else ""
        L += [f"## {r['capture']}", "",
              f"{r['flows']:,} flows, {r['attack_flows']:,} attack ({r['attack_flows'] / r['flows']:.1%}).{since} "
              f"{r.get('notes') or ''}", "",
              "| Detector | Alerts | Recall | Precision | F1 | False alarm rate | Attackers found | Normal hosts flagged "
              "| Time to detect |", "|---|---|---|---|---|---|---|---|---|"]
        for name, d in r["detectors"].items():
            f, a = d["flow"], d["attacker"]
            ttd = ", ".join(f"{ip} {s:g} s" for ip, s in a["time_to_detect_s"].items()) or "-"
            L.append(f"| {name} | {d['alerts']:,} | {pct(f['recall'])} | {pct(f['precision'])} | {pct(f['f1'])} | "
                     f"{pct(f['false_alarm_rate'])} | {a['attackers_found']} / {a['attackers']} | "
                     f"{a['normal_hosts_flagged']} / {a['normal_hosts']} | {ttd} |")
        missed = {n: d["attacker"]["attackers_missed"] for n, d in r["detectors"].items() if d["attacker"]["attackers_missed"]}
        if missed:
            L += ["", "Attackers missed: " + "; ".join(f"{n}: {', '.join(m)}" for n, m in missed.items()) + "."]
        L.append("")
    return "\n".join(L) + "\n"


def print_table(r: dict) -> None:
    print(f"\n{r['capture']}: {r['flows']:,} flows, {r['attack_flows']:,} attack")
    print(f"  {'detector':<15} {'alerts':>7} {'recall':>8} {'precision':>10} {'F1':>8} {'false alarms':>13} "
          f"{'attackers':>10} {'normal flagged':>15}")
    for name, d in r["detectors"].items():
        f, a = d["flow"], d["attacker"]
        print(f"  {name:<15} {d['alerts']:>7,} {pct(f['recall']):>8} {pct(f['precision']):>10} {pct(f['f1']):>8} "
              f"{pct(f['false_alarm_rate']):>13} {a['attackers_found']:>4} / {a['attackers']:<3} "
              f"{a['normal_hosts_flagged']:>7} / {a['normal_hosts']:<5}")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Step 8: score every detector on labelled captures.")
    ap.add_argument("--capture", action="append", required=True, help="a labelled capture (repeatable)")
    ap.add_argument("--db", action="append", default=[], help="its database (repeatable, in the same order)")
    ap.add_argument("--from", dest="since", action="append", default=[],
                    help="score only flows from this UTC time on (repeatable, in the same order; '-' = all)")
    ap.add_argument("--out", type=Path, default=REPORT_DIR)
    a = ap.parse_args(argv)
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    pad = lambda xs, default: xs + [xs[-1] if xs else default] * (len(a.capture) - len(xs))
    dbs, sinces = pad(a.db, None), pad(a.since, "-")
    results = []
    for capture, db, since in zip(a.capture, dbs, sinces):
        t = None if since in ("-", "") else datetime.fromisoformat(since.replace("Z", "+00:00"))
        if t is not None and t.tzinfo is None:
            ap.error(f"--from {since!r} needs a time zone (Z)")
        with connect(url_for(db) if db else None) as conn:
            try:
                r = score_capture(conn, capture, t)
            except ValueError as exc:
                print(f"ERROR: {exc}")
                return 2
        results.append(r)
        print_table(r)
    a.out.mkdir(parents=True, exist_ok=True)
    (a.out / "evaluation.json").write_text(json.dumps(results, indent=1, default=str), encoding="utf-8")
    (a.out / "evaluation.md").write_text(render(results), encoding="utf-8")
    print(f"\nreport: {a.out / 'evaluation.md'}")
    return 0
