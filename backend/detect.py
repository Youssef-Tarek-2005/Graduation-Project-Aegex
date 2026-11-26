"""The connection between the backend and the AI models (ai-models/lstm-vae-gat): score a recording, save the alerts.

    cd backend
    .venv/Scripts/python -m detect pcaps/poc-attack.pcap --normal pcaps/poc-normal.pcap

What it does, in 3 steps:
  1. runs the AI team's own script, score_traffic.py, on the recording: LSTM-AE, then VAE. `--normal` is a
     recording of normal traffic on OUR network: the models learn from it what "normal" looks like here.
  2. reads the result: alerts.csv, one row per suspicious window of one device
  3. saves every alert in the database's `alerts` table. The API shows them: GET /api/v1/alerts

The models are used exactly as the AI team wrote them; nothing here changes how they decide.
Running it again on the same recording replaces that recording's alerts (no duplicates).
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd
from psycopg.types.json import Jsonb

from ingest.db import connect

REPO = Path(__file__).resolve().parents[1]
MODELS = REPO / "ai-models" / "lstm-vae-gat"
SCORE_SCRIPT = MODELS / "scripts" / "models" / "score_traffic.py"
LSTM, VAE = "lstm_ae_v8", "vae_v5"                      # the pair HOW_TO_USE.md recommends
RUNS = Path(__file__).resolve().parent / "model_runs"   # the models' output files go here

# The VAE's "closest known attack" -> our scenario names (contract), so the dashboard speaks one language.
SCENARIO = {"scanning": "vulnerability_scanning", "ddos": "dos", "mirai": "mirai_botnet", "ransomware": "ransomware"}


def run_models(pcap: Path, normal: Path, name: str) -> Path:
    """Step 1: the AI team's script. Returns the folder with its results."""
    cmd = [sys.executable, "-I", str(SCORE_SCRIPT), str(pcap),
           "--model", str(MODELS / "models" / "lstm_ae" / LSTM), "--vae", str(MODELS / "models" / "vae" / VAE),
           "--calibrate", str(normal), "--recalibrate-threshold", "--name", name, "--out", str(RUNS)]
    print(f"running the models on {pcap.name} (calibrated on {normal.name}) ...", flush=True)
    subprocess.run(cmd, check=True)
    return RUNS / name


def severity(score: float) -> str:
    """Score = how far over the alarm line (1.0 = exactly on it)."""
    return "critical" if score >= 10 else "high" if score >= 3 else "medium" if score >= 1.5 else "low"


def save_alerts(results: Path, capture: str) -> int:
    """Steps 2 + 3: alerts.csv -> alerts table."""
    alerts = pd.read_csv(results / "alerts.csv")
    run = json.loads((results / "run.json").read_text(encoding="utf-8"))
    with connect() as conn, conn.transaction():
        ours = dict(conn.execute("SELECT host(ip), device_id FROM devices WHERE ip IS NOT NULL").fetchall())
        # the two models must be known to the database before their alerts can point at them
        for name, version, thr in (("lstm_ae", LSTM, run["threshold"]), ("vae", VAE, run.get("vae_threshold"))):
            conn.execute("INSERT INTO model_versions (model_name, version, feature_version, threshold, is_active) "
                         "VALUES (%s, %s, 'lstm-vae-gat', %s, FALSE) ON CONFLICT (model_name, version) "
                         "DO UPDATE SET threshold = EXCLUDED.threshold", (name, version, thr))
        conn.execute("DELETE FROM alerts WHERE evidence->>'capture' = %s", (capture,))   # re-run = replace
        for a in alerts.itertuples(index=False):
            lstm, vae = float(a.lstm_score), float(a.vae_score)
            model, version, score = ("lstm_ae", LSTM, lstm) if lstm >= vae else ("vae", VAE, vae)
            start = datetime.strptime(a.start_utc, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
            end = datetime.strptime(a.end_utc, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
            device_ip = str(a.device)
            evidence = {"capture": capture, "lstm_score": lstm, "vae_score": vae,
                        "vae_confidence": float(a.vae_confidence), "closest_known_class": a.closest_known_class,
                        "zero_day_candidate": bool(a.zero_day_candidate), "flows_in_window": int(a.flows_in_window),
                        "worst_features": str(a.worst_features), "results_folder": str(results)}
            conn.execute(
                "INSERT INTO alerts (ts, model_name, model_version, feature_version, entity_type, entity_id, device_id,"
                " window_start, window_end, score, threshold, is_anomaly, predicted_scenario, severity, evidence)"
                " VALUES (%s, %s, %s, 'lstm-vae-gat', 'device', %s, %s, %s, %s, %s, 1.0, TRUE, %s, %s, %s)",
                (end, model, version, ours.get(device_ip, device_ip), ours.get(device_ip), start, end, score,
                 SCENARIO.get(a.closest_known_class), severity(score), Jsonb(evidence)))
    return len(alerts)


def main() -> int:
    ap = argparse.ArgumentParser(description="Score a recording with the AI models and save the alerts.")
    ap.add_argument("pcap", type=Path, help="the recording to check (Wireshark .pcap)")
    ap.add_argument("--normal", type=Path, required=True, help="a recording of NORMAL traffic on the same network")
    ap.add_argument("--capture", help="name for this recording in the alerts (default: the file name)")
    a = ap.parse_args()
    for f in (a.pcap, a.normal):
        if not f.exists():
            print(f"ERROR: {f} not found")
            return 1
    if not SCORE_SCRIPT.exists():
        print(f"ERROR: the AI models are not here: {MODELS}")
        return 1
    capture = a.capture or a.pcap.stem
    results = run_models(a.pcap, a.normal, capture)
    n = save_alerts(results, capture)
    print(f"\nsaved {n} alerts for {capture}. See them: GET http://localhost:8001/api/v1/alerts?capture={capture}")
    if n:
        df = pd.read_csv(results / "alerts.csv")
        print(df.groupby(["device", "closest_known_class"]).size().rename("alerts").to_string())
    return 0


if __name__ == "__main__":
    sys.exit(main())
