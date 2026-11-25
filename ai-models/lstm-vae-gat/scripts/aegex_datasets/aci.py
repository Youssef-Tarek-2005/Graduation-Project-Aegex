"""ACI-IoT-2023 (Army Cyber Institute): CICFlowMeter-V4 flow CSV, one continuous week-long capture
(30 Oct - 3 Nov 2023: recon, benign, DoS, brute force, benign). Processed on Kaggle (file not kept locally)."""
import pandas as pd

import aegex_prep as ap

NAME = "aci"
TITLE = "ACI-IoT-2023"
SOURCE = "Kaggle emilynack/aci-iot-network-traffic-dataset-2023"
ORDER = 70
ACTIVE = False
FILE = "ACI-IoT-2023.csv"
ORIGINALS = [FILE]
WINDOW = ("2023-10-30", "2023-11-03")     # capture week (README)

BENCH = {"bases": ["all"], "attacks": ["all"], "same_capture": True, "classes": ["ddos", "scanning"],
         "attacker_min_flows": 100, "drop_compromised_sources": True}
QUOTED_RUN = "lstm_ae_aci_kaggle_v1__vae_aci_kaggle_v1__recal_dev"     # run on Kaggle


def label(lab):
    """ACI-IoT-2023 label -> project class: recon (ping sweep, OS / port / vulnerability scan) = scanning;
    ICMP / SYN / UDP / DNS floods and Slowloris = ddos (single-attacker DoS); brute force, ARP spoofing = other."""
    l = str(lab).lower()
    if "benign" in l:
        return "benign"
    if "scan" in l or "sweep" in l or "recon" in l or "discovery" in l:
        return "scanning"
    if "flood" in l or "slowloris" in l or "dos" in l:
        return "ddos"
    return "other"


def captures():
    return ["all"]


def build(name="all"):
    path, member = ap.locate(FILE)
    with ap.open_maybe_zip(path, member) as fh:
        raw = pd.read_csv(fh, usecols=lambda c: c.strip() in ap.CIC_COLS, dtype=str, low_memory=False)
    raw.columns = [c.strip() for c in raw.columns]
    df, st = ap.cicflowmeter_to_flows(raw, label, WINDOW)
    st["label_source"] = "official ACI-IoT-2023 Label column (recon -> scanning, floods/Slowloris -> ddos, rest -> other)"
    ap.log(f"[aci/{name}] labels: {st['labels']}")
    ap.log(f"[aci/{name}] rows {st['rows_in']:,}, bad timestamps {st['bad_timestamps']:,}")
    return df, st
