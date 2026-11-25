"""NF-ToN-IoT-v3 (Sarhan / Layeghy / Portmann, UQ): 27.5 M NetFlow v3 records, one capture per UTC day.

Too big for one DataFrame, so it uses run() (streaming) instead of captures()/build().
"""
import os

import pandas as pd

import aegex_prep as ap

NAME = "nf_toniot"
TITLE = "NF-ToN-IoT-v3"
SOURCE = "Kaggle athena21/netflow-v3-datasets (NF-ToN-IoT-v3.csv)"
ORDER = 40
# off in the default run (weak baseline: 26 % false alarms, scanning F1 0.29); still usable with
# --datasets nf_toniot and benchmarked on its own (model run *_nftoniot_v1)
ACTIVE = False
FILE = "NF-ToN-IoT-v3.csv"
ORIGINALS = [FILE]
CHUNK = 1_000_000

BASELINE_NOTE = "'other' = out-of-scope attacks (DoS, XSS, password, injection, backdoor, MITM)."
# Base = 29 Apr (1.96 M benign flows, no in-scope attack that day); attacks come from their own days:
# scanning 23-24 Apr, DDoS 25-26 Apr, ransomware 28 Apr. Its attacker hosts (.30-.39) also send lots of
# benign traffic, so only real sources of in-scope attacks are excluded from the base, and hosts that
# send any attack flow have their own flows dropped.
BENCH = {"bases": ["day_2019-04-29"],
         "attacks": ["day_2019-04-23", "day_2019-04-24", "day_2019-04-25", "day_2019-04-26", "day_2019-04-28"],
         "classes": ["ddos", "scanning", "ransomware"], "attacker_min_flows": 100,
         "drop_compromised_sources": True}
# saved thresholds: recalibration collapses on this network's calibration slice (one device dominates)
QUOTED_RUN = "lstm_ae_nftoniot_v1__vae_nftoniot_v1"

CLASS = {"benign": "benign", "scanning": "scanning", "ddos": "ddos", "ransomware": "ransomware"}


def to_flows(ch):
    out = pd.DataFrame({
        "ts": ch["FLOW_START_MILLISECONDS"] / 1000.0, "ts_end": ch["FLOW_END_MILLISECONDS"] / 1000.0,
        "src_ip": ch["IPV4_SRC_ADDR"], "src_port": ch["L4_SRC_PORT"].astype("int32"),
        "dst_ip": ch["IPV4_DST_ADDR"], "dst_port": ch["L4_DST_PORT"].astype("int32"),
        "proto": ch["PROTOCOL"].map(ap.PROTO_NAME).fillna("other"),
        "duration": ch["FLOW_DURATION_MILLISECONDS"] / 1000.0,
        "fwd_pkts": ch["IN_PKTS"], "bwd_pkts": ch["OUT_PKTS"],
        "fwd_bytes": ch["IN_BYTES"], "bwd_bytes": ch["OUT_BYTES"],
        "fwd_flags": ch["CLIENT_TCP_FLAGS"] & 0x3F, "bwd_flags": ch["SERVER_TCP_FLAGS"] & 0x3F,
        "original_label": ch["Attack"].astype(str),
    })
    low = ch["Attack"].str.lower()
    out["attack_class"] = low.map(CLASS).fillna("other").values
    out["is_attack"] = (ch["Label"] != 0).astype("int8").values
    out["mal_frac"] = out["is_attack"].astype("float32")
    out["campaign"] = ""
    return out


def run(report, log=ap.log):
    """Stream in chunks, one capture per UTC day, parts written as they fill:
    <out>/flows/nf_toniot/<day>/part-NNNN.parquet"""
    base = os.path.join(ap.PREPROCESSED_DIR, "flows", NAME)
    counts, part = {}, {}
    for i, ch in enumerate(pd.read_csv(ap.locate(FILE)[0], chunksize=CHUNK)):
        fl = to_flows(ch)
        day = pd.to_datetime(fl.ts, unit="s").dt.strftime("%Y-%m-%d")
        for d, g in fl.groupby(day, sort=True):
            cap = f"day_{d}"
            g = g.copy()
            g["dataset"], g["capture"] = NAME, cap
            n = part.get(cap, 0)
            ap.write_parquet(ap.to_schema(g), os.path.join(base, cap, f"part-{n:04d}.parquet"))
            part[cap] = n + 1
            c = counts.setdefault(cap, {"flows": 0, "attack_flows": 0, "classes": {}})
            c["flows"] += len(g); c["attack_flows"] += int(g.is_attack.sum())
            for k, v in g.attack_class.value_counts().items():
                c["classes"][k] = c["classes"].get(k, 0) + int(v)
        log(f"[nf_toniot] chunk {i + 1}: {(i + 1) * CHUNK:,} rows")
    for c in counts.values():
        c["label_source"] = "official NetFlow v3 labels (Attack column)"
    report[NAME] = counts
