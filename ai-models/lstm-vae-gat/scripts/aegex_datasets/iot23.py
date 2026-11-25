"""IoT-23 (Stratosphere Lab, CTU): Zeek conn.log records (features + metadata parquet per capture)."""
import numpy as np
import pandas as pd

import aegex_prep as ap

NAME = "iot23"
TITLE = "IoT-23"
SOURCE = "Stratosphere Lab IoT-23 (Zeek conn.log, parquet release)"
ORDER = 30
ACTIVE = True

CAPTURES = ["CTU-IoT-Malware-Capture-34-1", "CTU-IoT-Malware-Capture-48-1", "CTU-IoT-Malware-Capture-35-1",
            "CTU-Honeypot-Capture-4-1", "CTU-Honeypot-Capture-5-1", "CTU-Honeypot-Capture-7-1"]
ORIGINALS = [f"{c}.{k}.parquet" for c in CAPTURES for k in ("features", "metadata")]

BASELINE_NOTE = "Mirai scanning/C&C is labelled 'mirai'; Mirai-launched floods are 'ddos'."
# Leave-one-capture-out test: only meaningful where the same attack classes recur (the Mirai captures).
CROSS_CAPTURE = ["CTU-IoT-Malware-Capture-34-1", "CTU-IoT-Malware-Capture-35-1", "CTU-IoT-Malware-Capture-48-1"]
# (Malware-Capture-34-1 has no usable normal traffic once the infected device is removed)
BENCH = {"bases": ["CTU-Honeypot-Capture-5-1", "CTU-Honeypot-Capture-4-1"],
         "attacks": ["CTU-IoT-Malware-Capture-34-1", "CTU-IoT-Malware-Capture-48-1"]}
QUOTED_RUN = "lstm_ae_v8__vae_v5"

TELNET_PORTS = {23, 2323}
RELABEL_TELNET = "relabel: Benign->mirai (infected host, unanswered Telnet SYN to public IP)"


def to_flows(features, metadata):
    df = features.merge(metadata, on="source_row", how="inner")
    hist = df["history"].astype(object)
    uniq = {h: ap._zeek_history_flags(h) for h in pd.unique(hist)}
    flags = hist.map(uniq)
    out = pd.DataFrame({
        "ts": pd.to_numeric(df["ts"], errors="coerce"),
        "src_ip": df["id.orig_h"], "src_port": df["id.orig_p"].astype("int32"),
        "dst_ip": df["id.resp_h"], "dst_port": df["id.resp_p"].astype("int32"),
        "proto": df["proto"].str.lower().where(df["proto"].str.lower().isin(["tcp", "udp", "icmp"]), "other"),
        "duration": df["duration"].fillna(0.0),
        "fwd_pkts": df["orig_pkts"].astype("int64"), "bwd_pkts": df["resp_pkts"].astype("int64"),
        "fwd_bytes": df["orig_ip_bytes"].astype("int64"), "bwd_bytes": df["resp_ip_bytes"].astype("int64"),
        "fwd_flags": [f[0] for f in flags], "bwd_flags": [f[1] for f in flags],
        "original_label": df["label"].astype(str) + "|" + df["detailed-label"].astype(str),
    })
    out["ts_end"] = out.ts + out.duration
    mal = df["label"].str.lower().eq("malicious")
    out["is_attack"] = mal.astype("int8").values
    out["mal_frac"] = out["is_attack"].astype("float32")
    det = df["detailed-label"].astype(str)
    # IoT-23 Mirai captures: Mirai-launched floods -> ddos; propagation scans / C&C / loader -> mirai
    out["attack_class"] = np.where(~mal, "benign", np.where(det.str.contains("DDoS"), "ddos", "mirai"))
    out["campaign"] = np.where(mal, "mirai", "")
    out["label_note"] = ""
    # Behaviour relabel (documented label error): in capture 35-1 the infected host's 8.25M outbound
    # Telnet scan probes are labelled Benign, while the identical behaviour in 48-1 is labelled
    # PartOfAHorizontalPortScan. A Benign flow becomes 'mirai' only if ALL hold:
    #   originator = an infected host (originates flows the dataset itself labels Malicious)
    #   TCP SYN to Telnet 23/2323, responder is a public IP, and no reply was received.
    infected = set(out.loc[mal.to_numpy(), "src_ip"])
    pub = ~out.dst_ip.map({ip: ap.is_private(ip) for ip in pd.unique(out.dst_ip)}).astype(bool)
    scan = ((~mal.to_numpy()) & out.src_ip.isin(infected) & (out.proto == "tcp") &
            out.dst_port.isin(list(TELNET_PORTS)) & ((out.fwd_flags & ap.SYN) > 0) & (out.bwd_pkts == 0) & pub)
    out.loc[scan, ["attack_class", "campaign", "label_note"]] = ["mirai", "mirai", RELABEL_TELNET]
    out.loc[scan, "is_attack"] = 1
    out.loc[scan, "mal_frac"] = 1.0
    return out.dropna(subset=["ts"]).sort_values("ts", kind="stable").reset_index(drop=True)


def captures():
    return list(CAPTURES)


def build(name):
    f = pd.read_parquet(ap.locate(f"{name}.features.parquet")[0])
    m = pd.read_parquet(ap.locate(f"{name}.metadata.parquet")[0])
    df = to_flows(f, m)
    return df, {"flows": len(df), "relabeled_benign_to_mirai": int((df.label_note != "").sum()),
                "label_source": "official Zeek labels (label|detailed-label) + Telnet-scan behaviour relabel"}
