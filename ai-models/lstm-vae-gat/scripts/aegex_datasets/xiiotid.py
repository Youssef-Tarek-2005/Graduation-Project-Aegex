"""X-IIoTID (Al-Hawawreh et al.; Kaggle dhoogla/x-iiotid cleaned parquet release).

ONE continuous capture (Dec 2019 - Mar 2020, the whole kill chain in time order). class2 is the
kill-chain stage; Reconnaissance = Scanning_vulnerability / Generic_scanning / Discovering_resources.
Everything outside the project scope becomes 'other'.
"""
import io

import numpy as np
import pandas as pd

import aegex_prep as ap

NAME = "xiiotid"
TITLE = "X-IIoTID"
SOURCE = "Kaggle dhoogla/x-iiotid (archive.zip)"
ORDER = 60
ACTIVE = False                 # trained and benchmarked on its own (model run *_xiiotid_v1)
ZIP = "archive.zip"
ORIGINALS = [ZIP]

# Normal traffic and attacks come from the same file, at different times. Base = its benign flows of the
# phase period; attacks = its in-scope attack flows of the same split. Only the real DDoS / scan sources
# count as attackers for the base filter: the generic rule (any source of any attack flow) would also drop
# the gateway 172.24.1.1 and the pivot 192.168.2.10 (sources of out-of-scope 'other' flows) = 78 % of the
# normal traffic. Hosts that SEND any attack flow (also 'other': insider, C&C, lateral movement) are
# compromised; their own normal-labelled traffic is not a clean reference (training excludes it too,
# device_compromised), so flows they originate are dropped from the base. Flows TO them are kept.
BENCH = {"bases": ["all"], "attacks": ["all"], "same_capture": True, "classes": ["ddos", "scanning"],
         "attacker_min_flows": 100, "drop_compromised_sources": True}
QUOTED_RUN = "lstm_ae_xiiotid_v1__vae_xiiotid_v1__recal_dev"

CLASS2 = {"Normal": "benign", "Reconnaissance": "scanning", "RDOS": "ddos", "crypto-ransomware": "ransomware"}
NOTE_NOCOUNT = "dropped: no packet/byte counts in source"


def to_flows(features, labels, metadata):
    """X-IIoTID rows (Zeek-derived connection records + host telemetry) -> unified flows.

    Only network columns are used; host telemetry (CPU, memory, OSSEC, logins, file/process activity)
    and the authors' detector outputs (anomaly_alert, OSSEC_alert*) are ignored (project scope =
    network traffic). Returns (flows, stats).

      * time: `Timestamp Numeric` (1-s resolution). Ties are ordered by the source row number.
      * counts: Scr_/Des_pkts and Scr_/Des_ip_bytes (IP-layer bytes = our convention). Rows without
        packet counts (18.6 %, class-dependent: Normal 18 %, vuln scan 28 %, ransomware 95 %) are DROPPED,
        not imputed - filling them would turn missingness into a label shortcut.
      * duration: missing for single-packet flows (Zeek '-') -> 0.
      * flags: the source has direction-less booleans meaning 'seen in the connection' (like Zeek
        history). Mapped as: is_syn_only -> fwd SYN; Is_SYN_ACK -> bwd SYN|ACK; is_pure_ack -> fwd ACK;
        is_with_payload (TCP) -> fwd PSH; 'FIN or RST' -> fwd FIN if the handshake completed
        (Is_SYN_ACK), else RST from the responder if it answered, else from the originator.
      * dropped too: rows without timestamp / protocol, loopback (127.0.0.0/8, host-internal, not
        network traffic) and exact duplicate source rows (6,222).
    """
    SYN, ACK, PSH, FIN, RST = ap.SYN, ap.ACK, ap.PSH, ap.FIN, ap.RST
    df = metadata.join(labels).join(features)
    st = {"rows_in": len(df)}
    df = df[~df.drop(columns=["Source Row"]).duplicated()]
    st["dropped_exact_duplicates"] = st["rows_in"] - len(df)
    df = df[df["Timestamp Numeric"].notna() & df["Protocol"].notna()]
    loop = df.Scr_IP.str.startswith("127.") | df.Des_IP.str.startswith("127.")
    st["dropped_loopback"] = int(loop.sum())
    df = df[~loop]
    nocount = df.Scr_pkts.isna() | df.Des_pkts.isna() | df.Scr_ip_bytes.isna() | df.Des_ip_bytes.isna()
    st["dropped_no_counts_by_class"] = df.loc[nocount, "class1"].value_counts().to_dict()
    df = df[~nocount]
    df = df.sort_values(["Timestamp Numeric", "Source Row"], kind="stable")

    proto = df.Protocol.astype(str).str.lower()
    tcp = (proto == "tcp").to_numpy()
    b = {c: df[c].fillna(False).astype(bool).to_numpy() for c in
         ["is_syn_only", "Is_SYN_ACK", "is_pure_ack", "is_with_payload", "FIN or RST"]}
    answered = (df.Des_pkts > 0).to_numpy()
    est = b["Is_SYN_ACK"]
    finrst = b["FIN or RST"] & tcp
    fwd = (np.where(b["is_syn_only"] & tcp, SYN, 0) | np.where(b["is_pure_ack"] & tcp, ACK, 0)
           | np.where(b["is_with_payload"] & tcp, PSH, 0) | np.where(finrst & est, FIN, 0)
           | np.where(finrst & ~est & ~answered, RST, 0))
    bwd = np.where(est & tcp, SYN | ACK, 0) | np.where(finrst & ~est & answered, RST, 0)

    dur = df.Duration.fillna(0.0).to_numpy()
    ts = df["Timestamp Numeric"].to_numpy(float)
    c2 = df.class2.astype(str)
    out = pd.DataFrame({
        "ts": ts, "ts_end": ts + dur,
        "src_ip": df.Scr_IP.to_numpy(), "src_port": pd.to_numeric(df.Scr_port, errors="coerce").fillna(0).astype("int32").to_numpy(),
        "dst_ip": df.Des_IP.to_numpy(), "dst_port": pd.to_numeric(df.Des_port, errors="coerce").fillna(0).astype("int32").to_numpy(),
        "proto": proto.where(proto.isin(["tcp", "udp", "icmp"]), "other").to_numpy(),
        "duration": dur,
        "fwd_pkts": df.Scr_pkts.astype("int64").to_numpy(), "bwd_pkts": df.Des_pkts.astype("int64").to_numpy(),
        "fwd_bytes": df.Scr_ip_bytes.astype("int64").to_numpy(), "bwd_bytes": df.Des_ip_bytes.astype("int64").to_numpy(),
        "fwd_flags": fwd.astype("int16"), "bwd_flags": bwd.astype("int16"),
        "original_label": (df.class1.astype(str) + "|" + c2).to_numpy(),
        "attack_class": c2.map(CLASS2).fillna("other").where(df.class1.astype(str) != "fuzzing",
                                                             "other").to_numpy(),   # fuzzing is not scanning
    })
    out["is_attack"] = (out.attack_class != "benign").astype("int8")
    out["mal_frac"] = out.is_attack.astype("float32")
    out["campaign"] = np.where(out.is_attack == 1, "xiiotid_killchain", "")
    out["label_note"] = ""
    st["flows"] = len(out)
    st["classes"] = out.attack_class.value_counts().to_dict()
    return out.reset_index(drop=True), st


def captures():
    return ["all"]


def build(name="all"):
    rd = lambda n: pd.read_parquet(io.BytesIO(ap.read_original_bytes(ZIP, n)))
    df, st = to_flows(rd("X-IIoTID.parquet"), rd("X-IIoTID-labels.parquet"), rd("X-IIoTID-metadata.parquet"))
    st["label_source"] = "official class2 kill-chain labels (Reconnaissance->scanning, RDOS->ddos, " \
                         "crypto-ransomware->ransomware, rest->other)"
    ap.log(f"[xiiotid/{name}] dropped: dup {st['dropped_exact_duplicates']:,}, loopback {st['dropped_loopback']:,}, "
           f"no counts {sum(st['dropped_no_counts_by_class'].values()):,}")
    return df, st
