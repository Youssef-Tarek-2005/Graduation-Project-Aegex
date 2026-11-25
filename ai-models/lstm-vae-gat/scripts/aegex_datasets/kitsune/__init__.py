"""Kitsune (Mirsky et al., NDSS 2018): packet captures with per-packet labels.

Mirai uses the behaviour relabel in kitsune_mirai_relabeled/ (R1 ARP sweep / R2 Telnet / R3 new behaviour),
made and checked by the two tools in this folder:
    python -I relabel_mirai.py <Mirai pcap> <mirai_labels.csv> <project>/kitsune_mirai_relabeled
    python -I verify_mirai_relabel.py <project>/kitsune_mirai_relabeled
"""
import os

import numpy as np

import aegex_prep as ap

NAME = "kitsune"
TITLE = "Kitsune"
SOURCE = "Kaggle ymirsky/network-attack-dataset-kitsune (Mirai, SSDP Flood, OS Scan)"
ORDER = 10
ACTIVE = True

# capture: (pcap zip, label file, attack_class)
SOURCES = {
    "mirai": ("Mirai_pcap.pcap.zip", os.path.join("kitsune_mirai_relabeled", "mirai_labels_relabeled.csv"), "mirai"),
    "ssdp_flood": ("SSDP_Flood_pcap.pcap.zip", "SSDP_Flood_labels.csv.zip", "ddos"),
    "os_scan": ("OS_Scan_pcap.pcapng.zip", "OS_Scan_labels.csv.zip", "scanning"),
}
ORIGINALS = [v[0] for v in SOURCES.values()] + ["SSDP_Flood_labels.csv.zip", "OS_Scan_labels.csv.zip",
                                                 "mirai_labels.csv.zip"]

BASELINE_NOTE = "Small captures; OS Scan has only 95 benign flows."
BENCH = {"bases": ["ssdp_flood", "mirai"], "attacks": ["os_scan", "mirai", "ssdp_flood"]}
QUOTED_RUN = "lstm_ae_v8__vae_v5"


def read_labels(path, member=None):
    """Kitsune label files: either one value per line (Mirai) or '"",\"x\"' header + index,label."""
    out = []
    with ap.open_maybe_zip(path, member) as fh:
        for line in fh.read().split():
            try:
                out.append(int(float(line.split(b",")[-1].strip(b'"'))))
            except ValueError:
                pass
    return np.asarray(out, dtype=np.int8)


def captures():
    return list(SOURCES)


def build(name):
    pcap, labels, cls = SOURCES[name]
    lab = read_labels(*ap.locate(labels))
    ppath, pmember = ap.locate(pcap)
    df, st = ap.build_flows_from_pcap(ppath, member=pmember, packet_labels=lab,
                                      log=lambda m: ap.log(f"[kitsune/{name}]", m))
    df["is_attack"] = (df.mal_frac > 0).astype("int8")
    df["attack_class"] = np.where(df.is_attack == 1, cls, "benign")
    df["campaign"] = np.where(df.is_attack == 1, "mirai", "") if name == "mirai" else ""
    src = "relabeled per-packet labels" if name == "mirai" else "original per-packet labels"
    df["original_label"] = np.where(df.is_attack == 1, f"malicious ({src})", f"benign ({src})")
    df["label_note"] = "behaviour relabel: kitsune_mirai_relabeled (R1 ARP sweep / R2 Telnet / R3 new behaviour)" \
        if name == "mirai" else ""
    st["label_source"] = src
    return df, st
