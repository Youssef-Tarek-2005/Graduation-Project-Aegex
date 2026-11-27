"""IoT-23 EXTRA malware captures (Stratosphere Lab, CTU) - the captures NOT used by the `iot23` plug-in, so the
two never overlap. Added for GAT training variety (other botnet families on real infected devices).
Same Zeek conn.log parquet release as `iot23` (Kaggle dhoogla/iot23-dataset); processed on Kaggle.

Families (IoT-23 scenario list): Mirai and its variants (Okiru, Kenjiro, Hakai) -> class 'mirai' for scanning / C&C /
payload, 'ddos' for floods. Other families (Hide&Seek, Muhstik, Hajime, Torii, IRCBot, Gafgyt, Trojan) -> 'scanning'
for horizontal port scans, 'ddos' for floods, 'other' for C&C / downloads (outside the project's attack scope).

Several captures are huge (up to 73 M connections, almost all one long port scan). Only the first MAX_ROWS
connections of each capture are read (row groups in file order = capture order), which keeps the start of
the infection and plenty of scanning while fitting in Kaggle's memory.
"""
import os

import numpy as np
import pandas as pd
import pyarrow.parquet as pq

import aegex_prep as ap
from aegex_datasets import iot23 as base

NAME = "iot23x"
TITLE = "IoT-23 (extra captures)"
SOURCE = "Stratosphere Lab IoT-23 (Zeek conn.log, parquet release; Kaggle dhoogla/iot23-dataset)"
ORDER = 31
ACTIVE = False
MAX_ROWS = int(os.environ.get("AEGEX_IOT23X_MAX_ROWS", 600_000))

FAMILY = {"CTU-IoT-Malware-Capture-1-1": "hide_and_seek", "CTU-IoT-Malware-Capture-3-1": "muhstik",
          "CTU-IoT-Malware-Capture-7-1": "mirai", "CTU-IoT-Malware-Capture-8-1": "hakai",
          "CTU-IoT-Malware-Capture-9-1": "hajime", "CTU-IoT-Malware-Capture-17-1": "kenjiro",
          "CTU-IoT-Malware-Capture-20-1": "torii", "CTU-IoT-Malware-Capture-21-1": "torii",
          "CTU-IoT-Malware-Capture-33-1": "kenjiro", "CTU-IoT-Malware-Capture-36-1": "okiru",
          "CTU-IoT-Malware-Capture-39-1": "ircbot", "CTU-IoT-Malware-Capture-42-1": "trojan",
          "CTU-IoT-Malware-Capture-43-1": "mirai", "CTU-IoT-Malware-Capture-44-1": "mirai",
          "CTU-IoT-Malware-Capture-49-1": "mirai", "CTU-IoT-Malware-Capture-52-1": "mirai",
          "CTU-IoT-Malware-Capture-60-1": "gafgyt"}
MIRAI_FAMILY = {"mirai", "okiru", "kenjiro", "hakai"}
CAPTURES = list(FAMILY)
ORIGINALS = [f"{c}.{k}.parquet" for c in CAPTURES for k in ("features", "metadata")]
BASELINE_NOTE = "Extra IoT-23 captures, first %d connections each; Mirai variants -> 'mirai', others -> scanning/ddos/other." % MAX_ROWS
# no BENCH: these captures have no clean normal base (the benign rows come from the infected devices themselves);
# the GAT uses their own graphs (dataset split), not injected benchmark scenarios.


def read_head(path, n):
    pf = pq.ParquetFile(path)
    tabs, rows = [], 0
    for i in range(pf.num_row_groups):
        t = pf.read_row_group(i)
        tabs.append(t); rows += t.num_rows
        if rows >= n:
            break
    import pyarrow as pa
    return pa.concat_tables(tabs).to_pandas().iloc[:n]


def captures():
    return list(CAPTURES)


def build(name):
    f = read_head(ap.locate(f"{name}.features.parquet")[0], MAX_ROWS)
    m = read_head(ap.locate(f"{name}.metadata.parquet")[0], MAX_ROWS)
    df = base.to_flows(f, m)                                 # same Zeek mapping (+ Telnet relabel) as iot23
    fam = FAMILY[name]
    det = df.original_label.str.split("|", n=1).str[1].fillna("")
    mal = df.is_attack.to_numpy() == 1
    if fam in MIRAI_FAMILY:
        cls = np.where(det.str.contains("DDoS"), "ddos", "mirai")
    else:
        cls = np.where(det.str.contains("DDoS"), "ddos",
                       np.where(det.str.contains("PartOfAHorizontalPortScan") & ~det.str.contains("C&C"), "scanning", "other"))
    relabel = (df.label_note == base.RELABEL_TELNET).to_numpy()      # unanswered Telnet SYN sweeps = scanning
    cls = np.where(relabel, "mirai" if fam in MIRAI_FAMILY else "scanning", cls)
    df["attack_class"] = np.where(mal, cls, "benign")
    df["campaign"] = np.where(mal, fam, "")
    counts = df.attack_class.value_counts().to_dict()
    ap.log(f"[iot23x/{name}] family {fam}: {len(df):,} flows (cap {MAX_ROWS:,}) {counts}")
    return df, {"flows": len(df), "family": fam, "classes": counts, "row_cap": MAX_ROWS,
                "label_source": "official Zeek labels (label|detailed-label), family-aware class mapping"}
