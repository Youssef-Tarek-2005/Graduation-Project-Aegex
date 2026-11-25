# Aegex preprocessing pipeline

Turns six public datasets into **one uniform format** for the Aegex model chain
(LSTM autoencoder → VAE → Temporal GAT → attack analysis → RAG-LLM).

| Dataset | Source format | Captures used | Classes produced |
|---|---|---|---|
| Edge-IIoTset | pcap (in `edge-IIotset.zip`) | 10 normal device pcaps + ransomware, 3 scanning, 4 DDoS pcaps | benign, ransomware, scanning, ddos |
| NF-ToN-IoT-v3 | NetFlow v3 CSV | whole file, one capture per day (7) | benign, scanning, ddos, ransomware, other |
| IoT-23 | Zeek conn.log (parquet) | Mirai 34-1, 48-1, 35-1 + honeypots 4-1, 5-1, 7-1 | benign, mirai, ddos |
| Kitsune Mirai | pcapng + **relabeled** per-packet labels | Mirai | benign, mirai |
| Kitsune SSDP Flood | pcap + per-packet labels | SSDP Flood | benign, ddos |
| Kitsune OS Scan | pcapng + per-packet labels | OS Scan | benign, scanning |

Also installed: Gotham 2025, X-IIoTID and ACI-IoT-2023 (each trained and benchmarked on its own).

**Datasets are plug-ins** in `scripts\aegex_datasets\` (one file or folder each: originals, captures, adapter,
benchmark case). This folder holds only dataset-independent code. List them with
`python -m aegex_datasets` from `scripts\`. Add one by copying `_template.py`, remove one by deleting its file.

**Active datasets** (`ACTIVE = True`, the default for every step): Kitsune, Edge-IIoTset, IoT-23.
NF-ToN-IoT-v3 is **off** by default (weak baseline: 26 % false alarms, scanning F1 0.29); pass
`--datasets nf_toniot` to a step, or set `ACTIVE = True` in `aegex_datasets\nf_toniot.py`.

`other` = attacks outside the project scope that sit inside NF-ToN-IoT-v3's continuous capture
(DoS, XSS, password, injection, backdoor, MITM). They are kept so the timeline is not cut, and
can be masked out at evaluation time. Out-of-scope Edge-IIoTset attack files are simply not read.

## Run

```powershell
cd "<project folder>\scripts\preprocessing"

# one-time setup (already done on this machine: .venv exists)
python -m venv .venv
.venv\Scripts\python.exe -m pip install -r requirements.txt

# full pipeline (~15 min), output also saved to run_all.log
powershell -ExecutionPolicy Bypass -File run_all.ps1 -Python .venv\Scripts\python.exe *> run_all.log
```

Success = the log ends with the baseline results table and `Done.`; checks are in
`preprocessed\_verification.txt` (must say `FAILURES: 0`), scores in `preprocessed\baseline\summary.txt`.
Only the baseline: `.venv\Scripts\python.exe step5_baseline.py` (a few minutes).
Re-running is safe: outputs are overwritten, originals are only read.

Each step can also run alone and for selected datasets, e.g.
`python step2_features.py --datasets edge iot23`.
Runtime on a 16-thread laptop: about 15 minutes in total.

## Steps

| Step | Script | Output (`preprocessed\`) |
|---|---|---|
| 1 | `step1_flows.py` – runs each dataset plug-in's adapter → unified bidirectional **flow** schema | `flows\<dataset>\<capture>.parquet` |
| 2 | `step2_features.py` – same 50 features for all, chronological split, robust scaling | `features\<dataset>\<capture>.parquet`, `_scaler.json`, `feature_spec.json` |
| 3 | `step3_sequences_graphs.py` – LSTM windows + GAT time snapshots | `windows\<dataset>.parquet`, `graphs\<dataset>\<capture>_{edges,nodes}.parquet` |
| 4 | `step4_verify.py` – independent checks | `_verification.txt` |
| 5 | `step5_baseline.py` – Random Forest baseline per dataset (train split → full test split) | `baseline\summary.txt`, `baseline\<dataset>_report.txt`, `baseline\results.json` |

The baseline is **not** an Aegex model: it proves the preprocessed data is learnable and sets
the score the LSTM-AE / VAE / GAT have to beat. Training rows are capped at 200k per class
(`--per-class`), the whole test split is scored, and it reports per-class precision/recall/F1,
macro F1, attack detection rate, false-alarm rate, the confusion matrix and top features.

`aegex_prep.py` holds all shared logic; `aegex_data.py` loads the outputs for training.

## Design decisions

**One flow format for everything.** Packet captures (Edge, Kitsune) are assembled into
bidirectional flows by our own Zeek-style flow builder (inactivity timeouts TCP 300 s,
UDP/ICMP/ARP 60 s, plus a NetFlow-style 120 s active timeout so long streams become a time series).
IoT-23 (Zeek) and NF-ToN-IoT-v3 (NetFlow) are mapped field by field onto the same columns:
`ts, src/dst ip+port, proto, duration, fwd/bwd packets, fwd/bwd IP bytes, fwd/bwd TCP flags`.
ARP is kept as its own protocol in pcap sources because Mirai's local discovery is an ARP sweep.

**Features (50, identical for every dataset).**
17 continuous (log durations/packets/bytes, mean packet size per direction, packet and byte rates,
direction shares, time since the device's / host pair's previous flow, and **device context**:
flows per 10 s, new peers and new service ports per 60 s, share of replies in 60 s — all causal,
computed from the device's own past traffic, so identical on live traffic) and
33 binary (incl. `dev_new_peer`) (protocol, reply seen, SYN/ACK/FIN/RST/PSH per direction, service-port family).
IPs, ports, timestamps and device ids are **identity columns only**, never model inputs, which
blocks the "attacker IP" shortcut found in Edge-IIoTset and X-IIoTID.

**Splits.** Chronological 70/15/15 inside every (capture, attack class): no random-row leakage,
every class appears in train, val and test, and the test part is always the *latest* traffic.

**Normalisation.** Robust scaling `(x − median) / max(IQR, 0.1)` with logarithmic soft tails beyond ±3
(clip ±10), fitted **per dataset** on **train + clean benign** flows only (benign flows of a
`device_compromised` host — one that originates attacks — are excluded) (what an anomaly detector is allowed to see), then applied
to all splits. Binary features stay 0/1.

**LSTM windows.** Rows are sorted by (device, time); a window is 32 consecutive flows of one
device (stride 16), stored as row ranges, so nothing is duplicated on disk. "Device" is the LAN
endpoint of the flow, so spoofed-source floods land in the victim's sequence. Use
`split_pure=True` windows to avoid split boundaries. Benign-only train windows feed the
LSTM-AE and VAE; labelled windows evaluate them.

**GAT snapshots.** 60-second graphs per capture: nodes = hosts, edges = directed host pairs
with the mean flow features as edge attributes, node traffic aggregates, and labels for
attack edges, attack sources and attack targets. Single-contact public IPs are merged into one
`EXTERNAL` node.

**Label corrections (always traceable).** `original_label` always holds the source's own label;
`label_note` says why ours differs.
- Kitsune Mirai uses the behaviour-relabeled packet labels (`kitsune_mirai_relabeled\`).
- IoT-23 capture 35-1 labels the infected host's 8.25M outbound Telnet scan probes as *Benign*,
  while the identical behaviour in capture 48-1 is labelled *PartOfAHorizontalPortScan*. Left as is,
  this teaches models that Mirai scanning is normal and makes the in-capture baseline a perfect
  (memorised) 1.000. Rule: a Benign flow becomes `mirai` only if it comes from an infected host
  (one that originates flows IoT-23 itself labels Malicious), is a TCP SYN to Telnet 23/2323,
  goes to a public IP, and got no reply.

**Cross-capture test.** For IoT-23 the baseline also trains on all other captures and scores a
whole unseen capture (leave-one-capture-out), which measures generalisation instead of memory.

**Training notes.**
- Kitsune Mirai: train on time windows and weight the classes (97 % of its malicious packets
  are one ARP sweep).
- Fit models per dataset or with a dataset id; never merge graphs across datasets (IP ranges overlap).
- NF-ToN-IoT-v3 ransomware is small (3,971 flows) – use class weights.
- Edge-IIoTset attack pcaps contain only attack traffic (official file-level labels); its
  benign traffic comes from the separate normal-device pcaps.

**Provenance.** Original files are only read (zips are streamed, never extracted). Steps 1 and 4
re-check them against `ORIGINALS_SHA256.txt`.
