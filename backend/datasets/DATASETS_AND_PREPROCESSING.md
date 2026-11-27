# Aegex — datasets, labelling and preprocessing

Every dataset used to train or test the LSTM autoencoder (LSTM-AE), the VAE and the temporal GAT, how each
one was labelled, and the preprocessing applied to it. Status 26 Nov 2026.

Attack types in scope: **scanning** (incl. vulnerability scans), **DDoS / DoS floods**, **Mirai**,
**ransomware**. Every other attack becomes **other** (kept in the data, never used as a training target).
Original files are never modified: their SHA-256 checksums are in `ORIGINALS_SHA256.txt` and every output
goes to `preprocessed\` and `models\`.

## 1. Overview

| Dataset | Source (file) | Size | Format | Connections | Normal | Attacks used | LSTM-AE / VAE | GAT |
|---|---|---|---|---|---|---|---|---|
| Edge-IIoTset | Kaggle `mohamedamineferrag/edgeiiotset-cyber-security-dataset-of-iot-iiot` (`edge-IIotset.zip`) | 1.7 GB | pcaps, one per attack / device | 7.50 M | 675,186 | DDoS 6.81 M · scanning 13,354 · ransomware 971 | `lstm_ae_v8` / `vae_v5` | gat_v2 train; gat_v5 **test only** |
| Kitsune | Kaggle `ymirsky/network-attack-dataset-kitsune` (Mirai, SSDP Flood, OS Scan pcaps + labels) | 0.87 GB | pcaps + per-packet labels | 871,015 | 726,790 | scanning 65,583 · DDoS 65,538 · Mirai 13,104 | `lstm_ae_v8` / `vae_v5` | gat_v2 train; gat_v5 **test only** |
| IoT-23 | Kaggle `dhoogla/iot23-dataset` (6 captures, `.features` + `.metadata.parquet`) | 0.42 GB | Zeek conn.log | 13.87 M | 19,124 | Mirai 11.65 M · DDoS 2.20 M | `lstm_ae_v8` / `vae_v5` | gat_v2, gat_v5 train |
| IoT-23 extra captures (`iot23x`) | same release, 17 more malware captures | 9.1 GB | Zeek conn.log | first 600 k per capture | few | Mirai variants, scanning, DDoS | `lstm_ae_iot23x_kaggle_v2` / `vae_…` (GAT inputs only) | gat_v5 train |
| X-IIoTID | Kaggle `dhoogla/x-iiotid` (`archive.zip`) | 81 MB | Zeek-derived connection records | 629,056 | 307,087 | DDoS 141,261 · scanning 93,445 | `lstm_ae_xiiotid_v1` / `vae_xiiotid_v1` | gat_v5 train |
| Gotham 2025 | Zenodo `10.5281/zenodo.14502760` (`GothamDataset2025.zip`) | 23.8 GB | per-device pcaps | 6.50 M | 83,952 | DDoS 6.31 M · Mirai 93,063 · scanning 4,484 | `lstm_ae_gotham_v1` / `vae_gotham_v1` | gat_v5 train |
| ACI-IoT-2023 | Kaggle `emilynack/aci-iot-network-traffic-dataset-2023` (`ACI-IoT-2023.csv`) | 626 MB | CICFlowMeter flows | 1.23 M | 329,295 | scanning 590,271 · floods 305,460 | `lstm_ae_aci_kaggle_v1/_v2` / `vae_…` | gat_v5 train |
| NF-ToN-IoT-v3 | Kaggle `athena21/netflow-v3-datasets` (`NF-ToN-IoT-v3.csv`) | 5.3 GB | NetFlow v3 records | 27.52 M | 16.79 M | DDoS 4.14 M · scanning 1.36 M · ransomware 3,971 | `lstm_ae_nftoniot_v1` / `vae_nftoniot_v1` | gat_v3 only (failed, dropped) |

Gotham was downloaded from Zenodo (not on Kaggle). ACI-IoT-2023 and the extra IoT-23 captures were processed
on Kaggle without downloading them. Rejected after inspection: CICIoT2023 and CIC IoMT (no IP addresses or
timestamps), MU-IoT and MedBIoT Kaggle copies (pre-computed features, no IP addresses), TII-SSRC-23 (too little
normal traffic).

## 2. Per-dataset adapter and labelling

Each dataset has one adapter in `scripts\aegex_datasets\` that turns it into the shared flow table
(timestamp, source / destination IP and port, protocol, duration, packets and bytes in each direction, TCP
flags in each direction, label columns). Nothing else in the pipeline knows about individual datasets.

### Edge-IIoTset (`edge.py`)
* **Used:** 8 attack pcaps (ransomware, vulnerability scanner, port scanning, OS fingerprinting, DDoS HTTP /
  ICMP / TCP SYN / UDP floods) and the 10 normal-device pcaps (Distance, Flame sensor, Heart rate, IR
  receiver, Modbus, Soil moisture, Sound sensor, Temperature & humidity, Water level, pH).
* **Not used (out of scope):** SQL injection, XSS, uploading, backdoor, password, MITM.
* **Labels:** file-level, as the dataset ships them: every connection in an attack file is that attack
  (checked: `Attack_label = 1` for all rows of every in-scope attack CSV). Port scan, OS fingerprinting and
  vulnerability scanner → scanning; the four floods → ddos.
* **Caveat:** attacks are recorded in separate files with no normal traffic, so the dataset's own test split
  is trivially easy (a one-line rule gets 99.9 %). Only the realistic benchmark (§4) is quoted.

### Kitsune (`kitsune\`)
* **Used:** Mirai (camera network, 22 devices), SSDP Flood, OS Scan pcaps with their per-packet labels.
* **Labels:** per packet; a connection is an attack if any of its packets is (`mal_frac` keeps the share).
  SSDP flood → ddos, OS scan → scanning, Mirai → mirai.
* **Mirai relabel** (`kitsune_mirai_relabeled\`, made by `relabel_mirai.py`, checked by
  `verify_mirai_relabel.py`): the original labels mark everything after the attack start as malicious.
  Packets were relabelled by behaviour: R1 ARP sweep from an infected host (≥ 20 targets), R2 Telnet scans,
  R3 other new behaviour of infected hosts; normal background traffic after the start goes back to benign
  (73,290 packets 1 → 0; 642,516 → 569,226 malicious packets). Infected hosts: 192.168.2.107, 192.168.2.110.

### IoT-23 (`iot23.py`)
* **Used:** Mirai captures 34-1, 35-1, 48-1 and honeypot (normal) captures 4-1, 5-1, 7-1.
* **Labels:** official Zeek `label | detailed-label`. Malicious + "DDoS" → ddos; every other malicious
  connection (port scans, C&C, downloads) → mirai.
* **Telnet relabel:** in 35-1 the infected host's 8.25 M outgoing Telnet scan probes are labelled Benign,
  while the same behaviour in 48-1 is labelled malicious. A Benign connection becomes mirai only if all hold:
  sent by a host the dataset labels as infected, TCP SYN to port 23/2323, public destination, no reply.
  The original label is kept in `original_label` / `label_note`.

### IoT-23 extra captures (`iot23x.py`, GAT only)
* **Used:** the 17 malware captures not in `iot23` (1-1, 3-1, 7-1, 8-1, 9-1, 17-1, 20-1, 21-1, 33-1, 36-1,
  39-1, 42-1, 43-1, 44-1, 49-1, 52-1, 60-1). Only the **first 600,000 connections** of each capture are read
  (several have tens of millions, almost all one long port scan).
* **Labels:** family-aware. Mirai and its variants (Mirai, Okiru, Kenjiro, Hakai): floods → ddos, everything
  else malicious → mirai. Other families (Hide&Seek, Muhstik, Hajime, Torii, IRCBot, Gafgyt, Trojan): floods →
  ddos, horizontal port scans → scanning, C&C / downloads → other. Same Telnet relabel as `iot23`.
* **Caveat:** almost no normal traffic (7 clean normal test windows), so it teaches the GAT what attacks look
  like but gives no false-alarm rate.

### X-IIoTID (`xiiotid.py`)
* **Used:** the whole file (one continuous capture, Dec 2019 – Mar 2020, full kill chain in time order).
* **Labels:** official `class2` kill-chain stage: Normal → benign, Reconnaissance → scanning, RDOS → ddos,
  crypto-ransomware → ransomware, everything else (incl. fuzzing) → other.
* **Cleaning:** only network columns are used (host telemetry and the authors' detector outputs are ignored).
  Dropped: 6,222 exact duplicates, loopback traffic, rows without timestamp or protocol, and rows without
  packet / byte counts (18.6 %; dropped, not filled in, because missing counts depend on the class).
  TCP flags rebuilt from the dataset's direction-less flag columns. Timestamps have 1-second resolution.
* **Caveat:** ransomware has 1 usable connection, so ransomware comes from Edge-IIoTset and NF-ToN-IoT-v3.

### Gotham 2025 (`gotham\`)
* **Used:** all 6 scenarios (benign 2 h, Mirai infection, Mirai DoS, Merlin, network scanning, CoAP
  amplification). Per-device pcaps of a scenario are streamed from the zip, merged by time and de-duplicated.
* **Labels:** the official labeller's IP rules (`othmbela/gotham-network-packet-labeller` metadata), exact-IP
  matching; Unknown → benign. Mirai floods and Merlin floods → ddos; Mirai Telnet scan, brute force,
  loader, reporting, C&C → mirai; masscan / UDP scans → scanning; Merlin C&C → other.

### ACI-IoT-2023 (`aci.py`)
* **Used:** `ACI-IoT-2023.csv` only (CICFlowMeter flows; the payload CSV and pcaps are not needed).
* **Labels:** official `Label`: ping sweep, OS / port / vulnerability scan → scanning; ICMP / SYN / UDP / DNS
  floods and Slowloris → ddos; dictionary brute force, ARP spoofing → other.
* **Cleaning:** timestamps are written day-first and month-first in different rows; each is parsed with the
  format that falls inside the capture week (30 Oct – 3 Nov 2023). Bytes = payload + header bytes; protocol 0
  → ICMP; TCP flag counts mapped to the forward / backward direction.

### NF-ToN-IoT-v3 (`nf_toniot.py`)
* **Used:** the whole file, streamed in 1 M-row chunks and split into one capture per day.
* **Labels:** official `Attack` column: scanning, ddos, ransomware kept; DoS, XSS, password, injection,
  backdoor, MITM → other.

## 3. Shared preprocessing (identical for every dataset)

Code: `scripts\preprocessing\`. Settings below are the defaults used for every model.

**Step 1 — flows** (`step1_flows.py`): the adapter output, or packets → connections with `FlowBuilder` for
pcap datasets. Two-way connections keyed by the endpoint pair and protocol, originator = sender of the first
packet; inactivity timeout 300 s (TCP) / 60 s (UDP, ICMP, ARP); long connections are cut into 120 s records
(NetFlow-style active timeout). Reads IPv4 and ARP; IPv6 is skipped.

**Step 2 — features** (`step2_features.py`): the same **50 features** for every dataset (17 numeric incl. 4
device-behaviour features, 33 yes/no: protocol, TCP flags per direction, service port groups). IPs, ports and
timestamps are identity columns only, never model inputs.
* **Split:** chronological per (capture, attack class): first 70 % train, next 15 % validation, last 15 %
  test. Never random, so models are always tested on traffic that comes after what they learned from.
* **Scaling:** a robust scaler per dataset, fitted on **train + clean normal** traffic only.
* **Compromised devices:** hosts that send any attack traffic are marked `device_compromised`; their own
  normal-labelled traffic is not used as a clean reference.

**Step 3 — windows and graphs** (`step3_sequences_graphs.py`):
* **LSTM / VAE windows:** each device's connections sorted by time, **32 connections per window, a new
  window every 16** (half overlap), plus one window ending at the device's last connection. Window label = 1
  if any connection is an attack; window class = the attack class with the most connections.
* **GAT graphs:** one snapshot every **60 seconds** per capture; nodes = hosts, edges = host pairs (mean of
  the 50 features + connection count). Public IPs that talk to only one host in a snapshot are merged into
  one EXTERNAL node.

**Training** (`scripts\models\`):
* LSTM-AE and VAE learn from **clean normal windows only**. Alarm line = 99th percentile of validation normal
  windows (≈ 1 % false alarms), one per network. Window score = mean of the 8 worst connections.
* VAE inputs: 152 numbers per window (LSTM summary, error, and window statistics); input standardisation
  capped (std floor 0.1, clip ±5) so no single rare input can trigger an alarm.
* GAT (`gat_v5`): supervised on attack labels; each network fed through its own LSTM-AE + VAE; stage scores
  divided by that network's alarm line; **no port / service link inputs** (they were dataset-specific
  shortcuts, e.g. only Mirai uses Telnet in Gotham).

## 4. How the datasets were used to train each model

### Which data each model saw

| Model run | Trained on | Data used for training | Validation (stopping + alarm line) | Tested on |
|---|---|---|---|---|
| `lstm_ae_v8` (LSTM-AE) | Kitsune + Edge-IIoTset + IoT-23 together | **clean normal** windows of the train split only (no attacks, no compromised devices) | clean normal windows of the val split | test split + realistic benchmark |
| `vae_v5` (VAE) | same 3 datasets, on top of `lstm_ae_v8` | clean normal train windows, described by the LSTM-AE's outputs | same | same |
| `lstm_ae_gotham_v1` + `vae_gotham_v1` | Gotham alone | clean normal train windows | val | test split + benchmark |
| `lstm_ae_xiiotid_v1` + `vae_xiiotid_v1` | X-IIoTID alone | clean normal train windows | val | test split + benchmark |
| `lstm_ae_nftoniot_v1` + `vae_nftoniot_v1` | NF-ToN-IoT-v3 alone | clean normal train windows | val | test split + benchmark |
| `lstm_ae_aci_kaggle_v1/_v2` + `vae_…` | ACI-IoT-2023 alone (on Kaggle) | clean normal train windows | val | test split + benchmark |
| `lstm_ae_iot23x_kaggle_v2` + `vae_…` | IoT-23 extra captures (on Kaggle) | its few clean normal windows | val | only as GAT inputs |
| **`gat_v5` (GAT)** | Gotham, IoT-23, IoT-23 extra, X-IIoTID, ACI-IoT-2023 | **labelled** graphs: each dataset's own train-split graphs + train-phase benchmark scenarios (attacks injected into normal traffic) | val-split graphs + val-phase scenarios | test-phase benchmark scenarios; Kitsune and Edge-IIoTset as networks never trained on |

Why separate models per network: training one LSTM-AE + VAE pair on Kitsune, Edge-IIoTset, IoT-23 *and*
X-IIoTID together cut IoT-23 detection from 83.6 % to 60.3 %, so each new network got its own pair. The GAT is
the one model that spans several networks; it reads each network through that network's own pair.

### LSTM autoencoder (`train_lstm_ae.py`)
* **Learns normal behaviour only.** Input: a window of 32 consecutive connections of one device (50 features
  each). It compresses the window to 16 numbers and rebuilds it; the rebuild error is the anomaly score.
* **Balanced sampling:** every round, 20,000 clean normal windows per dataset, drawn equally from every
  capture, so one big capture or dataset does not define "normal" for the others.
* **Settings:** 1 LSTM layer, 64 hidden units, 16-number summary, batch 256, learning rate 0.001, up to 40
  rounds, stopped early after 5 rounds without improvement on validation (`lstm_ae_v8` stopped at 35).
* **Window score:** mean error of the window's 8 worst connections (chosen on validation scenarios).
* **Alarm line:** 99th percentile of the clean normal validation windows, per network (≈ 1 % false alarms).
  With too little validation normal traffic, train + validation is used and marked "low confidence".

### VAE (`train_vae.py`)
* **Learns normal behaviour only**, on top of the LSTM-AE. Input per window, 152 numbers: the LSTM-AE's
  16-number summary, its error and peak error, and the window's mean / spread / maximum / minimum per feature.
* **Standardisation** fitted on clean normal train windows, with every input's spread floored at 0.1 and
  values clipped to ±5, so a single rare input (e.g. one Telnet connection) cannot set off an alarm alone.
* **Settings:** layers 128 → 64 → 8-number latent, batch 512, learning rate 0.001, up to 80 rounds, early stop
  after 8 rounds without improvement; 20,000 normal windows per dataset per round.
* **Alarm line:** 99th percentile of clean normal validation scores per network.
* **Extra outputs:** confidence (how unusual compared with normal traffic), the closest known attack type
  (prototypes built from the labelled train windows, used only as a hint, never for detection) and a zero-day
  flag (anomalous and unlike every known type).

### Temporal GAT (`train_gat.py`, `gat_v5`)
* **Supervised:** learns from labels which host is an attack source or target and which links carry attack
  traffic, every 60 s.
* **Inputs per host:** 9 traffic numbers (connections, peers and bytes in / out, private / external, time since
  last seen) + 10 numbers from that network's LSTM-AE and VAE (scores divided by the network's alarm line,
  alerts, confidence, zero-day flag). **Per link:** 33 behaviour features + connection count + direction
  (17 port / service inputs removed).
* **Training data:** 120 sequences / 22,728 snapshots (12,013 attacker host-minutes); validation 70
  sequences; benchmark test 265 sequences / 59,550 snapshots; 66 control sequences.
* **Settings:** 2 attention layers, 4 heads, 64 hidden units, a memory per host carried from minute to minute;
  loss = host source/target (weighted for rare attackers) + 0.5 × link loss; learning rate 0.001, up to 20
  rounds, early stop after 4 (`gat_v5` stopped at 12, best at round 8).
* **Alarm line:** 99th percentile of uninvolved hosts' scores on validation data, per network; networks never
  trained on get the pooled line.
* **Earlier GATs** kept for comparison: `gat_v2` (Kitsune, Edge-IIoTset, IoT-23; also the 4 unseen-attack-type
  tests), `gat_v3` (with NF-ToN-IoT, which failed), `gat_v4` (with the port / service inputs).

## 5. How results were measured

* **Realistic benchmark** (`aegex_bench.py`, `benchmark.py`): up to 300 real attack connections from a test
  split are hidden in the real normal traffic of a busy device (the attacker takes that device's address), at
  normal speed and 10× / 100× slower; test data only; alarm lines from validation data. This is the only
  source of quoted numbers.
* **Controls:** normal traffic inserted exactly like an attack, to measure how much the insertion itself
  triggers (noise floor).
* **One-line rule:** the single best statistic, chosen on validation data. The LSTM / VAE / GAT only count for
  what they add above it.
* **Calibration:** `--recalibrate --per-device` resets the alarm lines on each network's own validation-period
  normal traffic, with one line per device that has ≥ 50 windows.

## 6. Commands to reproduce

```powershell
# originals in one folder (AEGEX_DATA); outputs (preprocessed\, models\, model_results\) in AEGEX_OUT
cd scripts\preprocessing
python -I step1_flows.py --datasets kitsune edge iot23        # or xiiotid / gotham / aci / nf_toniot / iot23x
python -I step2_features.py --datasets kitsune edge iot23
python -I step3_sequences_graphs.py --datasets kitsune edge iot23 --window 32 --stride 16 --snapshot 60
cd ..\models
python -I train_lstm_ae.py --datasets kitsune edge iot23 --run lstm_ae_v8
python -I train_vae.py --lstm-run lstm_ae_v8 --run vae_v5
python -I benchmark.py --lstm-run lstm_ae_v8 --vae-run vae_v5
# separate networks: same steps with --datasets <name> and run names lstm_ae_<name>_v1 / vae_<name>_v1,
# benchmark with --recalibrate --per-device
python -I train_gat.py --run gat_v5 --datasets gotham iot23 iot23x xiiotid aci --test-datasets kitsune edge `
    --chain gotham=lstm_ae_gotham_v1:vae_gotham_v1 xiiotid=lstm_ae_xiiotid_v1:vae_xiiotid_v1 `
            aci=lstm_ae_aci_kaggle_v2:vae_aci_kaggle_v2 iot23x=lstm_ae_iot23x_kaggle_v2:vae_iot23x_kaggle_v2 `
    --node-blocks traffic stage --relative-scores --drop-edge-features svc_
```

ACI-IoT-2023, the extra IoT-23 captures and `gat_v4` / `gat_v5` were run on Kaggle with
`scripts\kaggle\run_gat_on_kaggle.py` (see `HOW_TO_USE.md`).
