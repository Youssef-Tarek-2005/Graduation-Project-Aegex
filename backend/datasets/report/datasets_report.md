# Dataset analysis (Step 1)

Generated 2026-11-27 13:42 UTC from `C:\aegex_data`. Catalogue: `backend/datasets/sources.json` (AI team, 2026-11-26).

**Measured** = counted by `python -m datasets.analyze` from the files on this PC. **Reported** = taken from the AI team's documents, not re-counted here.

## 1. The datasets (catalogue)

| Dataset | Source | Download (used files) | Labels | Used by models | Files here |
|---|---|---|---|---|---|
| Edge-IIoTset | kaggle `mohamedamineferrag/edgeiiotset-cyber-security-dataset-of-iot-iiot` | 1.75 GB | file-level (official): every flow in an attack pcap is that attack | lstm_ae_v8, vae_v5, gat_v2 (train), gat_v5 (test only, never trained on) | 0 / 1 |
| Kitsune Network Attack Dataset | kaggle `ymirsky/network-attack-dataset-kitsune` | 0.53 GB | official per-packet labels; a flow is an attack if any of its packets is | lstm_ae_v8, vae_v5, gat_v2 (train), gat_v5 (test only) | 2 / 6 |
| IoT-23 (Stratosphere Lab, Zeek conn.log parquet release) | kaggle `dhoogla/iot23-dataset` | 0.42 GB | official Zeek label|detailed-label | lstm_ae_v8, vae_v5, gat_v2 (train), gat_v5 (train) | 0 / 12 |
| IoT-23 extra malware captures (same release as iot23) | kaggle `dhoogla/iot23-dataset` | 9.11 GB | official Zeek labels, family-aware mapping (family per capture in iot23x.FAMILY) | lstm_ae_iot23x_kaggle_v2 + vae_iot23x_kaggle_v2 (GAT inputs only), gat_v4, gat_v5 (train) | 0 / 34 |
| X-IIoTID (cleaned parquet release) | kaggle `dhoogla/x-iiotid` | 81.5 MB | official class2 kill-chain stage | lstm_ae_xiiotid_v1, vae_xiiotid_v1, gat_v3, gat_v4, gat_v5 (train) | 0 / 1 |
| Gotham Dataset 2025 (Belarbi et al., Cardiff / Toshiba) | zenodo `https://doi.org/10.5281/zenodo.14502760` | 23.82 GB | official labeller IP rules (github.com/othmbela/gotham-network-packet-labeller metadata), exact-IP matching; Unknown -> benign | lstm_ae_gotham_v1, vae_gotham_v1, gat_v3, gat_v4, gat_v5 (train) | 0 / 1 |
| ACI-IoT-2023 (Army Cyber Institute) | kaggle `emilynack/aci-iot-network-traffic-dataset-2023` | 0.63 GB | official Label column | lstm_ae_aci_kaggle_v1/_v2, vae_aci_kaggle_v1/_v2, gat_v4, gat_v5 (train) | 0 / 1 |
| NF-ToN-IoT-v3 (NetFlow v3, UQ) | kaggle `athena21/netflow-v3-datasets` | 5.30 GB | official Attack column | lstm_ae_nftoniot_v1, vae_nftoniot_v1, gat_v3 (train; failed, dropped from later GATs) | 0 / 1 |

## 2. Measured

Connections = two-way flows made by the AI team's adapter (the unit the models use). Hosts = every IP address seen, including addresses that were only probed by a scan.

| Dataset | Capture | Connections | Attack connections | Classes | Hosts (LAN) | Attack sources | Time span (UTC) | Rows with a label note |
|---|---|---|---|---|---|---|---|---|
| Kitsune Network Attack Dataset | mirai | 50,032 | 13,104 (26.2%) | benign 36,928, mirai 13,104 | 311 (257) | 2 | 2018-10-25 05:46:22 → 2018-10-25 07:45:19 (1.98 h) | 50,032 |

Protocols and data quality per capture:

- **Kitsune Network Attack Dataset / mirai**: protocols udp 22,364, tcp 21,128, arp 6,112, icmp 426, other 2; 758,609 packets, 29.4 MB; missing values: none; attack sources: 192.168.2.107, 192.168.2.110.
  - label note: behaviour relabel: kitsune_mirai_relabeled (R1 ARP sweep / R2 Telnet / R3 new behaviour)

## 3. Still to download

- **Edge-IIoTset** (1 file(s), 1.75 GB): https://www.kaggle.com/datasets/mohamedamineferrag/edgeiiotset-cyber-security-dataset-of-iot-iiot
  - `kaggle datasets download -d mohamedamineferrag/edgeiiotset-cyber-security-dataset-of-iot-iiot -f "edge-IIotset.zip" -p C:\aegex_data`
- **Kitsune Network Attack Dataset** (4 file(s), 0.52 GB): https://www.kaggle.com/datasets/ymirsky/network-attack-dataset-kitsune
  - `kaggle datasets download -d ymirsky/network-attack-dataset-kitsune -f "SSDP_Flood_pcap.pcap.zip" -p C:\aegex_data`
  - `kaggle datasets download -d ymirsky/network-attack-dataset-kitsune -f "SSDP_Flood_labels.csv.zip" -p C:\aegex_data`
  - `kaggle datasets download -d ymirsky/network-attack-dataset-kitsune -f "OS_Scan_pcap.pcapng.zip" -p C:\aegex_data`
  - `kaggle datasets download -d ymirsky/network-attack-dataset-kitsune -f "OS_Scan_labels.csv.zip" -p C:\aegex_data`
- **IoT-23 (Stratosphere Lab, Zeek conn.log parquet release)** (12 file(s), 0.42 GB): https://www.kaggle.com/datasets/dhoogla/iot23-dataset
- **IoT-23 extra malware captures (same release as iot23)** (34 file(s), -): https://www.kaggle.com/datasets/dhoogla/iot23-dataset
- **X-IIoTID (cleaned parquet release)** (1 file(s), 81.5 MB): https://www.kaggle.com/datasets/dhoogla/x-iiotid
  - `kaggle datasets download -d dhoogla/x-iiotid -f "archive.zip" -p C:\aegex_data`
- **Gotham Dataset 2025 (Belarbi et al., Cardiff / Toshiba)** (1 file(s), 23.82 GB): https://doi.org/10.5281/zenodo.14502760
- **ACI-IoT-2023 (Army Cyber Institute)** (1 file(s), 0.63 GB): https://www.kaggle.com/datasets/emilynack/aci-iot-network-traffic-dataset-2023
  - `kaggle datasets download -d emilynack/aci-iot-network-traffic-dataset-2023 -f "ACI-IoT-2023.csv" -p C:\aegex_data`
- **NF-ToN-IoT-v3 (NetFlow v3, UQ)** (1 file(s), 5.30 GB): https://www.kaggle.com/datasets/athena21/netflow-v3-datasets
  - `kaggle datasets download -d athena21/netflow-v3-datasets -f "NF-ToN-IoT-v3.csv" -p C:\aegex_data`

## 4. Rejected by the AI team (reported)

- CICIoT2023 / CIC IoT-DIAD 2024 CSVs: no IP addresses or timestamps (shuffled window features)
- CIC IoMT 2024: no IP addresses or timestamps
- MU-IoT (Kaggle ubobyclinton/mu-iot): Kaggle copy is normalised features with encoded labels, no IPs or timestamps
- MedBIoT (Kaggle shaily20/medbiot-legit-and-malware): per-device statistical features, no IPs; Kaggle usability 0.24
- TII-SSRC-23 (Kaggle daniaherzalla/tii-ssrc-23): only 1,301 benign flows, 5-6 nodes
