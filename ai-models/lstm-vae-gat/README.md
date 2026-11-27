# Aegex detection models — LSTM autoencoder → VAE → temporal GAT

The detection block of the Aegex architecture (replaces the earlier per-flow Keras autoencoder).
Network traffic from IoT devices is turned into per-device flow windows and communication graphs, then
checked by three stages:

```
pcap / flow records ──► unified flows ──► 50 features ──► windows (32 flows) ──► LSTM autoencoder ─┐
                                                      └─► 60 s graph snapshots ───────────────────┤
                                                                         VAE (confidence, class hint, zero-day flag)
                                                                                                  └─► temporal GAT (which device)
```

Attack types in scope: vulnerability scanning, DDoS, ransomware, Mirai (plus zero-day checks). Scope is network
traffic only.

## Folder layout (`ai-models/lstm-vae-gat/`)

| Folder | What it holds |
|---|---|
| `models/` | the trained bundles of the quoted runs (`model.pt` + `bundle.json`: scalers, thresholds, feature order) |
| `scripts/aegex_datasets/` | **one plug-in per dataset**: original files, captures, adapter, benchmark case, quoted run |
| `scripts/preprocessing/` | dataset-independent pipeline: `aegex_prep.py` (flow builder, features, scaler) + steps 1–5 |
| `scripts/models/` | LSTM-AE + VAE (`aegex_models.py`), GAT (`aegex_gat.py`), training, live scoring, realistic benchmark |
| `scripts/kaggle/` | run the pipeline in a Kaggle notebook |
| `results_summary/` | the result tables (CSV, open in Excel); `quoted = yes` rows are the reported numbers |
| `model_results/results_page/` | the results web page |
| `ORIGINALS_SHA256.txt` | checksums of the original datasets: step 1 refuses to run on altered originals |

Not in the repository (see `.gitignore`): the datasets themselves (~38 GB, each under its own licence),
`preprocessed/`, the other training runs, full `model_results/`, run logs.

## Quick start

```powershell
python -m venv .venv
.venv\Scripts\pip install -r requirements.txt
cd scripts
..\.venv\Scripts\python -m aegex_datasets            # which datasets are installed / active
```

1. Download the originals (sources are in each plug-in's `SOURCE`) into the project folder (or set `AEGEX_DATA`).
2. `scripts\preprocessing\run_all.ps1`, or steps 1–3 with `--datasets <name>`.
3. `scripts\models\train_lstm_ae.py`, then `train_vae.py`, then `benchmark.py` (see [HOW_TO_USE.md](HOW_TO_USE.md)).
4. Score your own capture: `scripts\models\score_traffic.py capture.pcap --calibrate normal.pcap --recalibrate-threshold --per-device`.

## Adding or removing a dataset

Copy `scripts/aegex_datasets/_template.py` to `<name>.py` and fill it in, or delete a plug-in. Nothing else
changes: preprocessing, training, the benchmark and the results summary read the plug-ins. Details:
[HOW_TO_USE.md §F](HOW_TO_USE.md#f-adding-or-removing-a-dataset).

| Plug-in | Dataset | Default run |
|---|---|---|
| `kitsune` | Kitsune (Mirai, SSDP flood, OS scan) | active |
| `edge` | Edge-IIoTset | active |
| `iot23` | IoT-23 | active |
| `nf_toniot` | NF-ToN-IoT-v3 | separate model |
| `gotham` | Gotham 2025 | separate model |
| `xiiotid` | X-IIoTID | separate model |
| `aci` | ACI-IoT-2023 | separate model (run on Kaggle) |
| `iot23x` | 17 extra IoT-23 malware captures | Kaggle only (GAT training) |

## Results (realistic benchmark)

Attacks are injected into real normal traffic of each network's test period. False alarms are measured on
hours of clean normal traffic. Control injections give a noise floor. Full tables: `results_summary/`.

| Dataset | VAE detection | VAE false alarms | VAE noise floor* | LSTM-AE detection |
|---|---|---|---|---|
| Kitsune | 100 % | 2.8 % | 39.2 % | 80.4 % |
| Edge-IIoTset | 99.9 % | 2.5 % | 26.8 % | 46.8 % |
| IoT-23 | 83.6 % | 10.0 % | 0 % | 48.1 % |
| X-IIoTID | 90.7 % | 1.1 % | 0 % | 4.8 % |
| ACI-IoT-2023 | 80.3 % | 1.7 % | 0 % | 1.6 % |
| Gotham 2025 | 96.5 % | 0.2 % | 0 % | 28.4 % |
| NF-ToN-IoT-v3 | 94.2 % | 3.5 % | 22.2 % | 18.4 % |

Detection is the macro average over attack scenarios. \*Noise floor = share of a control injection (the
device's own normal traffic inserted the same way) that is flagged. Where it is high (Kitsune, Edge,
NF-ToN-IoT), part of the detection comes from the insertion itself, not the attack, so those detection
numbers are upper bounds. The VAE does most of the detecting, and the LSTM-AE alone is weak on varied
networks. Thresholds use per-device calibration where it helped (X-IIoTID, ACI, Gotham); otherwise the
thresholds saved in the models are used.

## Temporal GAT — final model: `gat_v5`

`models/gat/gat_v5` finds WHICH hosts are the attacker and the target, and which links carry the attack, per
60 s graph snapshot. Inputs: per-host traffic + the LSTM-AE / VAE outputs of that network (scores divided by
their alarm line) and per-link flow features. Port / service flags are left out on purpose: alone they gave
85 % on Gotham (a shortcut, not learned behaviour). Trained on Gotham 2025, IoT-23, X-IIoTID, ACI-IoT-2023 and
the extra IoT-23 captures; Kitsune and Edge-IIoTset were kept out of training (test only).

Realistic benchmark, host level (attack source or target in a 60 s snapshot; thresholds set on validation data):

| Network | GAT detection | GAT false alarms | Best single input (one-input rule) | Controls* |
|---|---|---|---|---|
| Gotham 2025 | 99.9 % | 0.23 % | 46.0 % | 0 % |
| IoT-23 | 98.5 % | 1.43 % | 38.5 % | 0 % |
| ACI-IoT-2023 | 93.5 % | 0.20 % | 81.5 % | 0–0.4 % |
| X-IIoTID | 100 % (only 36 attacked host-minutes; own test split 1.5 %) | 0.09 % | 0 % | 0–2.3 % |
| Kitsune (never trained on) | 100 % | 42.6 % | – | high |
| Edge-IIoTset (never trained on) | 49.9 % | 39.2 % | – | high |

\*Normal traffic injected exactly like an attack; should be flagged at about the false-alarm rate.
**Limit:** the GAT works on networks it was trained on and does not transfer to unseen networks (Kitsune, Edge).
A per-network alarm line (`calibrate_gat.py`) and relative inputs (`train_gat.py --relative-inputs`, gat_v6)
were both tested and did not fix this; a new network needs its own training data. The GAT does not classify
the attack type. Full numbers: `model_results/gat/gat_v5/evaluation.txt`, `results_summary/gat_*.csv`.

### Hand-off to the back end and the LLM / RAG

`scripts/models/gat_handoff.py` runs `gat_v5` exactly as evaluated and groups its alerts into incidents (a
source host flagged in consecutive snapshots + its flagged links). It writes:

| File | Read by |
|---|---|
| `alerts.json` | `backend/` `alerts` table (`database/schema_v2.sql`, contract `alert_format`): `model_name = temporal_gat`, entity = attack source, score = P(source), `attention_edges` = flagged links. `python -m detect <pcap> --normal <pcap> --gat` saves them. |
| `detections.json` | `ai-models/threat-intel/llm-rag/report.py --detections detections.json` (same format as `examples/detections.json`) |
| `attack_analyses.json` | the `aegex/` API's `attack_analyses` table (`--postgres-url` inserts them) |
| `incidents.csv` | people |

`predicted_scenario` / `attack_type` come from a transparent behaviour rule on the flagged links (Telnet →
Mirai, many targets / new ports → scanning, high volume to few targets → DoS), not from the GAT; the files say
so. On a live capture: `score_traffic.py capture.pcap --calibrate normal.pcap --recalibrate-threshold --gat
..\..\models\gat\gat_v5` (adds `handoff/` to the output). Traffic from a network the GAT never trained on gets the
pooled threshold and a warning. `models/gat/gat_v2` is the earlier GAT (trained on Kitsune, Edge, IoT-23 with
port inputs), kept for the unseen-attack-type tests; `gat_v5` replaces it.
