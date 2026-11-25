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
