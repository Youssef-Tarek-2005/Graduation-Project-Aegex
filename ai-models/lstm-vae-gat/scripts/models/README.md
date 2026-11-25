# Aegex models

Stage 1 **LSTM autoencoder** (LSTM-AE) and stage 2 **VAE** of the detection chain. The Temporal GAT and
attack-analysis stages plug into the same building blocks (`aegex_models.py`).

```
preprocessing/ --> features + windows + graph snapshots
                        |
                        v
                  LSTM-AE (stage 1) --> window: lstm_score, z_*, worst features
                        |
                        v
                  VAE (stage 2)     --> window: vae_score, vae_confidence, closest known class,
                        |                       zero_day_candidate, mu_*
                        v
     node-snapshot tables (per device per 60 s) --> join onto GAT graph nodes (snapshot, node)
                        |
                        v
                  GAT / attack analysis / RAG report (next)
```

## Files

| File | Purpose |
|---|---|
| `aegex_models.py` | models (LSTM-AE, VAE), model registry + bundle (save/load + compatibility checks), window scoring, VAE inputs / prototypes / confidence, output contracts, real-traffic preprocessing |
| `train_lstm_ae.py` | stage 1: train on clean benign windows, threshold, evaluate, export outputs |
| `train_vae.py` | stage 2: train on top of an LSTM run, threshold + confidence reference, class prototypes, zero-day test, export outputs |
| `score_traffic.py` | score a real capture (honeypot pcap) with LSTM-AE (+ `--vae`) and write alerts + GAT inputs |
| `requirements.txt` | `torch` (plus the preprocessing requirements) |

## Setup (once)

Uses the same environment as the preprocessing:

```powershell
cd "<project folder>\scripts\preprocessing"
.venv\Scripts\python.exe -m pip install -r ..\models\requirements.txt
```

This installs the CPU build (works everywhere, enough for these datasets). For the RTX 4060 GPU instead:
`.venv\Scripts\python.exe -m pip install torch --index-url https://download.pytorch.org/whl/cu126`

## Train + evaluate

```powershell
cd "<project folder>\scripts\models"
..\preprocessing\.venv\Scripts\python.exe train_lstm_ae.py --run lstm_ae_v7
```

* trains on **benign** train windows only (Kitsune, Edge-IIoTset, IoT-23 — the plug-ins with `ACTIVE = True`
  in `scripts\aegex_datasets\`),
  equal share per dataset each epoch, early stopping on benign validation windows
* alarm threshold = 99th percentile of **validation** benign errors (≈1 % false alarms by design;
  the test split is never used to choose it)
* evaluates on the test split: ROC-AUC, PR-AUC, detection rate per attack class, false-alarm rate

Outputs

| Path | Content |
|---|---|
| `models\lstm_ae\<run>\` | `model.pt` + `bundle.json` (the deployable model) |
| `model_results\lstm_ae\<run>\evaluation.txt`, `metrics.json` | test results |
| `preprocessed\model_outputs\lstm_ae\<run>\<dataset>_windows.parquet` | every window scored + latent z (VAE input) |
| `preprocessed\model_outputs\lstm_ae\<run>\<dataset>_node_snapshots.parquet` | LSTM outputs per device per 60 s snapshot (GAT node features) |

## Stage 2: VAE

```powershell
..\preprocessing\.venv\Scripts\python.exe train_vae.py --lstm-run lstm_ae_v7 --run vae_v3
```

* **Input per window (84 values by default):** the LSTM-AE latent `z_*`, `log(lstm_error)` and window
  statistics of the flows (`mean_<feature>` for all features, `std_<feature>` for continuous ones).
  Choose blocks with `--inputs lstm_latent lstm_error window_stats`.
* **Trained on clean benign windows** (not on compromised devices), an equal share per capture.
* **Threshold** = capture-balanced 99th percentile of validation clean-benign scores.
* **`vae_confidence`** = share of normal validation windows that are less unusual (0.99 = more unusual
  than 99 % of normal traffic): the calibrated confidence the attack-analysis stage needs.
* **Known-class prototypes:** a Gaussian per class (benign, scanning, ddos, mirai, ransomware) in the
  latent space. `vae_class_hint` = closest one; `zero_day_candidate` = anomalous AND outside every known
  class. `--unknown-class mirai` hides a class to simulate a zero-day.
* The VAE bundle records the exact LSTM-AE it was trained on (SHA-256 of its weights); scoring with a
  different LSTM-AE is refused.

### Current models and results (2026-11-20)

Current pair: **`lstm_ae_v7` + `vae_v3`**. Training is balanced per capture (each capture is a different
network / device set); thresholds are window-weighted 99th percentiles of validation clean benign
(`--threshold-weighting capture` exists but let a few tiny captures dominate the LSTM threshold).

| Test split | Kitsune | Edge-IIoTset | IoT-23 |
|---|---|---|---|
| LSTM ROC-AUC / detection / false alarms | 0.9999 / 100 % / 1.7 % | 0.998 / 100 % / 1.2 % | 0.9999 / 89 % / 0 % (25 benign) |
| **VAE** ROC-AUC / detection / false alarms | **1.000 / 100 % / 1.3 %** | **1.000 / 100 % / 1.5 %** | 0.948 / 100 % / 100 % (25 benign) |
| VAE confidence >= 0.99 on clean benign (ideal 1 %) | 1.3 % | 1.5 % | - |
| closest-known-class correct | scanning 99.8 %, ddos 0 %, mirai 0 % | ddos 99.9 %, scanning 96 %, ransomware 100 % | ddos 99 %, mirai 47 % |

Per-network calibration (threshold from that network's own earliest normal traffic), Kitsune Mirai network:
LSTM 43 % -> 0 % false alarms but detection 100 % -> 50 %; **VAE 17 % -> 0.4 % false alarms with 100 %
detection** - after calibration the VAE is the stage that keeps detection.

Zero-day simulation (class hidden from the known-class prototypes; share of its windows flagged as zero-day
candidates): hidden DDoS -> Kitsune 100 %, Edge 86 %, IoT-23 18 %; hidden Mirai -> Kitsune 79 %, IoT-23 0.06 %.
The flag means "unlike every KNOWN class": attacks resembling a known one (Mirai propagation ~ scanning,
IoT-23 floods from the same bot ~ its Mirai) are still flagged anomalous (100 %) but not as zero-day.

Limits: IoT-23 has 25 clean benign test windows (false-alarm figures meaningless); class hints transfer
poorly across datasets (Kitsune's SSDP flood is unlike the Edge/IoT-23 floods that shape the DDoS prototype);
Edge-IIoTset remains an easy dataset (see tuning history).

## Changing datasets or features later

| Change | Where | Then |
|---|---|---|
| drop IoT-23 / add a dataset | `ACTIVE` in its plug-in `scripts\aegex_datasets\<name>.py` (a new dataset = a new plug-in, copy `_template.py`) | rerun preprocessing (`run_all.ps1`), `train_lstm_ae.py`, `train_vae.py` |
| remove device-context features | `USE_DEVICE_CONTEXT = False` in `aegex_prep.py` | same |

Nothing in the model code names a dataset or a feature: input sizes, feature names, VAE input names and
class prototypes are all derived at training time and stored in the bundles. Old bundles refuse to load
after such a change (pipeline fingerprint), so stale models cannot be used by mistake.

## Score real traffic (honeypot)

```powershell
..\preprocessing\.venv\Scripts\python.exe score_traffic.py capture.pcap --model ..\..\models\lstm_ae\lstm_ae_v7 --vae ..\..\models\vae\vae_v3 --calibrate normal_day.pcap --recalibrate-threshold
```

* `--calibrate` fits the feature scaler (and with `--recalibrate-threshold` the alarm threshold) on a
  capture of **your network's normal traffic**. This mirrors how every training dataset was scaled on
  its own benign traffic, so a new network is put on the same footing.
  Without your own normal capture, use `--reference-scaler edge|kitsune|iot23`.
* writes to `live_results\<capture>\`: `alerts.csv` (device, time, score, worst features),
  `lstm_windows.parquet`, `lstm_node_snapshots.parquet`, `graph_edges/nodes.parquet` (GAT input with
  LSTM scores already attached to the nodes), `flows.parquet`, `run.json`.

## Why this stays compatible with real traffic, the VAE and the GAT

1. **One preprocessing code path.** Real captures use the same `FlowBuilder`, features, scaler and
   window/graph builders as the datasets (tested: the Kitsune Mirai pcap scored as unlabeled "live"
   traffic gives bit-identical features — max difference 0 over 50,032 flows).
2. **Self-describing model bundle.** `bundle.json` stores the feature order, window size, stride,
   snapshot length, flow timeouts, service-port map, scalers, threshold and a fingerprint of the
   preprocessing settings. Loading refuses a model whose inputs would be built differently
   (prevents silent garbage scores after a code change).
3. **Scale-free scores.** `lstm_score = error / threshold` (≥ 1 = anomaly) means the same thing on
   every dataset and on live traffic, so later stages can combine it without re-tuning.
4. **Fixed output contract** (documented at the top of `aegex_models.py`):
   * windows: `capture, device, row_start, row_end, n_flows, t_start, t_end, lstm_error, lstm_score,
     lstm_anomaly, lstm_top_features, z_0..z_15`
   * node snapshots: `capture, snapshot, node, lstm_max_score, lstm_mean_score, lstm_n_windows,
     lstm_any_anomaly, z_0..z_15` — `snapshot`/`node` match the GAT graph tables exactly; a window
     belongs to the snapshot in which it ends (what a live system can know at that moment).
   * VAE: consumes `z_*` (+ `lstm_score`) per window; GAT: node features + `lstm_*` columns.
5. **Explainable alerts.** `lstm_top_features` names the 3 worst-reconstructed features per window,
   which the attack-analysis / RAG-LLM stage can cite in the Blue Team report.
6. **No dataset identity in the model.** IPs, ports, timestamps and dataset names are never inputs.

## Tuning history and what the scores really mean (2026-11-20)

Held-out test = `--holdout edge/normal_water_level edge/normal_sound_sensor kitsune/ssdp_flood`
(those captures are removed from training entirely and scored as unseen traffic).

| | v1 hard clip | v2 + scale floor 0.1 | v3 + soft tails | v4 + device context (50 features) | **v5 + clean-benign rule (current)** |
|---|---|---|---|---|---|
| Kitsune ROC-AUC / false alarms | 0.966 / 1.8 % | 0.995 / 1.9 % | 0.9996 / 1.7 % | 1.000 / 1.7 % | **0.9999 / 1.7 %** |
| Kitsune SSDP flood detected | 3 % | 100 % | 100 % | 100 % | 100 % |
| Edge ROC-AUC / false alarms | 0.995 / 1.2 % | 0.994 / 0.9 % | 0.995 / 1.0 % | 0.9995 / 1.1 % | **0.9975 / 1.2 %** |
| Edge DDoS detected when 2 sensors held out | **38 %** (fragile) | 100 % | 100 % | 100 % | 100 % |
| Unseen Edge sensors: false alarms | 0.1 % | 0.04 % | 0.07 % | 0.07 % | 0.07 % |
| Unseen Kitsune network: detection / false alarms | 0.5 % / 3 % | 5 % / 6 % | 100 % / 21 % | 100 % / 41 % | **100 % / 6.2 %** |
| ... same, threshold calibrated on that network's normal traffic | | | 99.9 % / 0.5 % | 99.8 % / 0.7 % | **99.9 % / 0.1 %** |
| IoT-23 ROC-AUC | 0.001 | 0.04 | 0.03 (unstable) | 0.21 | **0.9998** (25 clean benign windows) |
| IoT-23 DDoS / Mirai detected (global threshold) | 0.6 % / 0 % | 10 % / 0 % | 0.6 % / 0 % | 95 % / 0.1 % | **100 % / 37 %** |

Findings
* v1's "perfect" scores were a **scaling artefact**: near-constant benign features (IQR 0.001) blew any
  deviation up to the clip, and attacks sat on a knife-edge (Edge DDoS 100 % -> 38 % from a small data change).
  The scale floor (`MIN_SCALE`) and soft tails (`TAIL_START`) in `aegex_prep.RobustScaler` fix that.
* Edge-IIoTset's remaining 100 % is a **dataset property**: its normal traffic is MQTT sensor heartbeats and
  its attacks were captured in separate files without normal background, so floods/scans are trivially
  different (its normal Modbus capture is as extreme as the attacks). It does not prove generalisation.
* A model **over-flags a network it has never seen** (21 % false alarms) until it is calibrated on that
  network's own normal traffic (0.5 %). For the honeypot: always run `score_traffic.py --calibrate`.
* **Device-context features** (v4: flows per 10 s, new peers / new ports per 60 s, reply share, new-peer
  flag) give the model what single flows cannot show: floods, fan-out scanning, unanswered probing.
  IoT-23 DDoS detection 0.6 % -> 95 %.
* **Clean-benign rule** (v5): 89.7 % of IoT-23's "benign" flows come from the infected bots themselves
  (median ~2,900 new peers/min, identical to the scans), so they taught the model that scanning is normal.
  Flows of a device that originates attacks are marked `device_compromised` and excluded from scaler
  fitting and autoencoder training. IoT-23 ROC-AUC 0.21 -> 0.9998; unseen-network false alarms 41 % -> 6 %.
* IoT-23's remaining gap is the **threshold, not the ranking**: 99.9 % of Mirai windows score above every
  clean benign window, but the global threshold sits at the Mirai median (37 % detected) and IoT-23 has
  only ~100 clean benign windows (honeypots) to set its own. Again: calibrate on the deployment's normal traffic.
* Small classes: Edge ransomware = 7 test windows, Edge scanning = 117; "100 %" on them has wide uncertainty.

## Notes

* NF-ToN-IoT-v3 is off in the default run (`ACTIVE = False` in `scripts\aegex_datasets\nf_toniot.py`).
  It has its own model pair (`*_nftoniot_v1`), so ransomware is covered by Edge-IIoTset and NF-ToN-IoT.
* Kitsune Mirai rule (time windows + class weights) applies to the supervised stages; the LSTM-AE is
  trained on benign windows only, so class weights do not apply to it.
