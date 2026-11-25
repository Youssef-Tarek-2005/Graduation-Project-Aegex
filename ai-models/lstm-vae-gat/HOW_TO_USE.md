# Aegex – how to use the LSTM-AE and the VAE

This guide covers the two detection stages:
1. **LSTM autoencoder** (`lstm_ae_v8`): learns normal per-device traffic and flags windows it cannot rebuild.
2. **VAE** (`vae_v5`): reads the LSTM's output and adds a calibrated confidence, the closest known attack
   class and a zero-day flag.

You can use them in two ways:
- **A. Score a capture** (a pcap from the honeypot or any network). This is the normal way to use them.
- **B. Retrain** them on the preprocessed datasets.

All paths are relative to this folder (`ai-models\lstm-vae-gat\`, called "the project folder" below).

---

## Just the results? → `results_summary\`

The project folder has small summary tables with the final numbers (no per-window or per-flow rows). They open
in Excel. Rows marked `quoted = yes` are the numbers on the results page; `README.txt` explains every column.

| File | What it holds |
|---|---|
| `headline_results.csv` | **start here:** one row per dataset, LSTM-AE, VAE, LSTM-or-VAE and the one-line rule side by side |
| `benchmark_summary.csv` | all benchmark runs: detection, false alarms and noise floor per dataset and model |
| `benchmark_by_attack.csv` | detection per attack type and speed |
| `benchmark_false_alarms_by_capture.csv` | false alarms per normal recording |
| `gat_summary.csv` | GAT vs window alerts per dataset (incl. attacker ranked first) |
| `gat_by_attack.csv` | GAT per attack type; `seen_in_training = no` = attack type it never saw |
| `gat_controls.csv` | GAT on injected normal traffic (shortcut check) |
| `test_split_summary.csv` | datasets' own test splits per class (optimistic, not quoted) |

Refresh them after any new training or benchmark run:

```powershell
& $py -I export_results_summary.py
```

---

## Running somewhere else (e.g. a Kaggle notebook)

Two settings tell every script where things are. Without them, everything stays in the project folder.

| Setting | Meaning | Default |
|---|---|---|
| `AEGEX_DATA` | folder with the original datasets (only read, may have sub-folders) | project folder |
| `AEGEX_OUT` | folder where everything is written: `preprocessed\`, `models\`, `model_results\`, `live_results\`, `results_summary\` | project folder |

Kaggle unpacks uploaded archives, so the scripts also find an original as an unpacked file. For example,
`edge-IIotset.zip` becomes `…/Edge-IIoTset dataset/Attack traffic/Ransomware attack.pcap`, and
`Mirai_pcap.pcap.zip` becomes `…/Mirai_pcap.pcap`. Outside your own verified copy the checksum file is not
there, so step 1 needs `--skip-checksums`.

Kaggle notebook recipe:
1. Upload `scripts\` (and `kitsune_mirai_relabeled\` if you use Kitsune) as a private Kaggle dataset.
2. In a notebook, add it and the candidate dataset as inputs, and turn on the GPU.
3. Run:

```python
import os, subprocess
os.environ["AEGEX_DATA"] = "/kaggle/input"
os.environ["AEGEX_OUT"] = "/kaggle/working"
code = "/kaggle/input/<your-code-dataset>/scripts"
run = lambda *a: subprocess.run(["python", *a], check=True)
run(f"{code}/preprocessing/step1_flows.py", "--datasets", "xiiotid", "--skip-checksums")
run(f"{code}/preprocessing/step2_features.py", "--datasets", "xiiotid")
run(f"{code}/preprocessing/step3_sequences_graphs.py", "--datasets", "xiiotid")
run(f"{code}/models/train_lstm_ae.py", "--datasets", "xiiotid", "--run", "lstm_try")
run(f"{code}/models/train_vae.py", "--lstm-run", "lstm_try", "--run", "vae_try")
run(f"{code}/models/benchmark.py", "--lstm-run", "lstm_try", "--vae-run", "vae_try", "--datasets", "xiiotid")
print(open("/kaggle/working/model_results/benchmark/lstm_try__vae_try/report.txt").read())
```

A brand-new dataset needs its plug-in file in `scripts\aegex_datasets\` first (see "Adding or removing a dataset"
below).

**From the command line** (Kaggle CLI, signed in with your own Kaggle token; never commit the token):
put `scripts\` into a folder with a `dataset-metadata.json` and the notebook into one with a
`kernel-metadata.json`, then:

```powershell
kaggle datasets version -p <code-folder> -m "update" --dir-mode zip
kaggle kernels push -p <notebook-folder>
kaggle kernels status <your-kaggle-user>/<notebook>
kaggle kernels output <your-kaggle-user>/<notebook> -p kaggle_results\<run>
```

The ACI-IoT-2023 models (`*_aci_kaggle_v1`) were trained this way.

---

## 0. Setup (once)

Use the project's Python environment and run the model scripts from `scripts\models`:

```powershell
cd "<project folder>\scripts\models"
$py = "..\preprocessing\.venv\Scripts\python.exe"
```

The commands below use `& $py -I <script>`.

| What | Where |
|---|---|
| Trained LSTM-AE | `models\lstm_ae\lstm_ae_v8\` (`model.pt` + `bundle.json` with scalers, thresholds, settings) |
| Trained VAE | `models\vae\vae_v5\` (it only works with the LSTM run it was trained on: `lstm_ae_v8`) |
| GPU | used automatically if available (`--device cpu` forces the CPU) |

---

## A. Score a capture (LSTM → VAE)

```powershell
& $py -I score_traffic.py "C:\path\capture.pcap" `
    --model ..\..\models\lstm_ae\lstm_ae_v8 `
    --vae   ..\..\models\vae\vae_v5 `
    --calibrate "C:\path\normal_traffic_of_same_network.pcap" --recalibrate-threshold --per-device
```

**You must pick one scaling option:**
- `--calibrate normal.pcap` (**recommended for a new network**, such as the honeypot). It fits the scaler on
  a capture of that network's normal traffic. `--recalibrate-threshold` also sets the alarm thresholds from
  it (99th percentile of the normal windows), so about 1% of normal windows will alarm.
  `--per-device` (needs both options above) also gives every device with at least 50 windows in the
  calibration capture its own threshold, never lower than the network's. Devices that are noisy by nature
  (lots of discovery or multicast traffic, many peers) stop flooding the alert list. On X-IIoTID this cut VAE
  false alarms from 2.6% to 1.1% with the same detection. The thresholds used are saved in `run.json`.
- `--reference-scaler edge` (or `kitsune` / `iot23`) reuses the scaler of a training dataset stored in the
  bundle. Only use this when the traffic comes from that dataset's network.

**Other options:**
- `--member "path\inside.zip"` reads a pcap that sits inside a zip.
- `--calibrate-member` does the same for the calibration capture.
- `--name myrun` sets the output folder name (default: the file name).
- `--out <folder>` changes where results go.

Example on data already in the project (Kitsune Mirai capture, Kitsune scaler):

```powershell
& $py -I score_traffic.py ..\..\Mirai_pcap.pcap.zip --model ..\..\models\lstm_ae\lstm_ae_v8 `
    --vae ..\..\models\vae\vae_v5 --reference-scaler kitsune --name kitsune_mirai_test
```

### Where the output goes: `live_results\<name>\`

Every table is written twice: as `.parquet` (fast, for code) and as `.csv` (opens in Excel).

| File | One row per | What it is for |
|---|---|---|
| `alerts.csv` | flagged window | **Start here.** Device, start/end time (UTC), LSTM score, the features that looked most wrong, VAE score, confidence, closest known class, zero-day flag |
| `windows.(parquet/csv)` | window of 32 flows of one device (window starts every 16 flows) | Full LSTM + VAE output for every window, flagged or not |
| `lstm_node_snapshots.*` / `vae_node_snapshots.*` | device per 60-second snapshot | Stage outputs summarised per device and minute (what the GAT consumes) |
| `graph_nodes.*` / `graph_edges.*` | device / device pair per 60 s | The communication graph, with both stages' outputs already joined onto the nodes |
| `flows.*` | flow | The traffic converted to flows (same layout as the training data) |
| `run.json` | — | What was used: bundles, scaler source, thresholds (and per-device thresholds), counts of flows/devices/alerts |

---

## B. Retrain on the preprocessed datasets

Preprocessing must have been run first (`scripts\preprocessing\run_all.ps1`, or steps 1–3).

```powershell
& $py -I train_lstm_ae.py --run lstm_ae_v9                         # defaults: active datasets, top-k:8 scoring, 1 % false alarms
& $py -I train_vae.py     --lstm-run lstm_ae_v9 --run vae_v6       # VAE must name the LSTM run it builds on
```

**Useful options:**

| Option | Script | Meaning |
|---|---|---|
| `--datasets edge kitsune xiiotid` | both | which preprocessed datasets to use (default: the plug-ins with `ACTIVE = True` in `scripts\aegex_datasets\`) |
| `--fpr 0.01` | both | target false-alarm rate on validation normal traffic (sets the threshold) |
| `--threshold-mode per_dataset\|global` | both | one threshold per dataset (default) or one shared threshold |
| `--holdout edge/ddos_udp` | both | leave a capture out of training (unseen-network test) |
| `--unknown-class mirai` | VAE | hide a class from the VAE's known prototypes (zero-day test) |
| `--epochs`, `--hidden`, `--latent`, `--lr`, `--batch` | both | model size and training settings |

**Training writes three places:**

| Folder | Contents |
|---|---|
| `models\lstm_ae\<run>\`, `models\vae\<run>\` | the trained bundle (needed for scoring) |
| `model_results\lstm_ae\<run>\`, `model_results\vae\<run>\` | `evaluation.txt` (readable test-set report per dataset and class) and `metrics.json` |
| `preprocessed\model_outputs\lstm_ae\<run>\`, `preprocessed\model_outputs\vae\<run>\` | per dataset: `<dataset>_windows.(parquet/csv)` and `<dataset>_node_snapshots.(parquet/csv)`, covering every window of the train, val and test splits |

If an older run only has parquet files, `export_csv.py` makes the CSV copies:

```powershell
& $py -I export_csv.py --runs lstm_ae/lstm_ae_v8 vae/vae_v5
```

---

## C. What the output columns mean

### Window identity (both stages)

| Column | Meaning |
|---|---|
| `capture`, `device` | which capture and which device (its IP) the window belongs to |
| `t_start`, `t_end` | window time span (Unix seconds) |
| `n_flows`, `row_start`, `row_end` | number of flows and their row range in the flow table |
| `label`, `window_class`, `attack_frac` | ground truth (training data only): attack yes/no, main attack class, share of attack flows |
| `split` | train / val / test (training data only) |

### LSTM-AE

| Column | Meaning |
|---|---|
| `lstm_error` | reconstruction error of the window (average of the 8 worst flows) |
| `lstm_score` | `lstm_error / threshold`; **≥ 1 means anomalous** |
| `lstm_anomaly` | 1 if flagged |
| `lstm_top_features` | the features the model could least reconstruct (why it alarmed) |
| `lstm_error_peak`, `lstm_peak_row` | the single worst flow's error and its row |
| `z_0 … z_15` | the window's learned summary (latent vector), used by the VAE and GAT |

### VAE

| Column | Meaning |
|---|---|
| `vae_score` | VAE error / its threshold; **≥ 1 means anomalous** |
| `vae_anomaly` | 1 if flagged |
| `vae_confidence` | 0–1: how much more unusual the window is than normal validation traffic (≥ 0.99 matches only ~1% of normal) |
| `vae_class_hint` | closest known class: benign / ddos / scanning / mirai / ransomware |
| `vae_class_distance` | how close it is to that class |
| `vae_novelty`, `zero_day_candidate` | far from **every** known class → possible unseen (zero-day) attack |
| `mu_0 … mu_7` | the VAE's latent vector |

### Node snapshots (per device per 60 s)

| Column | Meaning |
|---|---|
| `lstm_max_score` / `vae_max_score` | worst window score of that device in that minute |
| `*_mean_score` | average window score |
| `*_n_windows` | number of windows in that minute |
| `*_any_anomaly` | 1 if any window was flagged |
| latent averages | `z_*`, `mu_*` |

---

## D. Reading the results in Python

```python
import pandas as pd
w = pd.read_parquet(r"preprocessed\model_outputs\vae\vae_v5\edge_windows.parquet")
test = w[w.split == "test"]
print(test.groupby("window_class").vae_anomaly.mean())       # detection rate per class (benign = false alarms)
alerts = pd.read_csv(r"live_results\kitsune_mirai_test\alerts.csv")
```

**Note on results:** the per-dataset `evaluation.txt` numbers are on the datasets' own test split and are
optimistic (attacks there come as large pure blocks). For the figures to quote, use the realistic benchmark
(`benchmark.py`: attacks injected into real normal traffic, plus control injections). See `AGENT_CONTEXT.md`
§5 and §7.

## E. Realistic benchmark

```powershell
& $py -I benchmark.py --lstm-run lstm_ae_xiiotid_v1 --vae-run vae_xiiotid_v1 --datasets xiiotid --recalibrate --per-device
```

| Option | Meaning |
|---|---|
| `--lstm-run`, `--vae-run` | which trained pair to test (default `lstm_ae_v8` / `vae_v5`) |
| `--datasets` | which datasets (each needs a `BENCH` case in its plug-in file, `scripts\aegex_datasets\<name>.py`) |
| `--recalibrate` | first resets the alarm thresholds to the 99th percentile of the network's clean normal traffic from the validation period (what a deployment does with `--calibrate`). Test data is never used. Without it, the thresholds saved in the models are used |
| `--per-device` | with `--recalibrate`: each device with ≥ 50 validation windows also gets its own threshold, set from its own normal traffic. It is never lower than the network threshold, so only devices that are noisy by nature get more room |
| `--slowdowns 1 10 100`, `--reps 2`, `--n-attack 300` | attack speeds, repeats per attack, attack flows per scenario |

Results: `model_results\benchmark\<lstm run>__<vae run>[__recal][_dev]\`

| File | Contents |
|---|---|
| `report.txt` | the readable report |
| `metrics.json` | the same numbers for code |
| `scenarios.csv` | one row per scenario and method |

## F. Adding or removing a dataset

Each dataset is **one plug-in** in `scripts\aegex_datasets\`: a file (`edge.py`) or a folder (`kitsune\`,
`gotham\`) when it has helper tools. The plug-in holds everything specific to that dataset: its original
files, captures, adapter (raw format → unified flows), benchmark case (`BENCH`) and the benchmark run quoted
in the results summary (`QUOTED_RUN`). Every step, model script, the benchmark and `export_results_summary.py`
find the plug-ins automatically.

```powershell
cd "..\"                                         # the scripts folder
& .\preprocessing\.venv\Scripts\python.exe -m aegex_datasets      # list installed plug-ins
```

| To… | Do |
|---|---|
| add a dataset | copy `_template.py` to `<name>.py`, fill it in, add the originals' SHA-256 to `ORIGINALS_SHA256.txt`, run steps 1–3 with `--datasets <name>` |
| remove a dataset | delete its file / folder (its preprocessed data and models stay on disk until you delete them) |
| switch it off by default | `ACTIVE = False` in its file (still usable with `--datasets <name>`) |
| quote a new benchmark run | set `QUOTED_RUN` in its file, then rerun `export_results_summary.py` |

The models never name a dataset: they train on whatever `--datasets` you give, and each saved bundle records
which datasets and preprocessing settings it was trained with.
