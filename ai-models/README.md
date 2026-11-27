# AI Models — Detection & Threat Intelligence

The machine-learning half of Aegex: models that take raw network traffic
from the honeypot and turn it into a written incident report backed by
MITRE ATT&CK and CISA sources.

```
traffic ──▶ 1. LSTM-AE → VAE → temporal GAT ──▶ 2. E-GraphSAGE ──▶ 3. type classifier ──▶ 4. RAG ──▶ report
            is it anomalous? which device?        is it an attack?    which attack?          grounded answer
```

All four run locally. No cloud API, no API key, and no honeypot data leaves
the machine.

---

## Dataset

**Edge-IIoTset** — Ferrag et al., *IEEE Access* 2022
([10.1109/ACCESS.2022.3165809](https://doi.org/10.1109/ACCESS.2022.3165809)).

| | |
|---|---|
| Flows | 2,219,201 |
| Features used | 38 (after dropping identifier, text and constant columns) |
| Attack classes | 15 (including `Normal`) |
| Class balance | `Normal` is 72.8% of the data |

The CSV is ~1.1 GB and is **not** in this repository. Download it separately
and point the scripts at it.

---

## Layer 1 — LSTM autoencoder → VAE → temporal GAT (anomaly detection)

Lives in **[`lstm-vae-gat/`](lstm-vae-gat/README.md)** and replaces the earlier
per-flow Keras autoencoder. It works on **sequences**, not single flows:
each device's traffic is cut into windows of 32 flows, and devices form a
communication graph every 60 s.

- **LSTM autoencoder**: trained on normal traffic only; rebuilds each
  device's flow sequence and flags what it cannot rebuild.
- **VAE**: scores every window again from the LSTM's summary plus window
  statistics. It adds a calibrated confidence, the closest known attack class
  and a **zero-day flag** (far from normal traffic *and* from every known attack).
- **Temporal GAT**: points at *which device* is attacking or attacked, per minute.

Data: 7 public IoT datasets, all read through one shared feature extractor
(Kitsune, Edge-IIoTset, IoT-23, X-IIoTID, Gotham 2025, ACI-IoT-2023,
NF-ToN-IoT-v3). Each dataset is one plug-in file, so it is easy to add or remove one.
The same code scores a live **pcap** from the honeypot.

**Realistic benchmark.** Real attack traffic is mixed into real normal traffic
of each network, using test data only. Control injections give a noise floor. VAE detection:
80–100 %, false alarms 0.2–10 % depending on the network. Full tables and the
noise floor: `lstm-vae-gat/results_summary/`.

→ `lstm-vae-gat/README.md`, `lstm-vae-gat/HOW_TO_USE.md`

---

## Layer 2 — E-GraphSAGE (graph context)

Lo et al., *IEEE/IFIP NOMS* 2022 ([arXiv:2103.16329](https://arxiv.org/abs/2103.16329)).

Hosts are nodes, flows are edges, and each flow is classified while seeing its
neighbours. A single connection can look ordinary; eighty connections from one
host to eighty ports in a second do not. That signal lives in the relationship
between flows, not in any one of them.

- Beats a **no-graph MLP control** — identical features, identical split — at
  every window size tested.
- **Zero-day evaluation**: three attack families (`XSS`, `SQL_injection`,
  `Backdoor`) held out of training entirely.
- Window size turned out to dominate performance, so it is swept rather than
  assumed.

→ `notebooks/04_egraphsage.ipynb`

---

## Layer 3 — Attack-type classifier

Layers 1 and 2 answer *whether* something is an attack, not *which* attack.
This classifier covers all 15 classes on the same 38 features.

| Metric | Value |
|---|---|
| Overall accuracy | 96.30% |
| **Macro recall (all 15 classes)** | **86.85%** |
| Baseline — predict `Normal` always | 72.78% |

**Report macro recall, not overall accuracy.** `Normal` is 72.8% of the data,
so overall accuracy is dominated by one class. Macro recall weights every
class equally.

**Split design.** Neighbouring flows belong to the same attack burst and are
near-duplicates. Splitting individual flows at random puts copies of one burst
on both sides and inflates the score — in a controlled test that mistake
reported **100%** accuracy for a model that had learned nothing generalisable,
against **16.3%** (chance) under a correct split. Whole blocks of 500 flows are
therefore assigned to one side, stratified so every class appears in both.

Weakest classes are `Password` (38.0%), `DDoS_HTTP` (70.7%) and `Uploading`
(70.9%) — all HTTP-based attacks that look alike at flow level, because what
separates them is request *content*, deliberately excluded from the features
to avoid leakage. This is a known limit of flow-level classification, not a
training failure.

→ `scripts/train_type_classifier.py`

---

## Layer 4 — RAG threat intelligence

Built on [`rvong65/threat-intelligence-assistant`](https://github.com/rvong65/threat-intelligence-assistant)
(MIT). Runs locally through Ollama.

| Source | Documents |
|---|---|
| MITRE ATT&CK — techniques | 697 |
| CISA KEV — exploited vulnerabilities | 1,614 |
| MITRE — software and malware | 821 |
| MITRE — threat groups | 174 |
| **Total chunks** | **3,312** |

Three guards against hallucination: every sentence must carry a citation such
as `[T1059]`, inventing an ID is forbidden, and the system **abstains** when
the evidence is too weak rather than inventing an answer.

---

## The bridge

`scripts/detect_and_report.py` runs all four layers in one command and writes
`incident_report.md`. **Note:** its layer 1 still loads the earlier per-flow
autoencoder from a local `PoC_results/` folder. Wiring it to
`lstm-vae-gat/scripts/models/score_traffic.py` (window and device alerts) is
still to do. Nothing in that report comes from the dataset's own
labels — the attack type is predicted.

```bash
python scripts/detect_and_report.py --csv <path>/DNN-EdgeIIoT-dataset.csv --top 3
python scripts/detect_and_report.py --csv <path>/DNN-EdgeIIoT-dataset.csv --top 3 --no-rag
```

Flows the two detectors **both** flag are ranked first and marked
`both layers agree`. The detectors are independent — one measures how badly a
flow reconstructs, the other looks at its neighbourhood — so their errors are
uncorrelated and agreement filters noise.

### Two constraints the script enforces

**Whole windows, spread across the file.** Edge-IIoTset is ordered, so reading
the first N rows returns normal traffic only. But E-GraphSAGE was trained on
windows of 100 *consecutive* flows, and sampling individual rows would hand it
windows that never existed. The script samples whole windows at a stride,
which satisfies both.

**Every feature column must be present.** Dropping even one of the 38 features
and zero-filling it pushed *every* flow above the threshold — 100% false
positives. A zero column is not neutral; the model never saw one in training.
The script refuses to run rather than produce meaningless output.

---

## Repository layout

```
ai-models/
├── lstm-vae-gat/                           layer 1: LSTM-AE → VAE → temporal GAT (own README)
├── notebooks/
│   ├── 03_gat_first_attempt.ipynb          GAT, superseded by E-GraphSAGE
│   └── 04_egraphsage.ipynb                 graph layer + zero-day + sweep
├── scripts/
│   ├── detect_and_report.py                all four layers, one command
│   ├── train_type_classifier.py            layer 3 training
│   └── recover_egs_scaler.py               rebuilds the E-GraphSAGE scaler
├── models/                                 trained artifacts (see below)
└── docs/                                   walkthroughs (Arabic)
```

### `models/`

Small artifacts, committed so the pipeline runs without retraining.

| File | What it is |
|---|---|
| `egraphsage.pt` | layer 2 weights |
| `egs_scaler.pkl`, `egs_features.json` | its StandardScaler and feature order |
| `type_classifier.keras` | layer 3 network |
| `type_scaler.pkl`, `type_classes.json` | its scaler and class order |

A scaler is not optional packaging. Each model only accepts input transformed
exactly the way its training data was, and the files also pin the feature
order — without them the weights cannot be applied to new data.

---

## Running it

```bash
python -m venv .venv
.venv\Scripts\activate          # Windows
pip install -r requirements.txt
```

Layer 4 additionally needs [Ollama](https://ollama.com) with two models:

```bash
ollama pull nomic-embed-text    # must match the committed FAISS index
ollama pull gemma3:4b
```

`nomic-embed-text` is not interchangeable. The prebuilt index was embedded
with it; another embedding model produces the same 768 dimensions, so nothing
errors — retrieval just quietly returns the wrong documents.

---

## Status

| | |
|---|---|
| Layers 1–4 | done |
| Bridge using the new layer 1 (LSTM-AE / VAE / GAT) | to do |
| ESP32 honeypot | implementation phase |
| Live traffic capture and feature extraction | implementation phase |
| OWASP IoT Top 10 in the knowledge base | planned |

The last row is not cosmetic. Counting the corpus: `IoT` appears in 12
documents and `MQTT` in one. The knowledge base is strong on general network
attacks and thin on IoT, which is this project's subject.

---

## Credits

The RAG layer builds on an MIT-licensed open-source project (linked above).
The contribution here is the detection stack, the attack-type classifier, the
bridge that chains all four layers, and the planned IoT knowledge sources.
