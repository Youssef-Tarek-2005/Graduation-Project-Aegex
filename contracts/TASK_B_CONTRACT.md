# Task B contract: datastore schema + feature contract (draft v1.0.0)

**Status:** draft. A, C, D and E should review it before anyone implements against it.

This is the agreement between Task B (data engineering and backend) and everyone else. It covers what data comes in, how it is stored, which features the models get, and what the models send back.

| File | What it is |
|---|---|
| [`database/schema_v2.sql`](../database/schema_v2.sql) | The unified datastore (PostgreSQL 16 + TimescaleDB) |
| [`contracts/feature_contract.json`](feature_contract.json) | Machine-readable feature contract. Code reads this file; nobody hardcodes feature lists. |
| this file | Explanation for humans |

---

## 1. Big picture

```
 Task A                      Task B                                         Task C / D / E
 ──────                      ──────                                         ──────────────
 pcaps, Zeek, Cowrie,  ──►  POST /ingest/*  ──► events, flows   ──► features ──► windows/sequences ──► C (LSTM-AE, VAE)
 MQTT, ESP32 CSV                                (one database)               edges/nodes        ──► D (Temporal GAT)
 attack log            ──►  POST /attack-runs ──► attack_runs ──► labels                            │
                                                                                                     ▼
                            GET  /alerts   ◄──────────────────────────────── POST /alerts (D's inference)
                            POST /reports  ◄──────────────────────────────── E (RAG + LLM)
```

Lessons from the proof of concept that this contract enforces:
1. **One feature list, owned by one place.** In the PoC, the pipeline produced 8 features while the models expected 38, so they never ran together. Now every vector is defined in `feature_contract.json` and versioned.
2. **The scaler and feature order ship with the data.** B fits them once and C/D load them, so nobody re-fits their own.
3. **Splits use whole captures or attack runs, never random rows.** A random split reported a fake 100% in the PoC.
4. **No fake features.** The PoC filled empty windows with random "mock" values. Here an empty window inside a capture means real zero activity, and nothing is invented outside captures.
5. **No identifiers as features.** IPs, ports, timestamps and IDs are banned as model inputs (`forbidden_as_features`).

---

## 2. Datastore (`database/schema_v2.sql`)

PostgreSQL + TimescaleDB replaces the PoC's three stores (Postgres + Elasticsearch + MinIO). Raw pcaps stay as files; the `captures.pcap_path` column points to them.

| Table | One row per | Written by | Read by | Hypertable? |
|---|---|---|---|---|
| `devices` | honeypot device / gateway | B (setup) | all | no |
| `captures` | recording session (start → stop of capture) | B | B (windows, splits) | no |
| `attack_runs` | executed attack from Task A's log | A via B's API | B (labeling), evaluation | no |
| `events` | any log line / message / reading, from any source | B (parsers) | B, dashboard, E (context) | **yes**, on `ts` |
| `flows` | network connection (Zeek `conn.log`) | B | D (edges), dashboard | **yes**, on `ts_start` |
| `feature_windows` | (device, 10-second window) | B | C | **yes**, on `window_start` |
| `model_versions` | trained model version (mirror of MLflow) | D | backend, all | no |
| `alerts` | model detection | D (via `POST /alerts`) | E, dashboard | no |
| `reports` | LLM report for an alert | E (via `POST /reports`) | dashboard | no |

Design notes:
- **The `events` table is the "unified schema".** Common fields are real columns (`ts`, `source`, `event_type`, `layer`, `device_id`, `src_ip`, `dst_ip`, ports, `proto`, `label`). Anything source-specific goes in `payload` (JSONB). For example, a Cowrie command is `payload.input` and an MQTT publish is `payload.topic`.
- **Hypertables need the time column in every unique key.** That's why `events` uses `(event_id, ts)` as its key, and why `alerts` stores `flow_ids` / `event_ids` inside `evidence` instead of as foreign keys.
- **No duplicates on replay.** `events.dedup_key` (a hash of source + raw line) has a unique index. Re-ingesting the same log file is safe (`INSERT ... ON CONFLICT DO NOTHING`).
- **Labeling is one SQL call per capture:** `CALL label_capture('cap-2026-11-20-a');`. It resets that capture's labels, then applies `attack_runs`, so you can re-run it after fixing the attack log. `SELECT * FROM v_label_summary;` shows how much data you have per scenario.
- **Feedback loop (Task 13).** Analysts set `alerts.status` and `alerts.analyst_label`. D's retraining job pulls those rows as new labeled data.

### 2.1 Unified connection record: honeypot flows and public datasets (Step 2, 2026-11-27)

Every network connection uses the same `flows` columns, whichever source it came from. That way replay,
correlation and evaluation run the same code on our honeypot and on the public datasets.

| Source | Reader | Database |
|---|---|---|
| Our honeypot (Zeek `conn.log`) | `backend/ingest/flows.py` | `aegex_poc` (or `aegex` for the sample lab) |
| Public datasets (Kitsune, IoT-23, X-IIoTID, …; catalogue in `backend/datasets/sources.json`) | The AI team's adapters (`ai-models/lstm-vae-gat/scripts/aegex_datasets`), then `python -m datasets.to_unified` | `aegex_datasets`, a separate database with the same schema |

| `flows` column | Honeypot (Zeek) | Public dataset (AI team's flow table, `aegex_prep.FLOW_COLUMNS`) |
|---|---|---|
| `flow_id` | hash of start time + proto + both IP:port ends | same hash |
| `ts_start`, `ts_end`, `duration_s` | `ts`, `ts + duration`, `duration` | `ts`, `ts_end` (NULL if before `ts`), `duration` |
| `src_ip/port`, `dst_ip/port`, `proto` | `id.orig_*`, `id.resp_*`, `proto` | `src_*`, `dst_*`, `proto` (tcp, udp, icmp, arp, other) |
| `orig_bytes/pkts`, `resp_bytes/pkts` | Zeek's counts | `fwd_bytes/pkts`, `bwd_bytes/pkts` |
| `fwd_flags`, `bwd_flags` (**new**) | from `history` (upper case = originator, lower case = responder) | `fwd_flags`, `bwd_flags` |
| `label`, `scenario` | `label_capture()` + `attack_runs` | `is_attack`; `attack_class` mapped to our scenario words |
| `attack_class` (**new**) | NULL | the AI team's class: benign, scanning, ddos, mirai, ransomware, other |
| `label_info` (**new**, JSONB) | NULL | where the label came from: `original_label`, `label_note` (e.g. the Mirai behaviour relabel), `campaign`, `mal_frac` |
| `capture_id` | the recording session | `ds-<dataset>-<capture>`, e.g. `ds-kitsune-mirai`; `captures.dataset` (**new**) = catalogue id |
| `device_id` | our device on either end | NULL (dataset hosts are not our devices) |
| `service`, `conn_state`, `history`, `zeek_uid` | Zeek | NULL |

TCP flags are bits OR-ed together, the same numbers in both readers: FIN=1, SYN=2, RST=4, PSH=8, ACK=16, URG=32.
For example, a refused scan probe is `fwd_flags = 2` (SYN) and `bwd_flags = 20` (RST+ACK).

Class mapping (AI class → `scenario`): scanning → `vulnerability_scanning`, ddos → `dos`, mirai → `mirai_botnet`,
ransomware → `ransomware`, other → `other`, benign → NULL with `label = 0`.

The new columns were added with `ALTER TABLE … ADD COLUMN IF NOT EXISTS`, so older databases get them by
re-applying `schema_v2.sql` (`python -m ingest.poc_db` does this). Rows that already existed keep NULL there.
The model feature vectors (41 in this contract, 50 in the AI team's pipeline) stay model-specific and are not
part of the connection record.

---

## 3. What Task A sends: event ingestion format

`POST /api/v1/ingest/events` takes a JSON list. B's parsers (Zeek, Cowrie, Mosquitto, ESP32) produce exactly this shape, and so can any device posting directly:

```json
[
  {
    "ts": "2026-11-20T10:05:03.120Z",
    "source": "cowrie",
    "event_type": "login_failed",
    "device_id": "gw-01",
    "capture_id": "cap-2026-11-20-a",
    "src_ip": "192.168.50.66", "src_port": 51234,
    "dst_ip": "192.168.50.10", "dst_port": 2222, "proto": "tcp",
    "payload": {"username": "root", "password": "admin", "session": "a1b2c3"}
  }
]
```

- `layer` is filled in by B from `event_types` in the contract, so senders don't set it.
- Allowed `event_type` values are listed in `feature_contract.json → event_types`.

**Attack log (Task A).** `POST /api/v1/attack-runs` takes one row per attack:

```json
{"run_id": "run-017", "capture_id": "cap-2026-11-20-a", "scenario": "bruteforce", "tool": "hydra",
 "command": "hydra -l root -P rockyou.txt ssh://192.168.50.10:2222", "attacker_ip": "192.168.50.66",
 "target_device": "gw-01", "start_ts": "2026-11-20T10:05:00Z", "end_ts": "2026-11-20T10:12:30Z"}
```

Allowed scenarios: `vulnerability_scanning`, `bruteforce`, `dos`, `mirai_botnet`, `mqtt_spoofing`, `sensor_manipulation`, `unauthorized_camera_access`, `ransomware`, `other`.

**Rules for A:**
- NTP-sync every device and log everything in UTC.
- Attack from a known attacker IP (the Kali box).
- Run normal-only captures as well as attack captures.
- Write the attack log as you go, not afterwards from memory.

---

## 4. Features

### 4.1 Flow features: 41 dims, one per connection
Used as **GAT edge features** (D) and stored in `flows.features`.

| # | Feature | How |
|---|---|---|
| 1–5 | `duration_s`, `orig_bytes`, `resp_bytes`, `orig_pkts`, `resp_pkts` | from Zeek `conn.log`, missing `-` → 0, then log1p + standard scaling |
| 6–7 | `bytes_per_sec`, `pkts_per_sec` | total ÷ max(duration, 1 ms), log1p + scaling |
| 8 | `bytes_ratio_out` | orig ÷ (orig + resp + 1), already 0–1 |
| 9 | `mean_pkt_size_orig` | orig_bytes ÷ orig_pkts, log1p + scaling |
| 10–13 | `proto` one-hot | tcp, udp, icmp, other |
| 14–24 | `service` one-hot | http, ssh, telnet, mqtt, dns, rtsp, ssl, dhcp, ntp, other, none |
| 25–38 | `conn_state` one-hot | the 13 Zeek states + other |
| 39–41 | `dst_port_class` one-hot | well-known (<1024), registered, dynamic |

### 4.2 Window features: 24 dims, one per (device, 10 s)
Used by the **LSTM-AE and VAE** (C) and stored in `feature_windows`.

| Group | Features | Why it matters |
|---|---|---|
| Traffic volume | `n_conn_in`, `bytes_in_total`, `bytes_out_total`, `pkts_in_total`, `mean_conn_duration` | DoS / flood |
| Spread | `n_unique_src_ip`, `n_unique_dst_port` | scans (many ports), botnets (many sources) |
| Failure | `ratio_failed_conn` | half-open/rejected conns: scans, SYN floods |
| Sessions | `n_ssh_telnet_conn`, `n_login_failed`, `n_login_success`, `n_commands` | brute force, Mirai, post-login activity |
| IoT protocols | `n_mqtt_connect`, `n_mqtt_publish`, `n_mqtt_subscribe`, `n_http_rtsp_req` | MQTT spoofing, camera access |
| Sensor health | `sensor_n_readings`, `sensor_smoke_delta_max`, `sensor_temp_delta_max`, `sensor_humidity_delta_max` | DoS'd sensor goes quiet; manipulation causes jumps |
| Context | `device_type` one-hot (4) | lets one model handle camera and sensor |

The exact definition of every feature (source field, transform, scaling) is in `feature_contract.json`.

### 4.3 Scaling
- Numeric columns are log1p-transformed (counts) and then standard-scaled. One-hot and ratio columns pass through unchanged.
- The scaler is fitted **only on the train split's normal rows**.
- B publishes these files under `artifacts/features/v1.0.0/`:
  - `flow_scaler.joblib` and `window_scaler.joblib`
  - `feature_order.json`
  - `splits.json`
  - a copy of the contract

### 4.4 Never a feature
`src_ip`, `dst_ip`, `src_port`, MAC, any ID (`flow_id`, `event_id`, `uid`), timestamps, `capture_id`, `run_id`, `label`, `scenario`, and Suricata alert signatures (those are another detector's answer). D may use IPs as **node identity** in the graph, never as input values.

---

## 5. Dataset exports (what C and D receive)

Everything goes under `data/processed/v1.0.0/`.

| File | For | Content |
|---|---|---|
| `flows.parquet` | all | one row per flow: IDs and labels (for joining and evaluation) + the 41 features + `split` |
| `windows.parquet` | C | one row per (device, window): labels + the 24 features + `split` |
| `sequences_{train,val,test}.npz` | C | `X [N, 30, 24]` float32, `y [N]`, `y_window [N, 30]`, `entity_id`, `window_start`. 30 windows = 5 minutes, stride 1, never crossing captures. |
| `edges_{train,val,test}.parquet` | D | one row per flow, sorted by `ts`: `src_node`, `dst_node`, raw IP/port/proto columns, `label`, `scenario`, the 41 edge features |
| `nodes.parquet` | D | `node_id`, `node_type`, `device_type`, first/last seen |

**Labels.**
- A flow is an attack if the attacker IP is on either end and the flow starts inside the run's time window.
- A window is an attack if any attack flow or event touches that device in that window.
- A sequence is an attack if any of its windows is.
- Live data is `NULL` until an analyst labels it.

**Splits.**
- Split by whole capture or attack run, in time order: about 70% train, 15% validation, 15% test.
- The test split contains every scenario.
- Optional: hold out one scenario (e.g. `mqtt_spoofing`) completely as a zero-day test.

---

## 6. What models send back: the alert format

D's inference posts to `POST /api/v1/alerts`, and E reads `GET /api/v1/alerts/{id}`. The full example is in `feature_contract.json → alert_format`. The main fields:

- `model_name`, `model_version`, `feature_version`. The backend **rejects** an alert whose `feature_version` doesn't match the model's registered one.
- `entity_type` / `entity_id`, `device_id`, `src_ips`, `window_start` / `window_end`
- `score`, `threshold`, `is_anomaly`, `predicted_scenario` (null for the autoencoders), `severity`
- `evidence`: top contributing features (C), `flow_ids` / `event_ids`, `attention_edges` (D's GAT). E puts these into its prompt.

---

## 7. Backend endpoints this implies (Task 6)

| Method | Path | Who calls it |
|---|---|---|
| POST | `/api/v1/ingest/events` | B's parsers, devices |
| POST | `/api/v1/ingest/sensor` | ESP32 (or the MQTT subscriber) |
| POST / GET | `/api/v1/attack-runs` | A |
| POST / GET | `/api/v1/captures` | A, B |
| GET | `/api/v1/devices` | all |
| GET | `/api/v1/events?from&to&device_id&source&event_type&label` | dashboard, E |
| GET | `/api/v1/flows?from&to&device_id&label` | dashboard, D |
| GET | `/api/v1/features/windows?from&to&device_id` | C, D (live inference) |
| GET | `/api/v1/graph/edges?from&to` | D (live inference) |
| POST / GET | `/api/v1/models` | D (register version, set active) |
| POST / GET | `/api/v1/alerts`, `GET /api/v1/alerts/{id}`, `PATCH /api/v1/alerts/{id}` (status, analyst_label) | D, E, dashboard |
| POST / GET | `/api/v1/reports` | E, dashboard |
| GET | `/health` | everyone |

POST endpoints require an API key header. All list endpoints are paginated (`limit`, `cursor`).

---

## 8. Open questions for the team

1. **A:** Zeek only, or Zeek + CICFlowMeter? This contract assumes Zeek `conn.log` (JSON). CICFlowMeter would add a second flow format and needs a contract bump.
2. **A:** Is there a BLE capture? If yes, add `n_ble_events` to the window features (v1.1.0).
3. **C:** Are 10-second windows and 30-step sequences right for your models? Both are a one-line change in the contract.
4. **C:** Do you also want per-attacker windows (`entity_type = src_ip`)? The schema already supports them.
5. **D:** Graph node types: IP + device only, or service nodes too? The raw columns are exported, so either works.
6. **D:** One active version per model, as the schema assumes, or A/B testing two?
7. **E:** Besides `evidence`, what else should `GET /alerts/{id}` include for your prompt? Raw events from the window? The device's recent history?
