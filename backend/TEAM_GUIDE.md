# AEGEX backend: a short guide for the team

Task B (data engineering and backend). This page is the short version: what the backend does, how to start and
test it, what each of the 12 steps built, and **what each of you does with it**. The long explanation of every
step is in [README.md](README.md); the agreement on formats is in
[contracts/TASK_B_CONTRACT.md](../contracts/TASK_B_CONTRACT.md).

> **For the November 29 proof of concept (laptop hotspot + ESP32-S3), follow [POC_GUIDE.md](POC_GUIDE.md).** It
> uses its own database (`aegex_poc`), and the ESP32 sends its honeypot events to `POST /api/v1/ingest/honeypot`.
> Everything below still applies.

## What it is, in one picture

```
 A: lab devices                    B: backend (this folder)                          C / D / E / dashboard
 ──────────────                    ────────────────────────                          ─────────────────────
 Cowrie, Mosquitto, ESP32 ──POST──► API (port 8001) ──► one database (TimescaleDB) ──GET──► dashboard
 Zeek conn.log (pcap)     ──POST──►   same checks       events, flows, labels          ├──► C: window features
 attack log (what/when)   ──POST──►   as the tools      ──► features ──► dataset files ├──► D: graph edges
                                                                                       └──► E: events around an alert
```

**One rule behind everything:** the feature lists live in one file,
[contracts/feature_contract.json](../contracts/feature_contract.json). The backend computes features exactly as
it says, and C and D read the same file, so the models always get what they were trained on.

## Start it (on a computer with Docker)

```powershell
cd backend
docker compose up -d                                   # 1. the database (TimescaleDB on port 5433, backend/docker-compose.yml)
.venv/Scripts/python -m api                            # 2. the API on http://localhost:8001 (docs: /docs)
.venv/Scripts/python -m http.server 8095 --bind 127.0.0.1 --directory ../frontend
                                                       # 3. (another terminal) the dashboard:
                                                       #    http://localhost:8095/dashboard_new.html
```

First time only: `python -m venv .venv` then `.venv/Scripts/pip install -r requirements.txt`.

## Test it

| Command (from `backend`) | What it proves | Time |
|---|---|---|
| `.venv/Scripts/python -m pytest` | 162 unit tests: every piece alone | 25 s |
| `.venv/Scripts/python -m demo.check_all` | **steps 1-11 together, in order**, on a throw-away database; prints PASS/FAIL per step | 15 s |
| `.venv/Scripts/python -m demo.live_sim` | **live data without the hardware**: a fake ESP32, MQTT client and attacker send data to the API every 2 s; watch the dashboard in "Live" | until Ctrl+C |
| `.venv/Scripts/python -m demo.live_sim --clean` | deletes everything the simulator sent | 1 s |

`check_all` and `pytest` never touch the real `aegex` database: they create their own (`aegex_e2e`, `aegex_test`).

## The 12 steps, briefly

| # | What was built | How you can see it work |
|---|---|---|
| 1 | The database: PostgreSQL + TimescaleDB in Docker, 9 tables (`database/schema_v2.sql`) | `\dt` lists 9 tables |
| 2 | The lab inventory by hand: 3 devices (gateway, ESP32, camera), one sample capture, one attack run | `SELECT * FROM devices` |
| 3 | **Parsers:** turn Cowrie / Mosquitto / ESP32 log lines into events in one shared format | sample logs → 11 + 4 + 4 events |
| 4 | **Loader:** saves events; the same file twice saves nothing new; wrong time zone is refused | reload → 0 new rows |
| 5 | **Zeek:** pcap → `conn.log` → `flows` table (one row per network connection) | 9 flows with bytes, service, state |
| 6 | **Attack log + labels:** A writes down each attack (who, what, when); the backend marks matching traffic as attack | 11 attack events, 4 attack flows |
| 7 | **Flow features:** 41 numbers per connection (for D) | 41 columns, no missing values |
| 8 | **Window features:** 24 numbers per device per 10 seconds (for C); silent windows count as real zeros | 1080 windows = 3 devices × 360 |
| 9 | **Dataset for C and D:** split by whole captures (train / val / test), scalers, files | `sequences_train.npz` is `[N, 30, 24]` |
| 10 | **API, data in:** devices and scripts send events, sensor readings, raw log text, captures, the attack log | Swagger POST → row in the DB |
| 11 | **API, data out:** lists with filters and pages, window features, graph edges, dashboard summaries; the new dashboard | Swagger GET returns the data |
| 12 | *(next)* alerts, model registry, reports, API key | alert in → report attached |

### Step 9's "fake lab", explained

A fair test of a model needs data it never saw. So the split is by **whole recording sessions (captures)**:
older captures train, newer ones validate and test. Splitting single rows at random would let the model see
neighbouring seconds of the same attack in training and test, and report a fake 100%. That happened in our proof of
concept.

But we had only **one** capture, and you can't split one recording into train, validation and test. So
`demo/fake_lab.py` **generates 6 more captures** (`cap-demo-01` … `cap-demo-06`): log files in exactly the formats
the real devices write (Cowrie JSON, Mosquitto log, ESP32 CSV, Zeek conn.log) plus an attack log with the 4
scenarios (brute force, scanning, MQTT spoofing, DoS). It loads them **through the real pipeline** (steps 4-8),
so step 9 could be built and tested before real recordings exist. The data is labeled "fake lab, not real data".

When A's real captures arrive: `python -m demo.fake_lab --remove`, load the real ones, run step 9 again. No code
changes.

## What each of you does with the backend

**Task A (lab, devices, attacks)**
- Before recording: register the capture: `POST /api/v1/captures` (id, start, end or leave out while live).
- Send data: Cowrie / Mosquitto / ESP32 / Zeek lines to `POST /api/v1/ingest/logs/{source}`, or files with the
  command-line tools (`python -m ingest.load ...`, `python -m ingest.zeek ...`).
- For every attack, log one row: `run_id, capture_id, scenario, tool, command, attacker_ip, target_device,
  start_ts, end_ts` (times in UTC with `Z`). Check it first: `python -m ingest.attacks --check log.csv`.
  Then send it (`POST /api/v1/attack-runs?label=true`). **Without this log nothing gets an attack label.**
- ESP32: send readings to `POST /api/v1/ingest/sensor` (no clock needed: the server adds the time).
- Open items for A are in [TEAM_NOTES.md](TEAM_NOTES.md) (Zeek script fix, Mosquitto logging, ESP32 time zone).

**Task C (LSTM-AE / VAE on windows)**
- Training: `data/processed/v1.0.0/sequences_{train,val,test}.npz` (`X [N, 30, 24]`) and
  `artifacts/features/v1.0.0/window_scaler.joblib` (+ `feature_order.json`). Build them with
  `python -m features.dataset`.
- Live: `GET /api/v1/features/windows?from=...` gives the newest windows, features named and in contract order,
  **not scaled**: apply `window_scaler.joblib` yourself, exactly as in training.
- Please confirm the three window-feature questions in [TEAM_NOTES.md](TEAM_NOTES.md), item 6.

**Task D (Temporal GAT on flows, live inference)**
- Training: `edges_{split}.parquet` + `nodes.parquet` and `flow_scaler.joblib`.
- Live: `GET /api/v1/graph/edges?from=...`: one edge per connection, node ids `dev:gw-01` / `ip:192.168.56.99`,
  41 features, not scaled.
- In step 12 you'll send alerts to `POST /api/v1/alerts` and register model versions at `/api/v1/models`
  (format: contract section 6).

**Task E (RAG + LLM reports)**
- Context for a report: `GET /api/v1/events?from=...&to=...&device_id=...` (what happened around the alert).
- In step 12: read alerts at `GET /api/v1/alerts/{id}`, send reports to `POST /api/v1/reports`. Until then the
  threat-intelligence page of the dashboard keeps using the old API (port 8000).

**Dashboard**
- `frontend/dashboard.html` is **unchanged**: still the old API on port 8000.
- `frontend/dashboard_new.html` is the same page on the new API (port 8001), with a picker at the top: **Live**
  (last 15 min … 24 h) or **one recorded capture**. "Detected attacks" shows the attack log until the models'
  alerts exist (step 12). Its threat-intelligence page still uses port 8000.

## Rules everyone can rely on

- **All or nothing:** if anything in a request is wrong, nothing is saved, and the answer (`422`) lists every
  problem with its line or item number.
- **No duplicates:** sending the same data twice saves it once.
- **Times are UTC** and must say so (`...Z`). A file in the wrong time zone is refused, because a shifted row would
  get the wrong label.
- **Live data is unlabeled** (`label = null`) until A's attack log labels it.
- In scripts, use `http://127.0.0.1:8001`, not `localhost` (on Windows `localhost` adds 2 s per request).
- Until step 12 adds the API key, run the API only on your computer or the lab network.
