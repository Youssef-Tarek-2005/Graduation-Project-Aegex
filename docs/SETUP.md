# Setup guide

Two ways to run AEGEX: **A. Docker (recommended)** runs everything with one command. **B. Local Python** runs only the pipeline and API on your machine, with the databases still in Docker.

## 1. Prerequisites

| Requirement | Why | Notes |
|---|---|---|
| Docker Desktop (Windows/Mac) or Docker Engine + Compose v2 (Linux) | runs PostgreSQL, Elasticsearch, object storage, Kafka, pipeline, API | check with `docker compose version` |
| About 3 GB of free RAM | Elasticsearch is set to a 512 MB heap, plus the other containers | |
| Free ports | `5432` PostgreSQL, `9000` object storage (S3), `9333` object storage master, `9200` Elasticsearch, `9092` Kafka, `8000` dashboard/API | change the left side of a mapping in `docker-compose.yml` if one is taken |
| Your sensor CSV | the real sensor data | see section 2 |
| A browser with internet access | the dashboard loads Chart.js from `cdnjs.cloudflare.com` | without internet the charts do not draw (the API and `/docs` still work) |
| Python 3.12 (option B only) | runs the code outside Docker | |

## 2. Prepare your CSV

Put the file at **`data/my_data.csv`**.

- Expected columns: `time`, `esp_ms`, `smoke`, `tempeture`, `humidity_pct`.
- Header names are case-insensitive. Accepted aliases: `temperature`, `temperature_c`, `temp` (all become `tempeture`), and `humidity` (becomes `humidity_pct`).
- Delimiter is detected automatically (comma, semicolon or tab). A UTF-8 byte-order mark is fine.
- `esp_ms` is the ESP32 millisecond counter. It is used to replay the file at its original speed. If it is missing or not increasing, `AEGEX_DEFAULT_INTERVAL` (1 s) is used between rows.
- Bad data is tolerated: missing or out-of-range values are filled from the last valid reading, rows with the wrong number of fields are flagged, and a row with no usable values and no history is dropped (see [ARCHITECTURE.md](ARCHITECTURE.md), Cleaning).
- Valid ranges: smoke 0 to 4095 (12-bit ESP32 ADC), temperature -40 to 80 °C, humidity 0 to 100 %. Change them with `AEGEX_SMOKE_MAX`, `AEGEX_TEMP_MIN`, `AEGEX_TEMP_MAX`.

Example:

```csv
time,esp_ms,smoke,tempeture,humidity_pct
2026-10-10T02:13:40Z,1000,312,27.4,55.1
2026-10-10T02:13:41Z,2000,315,27.5,55.0
```

## 3A. Run with Docker (recommended)

```bash
# from the AEGEX folder
cp /path/to/your.csv data/my_data.csv      # Windows PowerShell: Copy-Item C:\path\your.csv data\my_data.csv
docker compose up -d --build
```

What happens:

1. Docker builds one image (Python 3.12) used by both the `pipeline` and `api` services.
2. `postgres` and `elasticsearch` start; Compose waits until their healthchecks pass (Elasticsearch can take 30 to 90 seconds).
3. `pipeline` starts: it creates the PostgreSQL tables, the object-storage bucket and the Elasticsearch index templates, archives your CSV, then replays it row by row.
4. `api` starts and serves the dashboard.

Check it:

```bash
docker compose ps                  # postgres and elasticsearch should say "healthy"
docker compose logs -f pipeline    # look for "processed=50 ... attacks_detected=..."
curl http://localhost:8000/health  # {"postgres":"up","elasticsearch":"up"}
```

Open:

- **Dashboard:** http://localhost:8000
- **Interactive API docs:** http://localhost:8000/docs

Stop and restart:

```bash
docker compose down        # stop, keep all data
docker compose up -d       # start again
docker compose down -v     # stop AND delete all data (databases, object storage, dead-letter file)
```

### Things to know about the Docker run

- **The pipeline replays the CSV in real time.** A file covering one hour takes one hour. A single wait between rows is capped at 5 seconds. To go faster set `AEGEX_REPLAY_SPEED=10` (ten times faster) or `0` (no waiting) under `pipeline.environment` in `docker-compose.yml`.
- **Timestamps are the ingestion time**, not the time in the CSV (`AEGEX_TIME_MODE=ingest`). With `AEGEX_REPLAY_SPEED=0` every row therefore gets almost the same timestamp. Use `AEGEX_TIME_MODE=csv` to keep the CSV's own times, and select a time range on the dashboard that covers them.
- **The pipeline container exits when the CSV ends.** The data stays in the databases. To keep tailing a file that is still being written, set `AEGEX_FOLLOW_CSV=true`.
- **Restarting the pipeline re-reads the whole CSV** and adds the rows again with new batch ids. Use `docker compose down -v` first if you want a clean start.
- **Kafka is started but not used** (`AEGEX_KAFKA_ENABLED=false`). See [DEVELOPMENT.md](DEVELOPMENT.md) to enable it.
- **Upgrading from an older version:** run `docker compose down -v` once so the new `attack_analyses` table and Elasticsearch mappings are created.

## 3B. Run locally with Python

Databases in Docker, code on your machine.

```bash
# 1. databases only
docker compose up -d postgres minio elasticsearch

# 2. Python environment
python3.12 -m venv .venv
source .venv/bin/activate            # Windows: .venv\Scripts\activate
pip install -r requirements.txt

# 3. settings (Linux/Mac shown; Windows PowerShell: $env:NAME="value")
export AEGEX_CSV_PATH=./data/my_data.csv
export AEGEX_MINIO_OBJECT_LOCK=false     # the bundled object store (SeaweedFS) does not do object lock
export AEGEX_KAFKA_ENABLED=false

# 4. terminal 1: the pipeline
python main.py

# 5. terminal 2: the API and dashboard
uvicorn aegex.api:app --host 0.0.0.0 --port 8000
```

The defaults in `aegex/config.py` already point to `localhost` for all databases, so no other variables are needed.

## 4. Verify it works

| Check | Expected |
|---|---|
| `curl localhost:8000/health` | `{"postgres":"up","elasticsearch":"up"}` |
| Dashboard top bar | both status dots green |
| `curl "localhost:8000/api/v1/sensors/timeseries?minutes=60"` | `meta.count` greater than 0 after a minute |
| `curl "localhost:8000/api/v1/attacks/summary?minutes=60"` | `total` greater than 0 after a few minutes (about 15% of windows contain an attack) |
| `curl "localhost:8000/api/v1/reports/blue-team?format=markdown"` | a markdown report |
| `curl "localhost:8000/api/v1/intel/search?q=mirai"` | knowledge-base hits |
| `docker compose exec postgres psql -U aegex -c "select count(*) from sensor_readings"` | row count grows |

An empty dashboard in the first minute is normal. The dashboard refreshes every 5 seconds. Its range buttons are 15m, 1h, 6h (default) and 24h; pick a longer one if you replayed old data.

## 5. Run the tests

```bash
pip install pytest
pytest tests
```

The tests need no databases. They run the simulator through the whole preprocessing and analysis pipeline.

## 6. Troubleshooting

| Symptom | Cause and fix |
|---|---|
| Elasticsearch keeps restarting (Linux) | the kernel limit is too low: `sudo sysctl -w vm.max_map_count=262144` |
| Elasticsearch exits with memory errors | give Docker more RAM (Docker Desktop, Settings, Resources), or lower `ES_JAVA_OPTS` |
| `port is already allocated` | another program uses the port; change the left side of the mapping in `docker-compose.yml` |
| Pipeline exits at once with `FileNotFoundError` | `data/my_data.csv` is missing |
| Pipeline logs `PostgreSQL not ready (n/30)` | normal while the database starts; it retries for about a minute |
| Pipeline logs `Dropping unusable CSV row` | that row had no valid sensor values and nothing earlier to fill from |
| Dashboard shows an error banner | the API cannot reach a database; check `docker compose ps` and `/health` |
| Dashboard charts empty but `/health` is fine | the time range does not cover your data (see the timestamp note above), or the pipeline has not written yet |
| `/api/v1/attacks` returns 503 | the `attack_analyses` table is missing: `docker compose down -v` and start again, or restart the pipeline so it creates the table |
| Kafka errors in the pipeline log | only if you enabled Kafka; see DEVELOPMENT.md (advertised listener) |
| `dead_letter.ndjson` appears | a sink failed and the payload was saved for replay; inside Docker it is in the `deadletter` volume at `/dead_letter/` |
| Object-storage upload errors about Object Lock | set `AEGEX_MINIO_OBJECT_LOCK=false` (already set in Compose) |

Look at the dead-letter file in Docker with:

```bash
docker compose run --rm --entrypoint sh pipeline -c "tail -n 5 /dead_letter/dead_letter.ndjson"
```
