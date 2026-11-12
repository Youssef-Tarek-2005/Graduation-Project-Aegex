# Configuration reference

All settings live in `aegex/config.py` (class `Settings`) and are read from environment variables when the program starts. Set them under `environment:` of the `pipeline` or `api` service in `docker-compose.yml`, or export them in your shell.
Booleans accept `1`, `true`, `yes`, `on` (case-insensitive); anything else is false.

## Collection (Task 1)

| Variable | Default | Meaning |
|---|---|---|
| `AEGEX_CSV_PATH` | `~/Desktop/my_data.csv` | Sensor CSV to read. Compose sets `/data/my_data.csv`. |
| `AEGEX_REPLAY_SPEED` | `1.0` | 1 = replay at the speed of the `esp_ms` counter, 10 = ten times faster, 0 = no waiting. |
| `AEGEX_FOLLOW_CSV` | `false` | `true` = keep waiting for new lines (like `tail -f`). `false` = stop at the end of the file. |
| `AEGEX_POLL_INTERVAL` | `1.0` | Seconds between checks for new lines when following. |
| `AEGEX_DEFAULT_INTERVAL` | `1.0` | Seconds between rows when `esp_ms` is missing or not increasing. |
| `AEGEX_MAX_SLEEP` | `5.0` | Longest single wait between two rows, so a gap in the data does not stall the replay. |
| `AEGEX_TIME_MODE` | `ingest` | `ingest` = stamp each batch with the current time. `csv` = use the CSV `time` column (falls back to now if unparseable). |
| `AEGEX_SIMULATE_NETWORK` | `true` | Generate honeypot, user and attacker events. `false` = only the CSV (features then use mock values). |
| `AEGEX_ATTACK_PROB` | `0.15` | Chance that a 1-row window contains one attack scenario. |
| `AEGEX_SIM_SEED` | `42` | Random seed of the simulator. Same seed and same CSV give the same simulated traffic. |

## Preprocessing (Task 2)

| Variable | Default | Meaning |
|---|---|---|
| `AEGEX_SMOKE_MAX` | `4095` | Upper bound of valid smoke values (12-bit ADC). Use `1023` for a 10-bit board. Also the normalisation ceiling. |
| `AEGEX_TEMP_MIN` / `AEGEX_TEMP_MAX` | `-40` / `80` | Valid temperature range in °C (DHT22). |
| `AEGEX_IP_BLOCKLIST` | empty | Path to a text file with one known-bad IP per line (`#` starts a comment). Added to the built-in mock list. |
| `AEGEX_DEVICE_ID` | `honeypot-01` | Name of the device in graph edges when an event names no device. |
| `AEGEX_WINDOW_SIZE` | `20` | Length of the sliding window of feature vectors (used for sequence models). |

## Storage (Task 3)

| Variable | Default | Meaning |
|---|---|---|
| `AEGEX_POSTGRES_URL` | `postgresql+psycopg2://aegex:aegex@localhost:5432/aegex` | SQLAlchemy URL. |
| `AEGEX_MINIO_ENDPOINT` | `localhost:9000` | S3 endpoint (`host:port`, no scheme). |
| `AEGEX_MINIO_ACCESS_KEY` / `AEGEX_MINIO_SECRET_KEY` | `minioadmin` / `minioadmin` | Dev credentials. Change them. |
| `AEGEX_MINIO_SECURE` | `false` | Use HTTPS to reach the object store. |
| `AEGEX_MINIO_BUCKET` | `aegex-cold-storage` | Bucket for the raw CSV and event logs. |
| `AEGEX_MINIO_OBJECT_LOCK` | `true` | Create the bucket with Object Lock and write-once retention. Compose sets `false` because the bundled SeaweedFS does not support it. |
| `AEGEX_MINIO_RETENTION_DAYS` | `30` | Retention for each object when Object Lock is on (GOVERNANCE mode). 0 = no retention. |
| `AEGEX_ARCHIVE_BATCH` | `200` | Events buffered before an NDJSON object is written. |
| `AEGEX_ARCHIVE_FLUSH_S` | `10` | Maximum seconds before the buffer is written anyway. |
| `AEGEX_ES_URL` | `http://localhost:9200` | Elasticsearch URL. |
| `AEGEX_ES_API_KEY` | empty | API key if Elasticsearch security is on. |
| `AEGEX_ES_PREFIX` | `aegex` | Prefix of index names (`aegex-raw-events-...`). |
| `AEGEX_ES_BATCH` | `100` | Documents buffered before a bulk request. |
| `AEGEX_ES_FLUSH_S` | `5` | Maximum seconds before the buffer is sent anyway. |

## Hand-off to the detection layer (Task 5)

| Variable | Default | Meaning |
|---|---|---|
| `AEGEX_KAFKA_ENABLED` | `true` in code, `false` in Compose | Publish to Kafka. |
| `AEGEX_KAFKA_BOOTSTRAP` | `localhost:9092` | Kafka bootstrap servers. |
| `AEGEX_KAFKA_TOPIC_FEATURES` | `aegex.detection.features` | Topic for vector, window and attack analysis (for LSTM, VAE, autoencoders). |
| `AEGEX_KAFKA_TOPIC_GRAPH` | `aegex.detection.graph` | Topic for graph edges (for the temporal GAT). |
| `AEGEX_WEBHOOK_URLS` | empty | Comma-separated URLs that receive the full payload as JSON (POST, 3 attempts each). |

## Orchestration

| Variable | Default | Meaning |
|---|---|---|
| `AEGEX_DEAD_LETTER` | `dead_letter.ndjson` | File where payloads of failed sinks are appended. Compose uses `/dead_letter/dead_letter.ndjson` on a volume. |
| `AEGEX_LOG_LEVEL` | `INFO` | Python log level. |

## Variables for the API service

The API only needs `AEGEX_POSTGRES_URL`, `AEGEX_ES_URL` (and `AEGEX_ES_PREFIX`, `AEGEX_ES_API_KEY` if you changed them). It does not read the CSV.

## Docker Compose settings

| Item | Value |
|---|---|
| `postgres` | image `postgres:16`, user/password/db all `aegex`, volume `pgdata`, `database/schema.sql` auto-applied on first start, healthcheck `pg_isready` |
| `minio` | image `chrislusf/seaweedfs` (S3-compatible; the service keeps the name `minio`), ports 9000 (S3) and 9333, volume `miniodata` |
| `elasticsearch` | image 8.13.4, single node, security off, 512 MB heap, volume `esdata`, healthcheck on `/_cluster/health` |
| `kafka` | image `apache/kafka:3.8.0`, port 9092, no volume |
| `pipeline` | built from `Dockerfile`, command `python main.py`, mounts `./data` read-only at `/data` and volume `deadletter` at `/dead_letter`, waits for healthy `postgres` and `elasticsearch` |
| `api` | same image, command `uvicorn aegex.api:app --host 0.0.0.0 --port 8000`, port 8000, waits for healthy `postgres` and `elasticsearch` |
| volumes | `pgdata`, `miniodata`, `esdata`, `deadletter` |
