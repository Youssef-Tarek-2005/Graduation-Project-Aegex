# File-by-file reference

Every file in the project, what it does, and what it contains. Line counts are approximate (about 2,600 lines in total, excluding documentation).

## Root

| File | Purpose |
|---|---|
| `main.py` (123 lines) | **Entry point of the pipeline.** Class `Pipeline` creates the collector, preprocessing pipeline and the four sinks. `setup()` waits for PostgreSQL, the object store and Elasticsearch (`retry()`: 30 attempts, 2 s apart), creates tables, bucket and index templates, and archives the raw CSV. `handle(batch)` preprocesses one batch and writes to PostgreSQL, object storage, Elasticsearch and the detection hook **concurrently**; each sink runs in a thread through `_safe()`, which catches errors and writes the payload to the dead-letter file. `_periodic_flush()` flushes the buffers every few seconds so quiet periods do not leave data stranded. Ctrl-C or SIGTERM cancels the loop and flushes. Logs `processed=... attacks_detected=...` every 50 batches. Run with `python main.py`. |
| `docker-compose.yml` (52 lines) | Defines the six services (`postgres`, `minio`, `elasticsearch`, `kafka`, `pipeline`, `api`), their healthchecks, volumes and environment. See [CONFIGURATION.md](CONFIGURATION.md). |
| `Dockerfile` | Python 3.12-slim image; installs `requirements.txt`, copies the project, default command `python main.py`. Used by both `pipeline` and `api`. |
| `requirements.txt` | `fastapi`, `uvicorn[standard]`, `sqlalchemy`, `psycopg2-binary`, `minio`, `elasticsearch` (8.x), `confluent-kafka`, `httpx`. `pydantic` comes with FastAPI. |
| `.dockerignore` | Keeps `.venv`, caches, dead-letter files, `data/`, `docs/` and `.git` out of the image (`data/` is mounted instead). |
| `.gitignore` | Ignores virtual environments, caches, dead-letter files and CSVs in `data/`. |
| `README.md` | Overview, quick start, status table, links to the documents below. |

## `aegex/` (the Python package)

| File | Purpose |
|---|---|
| `__init__.py` | Empty; marks the package. |
| `config.py` | `Settings` (frozen dataclass) reads every `AEGEX_*` environment variable once. `get_settings()` returns it. Also defines `MOCK_BAD_IPS`, the five blocklisted documentation-range IPs. |
| `models.py` | Shared types. `EventType` (13 event types), `LAYER_OF` / `LAYERS` / `layer_of()` (event type to collection layer), `SCENARIOS` (the 7 attack names), `ENTRY_VECTORS`, `HONEYPOTS` (device to honeypot name), `RawEvent` (one uncleaned event with a UUID), `TelemetryBatch` (one sensor row plus the events of that moment), `utcnow()`. |

### `aegex/testbed/` - attacker entry layer, honeypots, scenarios (simulated)

| File | Purpose |
|---|---|
| `__init__.py` | Exports `HoneypotEventSimulator`. |
| `simulator.py` (195 lines) | `HoneypotEventSimulator(seed, attack_probability)`. `generate_window(ts)` returns the events of one moment: maybe one attack, 0 to 3 normal users, maybe a syslog line, all tagged with `label`, `actor`, `entry_vector`, `honeypot`. One method per scenario (`_sc_vulnerability_scanning`, `_sc_ddos`, `_sc_mirai_botnet`, `_sc_ransomware`, `_sc_sensor_manipulation`, `_sc_unauthorized_camera_access`, `_sc_zero_day_exploit`), each returning `(events, target_device, entry_vector)`, plus `_benign()` and small builders (`_net`, `_pkt`, `_log`, `_ble`, `_logins`, `_session`). Deterministic for a given seed. Details: [ARCHITECTURE.md](ARCHITECTURE.md) section 4.1. |

### `aegex/collection/` - multi-layer event collection

| File | Purpose |
|---|---|
| `__init__.py` | Exports `TelemetryCollector`, `CSVSensorReader`. |
| `csv_reader.py` (80 lines) | `CSVSensorReader.stream()`: async generator of raw CSV rows as dicts. Detects delimiter, normalises header names via `COLUMN_ALIASES`, flags malformed rows, replays in real time from `esp_ms` gaps, can tail a growing file. Values stay raw strings. |
| `collector.py` (61 lines) | `TelemetryCollector`. `stream_batches()` turns each CSV row into a `TelemetryBatch` with the simulator's window and any externally pushed events. `submit_event()` is the hook for real honeypot sensors (Cowrie, an MQTT broker, a BLE sniffer). `_parse_csv_time()` parses ISO, `YYYY-MM-DD HH:MM:SS`, `DD/MM/YYYY`, `MM/DD/YYYY` and time-only values. |

### `aegex/processing/` - cleaning, features, sequence and graph

| File | Purpose |
|---|---|
| `__init__.py` | Empty. |
| `preprocessing.py` (249 lines) | `Cleaner`, `Normalizer`, `IPReputation`, `FeatureExtractor`, and `PreprocessingPipeline.process()` which runs the five steps and attack analysis. Data classes `CleanedBatch`, `NormalizedBatch`, `FeatureVector` (with `to_payload()`). Constants `FEATURE_ORDER`, `PACKET_CAP`, `SESSION_CAP`, `COUNT_CAP`. |
| `sequence_graph.py` (34 lines) | `SequenceGraphBuilder.build(vector, events)` keeps the sliding window (`AEGEX_WINDOW_SIZE`) and returns it with the (source IP, device) graph edges. |

### `aegex/detection/` - attack analysis and the hook for the AI models

| File | Purpose |
|---|---|
| `__init__.py` | Empty. |
| `attack_analysis.py` (105 lines) | `AttackAnalyzer.analyze(events)`: signature rules per scenario (four signals each), picks the best scenario with at least 2 signals, returns category, severity, confidence, signals, source IPs, MITRE IDs, entry vector, honeypot, ground truth. Rule-based, no ML. |
| `handoff.py` (92 lines) | Forwarding to the future detection models. `Forwarder` (abstract), `KafkaForwarder` (two topics, idempotent producer), `WebhookForwarder` (HTTP POST with 3 retries), `DetectionLayerHandoff.forward()` fans out to whichever are enabled; errors are logged, never raised. |

### `aegex/storage/` - unified event store

| File | Purpose |
|---|---|
| `__init__.py` | Empty. |
| `postgres_store.py` (157 lines) | SQLAlchemy models `SensorReading`, `FeatureRecord`, `AttackAnalysisRecord`; `PostgresStore` with `init_schema()`, `save(fv)` (idempotent inserts), and the dashboard queries `sensor_timeseries()` (optional server-side bucketing with `date_bin`, PostgreSQL 14+), `recent_attacks()`, `attack_summary()`. |
| `es_store.py` (154 lines) | `ElasticStore`: `init_indices()` (index templates), `index_events()` (buffered bulk writes into the daily raw and security indices), `flush()`, `recent_security_events()`, `layer_counts()`, `event_histogram()`. `classify()` holds the severity rules; `_MAPPINGS` the field types. |
| `minio_store.py` (91 lines) | `MinioStore`: `init_bucket()` (Object Lock at creation), `archive_csv()` (hash-named, once per content), `add_events()` / `flush()` (buffered NDJSON objects under `raw/telemetry/...`), retention via `_retention()`. |

### `aegex/intel/` - threat intelligence and reporting

| File | Purpose |
|---|---|
| `__init__.py` | Empty. |
| `knowledge_base.py` (122 lines) | `KBEntry`, the 45 seed entries (MITRE ATT&CK 15, OWASP IoT Top 10 8, CVE/NVD 4, CWE/CAPEC 10, threat feeds 8), `LAYER_TITLES`, `CATEGORY_PROFILE` (per scenario: title, base severity, MITRE / OWASP / CWE-CAPEC IDs, mitigation steps), `references_for(category)`. |
| `retriever.py` (44 lines) | `KnowledgeRetriever`: TF-IDF style keyword index, `search(query, layer, limit)` and `layers()`. The replacement point for a vector database. |
| `report.py` (74 lines) | `build_report(attacks, minutes)` creates findings and recommendations; `to_markdown(report)` renders them. |

### `aegex/api/` - dashboard backend

| File | Purpose |
|---|---|
| `__init__.py` | Exposes `app` so `uvicorn aegex.api:app` works. |
| `app.py` (54 lines) | Creates the FastAPI app, the `/docs` text and tags, CORS, registers the routers, serves `frontend/dashboard.html` at `/`. |
| `deps.py` (10 lines) | One shared `PostgresStore`, `ElasticStore` and `KnowledgeRetriever` for all routes. Clients connect lazily. |
| `schemas.py` (56 lines) | Pydantic response models with examples for health, time series, events and histogram. |
| `routes/__init__.py` | Empty. |
| `routes/system.py` | `GET /health`. |
| `routes/sensors.py` | `GET /api/v1/sensors/timeseries`. |
| `routes/security.py` | `GET /api/v1/security/events`, `/events/histogram`, `/layers`. |
| `routes/attacks.py` | `GET /api/v1/attacks`, `/attacks/summary`. |
| `routes/intel.py` | `GET /api/v1/intel/layers`, `/search`, `/categories`. |
| `routes/reports.py` | `GET /api/v1/reports/blue-team`. |

## Other folders

| File | Purpose |
|---|---|
| `database/schema.sql` | Plain SQL for `sensor_readings`, `feature_vectors`, `attack_analyses` and their indexes. Mounted into the PostgreSQL container and applied on first start. Mirrors the SQLAlchemy models. |
| `frontend/dashboard.html` (266 lines) | The whole dashboard in one file (HTML, CSS, JavaScript, Chart.js from a CDN, light and dark mode). Polls the API every 5 seconds. Sections: header with status dots and range buttons (15m, 1h, 6h, 24h); KPI cards; four collection-layer cards plus entry-vector and actor cards; temperature, smoke and humidity charts; security-event histogram; detected-scenario chart and recent-detections table; recent security events table with a severity filter; threat-intelligence search; blue team report viewer and download. The API address is editable in the footer. Dynamic text is inserted with `textContent`, not `innerHTML`. |
| `data/.gitkeep` | Keeps the folder in version control. Put `my_data.csv` here. |
| `tests/test_pipeline.py` | Three pytest tests: every scenario is generated and detected with no false positives, the feature vector and window have the right shape and range, and the report and retriever work. No databases needed. |
| `docs/architecture.jpeg` | The architecture diagram. |
| `docs/*.md` | This documentation. |
