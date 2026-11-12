# Data reference

## 1. Events

An event is one record from the honeypot or the sensor. Raw form (`RawEvent` in `aegex/models.py`):

```json
{"event_id": "9f1c...", "event_type": "failed_login", "timestamp": "2026-10-23T12:00:05+00:00",
 "source": "honeypot-sim", "payload": {"src_ip": "203.0.113.45", "protocol": "telnet", "username": "root", "reason": "bad_credentials",
                                       "label": "mirai_botnet", "actor": "attacker", "entry_vector": "wifi", "honeypot": "camera_honeypot"}}
```

`source` is `csv` (sensor reading), `honeypot-sim` (simulator) or `external` (pushed through `submit_event`).

### Event types and their fields

| Event type | Layer | Payload fields |
|---|---|---|
| `network_traffic` | network_traffic | `src_ip`, `dst_port`, `protocol`, `bytes`, `packets` |
| `packet_characteristics` | network_traffic | `src_ip`, `packet_size`, `ttl`, `tcp_flags`, `payload_entropy` |
| `source_ip` | network_traffic | `src_ip`, `first_seen`, `asn`, `country` |
| `device_log` | device_service_logs | `source` (`syslog`), `level` (`info`, `warning`, `error`, `critical`), `service`, `message`, optional `src_ip` |
| `mqtt_event` | device_service_logs | `src_ip`, `action`, `topic`, `client_id`, `payload_size` (`spoofed` is set only by the simulator) |
| `ble_event` | device_service_logs | `mac`, `action` (`scan`, `gatt_write`, `pair_attempt`), `rssi` (no `src_ip`) |
| `login_attempt` | session_interaction | `src_ip`, `protocol`, `username`, `success` |
| `failed_login` | session_interaction | `src_ip`, `protocol`, `username`, `reason` |
| `session_info` | session_interaction | `src_ip`, `session_id`, `protocol`, `duration_s`, `commands_count` |
| `command_request` | session_interaction | `src_ip`, `session_id`, `command` |
| `device_interaction` | session_interaction | `src_ip`, `device` (`smoke_detector` or `ip_camera`), `action` (`status_query`, `stream_request`, `config_change`, `firmware_download`) |
| `sensor_reading` | telemetry_media | the CSV row: `time`, `esp_ms`, `smoke`, `tempeture`, `humidity_pct` |
| `media_telemetry` | telemetry_media | `src_ip`, `device`, `media_type` (`video`, `image`, `audio`), `authenticated`, `frame_rate`, `bitrate_kbps`, `size_bytes` (metadata only, no media files) |

Testbed context tags added to every simulated event:

| Tag | Values |
|---|---|
| `label` | `benign` or one of the seven scenarios |
| `actor` | `attacker` or `normal_user` |
| `entry_vector` | `wifi` or `bluetooth` |
| `honeypot` | `sensor_honeypot` or `camera_honeypot` |

Real traffic would not carry these tags; they exist so the event store is labeled and the analysis can be evaluated.

## 2. Feature vector

Eight numbers per batch, in this fixed order (`FEATURE_ORDER`):

| # | Feature | Real-unit definition | Scaling to 0..1 |
|---|---|---|---|
| 1 | `smoke` | cleaned sensor value (ADC counts) | min-max over 0 to `AEGEX_SMOKE_MAX` |
| 2 | `tempeture` | cleaned sensor value (°C) | min-max over `AEGEX_TEMP_MIN` to `AEGEX_TEMP_MAX` |
| 3 | `humidity_pct` | cleaned sensor value (%) | min-max over 0 to 100 |
| 4 | `network_packet_size` | mean of all `packet_size` values and of `bytes ÷ packets` per `network_traffic` event | mean of log-scaled sizes, ceiling 65535 |
| 5 | `login_attempts` | number of `login_attempt` events (never less than failed logins) | count ÷ 50, capped at 1 |
| 6 | `session_duration` | longest `duration_s` among `session_info` events (seconds) | log scale, ceiling 3600 |
| 7 | `ip_reputation_score` | highest reputation score among source IPs (0 clean, 1 malicious) | unchanged |
| 8 | `failed_logins` | larger of the `failed_login` count and the `login_attempt` events with `success=false` | count ÷ 50, capped at 1 |

If the window has no network events, features 4 to 8 are deterministic mock values and `feature_source` is `mock`.

### Processed payload (`FeatureVector.to_payload()`)

This is what goes to Kafka and webhooks.

```json
{
  "schema_version": "1.0", "batch_id": "...", "timestamp": "2026-10-23T12:00:05+00:00",
  "sensor": {"smoke": 312.0, "tempeture": 27.4, "humidity_pct": 55.1, "esp_ms": 1000, "source_time": "...", "was_imputed": false},
  "features": {"network_packet_size": 512.3, "login_attempts": 6.0, "session_duration": 42.0, "ip_reputation_score": 0.93, "failed_logins": 6.0},
  "features_normalized": {"smoke": 0.076, "...": "all 8 values, 0..1"},
  "feature_order": ["smoke", "tempeture", "humidity_pct", "network_packet_size", "login_attempts", "session_duration", "ip_reputation_score", "failed_logins"],
  "vector": [0.076, 0.69, 0.55, 0.57, 0.12, 0.46, 0.93, 0.12],
  "feature_source": "observed",
  "quality": {"issues": [], "malformed_row": false, "dropped_events": 0},
  "graph_edges": [{"src": "203.0.113.45", "dst": "ip_camera", "count": 14, "failed": 6}],
  "window": [[...8 numbers...], "... up to 20 vectors, oldest first"],
  "attack_analysis": {"category": "mirai_botnet", "severity": "high", "confidence": 0.93,
                      "signals": ["repeated_failed_logins", "telnet_or_ssh_bruteforce", "dropper_command", "known_bad_source"],
                      "src_ips": ["203.0.113.45"], "mitre": ["T1110.001", "T1078.001", "T1105", "T1059.004"],
                      "entry_vector": "wifi", "honeypot": "camera_honeypot", "ground_truth": "mirai_botnet"}
}
```

`attack_analysis` is `null` when nothing was detected. The Kafka features message also carries `window_size`.

## 3. PostgreSQL tables (`database/schema.sql`)

| Table | Columns | Notes |
|---|---|---|
| `sensor_readings` | `id`, `batch_id` (unique), `ts`, `source_time`, `esp_ms`, `smoke`, `temperature_c`, `humidity_pct`, `was_imputed`, `created_at` | one row per CSV row; `temperature_c` is the CSV column `tempeture`; index on `ts` |
| `feature_vectors` | `id`, `batch_id` (unique, foreign key to `sensor_readings`, cascade delete), `ts`, `network_packet_size`, `login_attempts`, `session_duration`, `ip_reputation_score`, `failed_logins`, `features_normalized` (JSONB), `feature_source`, `quality` (JSONB), `created_at` | one row per batch |
| `attack_analyses` | `id`, `batch_id` (unique), `ts`, `category`, `severity`, `confidence`, `src_ips` (JSONB), `entry_vector`, `honeypot`, `signals` (JSONB), `mitre` (JSONB), `ground_truth`, `created_at` | only batches where an attack was detected; indexes on `ts` and `category` |

Inserts use `ON CONFLICT (batch_id) DO NOTHING`. Because batch ids are random per run, replaying the CSV creates new rows.
The tables are created by `schema.sql` on first Docker start and by SQLAlchemy `create_all()` when the pipeline starts.

Handy queries:

```sql
select category, severity, count(*) from attack_analyses group by 1,2 order by 3 desc;
select ts, smoke, temperature_c, humidity_pct from sensor_readings order by ts desc limit 20;
select category, ground_truth, count(*) from attack_analyses group by 1,2;   -- analysis vs simulator label
```

## 4. Elasticsearch

Index templates `aegex-raw` and `aegex-security` (1 shard, 0 replicas, 2 s refresh) apply to:

| Index pattern | Contents |
|---|---|
| `aegex-raw-events-YYYY.MM.dd` | every collected event |
| `aegex-security-events-YYYY.MM.dd` | the same documents, only where `severity` is above `info` |

Document fields: `@timestamp`, `event_id` (also the `_id`), `event_type`, `severity`, `reasons`, `source`, `batch_id`, `src_ip` (ip), `username`, `command` (text + keyword), `layer`, `label`, `actor`, `entry_vector`, `honeypot`, `payload` (flattened, the full original payload).

### Severity rules (`classify()` in `es_store.py`)

The highest matching level wins; every match adds a reason.

| Rule | Level | Reason |
|---|---|---|
| `failed_login` event | medium | `failed_login` |
| `command_request` matching wget, curl, busybox, nc, netcat, `/etc/passwd`, `chmod 7..`, `rm -rf`, tftp, mirai, `\| sh`, encrypt, `.locked`, ransom, `openssl enc` | high | `malicious_command` |
| `mqtt_event` with topic starting `$SYS` | medium | `mqtt_sys_topic_probe` |
| `ble_event` with action `pair_attempt` or `gatt_write` | medium | `ble_pairing_or_write` |
| `device_interaction` with action `firmware_download` or `config_change` | medium | `device_tamper_attempt` |
| `device_log` level `warning` / `error` / `critical` | low / medium / high | `device_log_<level>` |
| `network_traffic` with 800+ packets or 300,000+ bytes | medium | `traffic_flood` |
| `media_telemetry` with `authenticated=false` | high | `unauthenticated_media_access` |
| event labeled with a scenario (testbed only) | scanning low, DDoS medium, Mirai medium, ransomware high, sensor manipulation medium, camera access medium, zero-day high | `scenario:<label>` |

The last rule is a floor that uses the testbed's ground-truth label; real traffic has no label, so only the content rules apply there.

## 5. Object storage

Bucket `aegex-cold-storage` (configurable):

| Key | Contents |
|---|---|
| `raw/csv/<sha256-first-16>_<filename>` | the original CSV, stored once per unique content (the hash makes it idempotent) |
| `raw/telemetry/YYYY/MM/DD/HH/<YYYYMMDDTHHMMSS>_<id>.ndjson` | raw events, one JSON per line, written when 200 events are buffered or 10 s pass |

With Object Lock enabled (real MinIO or S3), every object gets a GOVERNANCE retention of 30 days. A failed upload keeps the events in the buffer for the next flush.

## 6. Kafka (optional)

| Topic | Key | Value |
|---|---|---|
| `aegex.detection.features` | `batch_id` | the processed payload above without `graph_edges`, plus `window_size` |
| `aegex.detection.graph` | `batch_id` | `{"batch_id", "timestamp", "edges": [...]}` (sent only if there are edges) |

Producer settings: idempotent, lz4 compression, 20 ms linger, 15 s message timeout.

## 7. Dead-letter file

Each line: `{"sink": "postgres" | "minio" | "elasticsearch" | "detection", "record": {...}}`. There is no automatic replay; re-send the records with a small script.
