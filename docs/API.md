# HTTP API

Base URL: `http://localhost:8000`. Interactive version with an **Execute** button: `/docs`. Machine-readable: `/openapi.json`.
All endpoints are `GET`, return JSON (except the markdown report and the dashboard page), have **no authentication**, and allow cross-origin `GET` from any origin (tighten `allow_origins` in `aegex/api/app.py` for production).
When a database is unreachable an endpoint answers `503` with a message such as `PostgreSQL unavailable: OperationalError`. Parameter ranges outside the limits give `422`.

| Endpoint | Source | Purpose |
|---|---|---|
| `GET /` | file | the dashboard page |
| `GET /health` | PG + ES | service status |
| `GET /api/v1/sensors/timeseries` | PostgreSQL | temperature, smoke, humidity over time |
| `GET /api/v1/security/events` | Elasticsearch | recent flagged events |
| `GET /api/v1/security/events/histogram` | Elasticsearch | flagged events per time bucket and type |
| `GET /api/v1/security/layers` | Elasticsearch | events per collection layer, scenario, entry vector, actor |
| `GET /api/v1/attacks` | PostgreSQL | detected attacks (newest first) |
| `GET /api/v1/attacks/summary` | PostgreSQL | attack counts by scenario, severity, entry vector, honeypot |
| `GET /api/v1/intel/layers` | in memory | knowledge-base layers and sizes |
| `GET /api/v1/intel/search` | in memory | search the knowledge base |
| `GET /api/v1/intel/categories` | in memory | every attack scenario with references and mitigations |
| `GET /api/v1/reports/blue-team` | PostgreSQL + KB | blue team report (JSON or markdown) |

## System

### `GET /health`
```json
{"postgres": "up", "elasticsearch": "up"}
```
A value is `up` or `down: <reason>`.

## Sensors

### `GET /api/v1/sensors/timeseries`
| Parameter | Default | Limits | Meaning |
|---|---|---|---|
| `minutes` | 60 | 1 to 10080 | how far back to look |
| `limit` | 1000 | 1 to 20000 | maximum points |
| `bucket_seconds` | none | 1 or more | average readings into buckets of this size (60 = one point per minute) |

Response: `meta` (`count`, `window_minutes`, `bucket_seconds`, `generated_at`), `labels` (ISO timestamps, oldest first), `series` (three entries: `tempeture` in °C, `smoke` in ADC, `humidity_pct` in %, each with `data` aligned to `labels`), and `points` (the same data as one object per time).

## Security events

### `GET /api/v1/security/events`
| Parameter | Default | Meaning |
|---|---|---|
| `minutes` | 60 | window (1 to 10080) |
| `limit` | 50 | maximum events (1 to 500) |
| `min_severity` | `low` | `info`, `low`, `medium`, `high`, `critical` |
| `event_type` | none | only this event type, e.g. `failed_login` |
| `src_ip` | none | only this source address |

Response: `meta` (`total`, `returned`, `window_minutes`, `generated_at`) and `events`, each `{id, timestamp, event_type, severity, reasons[], src_ip, details{}}`.

### `GET /api/v1/security/events/histogram`
Parameters: `minutes` (60), `interval` (`1m`; pattern number + `s`, `m`, `h` or `d`). Response: `labels` (bucket starts) and `series` (one per event type with `data` counts), ready for a stacked bar chart.

### `GET /api/v1/security/layers`
Parameter: `minutes` (60). Counts from the raw event index:
```json
{"meta": {"window_minutes": 60, "generated_at": "..."},
 "total": 1234,
 "layers": {"network_traffic": 410, "device_service_logs": 288, "session_interaction": 470, "telemetry_media": 66},
 "labels": {"benign": 1100, "ddos": 12, "mirai_botnet": 20},
 "entry_vectors": {"wifi": 1190, "bluetooth": 44},
 "actors": {"normal_user": 1100, "attacker": 134}}
```
`total` is capped at 10,000 by Elasticsearch's default count limit.

## Attack analysis

### `GET /api/v1/attacks`
| Parameter | Default | Meaning |
|---|---|---|
| `minutes` | 60 | window (1 to 10080) |
| `limit` | 50 | maximum rows (1 to 500) |
| `category` | none | one of `vulnerability_scanning`, `ddos`, `mirai_botnet`, `ransomware`, `sensor_manipulation`, `unauthorized_camera_access`, `zero_day_exploit` |

```json
{"meta": {"returned": 1, "window_minutes": 60, "generated_at": "..."},
 "attacks": [{"batch_id": "...", "ts": "2026-10-23T12:00:05+00:00", "category": "mirai_botnet", "severity": "high",
              "confidence": 0.93, "src_ips": ["203.0.113.45"], "entry_vector": "wifi", "honeypot": "camera_honeypot",
              "signals": ["repeated_failed_logins", "dropper_command", "known_bad_source"],
              "mitre": ["T1110.001", "T1078.001", "T1105", "T1059.004"], "ground_truth": "mirai_botnet"}]}
```

### `GET /api/v1/attacks/summary`
Parameter: `minutes` (60). Returns `total`, `by_category` (each with `category`, `count`, `max_severity`, `avg_confidence`, `first_seen`, `last_seen`), `by_entry_vector`, `by_honeypot`, `by_severity`.

## Threat intelligence

### `GET /api/v1/intel/layers`
`{"layers": [{"layer": "mitre_attack", "title": "MITRE ATT&CK (...)", "entries": 15}, ...]}` for `mitre_attack`, `owasp_iot_top10`, `cve_nvd`, `cwe_capec`, `threat_feeds`.

### `GET /api/v1/intel/search`
| Parameter | Default | Meaning |
|---|---|---|
| `q` | required | 2 to 200 characters, e.g. `mirai`, `camera`, `T1486`, `default credentials` |
| `layer` | none | limit to one layer name |
| `limit` | 8 | 1 to 30 |

Response: `{"query": "...", "results": [{"id", "layer", "title", "description", "tags", "score"}]}`, best match first.

### `GET /api/v1/intel/categories`
Every scenario with `title`, `base_severity`, `mitigations` and `references` grouped by layer (MITRE, OWASP, CWE/CAPEC entries).

## Reports

### `GET /api/v1/reports/blue-team`
| Parameter | Default | Meaning |
|---|---|---|
| `minutes` | 60 | window (1 to 10080); uses up to 5000 detections |
| `format` | `json` | `json` or `markdown` (downloads `aegex-blue-team-report.md`) |

JSON structure:
```json
{"generated_at": "...", "window_minutes": 60, "total_detections": 14,
 "findings": [{"category": "mirai_botnet", "title": "Mirai-style botnet infection", "count": 5, "max_severity": "high",
               "avg_confidence": 0.9, "first_seen": "...", "last_seen": "...",
               "top_sources": [{"ip": "203.0.113.45", "events": 3}], "entry_vectors": {"wifi": 5},
               "targets": {"camera_honeypot": 3, "sensor_honeypot": 2},
               "evidence": [{"signal": "dropper_command", "seen": 5}],
               "references": {"mitre_attack": [...], "owasp_iot_top10": [...], "cwe_capec": [...]},
               "mitigations": ["Change all default credentials ...", "..."]}],
 "recommendations": ["...", "Add these sources to the network blocklist: 203.0.113.45."]}
```
Findings are sorted by highest severity then count. Recommendations are the findings' mitigations in that order with duplicates removed, followed by the blocklist line. With no detections the markdown says "No attacks detected in this window."

## Using the API from your own code

```bash
curl "http://localhost:8000/api/v1/attacks?minutes=120&category=ddos"
curl -o report.md "http://localhost:8000/api/v1/reports/blue-team?minutes=1440&format=markdown"
```
```python
import httpx
print(httpx.get("http://localhost:8000/api/v1/attacks/summary", params={"minutes": 60}).json())
```
