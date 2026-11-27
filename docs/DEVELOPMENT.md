# Development guide

## 1. Tests

```bash
pip install pytest      # plus requirements.txt
pytest tests
```

`tests/test_pipeline.py` needs no databases:

| Test | Checks |
|---|---|
| `test_all_scenarios_generated_and_detected` | 600 simulated windows contain all 7 scenarios, each is detected at least once, and clean windows produce no detection |
| `test_vector_window_and_payload` | the vector has 8 values between 0 and 1 and the window never exceeds `AEGEX_WINDOW_SIZE` |
| `test_report_and_retriever` | the markdown report contains the finding, technique and source IP; the retriever answers; all 5 knowledge layers exist |

The database code (`storage/`) and the dashboard JavaScript are **not** covered by automated tests. Check them with the steps in [SETUP.md](SETUP.md), section 4.

## 2. Extending the project

### Add an attack scenario
1. `aegex/models.py`: add the name to `SCENARIOS`.
2. `aegex/testbed/simulator.py`: add a method `_sc_<name>(self, ts)` that returns `(events, target_device, entry_vector)`. It is picked up automatically (`getattr(self, f"_sc_{name}")`).
3. `aegex/intel/knowledge_base.py`: add a `CATEGORY_PROFILE[<name>]` entry (title, `base_severity`, MITRE / OWASP / CWE-CAPEC IDs, mitigations) and any new `KBEntry` records it references.
4. `aegex/detection/attack_analysis.py`: add a `<name>` list of four `(signal_name, condition)` pairs to the `sig` dictionary.
5. `aegex/storage/es_store.py`: add the scenario to `_LABEL_FLOOR` (testbed severity floor).
6. Run the tests and update the scenario table in `docs/ARCHITECTURE.md`.

### Use real honeypots instead of the simulator
Set `AEGEX_SIMULATE_NETWORK=false` and push events from your real sources (Cowrie, an MQTT broker log, a BLE sniffer, Zeek, a camera log) with `TelemetryCollector.submit_event(EventType.X, payload, source="cowrie")`. Use the field names in [DATA.md](DATA.md). Pushed events join the next batch (one batch per CSV row). Notes:
- Real events carry no `label`, `actor`, `entry_vector` or `honeypot`, so the analysis reports `entry_vector` and `honeypot` as `unknown`. Add these fields in your adapter if you can determine them (for example from the interface the packet arrived on).
- Several signals need the attacker IP to be on the blocklist. Point `AEGEX_IP_BLOCKLIST` at a real feed, or replace `IPReputation.score()`.
- With `AEGEX_SIMULATE_NETWORK=false` and nothing pushed, features 4 to 8 are mock values.

### Plug in the AI models (the skipped part)
Turn on the hook: `AEGEX_KAFKA_ENABLED=true`, `AEGEX_KAFKA_BOOTSTRAP=kafka:9092` for the pipeline service.

- **LSTM autoencoder, variational autoencoder:** consume `aegex.detection.features`. The field `window` is a list of up to 20 vectors of 8 numbers (0 to 1), oldest first; `vector` is the newest one.
- **Temporal GAT:** consume `aegex.detection.graph` (`edges` with `src`, `dst`, `count`, `failed`); keep your own history of graphs.
- **Results:** write them back to a new Kafka topic or a new table, and add an API route and a dashboard card. `attack_analyses.ground_truth` and the labeled Elasticsearch documents are the training and evaluation labels for the **continuous learning / feedback loop**.
- **Attack analysis:** model output can replace or be combined with `AttackAnalyzer`; keep the same dictionary keys so the table, API, report and dashboard keep working.
- **Kafka caveat:** the `kafka` service uses the image defaults. Containers on the Compose network may be told to reconnect to `localhost:9092`, which fails. If the pipeline logs Kafka connection errors, set `KAFKA_ADVERTISED_LISTENERS` (an internal `kafka:9092` listener) on the service. This was not tested here.

### Replace the keyword retriever and add a RAG-LLM
`KnowledgeRetriever.search()` is the only place that returns knowledge-base hits. Swap its internals for an embedding model and a vector store; the API and the report do not change. A RAG-LLM would take the report's findings plus the retrieved entries and write the narrative; `build_report()` already assembles that grounded context.

### Grow the knowledge base
Append `KBEntry` objects in `knowledge_base.py`. For live data, write a loader that fills `KNOWLEDGE_BASE` from the NVD API, the MITRE ATT&CK STIX files, and a threat feed. The CVE entries shipped here are well-known examples; confirm details in NVD before relying on them.

### Change a database schema
Edit the SQLAlchemy model in `postgres_store.py` **and** `database/schema.sql`. The project has no migration tool: existing tables are not altered by `create_all()`, so either write a migration yourself or run `docker compose down -v` (deletes all data).

## 3. Known limitations

| Area | Limitation |
|---|---|
| Realism | Attackers, normal users and honeypots are simulated. The 100% detection result on simulated data shows the rules match the simulator, not real-world accuracy. |
| Ground-truth leakage | The simulator tags events with `label`, `actor`, `entry_vector`, `honeypot` and (for sensor manipulation) `spoofed`. The analyzer does not use `label` or `spoofed` to decide, but it reads `entry_vector`, `honeypot` and `label` from the tags to fill its output fields, and Elasticsearch uses `label` as a severity floor. Real traffic would not have them. |
| Blocklist dependence | Many attack signals require the source IP to be on the blocklist. An unlisted attacker triggers fewer signals and may not be detected. |
| One attack per window | The simulator creates at most one scenario per window, and the analyzer reports one category per window, so overlapping attacks are not handled. |
| Duplicates on replay | Batch ids are random per run, so re-running `main.py` on the same CSV inserts the rows again. Making the id a hash of the row content would fix this. |
| Time handling | By default every batch is stamped with the ingestion time, not the CSV time. |
| Mock features | A window with no network events gets mock network features (`feature_source = mock`). Filter on that flag before training models. |
| Media layer | Only metadata (frame rate, bitrate, authenticated), no actual video, image or audio. |
| Event store | Elasticsearch, PostgreSQL and object storage together, not one store. |
| Dead letters | Failed payloads are saved but never replayed automatically. |
| Reports | Template-based; the same finding always reads the same way. |
| Knowledge base | 45 seed entries, not synchronised with MITRE, NVD or any threat feed. The IOC IPs are documentation-range placeholders. |
| Dashboard | One static page, no login, polling every 5 seconds, Chart.js loaded from a CDN. |
| Tests | No tests for the storage layer, the API against live databases, or the dashboard. |
| Kafka | Included in Compose but disabled and untested. |

## 4. Before using this outside a lab

1. Change every default password (`aegex/aegex`, `minioadmin`) and keep secrets out of `docker-compose.yml`.
2. Turn on Elasticsearch security (`xpack.security.enabled`), set `AEGEX_ES_API_KEY`, and use TLS for all services.
3. Use a real MinIO or S3 bucket with Object Lock (`AEGEX_MINIO_OBJECT_LOCK=true`).
4. Put authentication in front of the API and dashboard, and replace `allow_origins=["*"]`.
5. Do not publish the database ports (5432, 9200, 9000, 9333, 9092) to the host.
6. Add Elasticsearch index lifecycle management (retention) and PostgreSQL backups.
7. Replace the mock IP reputation and blocklist with a real feed.
8. Make batch ids deterministic and add a replay script for the dead-letter file.
9. Run honeypots on an isolated network. A honeypot is deliberately attackable.
