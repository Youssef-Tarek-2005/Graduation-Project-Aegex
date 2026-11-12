"""Central configuration. Every value can be overridden with an environment variable."""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


def _s(name: str, default: str) -> str:
    return os.getenv(name, default)


def _f(name: str, default: float) -> float:
    return float(os.getenv(name, default))


def _i(name: str, default: int) -> int:
    return int(os.getenv(name, default))


def _b(name: str, default: bool) -> bool:
    return os.getenv(name, str(default)).strip().lower() in {"1", "true", "yes", "on"}


# Mock "known bad" attacker IPs (RFC 5737 documentation ranges, so they can never be real hosts).
MOCK_BAD_IPS = ("203.0.113.45", "198.51.100.23", "192.0.2.77", "203.0.113.150", "198.51.100.200")


@dataclass(frozen=True)
class Settings:
    # ---- Task 1: ingestion -------------------------------------------------
    csv_path: Path = Path(_s("AEGEX_CSV_PATH", "~/Desktop/my_data.csv")).expanduser()
    replay_speed: float = _f("AEGEX_REPLAY_SPEED", 1.0)       # 1 = real time via esp_ms deltas, 0 = no sleeping
    follow_csv: bool = _b("AEGEX_FOLLOW_CSV", False)           # True = `tail -f` the CSV forever
    poll_interval: float = _f("AEGEX_POLL_INTERVAL", 1.0)
    default_interval: float = _f("AEGEX_DEFAULT_INTERVAL", 1.0)  # used when esp_ms is unusable
    max_sleep: float = _f("AEGEX_MAX_SLEEP", 5.0)
    time_mode: str = _s("AEGEX_TIME_MODE", "ingest")           # 'ingest' = stamp with now(); 'csv' = use CSV `time`
    simulate_network: bool = _b("AEGEX_SIMULATE_NETWORK", True)
    attack_probability: float = _f("AEGEX_ATTACK_PROB", 0.15)
    sim_seed: int = _i("AEGEX_SIM_SEED", 42)

    # ---- Task 2: preprocessing --------------------------------------------
    smoke_max: float = _f("AEGEX_SMOKE_MAX", 4095.0)           # 12-bit ESP32 ADC; set 1023 for a 10-bit scale
    temp_min: float = _f("AEGEX_TEMP_MIN", -40.0)              # DHT22 range
    temp_max: float = _f("AEGEX_TEMP_MAX", 80.0)
    ip_blocklist_path: str = _s("AEGEX_IP_BLOCKLIST", "")      # optional file: one IP per line
    honeypot_device_id: str = _s("AEGEX_DEVICE_ID", "honeypot-01")

    # ---- Task 3: storage ---------------------------------------------------
    postgres_url: str = _s("AEGEX_POSTGRES_URL", "postgresql+psycopg2://aegex:aegex@localhost:5432/aegex")
    minio_endpoint: str = _s("AEGEX_MINIO_ENDPOINT", "localhost:9000")
    minio_access_key: str = _s("AEGEX_MINIO_ACCESS_KEY", "minioadmin")
    minio_secret_key: str = _s("AEGEX_MINIO_SECRET_KEY", "minioadmin")
    minio_secure: bool = _b("AEGEX_MINIO_SECURE", False)
    minio_bucket: str = _s("AEGEX_MINIO_BUCKET", "aegex-cold-storage")
    minio_object_lock: bool = _b("AEGEX_MINIO_OBJECT_LOCK", True)
    minio_retention_days: int = _i("AEGEX_MINIO_RETENTION_DAYS", 30)
    archive_batch_size: int = _i("AEGEX_ARCHIVE_BATCH", 200)
    archive_flush_seconds: float = _f("AEGEX_ARCHIVE_FLUSH_S", 10.0)
    es_url: str = _s("AEGEX_ES_URL", "http://localhost:9200")
    es_api_key: str = _s("AEGEX_ES_API_KEY", "")
    es_prefix: str = _s("AEGEX_ES_PREFIX", "aegex")
    es_batch_size: int = _i("AEGEX_ES_BATCH", 100)
    es_flush_seconds: float = _f("AEGEX_ES_FLUSH_S", 5.0)

    # ---- Task 5: hand-off to the Multi-Stage Detection Layer ---------------
    kafka_enabled: bool = _b("AEGEX_KAFKA_ENABLED", True)
    kafka_bootstrap: str = _s("AEGEX_KAFKA_BOOTSTRAP", "localhost:9092")
    kafka_topic_features: str = _s("AEGEX_KAFKA_TOPIC_FEATURES", "aegex.detection.features")  # LSTM / VAE / AE
    kafka_topic_graph: str = _s("AEGEX_KAFKA_TOPIC_GRAPH", "aegex.detection.graph")           # Temporal GAT
    webhook_urls: str = _s("AEGEX_WEBHOOK_URLS", "")           # comma-separated, optional
    window_size: int = _i("AEGEX_WINDOW_SIZE", 20)             # sequence length for LSTM-style consumers

    # ---- Real honeypot feeds (Cowrie, Zeek, Mosquitto) ----------------------
    feeds_enabled: bool = _b("AEGEX_FEEDS_ENABLED", False)     # master switch; compose turns it on
    feeds_from_start: bool = _b("AEGEX_FEEDS_FROM_START", True)  # False = only new log lines; True = replay existing logs
    feeds_poll_interval: float = _f("AEGEX_FEEDS_POLL_INTERVAL", 1.0)
    cowrie_log_path: str = _s("AEGEX_COWRIE_LOG", "/feeds/cowrie/cowrie.json")
    zeek_log_dir: str = _s("AEGEX_ZEEK_LOG_DIR", "/feeds/zeek")  # conn.log and notice.log are read from here (JSON format)
    mosquitto_log_path: str = _s("AEGEX_MOSQUITTO_LOG", "/feeds/mosquitto/mosquitto.log")
    mqtt_host: str = _s("AEGEX_MQTT_HOST", "")                 # empty = do not subscribe to the broker
    mqtt_port: int = _i("AEGEX_MQTT_PORT", 1883)
    mqtt_topic: str = _s("AEGEX_MQTT_TOPIC", "#")
    mqtt_client_id: str = _s("AEGEX_MQTT_CLIENT_ID", "aegex-pipeline")

    # ---- Orchestration -----------------------------------------------------
    dead_letter_path: Path = Path(_s("AEGEX_DEAD_LETTER", "dead_letter.ndjson"))
    log_level: str = _s("AEGEX_LOG_LEVEL", "INFO")


def get_settings() -> Settings:
    return Settings()
