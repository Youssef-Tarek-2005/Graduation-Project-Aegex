-- AEGEX PostgreSQL schema (mirrors the SQLAlchemy models in aegex/storage/postgres_store.py).
-- Auto-applied by docker-compose; SQLAlchemy create_all() is also safe to run (IF NOT EXISTS semantics).

CREATE TABLE IF NOT EXISTS sensor_readings (
    id             BIGSERIAL PRIMARY KEY,
    batch_id       VARCHAR(64)      NOT NULL UNIQUE,          -- idempotency key
    ts             TIMESTAMPTZ      NOT NULL,                 -- event time used by the dashboard
    source_time    VARCHAR(64),                               -- original `time` string from the CSV
    esp_ms         BIGINT,
    smoke          DOUBLE PRECISION NOT NULL,
    temperature_c  DOUBLE PRECISION NOT NULL,                 -- CSV column `tempeture`
    humidity_pct   DOUBLE PRECISION NOT NULL,
    was_imputed    BOOLEAN          NOT NULL DEFAULT FALSE,
    created_at     TIMESTAMPTZ      NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS ix_sensor_readings_ts ON sensor_readings (ts DESC);

CREATE TABLE IF NOT EXISTS feature_vectors (
    id                   BIGSERIAL PRIMARY KEY,
    batch_id             VARCHAR(64)      NOT NULL UNIQUE REFERENCES sensor_readings(batch_id) ON DELETE CASCADE,
    ts                   TIMESTAMPTZ      NOT NULL,
    network_packet_size  DOUBLE PRECISION NOT NULL,
    login_attempts       INTEGER          NOT NULL,
    session_duration     DOUBLE PRECISION NOT NULL,
    ip_reputation_score  DOUBLE PRECISION NOT NULL,           -- 0 = clean, 1 = known bad
    failed_logins        INTEGER          NOT NULL,
    features_normalized  JSONB            NOT NULL,           -- model-ready vector (0..1) keyed by feature name
    feature_source       VARCHAR(16)      NOT NULL,           -- 'observed' | 'mock'
    quality              JSONB            NOT NULL DEFAULT '{}'::jsonb,
    created_at           TIMESTAMPTZ      NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS ix_feature_vectors_ts ON feature_vectors (ts DESC);

CREATE TABLE IF NOT EXISTS attack_analyses (
    id            BIGSERIAL PRIMARY KEY,
    batch_id      VARCHAR(64)      NOT NULL UNIQUE,
    ts            TIMESTAMPTZ      NOT NULL,
    category      VARCHAR(48)      NOT NULL,                  -- vulnerability_scanning | ddos | mirai_botnet | ransomware | ...
    severity      VARCHAR(16)      NOT NULL,                  -- low | medium | high | critical
    confidence    DOUBLE PRECISION NOT NULL,                  -- share of the scenario's signatures observed (rule-based)
    src_ips       JSONB            NOT NULL DEFAULT '[]'::jsonb,
    entry_vector  VARCHAR(16)      NOT NULL DEFAULT 'unknown', -- wifi | bluetooth
    honeypot      VARCHAR(32)      NOT NULL DEFAULT 'unknown', -- sensor_honeypot | camera_honeypot
    signals       JSONB            NOT NULL DEFAULT '[]'::jsonb,
    mitre         JSONB            NOT NULL DEFAULT '[]'::jsonb,
    ground_truth  VARCHAR(48),                                -- simulator label, evaluation only
    created_at    TIMESTAMPTZ      NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS ix_attack_analyses_ts ON attack_analyses (ts DESC);
CREATE INDEX IF NOT EXISTS ix_attack_analyses_category ON attack_analyses (category);
