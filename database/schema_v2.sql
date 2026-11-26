-- =====================================================================================================
-- AEGEX v2 - unified datastore schema (Task 5)
-- PostgreSQL 16 + TimescaleDB 2.x
--
-- One schema for every event from every device. Replaces the v1 split across PostgreSQL + Elasticsearch
-- + MinIO (database/schema.sql). Human-readable explanation: contracts/TASK_B_CONTRACT.md
--
-- Ownership:  B writes devices/captures/events/flows/feature_windows, A fills attack_runs (via B's API),
--             D writes model_versions + alerts, E writes reports.
--
-- TimescaleDB rule: on a hypertable, every PRIMARY KEY / UNIQUE constraint must include the time column.
-- That is why events/flows/feature_windows use (id, ts) keys, and why other tables store their ids
-- without a FOREIGN KEY to them.
-- =====================================================================================================

CREATE EXTENSION IF NOT EXISTS timescaledb;
CREATE EXTENSION IF NOT EXISTS pgcrypto;          -- gen_random_uuid()


-- -----------------------------------------------------------------------------------------------------
-- 1. devices: every honeypot device and the gateway (small, regular table)
-- -----------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS devices (
    device_id     TEXT PRIMARY KEY,                               -- e.g. 'esp32-smoke-01', 'cam-01', 'gw-01'
    device_type   TEXT NOT NULL CHECK (device_type IN ('esp32_sensor', 'ip_camera', 'gateway', 'other')),
    ip            INET,
    mac           MACADDR,
    is_virtual    BOOLEAN NOT NULL DEFAULT FALSE,                 -- TRUE for the VM gateway ("virtual Raspberry Pi")
    platform      TEXT,                                           -- e.g. 'virtualbox-debian12', 'rpi4', 'esp32-devkit'
    description   TEXT,
    monitored     BOOLEAN NOT NULL DEFAULT TRUE,                  -- FALSE: a known lab machine, not a honeypot (e.g. the
                                                                  -- laptop hotspot): no feature windows, but its IP still counts as "ours"
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
-- Databases created before `monitored` existed get the column here (safe to run again).
ALTER TABLE devices ADD COLUMN IF NOT EXISTS monitored BOOLEAN NOT NULL DEFAULT TRUE;


-- -----------------------------------------------------------------------------------------------------
-- 2. captures: one row per recording session (start tcpdump/Zeek ... stop).
--    Used to (a) know which time ranges were actually observed, so empty windows inside a capture are
--    real zeros and gaps between captures are not, and (b) split train/test by whole sessions.
-- -----------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS captures (
    capture_id    TEXT PRIMARY KEY,                               -- e.g. 'cap-2026-11-20-a'
    start_ts      TIMESTAMPTZ NOT NULL,
    end_ts        TIMESTAMPTZ,                                    -- NULL while still recording (live)
    kind          TEXT NOT NULL DEFAULT 'mixed' CHECK (kind IN ('normal_only', 'attack', 'mixed', 'live')),
    pcap_path     TEXT,                                           -- where the raw pcap lives (file/object storage)
    notes         TEXT,
    CHECK (end_ts IS NULL OR end_ts > start_ts)
);


-- -----------------------------------------------------------------------------------------------------
-- 3. attack_runs: Task A's attack log, the ground truth for labeling.
--    One row per executed attack (e.g. "hydra ssh bruteforce from Kali, 10:05:00 - 10:12:30").
-- -----------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS attack_runs (
    run_id        TEXT PRIMARY KEY,                               -- e.g. 'run-017'
    capture_id    TEXT REFERENCES captures (capture_id),
    scenario      TEXT NOT NULL CHECK (scenario IN (
                      'vulnerability_scanning', 'bruteforce', 'dos', 'mirai_botnet', 'mqtt_spoofing',
                      'sensor_manipulation', 'unauthorized_camera_access', 'ransomware', 'other')),
    tool          TEXT,                                           -- nmap, hydra, hping3, mosquitto_pub, custom script ...
    command       TEXT,                                           -- exact command that was run (reproducibility)
    attacker_ip   INET NOT NULL,
    target_device TEXT REFERENCES devices (device_id),
    start_ts      TIMESTAMPTZ NOT NULL,
    end_ts        TIMESTAMPTZ NOT NULL,
    notes         TEXT,
    CHECK (end_ts > start_ts)
);
CREATE INDEX IF NOT EXISTS ix_attack_runs_time ON attack_runs (start_ts, end_ts);
CREATE INDEX IF NOT EXISTS ix_attack_runs_ip   ON attack_runs (attacker_ip);


-- -----------------------------------------------------------------------------------------------------
-- 4. events: THE unified event table. Every log line / message / reading from every source lands here.
--    Common fields are real columns (fast filters); source-specific fields stay in payload JSONB.
-- -----------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS events (
    event_id      UUID        NOT NULL DEFAULT gen_random_uuid(),
    ts            TIMESTAMPTZ NOT NULL,                           -- when it happened (source clock, UTC)
    ingested_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    source        TEXT NOT NULL CHECK (source IN ('zeek', 'suricata', 'cowrie', 'mosquitto', 'mqtt', 'esp32',
                                                  'camera', 'ble', 'syslog', 'other')),
    event_type    TEXT NOT NULL,                                  -- see contracts/feature_contract.json -> event_types
    layer         TEXT NOT NULL CHECK (layer IN ('network_traffic', 'device_service_logs',
                                                 'session_interaction', 'telemetry_media')),
    device_id     TEXT REFERENCES devices (device_id),            -- honeypot device involved (NULL if unknown)
    capture_id    TEXT REFERENCES captures (capture_id),
    src_ip        INET,
    src_port      INTEGER CHECK (src_port BETWEEN 0 AND 65535),
    dst_ip        INET,
    dst_port      INTEGER CHECK (dst_port BETWEEN 0 AND 65535),
    proto         TEXT,                                           -- tcp | udp | icmp | ...
    severity      TEXT CHECK (severity IN ('info', 'low', 'medium', 'high', 'critical')),
    -- labels (NULL = unlabeled, e.g. live traffic)
    label         SMALLINT CHECK (label IN (0, 1)),               -- 0 normal, 1 attack
    scenario      TEXT,                                           -- attack_runs.scenario when label = 1
    run_id        TEXT,                                           -- attack_runs.run_id when label = 1
    dedup_key     TEXT,                                           -- hash of (source, raw line) so replays don't duplicate
    payload       JSONB NOT NULL DEFAULT '{}'::jsonb,             -- everything else, as parsed from the source
    PRIMARY KEY (event_id, ts)
);
SELECT create_hypertable('events', 'ts', chunk_time_interval => INTERVAL '1 day', if_not_exists => TRUE);
CREATE INDEX IF NOT EXISTS ix_events_device_ts ON events (device_id, ts DESC);
CREATE INDEX IF NOT EXISTS ix_events_src_ts    ON events (src_ip, ts DESC);
CREATE INDEX IF NOT EXISTS ix_events_type_ts   ON events (event_type, ts DESC);
CREATE INDEX IF NOT EXISTS ix_events_label_ts  ON events (label, ts DESC) WHERE label IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS ux_events_dedup ON events (dedup_key, ts) WHERE dedup_key IS NOT NULL;


-- -----------------------------------------------------------------------------------------------------
-- 5. flows: one row per network connection (Zeek conn.log or CICFlowMeter).
--    Raw values in columns; the model-ready vector (41 dims, see contract) in features JSONB.
--    These rows are also the edges for the Temporal GAT (Task D).
-- -----------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS flows (
    flow_id         TEXT        NOT NULL,                         -- stable id: hash of (start time, proto, 5-tuple), same on every Zeek run
    zeek_uid        TEXT,                                         -- Zeek's own uid (random per run); joins to ssh.log, http.log, ...
    ts_start        TIMESTAMPTZ NOT NULL,
    ts_end          TIMESTAMPTZ,
    capture_id      TEXT REFERENCES captures (capture_id),
    device_id       TEXT REFERENCES devices (device_id),          -- the honeypot device on either end, if any
    src_ip          INET NOT NULL,
    src_port        INTEGER,
    dst_ip          INET NOT NULL,
    dst_port        INTEGER,
    proto           TEXT NOT NULL,
    service         TEXT,
    conn_state      TEXT,
    history         TEXT,
    duration_s      DOUBLE PRECISION,
    orig_bytes      BIGINT,
    resp_bytes      BIGINT,
    orig_pkts       BIGINT,
    resp_pkts       BIGINT,
    features        JSONB,                                        -- the 41 flow features by name, after fill + log1p, NOT scaled (the step 9 scaler goes on top)
    feature_version TEXT,                                         -- contract version that produced `features`
    label           SMALLINT CHECK (label IN (0, 1)),
    scenario        TEXT,
    run_id          TEXT,
    PRIMARY KEY (flow_id, ts_start)
);
SELECT create_hypertable('flows', 'ts_start', chunk_time_interval => INTERVAL '1 day', if_not_exists => TRUE);
CREATE INDEX IF NOT EXISTS ix_flows_src_ts    ON flows (src_ip, ts_start DESC);
CREATE INDEX IF NOT EXISTS ix_flows_dst_ts    ON flows (dst_ip, ts_start DESC);
CREATE INDEX IF NOT EXISTS ix_flows_device_ts ON flows (device_id, ts_start DESC);


-- -----------------------------------------------------------------------------------------------------
-- 6. feature_windows: one row per (device, 10-second window). Input for LSTM-AE / VAE (Task C).
-- -----------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS feature_windows (
    window_start    TIMESTAMPTZ NOT NULL,
    window_end      TIMESTAMPTZ NOT NULL,
    entity_type     TEXT NOT NULL DEFAULT 'device' CHECK (entity_type IN ('device', 'src_ip')),
    entity_id       TEXT NOT NULL,                                -- device_id (or IP text when entity_type = 'src_ip')
    capture_id      TEXT REFERENCES captures (capture_id),
    feature_version TEXT NOT NULL,
    features_raw    JSONB NOT NULL,                               -- before log1p/scaling (for debugging + dashboard)
    features        JSONB NOT NULL,                               -- keyed by name, after log1p, NOT scaled (step 9 scaler on top)
    n_events        INTEGER NOT NULL DEFAULT 0,                   -- flows + events touching the entity (0 = silent window)
    label           SMALLINT CHECK (label IN (0, 1)),             -- 1 if any attack event/flow hit this entity in the window
    scenario        TEXT,
    run_id          TEXT,
    PRIMARY KEY (entity_type, entity_id, window_start, feature_version)
);
SELECT create_hypertable('feature_windows', 'window_start', chunk_time_interval => INTERVAL '7 days', if_not_exists => TRUE);
CREATE INDEX IF NOT EXISTS ix_fw_entity_ts ON feature_windows (entity_id, window_start DESC);


-- -----------------------------------------------------------------------------------------------------
-- 7. model_versions: registry mirror of MLflow (Task D writes, everyone reads).
-- -----------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS model_versions (
    model_name      TEXT NOT NULL CHECK (model_name IN ('lstm_ae', 'vae', 'temporal_gat', 'rules', 'other')),
    version         TEXT NOT NULL,                                -- e.g. '3' (MLflow version) or '2026-11-20'
    feature_version TEXT NOT NULL,                                -- MUST match the contract the model was trained on
    mlflow_run_id   TEXT,
    threshold       DOUBLE PRECISION,                             -- anomaly threshold chosen on validation data
    metrics         JSONB NOT NULL DEFAULT '{}'::jsonb,           -- precision, recall, f1, roc_auc, ...
    is_active       BOOLEAN NOT NULL DEFAULT FALSE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (model_name, version)
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_model_one_active ON model_versions (model_name) WHERE is_active;


-- -----------------------------------------------------------------------------------------------------
-- 8. alerts: model outputs (Task D's inference endpoint writes, Task E reads).
--    Regular table: low volume, needs a simple PK so reports can reference it.
-- -----------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS alerts (
    alert_id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    ts                 TIMESTAMPTZ NOT NULL DEFAULT now(),        -- when the alert was raised
    model_name         TEXT NOT NULL,
    model_version      TEXT NOT NULL,
    feature_version    TEXT NOT NULL,
    entity_type        TEXT NOT NULL CHECK (entity_type IN ('device', 'src_ip', 'flow', 'subgraph')),
    entity_id          TEXT NOT NULL,
    device_id          TEXT REFERENCES devices (device_id),
    src_ips            INET[] NOT NULL DEFAULT '{}',
    window_start       TIMESTAMPTZ,
    window_end         TIMESTAMPTZ,
    score              DOUBLE PRECISION NOT NULL,                 -- reconstruction error / probability / attention score
    threshold          DOUBLE PRECISION,
    is_anomaly         BOOLEAN NOT NULL,
    predicted_scenario TEXT,                                      -- NULL for pure anomaly detectors
    severity           TEXT CHECK (severity IN ('low', 'medium', 'high', 'critical')),
    evidence           JSONB NOT NULL DEFAULT '{}'::jsonb,        -- top features, flow_ids, event_ids, attention edges
    status             TEXT NOT NULL DEFAULT 'new' CHECK (status IN ('new', 'triaged', 'reported', 'confirmed', 'false_positive')),
    analyst_label      SMALLINT CHECK (analyst_label IN (0, 1)),  -- human feedback -> retraining (Task 13)
    FOREIGN KEY (model_name, model_version) REFERENCES model_versions (model_name, version)
);
CREATE INDEX IF NOT EXISTS ix_alerts_ts     ON alerts (ts DESC);
CREATE INDEX IF NOT EXISTS ix_alerts_status ON alerts (status, ts DESC);
CREATE INDEX IF NOT EXISTS ix_alerts_device ON alerts (device_id, ts DESC);


-- -----------------------------------------------------------------------------------------------------
-- 9. reports: grounded LLM reports (Task E writes through B's API).
-- -----------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS reports (
    report_id     UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    alert_id      UUID NOT NULL REFERENCES alerts (alert_id) ON DELETE CASCADE,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    llm_model     TEXT NOT NULL,                                  -- e.g. 'gemma3:4b'
    attack_type   TEXT,
    mitre_ids     TEXT[] NOT NULL DEFAULT '{}',                   -- e.g. {T1110, T1046}
    summary       TEXT NOT NULL,
    body_markdown TEXT NOT NULL,
    citations     JSONB NOT NULL DEFAULT '[]'::jsonb,             -- [{"source": "mitre_attack", "id": "T1110", "chunk_id": "..."}]
    abstained     BOOLEAN NOT NULL DEFAULT FALSE                  -- true when evidence was too weak to answer
);
CREATE INDEX IF NOT EXISTS ix_reports_alert ON reports (alert_id);


-- =====================================================================================================
-- Labeling helpers: run after each capture is loaded and attack_runs is filled.
-- Rule (see contract -> labeling): a flow/event is an attack if the attacker IP is on either end and it
-- starts inside the run's [start_ts, end_ts]. Everything else inside a capture is normal (0).
-- =====================================================================================================
CREATE OR REPLACE PROCEDURE label_capture(p_capture_id TEXT)
LANGUAGE plpgsql AS $$
BEGIN
    -- reset, so re-labeling after fixing attack_runs is safe
    UPDATE flows  SET label = 0, scenario = NULL, run_id = NULL WHERE capture_id = p_capture_id;
    UPDATE events SET label = 0, scenario = NULL, run_id = NULL WHERE capture_id = p_capture_id;

    UPDATE flows f
       SET label = 1, scenario = r.scenario, run_id = r.run_id
      FROM attack_runs r
     WHERE f.capture_id = p_capture_id
       AND (f.src_ip = r.attacker_ip OR f.dst_ip = r.attacker_ip)
       AND f.ts_start BETWEEN r.start_ts AND r.end_ts;

    UPDATE events e
       SET label = 1, scenario = r.scenario, run_id = r.run_id
      FROM attack_runs r
     WHERE e.capture_id = p_capture_id
       AND (e.src_ip = r.attacker_ip OR e.dst_ip = r.attacker_ip)
       AND e.ts BETWEEN r.start_ts AND r.end_ts;
END;
$$;

-- Quick sanity view: how much labeled data exists per scenario and capture.
CREATE OR REPLACE VIEW v_label_summary AS
SELECT capture_id, COALESCE(scenario, 'normal') AS scenario, label, count(*) AS n_flows,
       min(ts_start) AS first_ts, max(ts_start) AS last_ts
  FROM flows
 WHERE label IS NOT NULL
 GROUP BY capture_id, COALESCE(scenario, 'normal'), label;


-- =====================================================================================================
-- Optional (enable once data grows): compress raw events older than 7 days.
-- ALTER TABLE events SET (timescaledb.compress, timescaledb.compress_segmentby = 'device_id');
-- SELECT add_compression_policy('events', INTERVAL '7 days');
-- =====================================================================================================
