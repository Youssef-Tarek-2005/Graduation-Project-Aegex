-- =====================================================================================================
-- Step 2: sample data, typed by hand.
--
-- The story: on 20 Nov 2026, A records traffic from 14:00 to 15:00. The devices behave normally, then
-- from 14:10 to 14:18 A runs an SSH password-guessing attack (hydra) from Kali against the virtual Pi.
--
-- Run it:  docker exec -i aegex-db psql -U aegex -d aegex -v ON_ERROR_STOP=1 < backend/sql/step2_sample_data.sql
--
-- Safe to run more than once: every INSERT uses ON CONFLICT DO NOTHING, so a second run adds nothing.
-- All times are UTC ("+00").
-- =====================================================================================================

BEGIN;

-- -----------------------------------------------------------------------------------------------------
-- Group 1: who and when
-- -----------------------------------------------------------------------------------------------------

-- The honeypot devices. gw-01 is the virtual Raspberry Pi.
INSERT INTO devices (device_id, device_type, ip, mac, is_virtual, platform, description) VALUES
    ('gw-01',          'gateway',      '192.168.56.10', '08:00:27:aa:00:10', TRUE,  'virtualbox-debian12', 'Virtual Pi: Cowrie SSH honeypot + Mosquitto + Zeek'),
    ('esp32-smoke-01', 'esp32_sensor', '192.168.56.20', '24:6f:28:aa:00:20', FALSE, 'esp32-devkit',        'Smoke / temperature / humidity sensor'),
    ('cam-01',         'ip_camera',    '192.168.56.30', 'a4:14:37:aa:00:30', FALSE, NULL,                  'IP camera honeypot (RTSP)')
ON CONFLICT (device_id) DO NOTHING;

-- One recording session.
INSERT INTO captures (capture_id, start_ts, end_ts, kind, pcap_path, notes) VALUES
    ('cap-2026-11-20-a', '2026-11-20 14:00:00+00', '2026-11-20 15:00:00+00', 'mixed',
     'pcaps/cap-2026-11-20-a.pcap', 'Sample capture for step 2: normal traffic + one SSH brute force')
ON CONFLICT (capture_id) DO NOTHING;

-- A's attack log: the answer key for labeling.
INSERT INTO attack_runs (run_id, capture_id, scenario, tool, command, attacker_ip, target_device, start_ts, end_ts) VALUES
    ('run-001', 'cap-2026-11-20-a', 'bruteforce', 'hydra',
     'hydra -l root -P passwords.txt ssh://192.168.56.10',
     '192.168.56.99', 'gw-01', '2026-11-20 14:10:00+00', '2026-11-20 14:18:00+00')
ON CONFLICT (run_id) DO NOTHING;


-- -----------------------------------------------------------------------------------------------------
-- Group 2: what happened
-- label is left empty (NULL) on purpose. label_capture fills it in at the end.
-- dedup_key is normally a hash of the original log line; here it is a readable name.
-- -----------------------------------------------------------------------------------------------------

INSERT INTO events (ts, source, event_type, layer, device_id, capture_id, src_ip, src_port, dst_ip, dst_port, proto, severity, dedup_key, payload) VALUES
    -- normal: the sensor reads and publishes over MQTT, the camera streams
    ('2026-11-20 14:05:00+00', 'esp32',     'sensor_reading', 'telemetry_media',     'esp32-smoke-01', 'cap-2026-11-20-a', '192.168.56.20', NULL,  NULL,            NULL, NULL,  'info',     'sample-ev-01', '{"smoke": 12, "temperature_c": 24.1, "humidity_pct": 41.0}'),
    ('2026-11-20 14:05:00+00', 'mosquitto', 'mqtt_publish',   'device_service_logs', 'gw-01',          'cap-2026-11-20-a', '192.168.56.20', 50112, '192.168.56.10', 1883, 'tcp', 'info',     'sample-ev-02', '{"topic": "aegex/sensors/smoke", "payload_bytes": 58}'),
    ('2026-11-20 14:06:00+00', 'camera',    'media_stream',   'telemetry_media',     'cam-01',         'cap-2026-11-20-a', '192.168.56.30', 554,   '192.168.56.1',  51020, 'tcp', 'info',    'sample-ev-03', '{"protocol": "rtsp", "seconds": 30}'),

    -- attack: hydra guesses passwords, gets in, runs commands, downloads malware
    ('2026-11-20 14:10:03+00', 'cowrie',    'session_open',   'session_interaction', 'gw-01',          'cap-2026-11-20-a', '192.168.56.99', 40122, '192.168.56.10', 22,   'tcp', 'low',      'sample-ev-04', '{"session": "a1b2c3", "client_version": "SSH-2.0-libssh"}'),
    ('2026-11-20 14:10:04+00', 'cowrie',    'login_failed',   'session_interaction', 'gw-01',          'cap-2026-11-20-a', '192.168.56.99', 40122, '192.168.56.10', 22,   'tcp', 'medium',   'sample-ev-05', '{"session": "a1b2c3", "username": "root", "password": "1234"}'),
    ('2026-11-20 14:10:06+00', 'cowrie',    'login_failed',   'session_interaction', 'gw-01',          'cap-2026-11-20-a', '192.168.56.99', 40124, '192.168.56.10', 22,   'tcp', 'medium',   'sample-ev-06', '{"session": "a1b2c4", "username": "root", "password": "admin"}'),
    ('2026-11-20 14:12:40+00', 'cowrie',    'login_success',  'session_interaction', 'gw-01',          'cap-2026-11-20-a', '192.168.56.99', 40188, '192.168.56.10', 22,   'tcp', 'high',     'sample-ev-07', '{"session": "a1b2d9", "username": "root", "password": "raspberry"}'),
    ('2026-11-20 14:13:05+00', 'cowrie',    'command',        'session_interaction', 'gw-01',          'cap-2026-11-20-a', '192.168.56.99', 40188, '192.168.56.10', 22,   'tcp', 'high',     'sample-ev-08', '{"session": "a1b2d9", "input": "uname -a"}'),
    ('2026-11-20 14:13:20+00', 'cowrie',    'file_download',  'session_interaction', 'gw-01',          'cap-2026-11-20-a', '192.168.56.99', 40188, '192.168.56.10', 22,   'tcp', 'critical', 'sample-ev-09', '{"session": "a1b2d9", "url": "http://192.168.56.99/bot.arm", "sha256": "e3b0c442..."}'),

    -- normal again: the sensor keeps reading after the attack
    ('2026-11-20 14:25:00+00', 'esp32',     'sensor_reading', 'telemetry_media',     'esp32-smoke-01', 'cap-2026-11-20-a', '192.168.56.20', NULL,  NULL,            NULL, NULL,  'info',     'sample-ev-10', '{"smoke": 13, "temperature_c": 24.3, "humidity_pct": 40.6}')
ON CONFLICT (dedup_key, ts) WHERE dedup_key IS NOT NULL DO NOTHING;


INSERT INTO flows (flow_id, ts_start, ts_end, capture_id, device_id, src_ip, src_port, dst_ip, dst_port, proto, service, conn_state, history, duration_s, orig_bytes, resp_bytes, orig_pkts, resp_pkts) VALUES
    -- normal
    ('Csample01', '2026-11-20 14:05:00+00', '2026-11-20 14:05:00.4+00', 'cap-2026-11-20-a', 'esp32-smoke-01', '192.168.56.20', 50112, '192.168.56.10', 1883,  'tcp', 'mqtt', 'SF', 'ShADadFf', 0.4,  120,   40,     6,    4),
    ('Csample02', '2026-11-20 14:06:00+00', '2026-11-20 14:06:30+00',   'cap-2026-11-20-a', 'cam-01',         '192.168.56.1',  51020, '192.168.56.30', 554,   'tcp', 'rtsp', 'SF', 'ShADadFf', 30.0, 900,   2400000, 40,   1800),
    -- attack: three SSH connections from the attacker during the run
    ('Csample03', '2026-11-20 14:10:02+00', '2026-11-20 14:10:05.2+00', 'cap-2026-11-20-a', 'gw-01',          '192.168.56.99', 40122, '192.168.56.10', 22,    'tcp', 'ssh',  'SF', 'ShADadFf', 3.2,  1840,  2100,   18,   16),
    ('Csample04', '2026-11-20 14:10:05+00', '2026-11-20 14:10:08.1+00', 'cap-2026-11-20-a', 'gw-01',          '192.168.56.99', 40124, '192.168.56.10', 22,    'tcp', 'ssh',  'SF', 'ShADadFf', 3.1,  1830,  2090,   18,   16),
    ('Csample05', '2026-11-20 14:12:39+00', '2026-11-20 14:13:24+00',   'cap-2026-11-20-a', 'gw-01',          '192.168.56.99', 40188, '192.168.56.10', 22,    'tcp', 'ssh',  'SF', 'ShADadFf', 45.0, 5200,  9800,   60,   55),
    -- normal: the admin (host PC, .1) logs in to the Pi over SSH. Same port 22, but NOT the attacker's IP.
    ('Csample06', '2026-11-20 14:40:00+00', '2026-11-20 14:42:00+00',   'cap-2026-11-20-a', 'gw-01',          '192.168.56.1',  52001, '192.168.56.10', 22,    'tcp', 'ssh',  'SF', 'ShADadFf', 120.0, 3100, 7400,   45,   40)
ON CONFLICT (flow_id, ts_start) DO NOTHING;


-- -----------------------------------------------------------------------------------------------------
-- Labeling: compare every flow and event in this capture with attack_runs.
-- Attacker IP on either end AND inside 14:10-14:18  -> label 1, scenario bruteforce, run_id run-001.
-- Everything else in the capture                    -> label 0 (normal).
-- -----------------------------------------------------------------------------------------------------
CALL label_capture('cap-2026-11-20-a');

COMMIT;
