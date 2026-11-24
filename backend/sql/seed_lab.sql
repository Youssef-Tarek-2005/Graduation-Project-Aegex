-- =====================================================================================================
-- The lab inventory: devices, the sample capture, and its attack run (group 1 of the schema).
-- From step 4 on, events come from the parsers + loader instead of being typed by hand, but these rows
-- still have to exist first, because every event points at a device and a capture.
--
-- Run it:  docker exec -i aegex-db psql -U aegex -d aegex -v ON_ERROR_STOP=1 < backend/sql/seed_lab.sql
-- Safe to run more than once.
-- =====================================================================================================

INSERT INTO devices (device_id, device_type, ip, mac, is_virtual, platform, description) VALUES
    ('gw-01',          'gateway',      '192.168.56.10', '08:00:27:aa:00:10', TRUE,  'virtualbox-debian12', 'Virtual Pi: Cowrie SSH honeypot + Mosquitto + Zeek'),
    ('esp32-smoke-01', 'esp32_sensor', '192.168.56.20', '24:6f:28:aa:00:20', FALSE, 'esp32-devkit',        'Smoke / temperature / humidity sensor'),
    ('cam-01',         'ip_camera',    '192.168.56.30', 'a4:14:37:aa:00:30', FALSE, NULL,                  'IP camera honeypot (RTSP)')
ON CONFLICT (device_id) DO NOTHING;

INSERT INTO captures (capture_id, start_ts, end_ts, kind, pcap_path, notes) VALUES
    ('cap-2026-11-20-a', '2026-11-20 14:00:00+00', '2026-11-20 15:00:00+00', 'mixed',
     'pcaps/cap-2026-11-20-a.pcap', 'Sample capture: normal traffic + one SSH brute force')
ON CONFLICT (capture_id) DO NOTHING;

INSERT INTO attack_runs (run_id, capture_id, scenario, tool, command, attacker_ip, target_device, start_ts, end_ts) VALUES
    ('run-001', 'cap-2026-11-20-a', 'bruteforce', 'hydra',
     'hydra -l root -P passwords.txt ssh://192.168.56.10',
     '192.168.56.99', 'gw-01', '2026-11-20 14:10:00+00', '2026-11-20 14:18:00+00')
ON CONFLICT (run_id) DO NOTHING;
