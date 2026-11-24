-- =====================================================================================================
-- The proof-of-concept lab: a Windows laptop (Wi-Fi hotspot + gateway + Wireshark/Zeek + backend) and one
-- ESP32-S3 (the physical honeypot: fake IoT services + the sensors).
--
-- It goes into its OWN database, aegex_poc, so the old sample lab (gw-01, esp32-smoke-01, cam-01 on
-- 192.168.56.x) never mixes with real recordings. Don't run this file by hand: use
--     .venv/Scripts/python -m ingest.poc_db --esp32-ip 192.168.137.57
-- which creates the database, applies schema_v2.sql and this file, and puts in the ESP32's real address.
--
-- Windows Mobile Hotspot always gives itself 192.168.137.1 and hands out 192.168.137.2-254 to clients.
-- The ESP32-S3's address below is a placeholder until ingest.poc_db sets the real one.
-- =====================================================================================================

INSERT INTO devices (device_id, device_type, ip, mac, is_virtual, platform, description, monitored) VALUES
    ('esp32s3-01', 'esp32_sensor', '192.168.137.2', NULL, FALSE, 'esp32-s3',
     'ESP32-S3 honeypot: fake IoT services (Telnet / HTTP login) + smoke, temperature, humidity sensors', TRUE),
    ('laptop-gw',  'gateway',      '192.168.137.1', NULL, FALSE, 'windows-10-hotspot',
     'Windows laptop: Wi-Fi hotspot, gateway, Wireshark capture, Zeek, backend. Not a honeypot: no windows', FALSE)
ON CONFLICT (device_id) DO NOTHING;
