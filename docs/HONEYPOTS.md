# Real honeypots: Cowrie, Zeek, Mosquitto

Three extra containers run next to the pipeline. Each is separate, and the pipeline reads their output and turns it into the same events the simulator produces (see [DATA.md](DATA.md)).

| Container | Image | What it does | Ports (host) | Output the pipeline reads |
|---|---|---|---|---|
| `cowrie` | `cowrie/cowrie:latest` | SSH + Telnet honeypot (fake shell) | 2222 (SSH), 2223 (Telnet) | `cowrie.json` on volume `cowrielogs` |
| `mosquitto` | `eclipse-mosquitto:2` | MQTT decoy broker for the smoke detector, anonymous on purpose | 1883 | `mosquitto.log` on volume `mqttlogs`, plus a live MQTT subscription |
| `zeek` | `zeek/zeek:8.0` | Passive network monitor | none (host network) | `conn.log`, `notice.log` (JSON) on volume `zeeklogs` |

```
attacker --> cowrie    --> cowrie.json   --\
attacker --> mosquitto --> mosquitto.log  ---+--> pipeline (aegex/collection/honeypot_feeds.py) --> collector.submit_event() --> same path as the simulator
attacker --> mosquitto --> MQTT publishes --/
(any traffic) --> zeek --> conn.log / notice.log --/
```

## Run

```bash
cp .env.example .env        # set ZEEK_INTERFACE to a real interface name (ip a)
docker compose up -d --build
docker compose logs -f cowrie mosquitto zeek pipeline
```

Try them (from another machine, or the same one):

```bash
ssh -p 2222 root@<host>                                  # Cowrie: any password; look at the cowrie.json volume
mosquitto_pub -h <host> -p 1883 -t home/smoke/telemetry -m '{"smoke":900}' -i test-client
mosquitto_sub -h <host> -p 1883 -t '#' -v
```

Within a few seconds the events appear in Elasticsearch (`aegex-raw-events-*`) with `source` = `cowrie`, `zeek` or `mosquitto`, and in the dashboard's security events when severity is above info.

## Event mapping

| Source | AEGEX event types |
|---|---|
| Cowrie | `source_ip` (connect), `login_attempt` + `failed_login`, `command_request`, `device_interaction` (`file_download`), `session_info` (duration on close) |
| Zeek `conn.log` | `network_traffic` (bytes and packets are summed over both directions; `null` when Zeek has no count) |
| Zeek `notice.log` | `device_log` (level `warning`), e.g. port-scan notices from `misc/scan` |
| Mosquitto log | `mqtt_event` with `action` = `connect` or `subscribe` (carries `src_ip` and `client_id`) |
| MQTT subscription | `mqtt_event` with `action` = `publish` (topic, size, qos, retain) |

Real events have no `label`, `actor` or `entry_vector`; those are simulator ground truth. Their `honeypot` field is `cowrie_honeypot`, `mqtt_broker` or `zeek_monitor`.

## Settings

All `AEGEX_*` variables for this are in [CONFIGURATION.md](CONFIGURATION.md) terms: `AEGEX_FEEDS_ENABLED`, `AEGEX_FEEDS_FROM_START`, `AEGEX_FEEDS_POLL_INTERVAL`, `AEGEX_COWRIE_LOG`, `AEGEX_ZEEK_LOG_DIR`, `AEGEX_MOSQUITTO_LOG`, `AEGEX_MQTT_HOST`, `AEGEX_MQTT_PORT`, `AEGEX_MQTT_TOPIC`, `AEGEX_MQTT_CLIENT_ID`. In compose, `.env` also takes `ZEEK_INTERFACE`, `ZEEK_BPF`, `ZEEK_IMAGE`, `AEGEX_SIMULATE_NETWORK` and `AEGEX_FOLLOW_CSV`.

Compose sets `AEGEX_FOLLOW_CSV=true` by default so the pipeline keeps running after the CSV ends. Batches are created one per CSV row, so without this the real events would stop being collected when the CSV is exhausted. `AEGEX_SIMULATE_NETWORK` stays `true`; set it to `false` in `.env` to see only real traffic.

By default only log lines written after the pipeline starts are read. Set `AEGEX_FEEDS_FROM_START=true` to replay existing logs.

## Known limits

- **Zeek needs a Linux host.** It uses `network_mode: host` to sniff `ZEEK_INTERFACE`. On Docker Desktop (Windows/Mac) the "host" is a VM, so it will not see your real network card; this was not tested. To test Zeek anywhere, run it against a pcap instead (`zeek -r file.pcap LogAscii::use_json=T`) and copy the logs into the `zeeklogs` volume.
- **Zeek's BPF filter** (`ZEEK_BPF`) limits capture to the honeypot ports. Without it, traffic between your own containers (Postgres, Elasticsearch...) would flood the pipeline. If you publish Cowrie on port 22/23 the defaults already cover that.
- **conn.log is written when a connection ends.** A long-lived MQTT connection from the ESP32 shows up only after it closes.
- **Source IPs behind Docker.** Depending on how traffic reaches a container, Cowrie and Mosquitto may log Docker's gateway address (e.g. 172.x.x.1) instead of the real client.
- **MQTT publishes have no `src_ip`.** A broker does not tell subscribers who published. The connect and subscribe events do carry the IP and client id; they are linked only by `client_id`.
- **Detection is still the project's rule-based analyzer.** It was written against the simulator's events. Brute-force logins plus dropper commands from Cowrie will match `mirai_botnet`, but IP reputation is mock data (only blocklisted IPs score high, see `AEGEX_IP_BLOCKLIST`), so real attackers are not scored as malicious unless you list them.
- **Mosquitto is anonymous and Cowrie is internet-exposable by design.** Do not publish these ports to the internet from a machine you care about.
- Zeek logs are not rotated, so they grow until you clear the `zeeklogs` volume.

## What was and was not tested

Tested here: the parsers and file tailer (`tests/test_feeds.py`, 8 tests pass with the existing suite), the Mosquitto config against a real Mosquitto 2.0.18 broker, the MQTT subscription and the feed wiring against that broker, and that the compose file is valid YAML.
Not tested (no Docker, Cowrie or Zeek in the build environment): `docker compose up`, the Cowrie and Zeek containers themselves, and the Cowrie/Zeek parsers on real output. Those parsers follow the documented JSON fields (`eventid`, `src_ip`, `session`, `input`, ...; Zeek `id.orig_h`, `orig_bytes`, ...). Check the first real lines in `docker compose exec cowrie ...`/the volumes if something does not appear.
