# Notes for the team from Task B

Things found while building the backend that another member needs to act on. Each one says who, what, and why.

## For Task A (hardware / data collection)

### 1. `honeypots/zeek/aegex.zeek` does not start on Zeek 8.0

`docker-compose.yml` runs `zeek/zeek:8.0` with `aegex.zeek`. Zeek stops immediately with:

```
fatal error in /scripts/aegex.zeek, line 6: can't find misc/scan
```

Newer Zeek versions don't include the `misc/scan` script any more, so the live Zeek container never runs and
`conn.log` is never written.

**Fix:** remove the `@load misc/scan` line. Port-scan detection can come from Suricata, from the models, or from
an external Zeek package (for example `zeek/ncsa/bro-simple-scan` via `zkg`) if the team wants it in Zeek.

### 2. Mosquitto doesn't log publishes

Add `log_type debug` to `honeypots/mosquitto/mosquitto.conf`. Without it, Mosquitto never writes the
"Received PUBLISH from ..." lines, so the backend can't create `mqtt_publish` events. (Zeek's `mqtt_publish.log`
is a second source if the traffic is captured.)

### 3. ESP32 clock: UTC or local time?

The ESP32 CSV `time` column has no time zone. The backend needs to know which clock wrote it, or every reading
shifts by hours and gets the wrong label. Best: make the ESP32 log UTC (sync with NTP) or write the offset into the
time, e.g. `2026-11-20T14:05:00+02:00`.

### 4. For every attack, log exactly this

The backend labels data with the attack log. One row per attack run: `run_id`, `scenario`, `tool`, exact `command`,
`attacker_ip`, `target_device`, `start_ts`, `end_ts` (UTC, to the second, written with a `Z`, e.g.
`2026-11-20T14:10:00Z`). See `contracts/TASK_B_CONTRACT.md` and the example `backend/samples/attack_log.csv`.
Before sending a log, check it: `python -m ingest.attacks your_log.csv --check` lists every problem at once.
Write `end_ts` when the attack has really stopped. Attacker traffic after `end_ts` gets labeled *normal*.
Use bridged or host-only networking for the virtual Pi, not NAT: NAT replaces the attacker's IP, and then labeling
can't find the attacker's traffic.

### 5b. Proof-of-concept lab (laptop hotspot + ESP32-S3)

All of it is in [POC_GUIDE.md](POC_GUIDE.md). The short version for A:
- The ESP32-S3 POSTs sensor readings to `/api/v1/ingest/sensor` and every connection, login, command or web request
  on its fake services to `/api/v1/ingest/honeypot` (format and Arduino example in the guide, section 4). No clock
  needed on the ESP32.
- **Attack from a separate device** on the hotspot (phone, second laptop), never from the hotspot laptop: the
  attack log refuses `192.168.137.1` as the attacker, because its traffic couldn't be labeled apart.
- Before the first recording: connect a phone to the hotspot, ping the ESP32 from it, and check that Wireshark on the
  hotspot adapter shows those pings. If not, attacker → ESP32 traffic isn't being recorded.
- Record 2–3 normal-only sessions of ~30 min and 2 attack sessions (guide, section 6).

## For Task C and Task D (models)

### 5. Zeek reports RTSP as `http`

The camera's RTSP stream shows up in Zeek's `conn.log` with `service = http`, because RTSP looks like HTTP. The raw
`flows.service` column keeps Zeek's value; the feature step (step 7) maps port 554 to `rtsp` using the contract's
vocabulary, so the models see `rtsp`.

### 6. Window features: three readings of the contract to confirm (Task C)

Step 8 builds the 24 window features. Three places where the contract wording needed a decision:

- **`n_mqtt_publish` "excluding the device's own telemetry topic".** Implemented as: a publish is left out when the
  *publisher* is one of our own devices (the sensor sending its readings). Leaving out by *topic* would hide
  `mqtt_spoofing`, where the attacker publishes exactly on the sensor's topic.
- **`sensor_*_delta_max` "max change between consecutive readings; 0 if <2 readings".** The ESP32 sends one reading
  every 10 s, so a 10 s window almost never holds two, and the feature would always be 0. Implemented as: each
  reading is compared with the device's *previous* valid reading (even from an earlier window), and the window
  keeps the biggest change.
- **Outgoing connections are not in the window features.** All 9 flow features count connections *into* the
  device. When the honeypot downloads malware from the attacker (outgoing), the window is labeled attack but no
  feature changes. Suggestion for v1.1.0: add `n_conn_out` and `n_unique_dst_ip_out` (contacting new hosts is a
  classic sign of an infected device).

If you want a different choice for any of these, it's a small change, but it bumps `feature_version`.
