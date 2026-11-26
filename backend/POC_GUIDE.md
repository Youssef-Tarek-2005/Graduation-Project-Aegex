# The proof-of-concept lab: laptop hotspot + ESP32-S3

How the backend works with the small lab for the November 29 review. Everything here runs in **PowerShell, from the
`backend` folder**. The old sample lab (`gw-01`, `esp32-smoke-01`, `cam-01`) stays in its own database and keeps
working; nothing here changes it.

## The lab and the data path

**Decided with Task A (Nov 24):** the attacker is a **second laptop** on the hotspot; the ESP32-S3 runs a fake
**HTTP** service; the attacks are a **port scan** (scenario `vulnerability_scanning`) and a **flood** (scenario
`dos`). Task A has firmware already (not in this repo yet).

```
 attacker (2nd laptop, 192.168.137.x) ─────────┐
 normal user (phone, 192.168.137.x)  ──────────┼─ Wi-Fi ─► Windows laptop hotspot 192.168.137.1 ─► ESP32-S3 (192.168.137.x)
                                               │           │  Wireshark records every packet         fake HTTP service
                                               │           │  (pcap)                                 + smoke / temp / humidity
                                               │           ▼                                                 │
                                               │       Zeek (Docker) ─► flows ──┐                            │ HTTP POST
                                               │                                ▼                            ▼
                                               │                   database aegex_poc  ◄── API :8001 ◄── honeypot events + sensor readings
                                               │                                │
 attack log (what / when / from where) ────────┴──────────────► labels ─────────┤
                                                                                ▼
                                       window features (24 numbers per 10 s) ─► dataset [N, 30, 24] ─► LSTM-AE + VAE (Task C)
                                                                                └─► dashboard_new.html
```

**Devices** (`sql/seed_poc.sql`):

| device_id | what | IP | windows? |
|---|---|---|---|
| `esp32s3-01` | the honeypot + sensors | the address the hotspot gave it | **yes**: one window per 10 s, the models watch it |
| `laptop-gw` | hotspot, Wireshark, Zeek, backend | `192.168.137.1` (always, on Windows) | no: known, so it can't be named as the attacker, but not watched |

**Rule:** the attacker must be **another device** on the hotspot. If the attacks come from the laptop itself, its
attack traffic and its normal traffic share one IP and can't be labeled apart; the attack log refuses it.

## 1. Once: create the PoC database

```powershell
docker compose up -d
.venv/Scripts/python -m ingest.poc_db --esp32-ip 192.168.137.57
```

Use the ESP32's real address (Windows: **Settings → Network → Mobile hotspot**, list of connected devices). If it
changes later, run the same command with the new IP; nothing is deleted.

**You should see:** `esp32s3-01 ... monitored (feature windows)`, `laptop-gw 192.168.137.1 known, not monitored`.

## 2. Every terminal: use the PoC database

```powershell
$env:AEGEX_DB_URL = "postgresql://aegex:aegex@127.0.0.1:5433/aegex_poc"
```

Without this line the tools use the old `aegex` database. To check: the API prints
`AEGEX API -> database 'aegex_poc'` when it starts, and `GET /health` shows `"database_name": "aegex_poc"`.

## 3. Start the API so the ESP32 can reach it

```powershell
.venv/Scripts/python -m api --host 0.0.0.0
```

Windows blocks incoming connections by default. Once, in an **administrator** PowerShell, allow only the hotspot
network to reach port 8001:

```powershell
New-NetFirewallRule -DisplayName "AEGEX API (hotspot only)" -Direction Inbound -Protocol TCP -LocalPort 8001 -RemoteAddress 192.168.137.0/24 -Action Allow
```

The dashboard is the same as before: `http://localhost:8095/dashboard_new.html` (see `TEAM_GUIDE.md`).

## 4. What the ESP32-S3 sends (for Task A)

The ESP32 needs **no clock**: the API stamps the time when the request arrives. Wireshark runs on the same laptop,
so packets and ESP32 events share one clock.

**Sensor reading**, every few seconds: `POST http://192.168.137.1:8001/api/v1/ingest/sensor`

```json
{"device_id": "esp32s3-01", "smoke": 12.3, "temperature_c": 24.1, "humidity_pct": 41.0}
```

**Honeypot event**, each time a client touches a fake service: `POST http://192.168.137.1:8001/api/v1/ingest/honeypot`

```json
{"device_id": "esp32s3-01", "event": "http_request", "service": "http", "src_ip": "192.168.137.50",
 "src_port": 51234, "dst_port": 80, "method": "GET", "path": "/"}
```

With only an HTTP service, the ESP32 mostly sends `http_request` (and `login_failed` / `login_success` if its page has
a login form). **The port scan and the flood don't need the ESP32 to send anything:** Zeek sees them in the pcap
(many ports / hundreds of connections), and that's what the features count. During a flood, the ESP32 must **not**
POST every request, or it chokes on its own logging: send at most a few per second and skip the rest.

| `event` | send it when | extra fields |
|---|---|---|
| `connect` | a client connects to a fake service | |
| `login_failed` / `login_success` | a login is tried | `username`, `password` |
| `command` | a logged-in client types a command | `input` |
| `http_request` | the fake web page is requested | `method`, `path` |
| `disconnect` | the connection closes | |

`service` is `telnet`, `http`, `ssh`, `mqtt` or `other`. `session`: the same short id on every event of one
connection. `src_ip` is the **client's** address. Arduino (ESP32 core) example, to call from the web server's
request handler (`server.client().remoteIP()` gives the client's address):

```cpp
#include <HTTPClient.h>
void sendHttpRequest(IPAddress client, const String& method, const String& path) {
  HTTPClient http;
  http.begin("http://192.168.137.1:8001/api/v1/ingest/honeypot");
  http.addHeader("Content-Type", "application/json");
  String body = String("{\"device_id\":\"esp32s3-01\",\"event\":\"http_request\",\"service\":\"http\","
                       "\"dst_port\":80,\"src_ip\":\"") + client.toString() + "\",\"method\":\"" + method +
                "\",\"path\":\"" + path + "\"}";
  int code = http.POST(body);   // 200 = saved; 422 = refused, the answer says why
  http.end();
}
```

(Escape `"` and `\` in the path before putting it into the JSON.) **Task A: if your firmware already sends data
somewhere else (serial, MQTT, its own format), send it to Task B. Adding a reader for that format is quicker than
rewriting your firmware.** Try every request in Swagger first:
`http://localhost:8001/docs` → **Ingest** → **Try it out**.

## 5. One recording session, step by step

Name captures by date and content, e.g. `cap-poc-1125-normal-1`, `cap-poc-1125-attack-1`.

```powershell
# 1. Start Wireshark on the hotspot adapter ("Local Area Connection* N"), then register the capture:
.venv/Scripts/python -m ingest.captures add cap-poc-1125-attack-1 --start now --kind attack

# 2. Record. ESP32 events arrive by themselves and go into the open capture.
#    For every attack, write one row in the attack log (see TEAM_NOTES.md, item 4).

# 3. Stop Wireshark. Save as "Wireshark/tcpdump - pcap" (pcaps\cap-poc-1125-attack-1.pcap). Close the capture:
.venv/Scripts/python -m ingest.captures close cap-poc-1125-attack-1

# 4. Packets -> flows (Zeek in Docker):
.venv/Scripts/python -m ingest.zeek pcaps\cap-poc-1125-attack-1.pcap --capture cap-poc-1125-attack-1

# 5. Labels. With attacks: check, then load the attack log. Normal-only recording: label it directly.
.venv/Scripts/python -m ingest.attacks attack_log_1125.csv --check
.venv/Scripts/python -m ingest.attacks attack_log_1125.csv --label
.venv/Scripts/python -m ingest.attacks --label-capture cap-poc-1125-normal-1

# 6. Features:
.venv/Scripts/python -m features.build flows --capture cap-poc-1125-attack-1
.venv/Scripts/python -m features.build windows --capture cap-poc-1125-attack-1
```

**The attack log rows for our two attacks** (one row per attack run; times in UTC with `Z`, `attacker_ip` = the
second laptop's hotspot address):

```csv
run_id,capture_id,scenario,tool,command,attacker_ip,target_device,start_ts,end_ts
poc-1125-01,cap-poc-1125-attack-1,vulnerability_scanning,nmap,nmap -sS -p 1-1000 192.168.137.57,192.168.137.50,esp32s3-01,2026-11-25T10:05:00Z,2026-11-25T10:06:30Z
poc-1125-02,cap-poc-1125-attack-1,dos,hping3,hping3 -S --flood -p 80 192.168.137.57,192.168.137.50,esp32s3-01,2026-11-25T10:12:00Z,2026-11-25T10:13:00Z
```

Keep floods **short (30–60 s)**: a minute of SYN flood is already millions of packets, and the pcap and Zeek's
work grow with it. A gentler HTTP flood (`ab -n 5000 -c 50 http://192.168.137.57/`) shows the same thing.

**Check after step 5:** `--report` must end with `OK: every run matched traffic, and no attacker traffic is outside
the runs`. If a run matched nothing, the attacker IP or the times in the attack log are wrong.

## 6. The dataset for Task C

```powershell
.venv/Scripts/python -m features.dataset --dry-run
.venv/Scripts/python -m features.dataset
```

Whole captures go to one split: oldest → train, then validation, newest → test. **Record at least:**

- **2–3 normal-only captures of ~30 min.** The autoencoders learn only from normal windows (`y == 0`), and 30 min is
  just 180 windows.
- **2 attack captures**, each with every attack you will demo: one becomes validation (C picks the threshold
  there), one becomes test.

If the automatic split doesn't fit, write your own `splits.json` (`{"train": [...], "val": [...], "test": [...]}`)
and run `features.dataset --splits splits.json`.

## 6b. Sending the recordings to Task B

The backend runs on the **hotspot laptop** (where the ESP32 sends its data). Whoever has that laptop sends after
each recording day, through a shared Drive folder (not git: the files are big):

1. **The pcap files** (`pcaps\*.pcap`), so Zeek can be run again.
2. **The attack log** (`attack_log_<day>.csv`), checked first with `python -m ingest.attacks <file> --check`.
3. **The database**, which also holds what the ESP32 sent live (sensor readings, honeypot events):

```powershell
docker exec aegex-db pg_dump -U aegex -d aegex_poc -Fc -f /tmp/aegex_poc.dump
docker cp aegex-db:/tmp/aegex_poc.dump .\aegex_poc_1125.dump
```

**On the receiving laptop** (this **replaces** its own `aegex_poc` with the received one; tested 2026-11-24, the
copy matched the original row for row):

```powershell
docker cp .\aegex_poc_1125.dump aegex-db:/tmp/received.dump
docker exec aegex-db psql -U aegex -d aegex -c "DROP DATABASE IF EXISTS aegex_poc WITH (FORCE)" -c "CREATE DATABASE aegex_poc"
docker exec aegex-db psql -U aegex -d aegex_poc -c "CREATE EXTENSION IF NOT EXISTS timescaledb" -c "SELECT timescaledb_pre_restore()"
docker exec aegex-db pg_restore -U aegex -d aegex_poc --no-owner /tmp/received.dump
docker exec aegex-db psql -U aegex -d aegex_poc -c "SELECT timescaledb_post_restore()"
```

`pg_dump` prints warnings about "circular foreign-key constraints": that's normal for TimescaleDB and harmless.
Stop the API before restoring (the `WITH (FORCE)` would cut its connections anyway).

## 6c. Run the AI models on a recording (LSTM-AE + VAE)

The AI team's models live in `ai-models/lstm-vae-gat/`. `detect.py` is the connection: it runs their own script
on a recording and saves what they flag in the `alerts` table.

```powershell
.venv/Scripts/pip install torch --index-url https://download.pytorch.org/whl/cpu      # once
.venv/Scripts/python -m detect pcaps\cap-poc-1125-attack-1.pcap --normal pcaps\cap-poc-1125-normal-1.pcap
```

`--normal` must be a **normal-only recording of the same network**: the models learn from it what normal looks like
here (about 1% of normal windows will still alarm, by design). The alerts then appear at
`GET /api/v1/alerts?capture=cap-poc-1125-attack-1` (and in Swagger under **Data**).

**Try it now, without hardware:** `python -m demo.make_poc_pcaps` writes a made-up normal recording and an attack
recording (port scan + HTTP flood from `192.168.137.50`) into `pcaps\`. On 2026-11-25:
`python -m detect pcaps\poc-attack.pcap --normal pcaps\poc-normal.pcap` took 4 s and gave 100 alerts: 99 on the
attacker `192.168.137.50`, 1 false alarm on the phone. The normal recording alone gave 1 alert in 33 windows.

## 7. Test it all without the hardware

```powershell
# terminal 1
$env:AEGEX_DB_URL = "postgresql://aegex:aegex@127.0.0.1:5433/aegex_poc"
.venv/Scripts/python -m api

# terminal 2
$env:AEGEX_DB_URL = "postgresql://aegex:aegex@127.0.0.1:5433/aegex_poc"
.venv/Scripts/python -m demo.live_sim --lab poc
```

**You should see:** every ~40 s the second laptop (`192.168.137.50`) attacks, taking turns:
`port scan on the ESP32-S3, 19 ports`, then `HTTP flood on the ESP32-S3, 187 connections in 5 s (sensor goes quiet
for 12 s)`. The dashboard (Live → 15m) shows the readings, the flows jumping during each attack, and the gap in
the sensor readings after a flood. Ctrl+C, then delete it all with
`.venv/Scripts/python -m demo.live_sim --clean` (same terminal, so it cleans `aegex_poc`).

Tested on 2026-11-24: 90 s of simulation → 45 readings, 42 honeypot events, 11 flows. After the attack log row,
36 events and 5 flows were attack. Windows: 10 for `esp32s3-01` only (none for the laptop), 6 attack and 4 normal,
with the failed-login counts in `n_login_failed`.
