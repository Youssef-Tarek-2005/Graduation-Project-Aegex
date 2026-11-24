# Test every step by hand (no commit needed)

Run everything in **PowerShell, from the `backend` folder**. Every command is safe to repeat: loading the same
data again adds nothing. Under each command: **what you should see**, copied from a real run on 2026-11-22.

## Before you start (once per session)

```powershell
cd "C:\Users\ramez\OneDrive\Desktop\uni\year 3\grad\Graduation-Project-Aegex\backend"
docker compose up -d                     # the database
```

Keep two more terminals open later: one for the API (step 10) and one for the dashboard (step 11).

---

## Step 1: the database

```powershell
docker compose ps
docker exec aegex-db psql -U aegex -d aegex -c "\dt"
```

**You should see:** `aegex-db  Up ... (healthy)  0.0.0.0:5433->5432/tcp`, then a list of **9 tables**: alerts,
attack_runs, captures, devices, events, feature_windows, flows, model_versions, reports.

**What it means:** PostgreSQL + TimescaleDB runs in Docker on port 5433 (the old database on 5432 is untouched).

## Step 2: the lab inventory

```powershell
docker exec aegex-db psql -U aegex -d aegex -c "SELECT device_id, device_type, ip FROM devices"
docker exec aegex-db psql -U aegex -d aegex -c "SELECT capture_id, start_ts, end_ts FROM captures ORDER BY start_ts"
```

**You should see:** 3 devices (`gw-01` 192.168.56.10, `esp32-smoke-01` .20, `cam-01` .30) and the captures:
`cap-2026-11-20-a` (14:00-15:00 UTC), the 6 `cap-demo-*` from the fake lab, and any `cap-sim-*` from the simulator.

**What it means:** every event must point at a known device and capture, so these rows come first.

## Step 3: parsers (log line → event)

```powershell
.venv/Scripts/python -m ingest.parsers cowrie samples/cowrie.json --device gw-01
```

**You should see:** one row per event (time, type, layer, attacker IP, details), ending with
`samples/cowrie.json: 13 lines -> 11 events (1 ignored, 1 broken)`.

**What it means:** 13 lines in the file: 11 became events, 1 was valid but not needed, 1 was broken on purpose
(the parser skips it instead of crashing). Try `mosquitto samples/mosquitto.log --device gw-01 --broker-ip
192.168.56.10` and `esp32 samples/esp32.csv --device esp32-smoke-01` too.

## Step 4: loader (event → database, no duplicates)

```powershell
.venv/Scripts/python -m ingest.load cowrie samples/cowrie.json --device gw-01 --capture cap-2026-11-20-a
```

**You should see:** `saved 0 new rows, skipped 11 already in the database`. They were saved the first time; loading
again adds nothing. **That's the duplicate protection working.**

Now a deliberate mistake (wrong time zone):

```powershell
.venv/Scripts/python -m ingest.load esp32 samples/esp32.csv --device esp32-smoke-01 --capture cap-2026-11-20-a --device-ip 192.168.56.20 --tz Asia/Tokyo
```

**You should see:** `ERROR: 4 of 4 events are outside capture 'cap-2026-11-20-a' ... Wrong --tz or wrong --capture?
Nothing was saved.` A shifted time would give a wrong label, so the whole file is refused.

## Step 5: Zeek (pcap → network connections)

```powershell
.venv/Scripts/python -m ingest.zeek samples/cap-2026-11-20-a.pcap --capture cap-2026-11-20-a
```

**You should see:** `zeek wrote: conn.log, dns.log, ... ssh.log`, then `9 lines -> 9 flows` and
`saved 0 new flows, skipped 9 already in the database; 9 of 9 touch a honeypot device`.

**What it means:** real Zeek (in Docker) read the recorded packets and listed every connection. Each became a row
in `flows`.

## Step 6: attack log + labels

First, a log full of mistakes:

```powershell
.venv/Scripts/python -m ingest.attacks samples/attack_log_mistakes.csv --check
```

**You should see:** `ERROR: 8 problem(s) in the attack log. Nothing was saved.` and one line per mistake: a typo in
the scenario, a time without time zone, the attacker IP being a honeypot, end before start, an overlap, a run outside
the capture, an unknown device.

Then the report for the correct log:

```powershell
.venv/Scripts/python -m ingest.attacks --report cap-2026-11-20-a
```

**You should see:** `flows: 4 attack 5 normal`, `events: 11 attack 8 normal`, run-001 bruteforce with 4 flows and
11 events, and `OK: every run matched traffic, and no attacker traffic is outside the runs`.

**What it means:** traffic from the attacker IP during the attack's time is labeled "attack", everything else
"normal". This is what the models learn from.

## Step 7: flow features (41 numbers per connection, for D)

```powershell
.venv/Scripts/python -m features.build flows --capture cap-2026-11-20-a --show
```

**You should see:** `OK: 9 flows x 41 features, nothing missing, no NaN` and a table: the 4 SSH/HTTP flows of the
attack have label 1, and the last column shows the category, e.g. `tcp ssh SF well_known`.

## Step 8: window features (24 numbers per device per 10 seconds, for C)

```powershell
.venv/Scripts/python -m features.build windows --capture cap-2026-11-20-a --show
```

**You should see:** `1080 windows (3 devices x 360 windows of 10 s); 16 with activity, 1064 silent; 5 attack` and
`OK: 1080 windows x 24 features`. The attack windows at 14:10 and 14:12 show `n_login_failed=2`, `n_ssh_telnet_conn=2`.

**What it means:** one hour = 360 windows of 10 s, for each of the 3 devices. A silent window is real silence (0),
not missing data.

## Step 9: split + scalers + files for C and D

```powershell
.venv/Scripts/python -m features.dataset --dry-run      # only show the split
.venv/Scripts/python -m features.dataset                # build the files
```

**You should see:** train = `cap-2026-11-20-a` + `cap-demo-01..04`, val = `cap-demo-05` (dos), test =
`cap-demo-06` (all 4 attacks), then shapes `train [2805, 30, 24]`, `val [453, 30, 24]`, `test [453, 30, 24]` and the
folders `data\processed\v1.0.0` and `artifacts\features\v1.0.0`.

**What it means:** whole recordings go to one split, older ones train and newer ones test, so the test is fair. The
`cap-demo-*` captures are the **fake lab** (`demo/fake_lab.py`): generated recordings in the real devices' formats,
because one real recording can't be split three ways. Remove them before real data:
`.venv/Scripts/python -m demo.fake_lab --remove`.

## Step 10: the API, data in

Terminal 2:

```powershell
.venv/Scripts/python -m api
```

Open **http://localhost:8001/docs** (Swagger).
1. `GET /health` → **Try it out** → **Execute**. **You should see:** `"status": "ok", "database": "ok"` and the row
   counts.
2. `POST /api/v1/ingest/events` → **Try it out** → **Execute** (the example is filled in). **You should see:**
   `"inserted": 1`. Press **Execute** again: `"inserted": 0, "duplicates": 1`.
3. In the same box, delete the `Z` at the end of `ts` → **Execute**. **You should see:** `422` and
   `"Input should have timezone info"`. Nothing saved.

Remove the test event afterwards:

```powershell
docker exec aegex-db psql -U aegex -d aegex -c "DELETE FROM events WHERE payload->>'session' = 'swagger1'"
```

## Step 11: the API, data out + the new dashboard

In Swagger:
- `GET /api/v1/events` with `label = 1`, `capture_id = cap-2026-11-20-a` → the brute-force events (first one:
  `session_open` from 192.168.56.99 at 14:10:03). Answers have `next_cursor` when there are more pages.
- `GET /api/v1/stats/summary` with `capture_id = cap-demo-06` → `events: 514`, `flows: 1851`, the 4 scenarios.

Terminal 3, the dashboard:

```powershell
.venv/Scripts/python -m http.server 8095 --bind 127.0.0.1 --directory ../frontend
```

Open **http://localhost:8095/dashboard_new.html**, pick **cap-demo-06** at the top. **You should see:** sensor
charts, 514 security events, and on "Detected attacks" the 4 attack runs (scanning, brute force, MQTT spoofing, DoS).
The old **http://localhost:8095/dashboard.html** is unchanged (old API, port 8000).

## Live test without the hardware

Terminal 4, with the API running:

```powershell
.venv/Scripts/python -m demo.live_sim
```

**You should see:** `Fake lab running ... capture cap-sim-...` and every ~40 s a line like
`attacker 192.168.56.99: SSH session with 5 failed logins`. On the dashboard choose **Live → 15m**: the charts
grow every few seconds, and the attacker's logins appear at the top of "Recent events". The attack cards say
"not labeled yet": live data is only labeled by the attack log.

Stop with **Ctrl+C** (the capture gets its end time), then delete what it sent:

```powershell
.venv/Scripts/python -m demo.live_sim --clean
```

## Everything at once

```powershell
.venv/Scripts/python -m demo.check_all     # steps 1-11 together, on a throw-away database: "ALL STEPS PASS"
.venv/Scripts/python -m pytest             # 162 unit tests: "162 passed"
```
