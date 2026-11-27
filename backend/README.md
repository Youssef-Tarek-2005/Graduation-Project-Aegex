# Task B: step-by-step build

Task B is data engineering + backend: raw honeypot data in → clean, labeled features + one database + an API out.
The agreement with the rest of the team is in [`contracts/TASK_B_CONTRACT.md`](../contracts/TASK_B_CONTRACT.md).

We build it in small steps. Each step ends with something you can **run and see**, so you always know it works
before moving on.

## Roadmap

| # | Step | You can see it work when... | Status |
|---|---|---|---|
| **Phase 1: the database** ||||
| 1 | Start the database (TimescaleDB in Docker) and create the tables | `\dt` lists the 9 tables | done |
| 2 | Put sample data in by hand: devices, a capture, a few events | `SELECT * FROM events` shows rows | done |
| **Phase 2: getting data in** ||||
| 3 | Parsers: Cowrie / Mosquitto / ESP32 lines → event dicts (reuse the old parsers) | tests pass on sample log lines | done |
| 4 | Loader: write parsed events into the `events` table, no duplicates | load the same file twice → same row count | done |
| 5 | Zeek: pcap → `conn.log` → `flows` table | flows appear with bytes, conn_state, service | done |
| 6 | Attack log + labeling (`attack_runs`, `label_capture`) | `v_label_summary` shows attack vs normal counts | done |
| **Phase 3: features for the models** ||||
| 7 | Flow features (41 numbers per connection) | a feature table with 41 columns, no NaN | done |
| 8 | Window features (24 numbers per device per 10 s) | a window table you can plot over time | done |
| 9 | Scaler + train/val/test split + exports for C and D | `sequences_train.npz` has shape [N, 30, 24] | done |
| **Phase 4: the API** ||||
| 10 | FastAPI skeleton + `/health` + POST ingest endpoints | send an event with Swagger → it appears in the DB | done |
| 11 | GET endpoints for data, features and graph (for C, D, dashboard) | Swagger returns your data | done |
| 12 | Alerts, models and reports endpoints (for D and E) + API key + tests | full flow: alert in → report attached | |

## Step 1: start the database

**What:** run PostgreSQL 16 with the TimescaleDB extension in Docker, and create all tables from
[`database/schema_v2.sql`](../database/schema_v2.sql).

**Why Docker:** every team member gets the exact same database with one command, with nothing to install
except Docker Desktop.

**Files:**
- [`backend/docker-compose.yml`](docker-compose.yml): defines one service `db`
- [`database/schema_v2.sql`](../database/schema_v2.sql): the tables. Docker runs it automatically the **first** time the
  database starts (when its storage volume is empty).

**Run it** (from the project folder, with Docker Desktop open):

```bash
docker compose -f backend/docker-compose.yml up -d
```

```bash
docker compose -f backend/docker-compose.yml ps
```

Wait until `STATUS` says `healthy`. Then list the tables:

```bash
docker exec -it aegex-db psql -U aegex -d aegex -c "\dt"
```

You should see: `alerts, attack_runs, captures, devices, events, feature_windows, flows, model_versions, reports`.

Check that the three big tables are TimescaleDB hypertables:

```bash
docker exec -it aegex-db psql -U aegex -d aegex -c "SELECT hypertable_name FROM timescaledb_information.hypertables;"
```

Expected: `events`, `flows`, `feature_windows`.

**If you change the schema later**, the init script will not re-run on its own. During development, reset with
`docker compose -f backend/docker-compose.yml down -v` (deletes the data) and start again. In step 10 we switch to
proper migrations.

**Harmless log line:** during the first start, `docker logs aegex-db` shows
`ERROR: TimescaleDB background worker connected to template database, exiting`. That is normal TimescaleDB
start-up noise, not a problem with the schema.

**Connection details** for later steps and tools such as DBeaver or pgAdmin:
host `localhost`, port `5433`, database `aegex`, user `aegex`, password `aegex`.

## Step 2: sample data by hand

**What:** type a small, made-up story into the tables so you can see how they connect before any code writes
to them.

**The story:** capture `cap-2026-11-20-a` runs from 14:00 to 15:00. The sensor and camera behave normally. From
14:10 to 14:18, an attacker at `192.168.56.99` runs hydra (SSH password guessing) against the virtual Pi
`gw-01`, logs in with `root / raspberry`, runs `uname -a` and downloads a bot. At 14:40 the admin (`192.168.56.1`)
logs in to the Pi over SSH normally.

**File:** [`backend/sql/step2_sample_data.sql`](sql/step2_sample_data.sql): 3 devices, 1 capture, 1 attack run,
10 events, 6 flows, then `CALL label_capture(...)`.

**Run it:**

```bash
docker exec -i aegex-db psql -U aegex -d aegex -v ON_ERROR_STOP=1 < backend/sql/step2_sample_data.sql
```

**Look at it:**

```bash
docker exec aegex-db psql -U aegex -d aegex -c "SELECT ts, source, event_type, src_ip, label, scenario FROM events ORDER BY ts;"
```

```bash
docker exec aegex-db psql -U aegex -d aegex -c "SELECT * FROM v_label_summary;"
```

Expected summary: 3 `bruteforce` flows (label 1) and 3 `normal` flows (label 0).

**What it proves:**

| Check | Result |
|---|---|
| Labeling | the 6 attacker events and 3 attacker flows get `label 1, bruteforce, run-001`; everything else gets `label 0` |
| Same port, different person | the admin's SSH login at 14:40 (port 22, like the attack) stays **normal**: labels come from A's attack log, not from guessing |
| Run the file twice | the 2nd run inserts **0** rows (`ON CONFLICT DO NOTHING` + `dedup_key`) |
| Bad values | `device_type = 'toaster'`, port `70000`, and an attack that ends before it starts are all **rejected** by the database |
| Flexible `payload` | `payload->>'password'` reads Cowrie's password field out of the JSON, without a column for it |

**Clean slate:** `docker compose -f backend/docker-compose.yml down -v`, then `up -d` again. That deletes this
sample data. Later steps load real data the same way.

## Step 3: parsers

**What:** Python code that reads raw log lines and turns each one into an `Event`: a Python object with exactly
the columns of the `events` table. It does **not** touch the database yet; that is step 4.

```
cowrie.json line   ─┐
mosquitto.log line ─┼─► parser ─► Event(ts, source, event_type, src_ip, ..., payload, dedup_key) ─► (step 4: database)
esp32.csv row      ─┘
```

**Files:**

| File | What it does |
|---|---|
| [`ingest/event.py`](ingest/event.py) | the `Event` object. Reads the allowed event types and their layers from `contracts/feature_contract.json`, and refuses anything the contract doesn't allow |
| [`ingest/parsers/base.py`](ingest/parsers/base.py) | what all parsers share: skip and count bad lines, make the `dedup_key` |
| [`ingest/parsers/cowrie.py`](ingest/parsers/cowrie.py) | Cowrie SSH/Telnet JSON → `session_open`, `login_failed`, `login_success`, `command`, `file_download`, `session_close` |
| [`ingest/parsers/mosquitto.py`](ingest/parsers/mosquitto.py) | Mosquitto log → `mqtt_connect`, `mqtt_subscribe`, `mqtt_publish` |
| [`ingest/parsers/esp32.py`](ingest/parsers/esp32.py) | ESP32 CSV → `sensor_reading` |
| [`samples/`](samples/) | small log files that tell the same story as step 2, with a few broken lines on purpose |
| [`tests/test_parsers.py`](tests/test_parsers.py) | 16 tests |

Reused from the old project: the idea of remembering a Cowrie session's IP and ports, the Mosquitto regexes,
the CSV column aliases, and real Mosquitto 2.0.18 log lines for the tests. Rewritten so the output matches the
new `events` table and the contract.

**Set up once** (from the `backend` folder):

```bash
python -m venv .venv
```

```bash
.venv/Scripts/python -m pip install -r requirements.txt
```

(On Linux/macOS use `.venv/bin/python` instead of `.venv/Scripts/python`.)

**Run the tests:**

```bash
.venv/Scripts/python -m pytest -v
```

**Try a parser on a file:**

```bash
.venv/Scripts/python -m ingest.parsers cowrie samples/cowrie.json --device gw-01
```

```bash
.venv/Scripts/python -m ingest.parsers mosquitto samples/mosquitto.log --device gw-01 --broker-ip 192.168.56.10
```

```bash
.venv/Scripts/python -m ingest.parsers esp32 samples/esp32.csv --device esp32-smoke-01 --tz UTC
```

Each ends with a count like `13 lines -> 11 events (1 ignored, 1 broken)`.

**Rules every parser follows:**

1. **A bad line never stops the load.** It is counted as `broken` and skipped. One broken line in a million
   must not lose the other 999,999.
2. **A bug in our code always stops the load.** If a parser produces an event type that is not in the contract,
   or a time with no time zone, it raises an error instead of saving bad rows.
3. **All times are UTC.** Cowrie and Mosquitto already are. The ESP32 CSV has no time zone, so you pass `--tz`.
4. **Same file → same `dedup_key`s.** Two identical lines in one file still get different keys (an occurrence
   number is part of the fingerprint), so real repeats are kept and re-loads are skipped.
5. **The layer comes from the contract**, never from the parser. Changing the contract changes every parser.

**Two things to tell Task A:**

- **Mosquitto:** add `log_type debug` to `honeypots/mosquitto/mosquitto.conf`. Without it, Mosquitto never logs
  publishes, so `mqtt_publish` events can't exist.
- **ESP32 clock:** is the `time` column UTC or local time? If it's wrong, every reading shifts by hours and lands
  in the wrong attack window during labeling.

## Step 4: loader

**What:** take the Events from the step 3 parsers and save them into the `events` table, without ever creating
duplicates.

```
log file ─► parser (step 3) ─► Event ─► batch of 1000 ─► INSERT ... ON CONFLICT DO NOTHING ─► events table
```

**Files:**

| File | What it does |
|---|---|
| [`ingest/db.py`](ingest/db.py) | connects to the database (address from `AEGEX_DB_URL`, default: the dev database on port 5433) |
| [`ingest/loader.py`](ingest/loader.py) | reads a file line by line, saves in batches, skips duplicates, checks the capture's time range |
| [`ingest/load.py`](ingest/load.py) | the command you run |
| [`sql/seed_lab.sql`](sql/seed_lab.sql) | the devices, the sample capture and its attack run. These must exist before loading, because every event points at a device and a capture |
| [`tests/conftest.py`](tests/conftest.py) | builds a throw-away `aegex_test` database for the tests, so they never touch your real data |
| [`tests/test_loader.py`](tests/test_loader.py) | 11 database tests |

**Run it** (from the `backend` folder, with the database running):

```bash
docker exec -i aegex-db psql -U aegex -d aegex -v ON_ERROR_STOP=1 < sql/seed_lab.sql
```

```bash
.venv/Scripts/python -m ingest.load cowrie samples/cowrie.json --device gw-01 --capture cap-2026-11-20-a
```

```bash
.venv/Scripts/python -m ingest.load mosquitto samples/mosquitto.log --device gw-01 --capture cap-2026-11-20-a --broker-ip 192.168.56.10
```

```bash
.venv/Scripts/python -m ingest.load esp32 samples/esp32.csv --device esp32-smoke-01 --capture cap-2026-11-20-a --device-ip 192.168.56.20 --label
```

`--label` runs `label_capture` after loading (explained fully in step 6). Result: 19 events, the 11 Cowrie rows
from the attacker labeled `bruteforce`, the 8 MQTT and sensor rows labeled normal.

**The safety rules:**

| Rule | How | What you see |
|---|---|---|
| No duplicates | unique index on `(dedup_key, ts)` + `ON CONFLICT DO NOTHING` | 2nd load: `saved 0 new rows, skipped 11 already in the database` |
| A grown log only adds its new lines | same as above: old lines have the same keys | load yesterday's half, then today's full file → only the new half is added |
| All or nothing | the whole file is one transaction | if anything fails halfway, the rows already inserted from that file are rolled back |
| Unknown device or capture | checked before reading the file | `ERROR: device 'gw-99' does not exist` |
| Events outside the capture's time | counted while loading; if any, the whole file is rolled back | `ERROR: 4 of 4 events are outside capture ... Wrong --tz or wrong --capture? Nothing was saved.` |

The last rule exists because of a real mistake found while building this step: loading the ESP32 file with the
wrong time zone saved 4 readings shifted by 9 hours. The duplicate check can't catch that (the same line at a
different time is a different row), and a shifted row gets the wrong label. Now the whole file is refused
instead. Use `--allow-outside-capture` only if you are sure.

**Run the tests:**

```bash
.venv/Scripts/python -m pytest -v
```

27 tests: 16 parser tests and 11 database tests. If the database isn't running, the database tests are
skipped, not failed.

## Step 5: Zeek, pcap → flows

**What:** turn a network capture (pcap) into one row per connection in the `flows` table. Flows are what the
models in Task C and Task D mainly learn from.

```
pcap ─► Zeek 8.0 (in Docker) ─► conn.log ─► conn.log parser ─► Flow ─► flows table
```

**Files:**

| File | What it does |
|---|---|
| [`samples/make_sample_pcap.py`](samples/make_sample_pcap.py) | builds `samples/cap-2026-11-20-a.pcap` with scapy: the step 2 story as real packets (DNS, MQTT, RTSP, 3 attacker SSH connections, a malware download, ping, the admin's SSH) |
| [`ingest/flows.py`](ingest/flows.py) | the `Flow` object, the conn.log parser (JSON and Zeek's tab-separated format), the flow loader |
| [`ingest/zeek.py`](ingest/zeek.py) | runs Zeek in Docker, then loads its conn.log; the command you run |
| [`samples/zeek/conn.log`](samples/zeek/conn.log) | Zeek's real output for the sample pcap, so most tests don't need Docker |
| [`tests/test_zeek.py`](tests/test_zeek.py) | 12 tests, one of which runs real Zeek (skipped without Docker) |

**Run it** (from the `backend` folder, with Docker running):

```bash
.venv/Scripts/python -m ingest.zeek samples/cap-2026-11-20-a.pcap --capture cap-2026-11-20-a --label
```

To load a `conn.log` that Zeek already wrote (for example the live Zeek on the virtual Pi), skip running Zeek:

```bash
.venv/Scripts/python -m ingest.zeek --conn-log samples/zeek/conn.log --capture cap-2026-11-20-a
```

Add `--logs-dir zeek_out` to keep all of Zeek's logs (`ssh.log`, `http.log`, `dns.log`, ...) for a look.

**Result:** 9 flows. The 3 attacker SSH connections **and** the malware download (where the attacker is the
*destination*) are labeled `bruteforce`. The admin's SSH login on the same port 22 stays normal.

**Three design decisions:**

1. **Stable `flow_id`.** Zeek's `uid` is random on every run, so it can't be the key: re-processing a pcap would
   duplicate every flow. `flow_id` is a fingerprint of the start time (to the microsecond), protocol and both
   IP:port ends, which never change. Zeek's uid is kept in a new `zeek_uid` column to join with Zeek's other logs.
   This added one column to `database/schema_v2.sql`. For an existing database, run:
   `docker exec aegex-db psql -U aegex -d aegex -c "ALTER TABLE flows ADD COLUMN IF NOT EXISTS zeek_uid TEXT;"`
2. **The device comes from the `devices` table.** The flow loader looks up both IPs; the destination wins if both
   are devices. So the download from the attacker still belongs to `gw-01`.
3. **Unknown stays unknown.** Zeek writes `-` when it doesn't know a value (e.g. bytes of a connection that never
   finished). That is saved as empty (NULL), never as 0, because 0 would claim "no data was sent".

**Same safety rules as step 4:** no duplicates, all or nothing, unknown capture refused, flows outside the
capture's time refused.

**Found while building this step:** the team's `honeypots/zeek/aegex.zeek` doesn't start on Zeek 8.0. Details and
the other open items for teammates are in [`TEAM_NOTES.md`](TEAM_NOTES.md).

**Run the tests:**

```bash
.venv/Scripts/python -m pytest -v
```

39 tests in total.

## Step 6: attack log + labeling

**What:** bring in Task A's attack log from a file, check it hard, save it to `attack_runs`, and label the data.
Until now `run-001` was typed in SQL by hand (`seed_lab.sql`).

```
A's attack log (CSV / JSON) ─► check file ─► check against DB ─► attack_runs ─► CALL label_capture ─► report
```

**Why so strict?** Every label in the dataset comes from this one file. The two kinds of input get different rules:

| | A honeypot log (steps 3 to 5) | The attack log (step 6) |
|---|---|---|
| a bad line | skipped and counted; the rest is saved | **the whole file is refused** |
| why | one broken line out of a million doesn't matter | one wrong row = thousands of wrong labels, and a model trained on wrong labels learns the wrong thing |
| errors shown | a count | **every problem at once**, with its line number, so A fixes everything in one round |

**Files:**

| File | What it does |
|---|---|
| [`ingest/attacks.py`](ingest/attacks.py) | reads the attack log (CSV, JSON list or JSON lines), all the checks, saving, the labeling report; the command you run |
| [`ingest/captures.py`](ingest/captures.py) | add and list captures (a new recording session must exist before its attack log and data) |
| [`samples/attack_log.csv`](samples/attack_log.csv) | the correct attack log for the sample capture: `run-001` |
| [`samples/attack_log_mistakes.csv`](samples/attack_log_mistakes.csv) | 7 rows, each with a typical mistake, to see the checks work |
| [`tests/test_attacks.py`](tests/test_attacks.py) | 18 tests |

**Run it** (from the `backend` folder):

```bash
.venv/Scripts/python -m ingest.attacks samples/attack_log.csv --check     # only check, save nothing
.venv/Scripts/python -m ingest.attacks samples/attack_log.csv --label     # save, label, show the report
.venv/Scripts/python -m ingest.attacks --report cap-2026-11-20-a          # only the report
.venv/Scripts/python -m ingest.captures list                              # captures and how much data each has
```

For a new recording session, add the capture first:

```bash
.venv/Scripts/python -m ingest.captures add cap-2026-11-21-a --start 2026-11-21T09:00:00Z --end 2026-11-21T10:00:00Z --kind attack
```

**Result** with `--label`:

```
1 attack runs: 0 new, 0 changed, 1 already saved

labeled capture cap-2026-11-20-a
  flows:      4 attack      5 normal
  events:    11 attack      8 normal
  run        scenario                 attacker         time (UTC)          flows  events
  run-001    bruteforce               192.168.56.99    14:10:00-14:18:00       4      11
  OK: every run matched traffic, and no attacker traffic is outside the runs
```

`0 new, 1 already saved` is correct: the seed already had `run-001` with exactly these values.

**What gets checked:**

| Check | Why it matters |
|---|---|
| scenario is one of the 9 allowed | `brute force` vs `bruteforce` would split one attack into two classes |
| times carry a time zone (`Z` or `+02:00`) | a time without one is a guess, and a wrong guess moves every label by hours |
| ends after it starts, valid IP, no unknown columns, no `run_id` twice | typos in the file |
| the capture exists and the run fits inside it | wrong capture, or times not in UTC |
| the target device exists | typo like `cam-02` |
| the attacker IP is **not** a honeypot device | otherwise every connection of that device becomes "attack". This happens with NAT, when the honeypot only sees the router's address |
| no overlap with another run **from the same attacker** (in the file or already saved) | a connection in the overlap would match both runs, and the database would pick one scenario at random |

Try `samples/attack_log_mistakes.csv` with `--check` to see all of them. Nothing is saved.

**The report catches two mistakes the checks can't** (they need the traffic):

1. **A run that matched no traffic.** The attacker IP is wrong (NAT), the times aren't UTC, the data isn't loaded,
   or the attack never actually ran.
2. **Attacker traffic outside every run.** It got labeled *normal*. Usually `end_ts` was written too early. The
   model would then learn "this attack is normal". The report lists those rows with their times.

**Fixing a mistake:** edit the attack log and load it again with `--label`. Changed runs are updated (the output
says which fields changed), unchanged runs are left alone, and `label_capture` first resets the capture's labels,
so the labels move with the fix.

**For A:** run `--check` on your attack log before sending it. It needs this repo, Python and the database (for the
capture and device checks).

**Run the tests:**

```bash
.venv/Scripts/python -m pytest -v
```

57 tests in total (at the end of step 6).

## Step 7: flow features (41 numbers per connection)

**What:** turn every row of `flows` into the 41 numbers the models learn from, and store them in `flows.features`.
This is the start of Phase 3. Task D's graph model uses these as **edge features**.

```
flows row (raw Zeek values) ─► fill missing ─► derive 4 numbers ─► log1p ─► one-hot 4 categories ─► flows.features (41)
```

**The 41 numbers:**

| Count | What | Example |
|---|---|---|
| 9 | numbers describing the connection: duration, bytes and packets each way, bytes/s, packets/s, share of bytes going out, average packet size sent | the camera stream: 84 KB back, 126 B out |
| 4 | `proto` one-hot: tcp, udp, icmp, other | `proto_tcp = 1`, the other three 0 |
| 11 | `service` one-hot: http, ssh, telnet, mqtt, dns, rtsp, ssl, dhcp, ntp, other, none | `service_ssh = 1` |
| 14 | `conn_state` one-hot: how the connection went (SF normal, S0 no answer, REJ refused, ...) | a port scan lights up `S0` / `REJ` |
| 3 | port class one-hot: well_known (<1024), registered (<49152), dynamic | port 1883 is `registered` |

**One-hot** means "a category as a row of 0s with a single 1". A model can't do maths with the word `ssh`, but it can
with `service_ssh = 1`.

**Files:**

| File | What it does |
|---|---|
| [`features/flow.py`](features/flow.py) | the 41 features: names and order read from the contract, the formulas, the category mapping |
| [`features/build.py`](features/build.py) | fills `flows.features` for flows in the database, the success check, the table / CSV; the command you run |
| [`tests/test_flow_features.py`](tests/test_flow_features.py) | 27 tests |

**Run it** (from the `backend` folder):

```bash
.venv/Scripts/python -m features.build flows --capture cap-2026-11-20-a --show
.venv/Scripts/python -m features.build flows --capture cap-2026-11-20-a --csv ../data/flow_features.csv   # open in Excel
```

**Result:**

```
computed features for 9 flows (0 already had version 1.0.0)
OK: 9 flows x 41 features, nothing missing, no NaN

time     to                 label    dur  o_byt  r_byt  o_pkt  r_pkt    B/s  pkt/s    out o_size   one-hot columns that are 1
14:04:50 192.168.56.10:53   0       0.02   3.43   4.08   0.69   0.69   8.39   4.62   0.34   3.43   udp dns SF well_known
14:05:00 192.168.56.10:1883 0       0.29   4.65   1.61   2.20   1.95   5.76   3.73   0.95   2.64   tcp mqtt SF registered
14:06:00 192.168.56.30:554  0       3.42   4.84  11.34   4.22   4.19   7.96   1.70   0.00   1.06   tcp rtsp SF well_known
14:10:02 192.168.56.10:22   1       1.37   5.79   5.97   2.71   2.56   5.50   2.28   0.45   3.19   tcp ssh SF well_known
14:10:05 192.168.56.10:22   1       1.35   5.79   5.97   2.71   2.56   5.53   2.31   0.45   3.19   tcp ssh SF well_known
14:12:39 192.168.56.10:22   1       3.81   7.19   7.41   3.89   3.85   4.23   1.14   0.44   3.35   tcp ssh SF well_known
14:13:20 192.168.56.99:80   1       0.89   4.28   9.91   3.09   3.00   9.56   3.37   0.00   1.48   tcp http SF well_known
14:30:00 192.168.56.20:0    0       1.10   3.43   3.43   1.39   1.39   3.43   1.39   0.49   2.40   icmp none OTH well_known
14:40:00 192.168.56.10:22   0       4.78   7.30   7.59   4.23   4.20   3.41   0.76   0.43   3.12   tcp ssh SF well_known
```

Running it again computes 0: only flows without features (or with features from an older contract version) are done.

**Design decisions:**

1. **The contract is the only list.** Names, order and categories are read from `feature_contract.json`. If
   someone changes the numeric list there without changing the formulas, the code refuses to start.
2. **log1p for big numbers.** `log1p(x) = log(1 + x)`. Without it, one 10 MB download outweighs everything else:
   100 bytes and 10 MB would be 10 million apart, after log1p they are 4.6 and 16.1. `+1` makes 0 stay 0.
3. **Stored without scaling.** The scaler (step 9) is *fitted* on training data. If scaled values were stored, they
   would change every time the split changes. So `flows.features` holds only the fixed steps, and C/D apply the
   step 9 scaler on top. The raw, readable values are still in the other columns (`orig_bytes`, `duration_s`, ...).
4. **Missing becomes 0 here, but only here.** In step 5 Zeek's `-` was stored as NULL ("unknown"). The contract
   says a model input is filled with 0, so a port-scan probe with no answer gets duration 0, bytes 0. The flows
   table still says NULL, so the difference isn't lost.
5. **No identifiers.** No IPs, no port numbers (only their class), no times, no IDs, no labels. A model that sees
   `192.168.56.99` learns "this lab's attacker", not "what an attack looks like".
6. **RTSP fix (promised in step 5).** Zeek reports the camera stream as `http`; on ports 554 / 8554 the feature
   says `rtsp`. The raw `service` column keeps Zeek's `http`.

**Look at the table:** the admin's SSH login at 14:40 (normal) and the attacker's long SSH session at 14:12
(attack) have almost the same numbers. **One connection on its own often can't show an attack.** That's why
step 8 looks at what happens to a device over time (10-second windows), and why D's model looks at the
connections together as a graph.

**Small quirk:** for ICMP (ping), Zeek puts the ICMP code where the port would be, so a ping's port class is
`well_known`. It doesn't hurt: `proto_icmp = 1` already tells the model it's a ping.

**Run the tests:**

```bash
.venv/Scripts/python -m pytest -v
```

84 tests in total (at the end of step 7).

## Step 8: window features (24 numbers per device per 10 s)

**What:** for every device and every 10 seconds of a capture, count what happened to it, across **all** sources
(network flows, Cowrie, Mosquitto, the sensor). Saved in the `feature_windows` table. Task C's models (LSTM-AE, VAE)
learn from these.

**Why:** step 7 showed one connection alone often can't reveal an attack. A window looks at one device over time.
In the sample, the window `gw-01 14:10:00` has 2 SSH connections **and** 2 failed logins from 1 source. The admin's
window at 14:40 has 1 SSH connection and nothing else.

```
flows into the device ─┐
events touching it ────┼─► group by (device, 10-second window) ─► 24 numbers + label ─► feature_windows
sensor readings ───────┘
```

**The 24 numbers:**

| Count | From | Features |
|---|---|---|
| 9 | flows **into** the device | connections, distinct source IPs, distinct ports (a scan lights this up), share of failed connections, bytes in, bytes out, packets in, average duration, SSH/Telnet connections |
| 7 | events | failed logins, successful logins, commands, MQTT connect / publish / subscribe, HTTP/RTSP requests |
| 4 | the sensor | number of readings (a DoS'd sensor sends fewer), biggest jump in smoke / temperature / humidity |
| 4 | `device_type` one-hot | esp32_sensor, ip_camera, gateway, other |

**Files:**

| File | What it does |
|---|---|
| [`features/window.py`](features/window.py) | the 24 features: windows on the clock, the counting (SQL), sensor jumps, the label rule |
| [`features/build.py`](features/build.py) | now also `windows`: saves them, the check, the table / CSV |
| [`tests/test_window_features.py`](tests/test_window_features.py) | 19 tests |

**Run it** (from the `backend` folder):

```bash
.venv/Scripts/python -m features.build windows --capture cap-2026-11-20-a --show
.venv/Scripts/python -m features.build windows --capture cap-2026-11-20-a --csv ../data/windows.csv   # plot it in Excel
```

**Result:**

```
capture cap-2026-11-20-a: 1080 windows (3 devices x 360 windows of 10 s); 16 with activity, 1064 silent; 5 attack
OK: 1080 windows x 24 features, nothing missing, no NaN

14:04:50  gw-01           normal             n_conn_in=1  ... n_mqtt_connect=1  n_mqtt_subscribe=1
14:06:00  cam-01          normal             n_conn_in=1  bytes_out_total=84069  mean_conn_duration=29.5455 ...
14:10:00  gw-01           ATTACK bruteforce  n_conn_in=2  n_unique_src_ip=1  ... n_ssh_telnet_conn=2  n_login_failed=2
14:12:30  gw-01           ATTACK bruteforce  n_conn_in=1  ... mean_conn_duration=44.0425  n_ssh_telnet_conn=1
14:12:40  gw-01           ATTACK bruteforce  n_login_success=1
14:13:00  gw-01           ATTACK bruteforce  n_commands=1
14:13:20  gw-01           ATTACK bruteforce  (touched, but nothing the features count)
14:25:00  esp32-smoke-01  normal             sensor_n_readings=1  sensor_smoke_delta_max=1 ...
14:30:00  esp32-smoke-01  normal             n_conn_in=1  ratio_failed_conn=1 ...
14:40:00  gw-01           normal             n_conn_in=1  ... mean_conn_duration=118.209  n_ssh_telnet_conn=1
```

`--show` prints only windows with activity, and only counts that aren't 0. The CSV has all 1080 rows.

**The rules:**

1. **Windows are on the clock:** 14:10:00, 14:10:10, 14:10:20 ... The same moment is always in the same window,
   for every device and every source.
2. **Silence counts.** Inside a capture, every device gets every window, even when nothing happened (1064 of
   1080 here). That's real information: an autoencoder must learn what "quiet" looks like, and a sensor under DoS
   suddenly *stops* sending. Outside captures, nothing is invented. (The old PoC filled empty windows with random
   numbers. Never again.)
3. **Which rows belong to a device:** flows where the device is the destination (contract: "into"); events the
   device logged, or with its IP on either end.
4. **Label:** a window is an attack if any attack flow or event touches the device in it; scenario and run = the
   one with the most attack rows. If the capture isn't labeled yet, the label is left empty (unknown), not 0, and
   you get a warning.
5. **Stored like step 7:** `features_raw` holds the counts as counted (for people, the dashboard, E's explanations),
   `features` holds them after log1p, not scaled. Each build replaces the capture's windows, because labels can change.

**Notice in the result:** the attack windows are only the moments the attacker *did* something. Between 14:10:10
and 14:12:20 the attacker was quiet, so those windows are normal. Labels come from evidence, not from the attack
log's time range. Step 9 joins 30 windows (5 minutes) into one sequence, which is how the models see the whole
attack.

**Three contract questions for Task C** (my choices are in the code and in [`TEAM_NOTES.md`](TEAM_NOTES.md), item 6):
own MQTT telemetry is recognised by publisher, not topic (so spoofing stays visible); sensor jumps compare with the
previous reading, because the ESP32 sends only one reading per window; and outgoing connections (like the malware
download at 14:13:20) aren't counted by any window feature yet.

**Run the tests:**

```bash
.venv/Scripts/python -m pytest -v
```

103 tests in total (at the end of step 8).

## Step 9: split, scaler, and the files for C and D

**What:** the hand-over. Split the windows and flows into **train / validation / test**, fit the **scalers**, and
write the files Task C and Task D load. This ends Phase 3.

```
feature_windows + flows ─► split by capture ─► fit scaler (train, normal only) ─► scale ─► parquet / npz files
```

### First: more than one capture (the fake lab)

The split works on **whole captures**, and so far there was only one. Until A delivers real captures,
[`demo/fake_lab.py`](demo/fake_lab.py) plays Task A for 6 days. It writes the same files A will send (Zeek
`conn.log`, Cowrie JSON, Mosquitto log, ESP32 CSV, attack log), then loads them with **our real steps 4 to 8**. So it
also proves that all the steps work together.

| Capture | 30 minutes of normal lab life, plus |
|---|---|
| `cap-demo-01`, `cap-demo-04` | nothing (normal only) |
| `cap-demo-02` | bruteforce (hydra, ~30 tries, then a login, commands, malware download) |
| `cap-demo-03` | vulnerability_scanning (nmap, 300 ports on the camera), mqtt_spoofing (fake smoke readings) |
| `cap-demo-05` | dos (SYN flood on the ESP32, which stops sending readings) |
| `cap-demo-06` | all four, so the test split has every scenario |

```bash
.venv/Scripts/python -m demo.fake_lab            # add them (5 seconds)
.venv/Scripts/python -m demo.fake_lab --remove   # take them out again before real data arrives
```

The step 6 report says `OK` for every attack capture: every run matched traffic, and no attacker traffic is left outside a run.

### The split: whole captures, in time order

**Why not shuffle all rows and take 70 / 15 / 15?** Window 14:10:00 and window 14:10:10 of the same attack are
almost twins. Shuffled, one twin lands in train and the other in test. The model "recognises" test rows it has
nearly seen, and the score is fake. The old PoC reported 100% this way. With whole captures, every test row comes
from a session the model never saw.

**Why in time order?** In real use, a model trained on the past runs on the future. So test = the newest captures.

**Rule:** a capture goes to train if its middle falls in the first 70% of all recorded time, validation if in the
next 15%, otherwise test. Then it's checked:

| Check | If it fails |
|---|---|
| test contains every scenario (contract) | refused: record a final capture with every attack, or write `splits.json` yourself |
| no split is empty, no capture in two splits, every capture labeled | refused |
| `--zero-day X`: scenario X only in test | refused if X leaks into train/val |
| validation has attacks (to choose thresholds) | warning |

### The scaler

`StandardScaler` turns every feature into "how far from normal": `(value - mean) / std`. Without it, `bytes_in_total`
(thousands) would drown `n_login_failed` (a few). Two rules:

1. **Fitted on train only.** Fitting on test data would leak information about the test set into training.
2. **Fitted on normal windows only** (label 0). C's autoencoders learn "what normal looks like", and the scale must
   describe normal, not attacks.

Columns the contract marks `scale: none` (one-hots, ratios) pass through unchanged. The scaler is fitted on the full
vector and those columns get mean 0 and std 1, so C and D just call `scaler.transform(X)` on all 24 (or 41) columns.

### Run it

```bash
.venv/Scripts/python -m features.dataset --dry-run                   # only show the split
.venv/Scripts/python -m features.dataset                             # build everything
.venv/Scripts/python -m features.dataset --zero-day mqtt_spoofing    # keep one attack completely unseen until test
```

**Result:**

```
split  captures   windows  attack  scenarios
train  5             3240      34  bruteforce, mqtt_spoofing, vulnerability_scanning
val    1              540       7  dos
test   1              540      34  bruteforce, dos, mqtt_spoofing, vulnerability_scanning

split   windows  attack  sequences  attack  flows  attack  X shape
train      3240      34       2805     166    431     341  [2805, 30, 24]
val         540       7        453      36   1521    1500  [453, 30, 24]
test        540      34        453     145   1851    1830  [453, 30, 24]
```

**Success check:** `sequences_train.npz` → `X` has shape `[2805, 30, 24]`. 2805 = 5 train captures × 3 devices ×
(windows − 29): a 30-window sequence can start at every window except the last 29.

### The files

| File | For | What's in it |
|---|---|---|
| `artifacts/features/v1.0.0/window_scaler.joblib`, `flow_scaler.joblib` | C, D | the fitted scalers. **Load these, never fit your own** |
| `artifacts/features/v1.0.0/feature_order.json` | C, D | the exact column order of every vector |
| `artifacts/features/v1.0.0/splits.json`, `contract.json` | everyone | which capture is in which split; the contract at fit time |
| `data/processed/v1.0.0/sequences_{train,val,test}.npz` | C | `X [N, 30, 24]`, `y`, `y_window`, `entity_id`, `window_start`. 30 windows = 5 minutes of one device, never across captures |
| `data/processed/v1.0.0/windows.parquet` | C | one row per device per 10 s, scaled |
| `data/processed/v1.0.0/edges_{train,val,test}.parquet` | D | one row per connection sorted by time, with `src_node` / `dst_node` (`dev:gw-01`, `ip:192.168.56.99`) and the 41 features |
| `data/processed/v1.0.0/nodes.parquet` | D | every device and IP: type, first and last seen |
| `data/processed/v1.0.0/flows.parquet` | everyone | every flow with ids, labels, split, 41 features |

How C reads them (`numpy`, `joblib`):

```python
import numpy as np
train = np.load("data/processed/v1.0.0/sequences_train.npz")
X_normal = train["X"][train["y"] == 0]          # the autoencoders learn only from normal sequences
```

Both folders are in `.gitignore`: they are rebuilt from the database in 2 seconds, and today they hold fake-lab
data. Send them to C and D through the team drive when there is real data.

**Files:**

| File | What it does |
|---|---|
| [`demo/fake_lab.py`](demo/fake_lab.py) | the fake lab: writes A-style logs for 6 captures and loads them with steps 4 to 8 |
| [`features/split.py`](features/split.py) | the capture split: proposal, checks, `splits.json` |
| [`features/dataset.py`](features/dataset.py) | scalers, sequences, graph edges and nodes, all export files; the command you run |
| [`tests/test_dataset.py`](tests/test_dataset.py) | 16 tests, including the whole fake lab end to end |

New libraries in `requirements.txt`: numpy, pandas, pyarrow, scikit-learn. Install with
`.venv/Scripts/python -m pip install -r requirements.txt`.

**Run the tests:**

```bash
.venv/Scripts/python -m pytest -v
```

119 tests in total (at the end of step 9).

## Step 10: the API (FastAPI), `/health`, and the POST endpoints

**What:** Phase 4 starts. Until now, data came in through command-line tools reading files. Now there's a web
**API**: devices and teammates send data over the network, and later (step 11) the dashboard, C, D and E fetch
data the same way.

```
ESP32 / honeypot / Task A ──HTTP POST──► API (FastAPI, port 8001) ──► same checks as the command line ──► database
```

**An API in one sentence:** a program that waits for requests like "here is an event, save it" (POST) or "give me
the alerts" (GET) at fixed addresses, and answers in JSON.

**Port 8001**, on purpose: the old API (`aegex/api`, port 8000) keeps running for the current dashboard. Nothing
breaks. (Step 11 adds `frontend/dashboard_new.html` for the new API; the old `dashboard.html` stays as it is.)

**Run it** (from the `backend` folder, database running):

```bash
.venv/Scripts/python -m api            # then open http://localhost:8001/docs
.venv/Scripts/python -m api --reload   # while editing the code: restarts by itself
.venv/Scripts/python -m api --host 0.0.0.0   # so the ESP32 / Pi on the lab network can reach it
```

**`/docs` is Swagger:** a web page that FastAPI builds from the code. It lists every endpoint with an example. Press
**Try it out**, then **Execute**, and you have sent a real request. That's the success check for this step.

**The endpoints:**

| Method | Path | Who calls it | What it does |
|---|---|---|---|
| GET | `/health` | everyone | is the API up, is the database reachable, how many rows |
| POST | `/api/v1/ingest/events` | devices, parsers | one event, or a list of up to 5000, in the contract's format |
| POST | `/api/v1/ingest/sensor` | ESP32 | one reading (`smoke`, `temperature_c`, `humidity_pct`) |
| POST | `/api/v1/ingest/logs/{source}` | the Pi, scripts | raw log text: `cowrie`, `mosquitto`, `esp32` (CSV), `zeek-conn` |
| POST | `/api/v1/captures` | A, B | register a recording session |
| POST | `/api/v1/attack-runs` | A | the attack log (one run or a list); `?label=true` re-labels afterwards |

**Result** (success check):

1. In Swagger: `POST /api/v1/ingest/events` → Try it out → Execute → `200`,
   `{"received": 1, "inserted": 1, "duplicates": 0, "captures": {"(none)": 1}}`
2. In the database:
   ```
   ts                        | source | event_type   | layer               | device_id | src
   2026-11-22 12:00:03.12+00 | cowrie | login_failed | session_interaction | gw-01     | 192.168.56.99
   ```
   `layer` was filled in from the contract; the sender doesn't send it. `"(none)"` means the example's time is
   outside every capture: saved, but never labeled, so trying the examples can't spoil the sample data.

**The API uses the same rules as the command-line tools.** It doesn't reimplement them, it calls the same code:

| Rule | Example answer |
|---|---|
| shape checked before our code runs (pydantic) | time without a zone, port 70000, a misspelled field → `422` with the exact place: `["body", 0, "ts"]` |
| contract checked (event type, which source may send it) | `item 2: source 'esp32' is not allowed for event_type 'login_failed'` |
| everything or nothing | one bad event in a list of 100 → `422`, all problems listed, **0 saved** |
| no duplicates | the same event again → `"inserted": 0, "duplicates": 1` |
| capture found by time | leave `capture_id` out → the capture recording at that moment is used |
| database down | `503` "The database is not reachable", and `/health` says `degraded`. The server doesn't crash |

**New ideas in this step:**

- **pydantic models** ([`api/schemas.py`](api/schemas.py)) describe what a request must look like. FastAPI uses them
  to check every request *and* to build the Swagger page, so the docs can never be out of date.
- **A connection pool** ([`api/db.py`](api/db.py)) keeps a few database connections open and lends one to each request.
  Opening a new connection for every request would be slow.
- **Status codes:** `200` OK, `201` created, `409` conflict (a capture with that id exists with other values),
  `422` refused by the checks, `503` database down.

**Files:**

| File | What it does |
|---|---|
| [`api/main.py`](api/main.py) | the app: start/stop, `/health`, error answers, CORS (so the browser dashboard may call it) |
| [`api/ingest.py`](api/ingest.py) | events, sensor, raw logs |
| [`api/lab.py`](api/lab.py) | captures, attack runs |
| [`api/schemas.py`](api/schemas.py) | the request and answer shapes, with the Swagger examples |
| [`api/db.py`](api/db.py) | the connection pool |
| [`tests/test_api.py`](tests/test_api.py) | 20 tests (FastAPI's TestClient calls the app directly, no server needed) |

New libraries in `requirements.txt`: fastapi, uvicorn, pydantic, psycopg-pool, httpx.

**Not yet:** the API key that the contract wants on POST endpoints comes in step 12. Until then, run the API only
on your own computer or the lab network, never on the internet.

**Run the tests:**

```bash
.venv/Scripts/python -m pytest -v
```

139 tests in total (at the end of step 10).

## Step 11: the GET endpoints (reading data back out)

**What:** step 10 let data come **in**. Step 11 lets everyone read it back **out**, over the network, without
touching the database or the parquet files: the dashboard and E read events, C reads window features, D reads
flows and graph edges. All the routes are in [`api/read.py`](api/read.py).

```
database ──► API (port 8001) ──GET──► dashboard (events, flows)
                                 ├──► C: /features/windows   (live inference on the newest windows)
                                 ├──► D: /graph/edges        (live inference on the newest flows)
                                 └──► E: /events             (what happened around an alert)
```

**The endpoints** (all under `/api/v1`):

| GET | Filters | Who |
|---|---|---|
| `/devices` | | everyone |
| `/captures` | `from`, `to` (captures overlapping the range), `kind` | A, B |
| `/attack-runs` | `from`, `to`, `capture_id`, `scenario` | A, evaluation |
| `/events` | `from`, `to`, `device_id`, `source`, `event_type`, `label`, `capture_id` | dashboard, E |
| `/flows` | `from`, `to`, `device_id` (either end), `label`, `capture_id`, `include_features` | dashboard, D |
| `/features/windows` | `from`, `to`, `device_id`, `label`, `capture_id`, `include_raw` | C |
| `/graph/edges` | `from`, `to`, `label`, `capture_id` | D |

**Every list answers the same way:**

```json
{ "items": [ ... ], "count": 100, "next_cursor": "WyIyMDI2LTExLTIw..." }
```

- **Time range:** `from` is included, `to` is not, so `from=14:00&to=14:10` followed by `from=14:10&to=14:20`
  never counts a row twice. Write times with `Z` (`2026-11-20T14:00:00Z`). In a URL, a `+` turns into a space.
- **Pages:** at most `limit` items per answer (default 100, max 5000). If `next_cursor` is not null, ask again with
  `?cursor=<that value>` and the **same filters**. When it is null, you have everything.
- **Order:** `order=asc` (oldest first, the default: what models replay) or `order=desc` (newest first: what the
  dashboard shows).
- **Mistakes** get a `422` that says what's wrong: an unknown `event_type` or `scenario`, `from` after `to`, a time
  without a time zone, `limit=9999`, a damaged cursor.

**Why a cursor and not `?page=2`?** Events keep arriving while someone reads. With page numbers, one new row pushes
everything down by one: the reader sees a row twice or misses one. The cursor means "continue **after this row**"
(its time and id), so new rows can't shift anything. A test proves it: an event arrives between page 1 and page 2,
and every event still comes exactly once.

**What the models get:**
- **Features come in contract order** (the same order as `feature_order.json`), named, and **not scaled**: C and D
  apply the step 9 scalers themselves, exactly as with the files.
- `/features/windows` is sorted by time, then device: all devices' 14:00:00 windows, then all devices' 14:00:10
  windows, and so on. `include_raw=true` adds the counts as counted, which helps a person read them.
- `/graph/edges` uses the same node ids as `edges_*.parquet`: `dev:gw-01` for our devices, `ip:192.168.56.99` for
  everything else. A flow only becomes an edge once its features are built (`python -m features.build flows`).
- `/flows` leaves the 41 features out unless you ask (`include_features=true`), so the dashboard's answers stay small.

**Try it:** start the API (`.venv/Scripts/python -m api`), open http://localhost:8001/docs, open
`GET /api/v1/events`, press **Try it out**, set `label = 1` and `capture_id = cap-2026-11-20-a`, press **Execute**.
You get the brute force's events, starting with the `session_open` from `192.168.56.99` at 14:10:03.

From Python (what C and D will do), following the cursor until the end:

```python
import httpx

def fetch_all(path, **params):
    items, cursor = [], None
    while True:
        page = httpx.get(f"http://127.0.0.1:8001/api/v1{path}",
                         params={**params, "limit": 5000, **({"cursor": cursor} if cursor else {})}).json()
        items += page["items"]
        cursor = page["next_cursor"]
        if cursor is None:
            return items

windows = fetch_all("/features/windows", **{"from": "2026-11-26T10:00:00Z"})
```

**Use `127.0.0.1` in scripts, not `localhost`.** On Windows, Python tries `localhost` over IPv6 first, waits
2 seconds, and only then tries `127.0.0.1`, which is where the server listens. That adds 2 seconds to **every**
request. Browsers don't have this problem. With `127.0.0.1`, the whole dev database comes back fast: all 4320
windows in 0.3 s, all 3803 edges in 0.8 s.

**Files:**

| File | What it does |
|---|---|
| [`api/read.py`](api/read.py) | the 7 GET endpoints, the filters, and the cursor pagination (`fetch_page`) |
| [`api/schemas.py`](api/schemas.py) | the answer shapes (`Page`, `EventOut`, `FlowOut`, `WindowOut`, `EdgeOut`, ...) |
| [`tests/test_api_read.py`](tests/test_api_read.py) | 12 tests on the step 2 story, loaded through the real pipeline |

151 tests in total (at the end of step 11).

### The dashboard on the new API

`frontend/dashboard_new.html` is a copy of the team's dashboard that reads the new API (port 8001).
`frontend/dashboard.html` is **unchanged** and still reads the old API (port 8000), so nothing the team uses breaks.

**Three small summary endpoints** ([`api/stats.py`](api/stats.py)), because a chart needs counts, not thousands
of rows:

| GET | Gives | Panel |
|---|---|---|
| `/api/v1/stats/summary` | events per layer / source / label, flows, attack events + flows per scenario and per run | the cards, the attacks chart |
| `/api/v1/stats/events-histogram` | events per time bucket, one series per event type; empty buckets are 0 | events over time |
| `/api/v1/stats/sensors` | temperature, smoke, humidity over time (raw up to 2 h, averaged beyond) | the sensor charts |

All take `from`, `to` and `capture_id`. `/events` also got `min_severity` for the table's severity filter.

**What each page shows now:**

| Page | Before (old API) | Now (new API) |
|---|---|---|
| Overview | sensors, layer counts, Wi-Fi/Bluetooth and attacker/normal counts | sensors, layer counts (network traffic = Zeek flows), attack/normal events, attack flows |
| Events over time | Elasticsearch histogram | `/stats/events-histogram` |
| Detected attacks | the old rule-based detections | **Task A's attack log**: attack events + flows per scenario, and the attack runs. The models' alerts replace this in step 12. |
| Recent events | Elasticsearch events | `/events`, newest first; attack events are tagged `[attack: scenario]` |
| Threat intelligence | old API | **still the old API** (knowledge base and blue-team report belong to E; step 12 adds `/reports`) |

**New at the top: Live or a capture.** "Live" with the 15m / 1h / 6h / 24h buttons works as before. Picking a
capture shows exactly that recording session, start to end, and stops the 5-second refresh (a finished
recording doesn't change). That's how you show the lab's data in a demo, since it was not recorded "in the last
hour". The live ESP32 link (Wi-Fi or USB) only draws in Live mode, so it never mixes into a past capture.

**At the bottom:** "API address" (new API, default `http://localhost:8001`) and "Threat-intel API" (old API,
default `http://localhost:8000`). The header pills show whether each one answers.

**Open it:** the browser blocks some things on pages opened as files, so serve the folder:

```bash
.venv/Scripts/python -m http.server 8095 --bind 127.0.0.1 --directory ../frontend
# then open http://localhost:8095/dashboard_new.html (with the API running)
```

(Port 8095 because something on this computer already uses 8090.) In the Claude app, `.claude/launch.json` has
both servers: `aegex-api` and `dashboard`.

**Tests:** 4 more in [`tests/test_api_read.py`](tests/test_api_read.py) for the summary endpoints and
`min_severity`. The dashboard page itself was checked by hand in the browser: every panel loaded for
cap-demo-06, the numbers matched the database (514 events, 4 attack runs), and the console showed no errors.

**Run the tests:**

```bash
.venv/Scripts/python -m pytest -v
```

155 tests in total at the end of step 11; 162 after the proof-of-concept lab (`tests/test_poc.py`, see [POC_GUIDE.md](POC_GUIDE.md)); 163 with the AI models connection (`tests/test_detect.py`).

## Test everything, from start to end

Three levels, all from the `backend` folder, with the database running:

```bash
.venv/Scripts/python -m pytest                 # 163 unit tests: each piece alone (25 s)
.venv/Scripts/python -m demo.check_all         # steps 1-11 together, in order, PASS/FAIL per step (15 s)
.venv/Scripts/python -m demo.live_sim          # live data without the hardware (Ctrl+C to stop)
```

**`demo.check_all`** ([`demo/check_all.py`](demo/check_all.py)) builds a throw-away database `aegex_e2e` (your
`aegex` data is not touched) and runs the whole story: tables, inventory, parsers, loader, real Zeek on the sample
pcap, attack log + labels, flow and window features, the fake lab + dataset files, then starts the real API and
uses it over HTTP (send data in, read it back out, follow the pages, the dashboard summaries). `--keep` keeps the
database to look around; `--no-zeek` skips Docker's Zeek and uses the saved `conn.log`.

**`demo.live_sim`** ([`demo/live_sim.py`](demo/live_sim.py)) pretends to be the lab while the hardware is away: a
fake ESP32 reading every 2 s, an MQTT publish every 5 s, and an SSH brute force from `192.168.56.99` about every
40 s (as Cowrie's JSON lines and Zeek conn.log lines). It uses the same endpoints the real devices will. Open
`dashboard_new.html` in **Live** mode and watch the charts and the event table move. It keeps its data in a
`cap-sim-<time>` capture; `--clean` deletes it all afterwards. Live data stays unlabeled (`label = null`): only
Task A's attack log labels data.

## One command per recording: the pipeline (8-step plan, Step 3)

Steps 4-8 above are separate commands. [`ingest/pipeline.py`](ingest/pipeline.py) runs them together for one
recording session, described in a small JSON file ([`sessions/sample-lab.json`](sessions/sample-lab.json) is the
sample lab):

```powershell
.venv\Scripts\python -m ingest.pipeline run sessions\sample-lab.json --check   # check the inputs, save nothing
.venv\Scripts\python -m ingest.pipeline run sessions\sample-lab.json           # every stage
.venv\Scripts\python -m ingest.pipeline run sessions\datasets-small.json       # public datasets -> aegex_datasets
```

The stages are: check inputs → capture → flows (pcap → Zeek) → logs → attack log + labels → features → detect
(optional, the AI models). Each prints PASS / WARN / FAIL with its counts. The first FAIL stops the run, and if the
inputs are wrong, nothing is saved. Running it again saves nothing new. Each run's report is kept in
`pipeline_runs/` (not in git).

## The datastore: size, compression, backup (8-step plan, Step 4)

There is one schema (`database/schema_v2.sql`) in three databases: `aegex` (sample lab), `aegex_poc` (the PoC
lab, which the dashboard reads) and `aegex_datasets` (public datasets). [`ingest/datastore.py`](ingest/datastore.py)
looks after them:

```powershell
.venv\Scripts\python -m ingest.datastore status                                   # size, rows, compression of each
.venv\Scripts\python -m ingest.datastore compress --db aegex_datasets             # 20x smaller, still readable
.venv\Scripts\python -m ingest.datastore compress --db aegex_poc --older-than '7 days'
.venv\Scripts\python -m ingest.datastore backup --db aegex_poc                    # -> backups\aegex_poc_<time>.dump
.venv\Scripts\python -m ingest.datastore restore backups\<file>.dump --db aegex_poc_restored
```

- **Indexes:** `flows (capture_id, ts_start)` and `events (capture_id, ts)`, because "everything of one capture"
  is the most common read. On `aegex_poc`, counting one capture's flows went from 15 ms to 5 ms.
- **Compression** (TimescaleDB) stores finished chunks per column, grouped by capture. Kitsune Mirai's flows went
  from 56.7 MB to 2.6 MB with the same rows, and they can still be read, re-loaded and updated. Dataset loading
  (`datasets.to_unified`, the pipeline) compresses automatically. The honeypot databases are only compressed when
  you run `compress`.
- **Backup / restore** run `pg_dump` / `pg_restore` inside the database container, so nothing needs installing
  on Windows. A restore always creates a **new** database, so it can never overwrite live data. `backups/` is not
  in git.

## API additions (8-step plan, Step 5)

New endpoints ([`api/operations.py`](api/operations.py)), listed at http://localhost:8001/docs:

| Endpoint | What it gives |
|---|---|
| `GET /api/v1/datasets` | the 8 public datasets: source, size, labels, models, what is loaded in this database, Step 1's measured totals |
| `GET /api/v1/datasets/{id}` | one dataset's captures with flows per attack class, and its caveats |
| `GET /api/v1/pipeline/runs`, `/pipeline/runs/{run_id}` | the pipeline's run reports (Step 3), stage by stage |
| `GET /api/v1/datastore` | size, rows, chunks and compression of this database (Step 4) |

`GET /api/v1/flows` now also returns `fwd_flags`, `bwd_flags`, `attack_class` and `label_info`. It filters on
`scenario`, `attack_class`, `src_ip` and `dataset` (`kitsune`, …, or `honeypot`). `GET /api/v1/captures` shows and
filters `dataset`. Wrong filter values are refused with every problem listed (422). The API reads one database
(`AEGEX_DB_URL`); start it on `aegex_datasets` to browse the public datasets with every endpoint.

## Replay a recorded attack live (8-step plan, Step 6)

[`demo/replay.py`](demo/replay.py) plays a stored capture back as live traffic, through the same ingest endpoint
the real Zeek sensor uses:

```powershell
.venv\Scripts\python -m demo.replay --capture ds-kitsune-mirai --dry-run                      # the plan only
.venv\Scripts\python -m demo.replay --capture ds-kitsune-mirai --from 2018-10-25T06:58:00Z --speed 10
.venv\Scripts\python -m demo.replay --capture ds-kitsune-mirai --map 192.168.2.110=192.168.137.50
.venv\Scripts\python -m demo.replay --clean                                                   # remove replays
```

- Time is moved to now and compressed by `--speed`. `--from` / `--to` pick a part of the recording.
- TCP flags travel in Zeek's `history`, so they arrive unchanged.
- `--map` gives a recorded host one of our addresses.
- Replayed data is unlabelled, like real live traffic. The ground truth (which flow was an attack) goes to
  `replays/<capture>.json` for Step 8.

## Rule-based correlation baseline (8-step plan, Step 7)

[`correlate/rules.py`](correlate/rules.py) uses simple rules with no machine learning. It is the yardstick the AI
models have to beat. Each rule looks at one source address in one minute:

| Rule | Fires at | Scenario |
|---|---|---|
| port_scan | ≥ 20 ports tried on one host | vulnerability_scanning |
| host_sweep | ≥ 20 hosts tried, mostly unanswered (or ARP requests) | vulnerability_scanning |
| telnet_scan | Telnet tried on ≥ 5 hosts | mirai_botnet |
| flood | ≥ 100 connections to one service (host + port) | dos |
| brute_force | ≥ 5 failed logins in 10 minutes (fail2ban's defaults) | bruteforce |

Hits from the same source less than 2 minutes apart form **one incident**, even when different rules fired. The
incident also collects that source's events from the other sources (Cowrie logins, honeypot hits) and the devices
it reached. The thresholds are round numbers fixed before any evaluation.

```powershell
.venv\Scripts\python -m correlate --capture cap-2026-11-20-a        # database: AEGEX_DB_URL
.venv\Scripts\python -m correlate --all --db aegex_poc
.venv\Scripts\python -m correlate --capture ds-kitsune-mirai --db aegex_datasets --dry-run
```

Incidents are saved as alerts with `model_name = 'rules'`, so the API, the dashboard (AI alerts → "Rule baseline")
and Step 8 treat them like the AI models' alerts. A re-run replaces them. The pipeline runs it as the stage
"correlate (rule baseline)". The rules count per minute of the traffic's own clock, so a sped-up replay looks
faster to them: score the baseline on traffic at its original speed.

## Evaluation harness (8-step plan, Step 8)

[`evaluate/`](evaluate/) scores every detector on a labelled capture, side by side. The detectors are the rule
baseline, LSTM-AE, VAE, LSTM-AE + VAE (the AI team's alert), temporal GAT, and all of them together:

```powershell
.venv\Scripts\python -m evaluate --capture ds-kitsune-mirai --db aegex_datasets --from 2018-10-25T06:58:00Z `
                                 --capture poc-attack --db aegex_poc --from -
```

- **Ground truth** = flow labels (the dataset's own labels, or Task A's attack log through `label_capture`).
- **Covered flows:** an alert covers the flows in its time window that its host *sent* (rules, GAT), or that
  *belong to* its device by the AI team's own rule (`aegex_prep.assign_device`, for LSTM-AE / VAE windows).
- **Flow level:** recall, precision, F1 and false alarm rate. **Attacker level:** attack sources found, normal hosts
  flagged, and time from a host's first attack flow to its first alert.
- **Calibrated like the honeypot:** on our network the models calibrate on a normal recording first. For Kitsune,
  the 70 attack-free minutes play that part (`python -m demo.cut_pcap ... --before 2018-10-25T06:58:00Z`, then
  `python -m detect <pcap> --normal <cut>`). Only the time after the cut is scored (`--from`). `detect.py
  --reference-scaler kitsune` instead uses the scaler stored in the model, with no calibration.

Results (27 Nov 2026, `evaluate/report/evaluation.md`):

| Kitsune Mirai, infection period (27,966 flows, 13,104 attack) | Recall | Precision | F1 | False alarms | Bots found |
|---|---|---|---|---|---|
| Rule baseline | 100 % | 84.4 % | 91.5 % | 16.3 % | 1 / 2 |
| LSTM-AE | 57.0 % | 84.2 % | 68.0 % | 9.4 % | 1 / 2 |
| VAE | 94.3 % | 80.5 % | 86.9 % | 20.1 % | 1 / 2 |
| LSTM-AE + VAE | 98.3 % | 80.2 % | 88.3 % | 21.4 % | 1 / 2 |
| LSTM-AE + VAE, not calibrated (stored scaler, whole capture) | 100 % | 41.5 % | 58.6 % | 50.1 % | 2 / 2 |
| Temporal GAT (pooled threshold: never trained on Kitsune) | 100 % | 56.5 % | 72.2 % | 67.9 % | 2 / 2 |

On the PoC recording (synthetic, loud scan + flood), the rules score 100 % / 100 % with 0 false alarms. LSTM-AE + VAE
reach 100 % recall and 98 % precision, but also flag the phone (12 % false alarms).

What this shows, honestly: loud, known attacks are caught by simple rules. The AI models need calibration on our own
normal traffic (it halves their false alarms). The VAE is the stronger of the two AI stages. Only the GAT finds the
quiet second Mirai bot (.107), but it does not transfer to networks it was not trained on, as the AI team warns.
The test data is small: one public capture plus one synthetic recording.

**For the team:** [TEAM_GUIDE.md](TEAM_GUIDE.md) is the short version of this README: the steps in one table, and
what each task does with the backend.
