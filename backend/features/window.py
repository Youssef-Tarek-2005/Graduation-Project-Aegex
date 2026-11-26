"""Window features: 24 numbers per device per 10 seconds (contract -> window_features).

Step 7 showed that one connection on its own often can't reveal an attack: the admin's SSH login and the attacker's
look almost the same. A window looks at what happened to ONE device during 10 seconds, across all sources:

    9 from flows into the device      connections, distinct sources, distinct ports, failed share, bytes, packets,
                                      average duration, SSH/Telnet connections
    7 from events                     failed / successful logins, commands, MQTT connect / publish / subscribe,
                                      HTTP / RTSP requests
    4 from the sensor                 number of readings, biggest jump in smoke / temperature / humidity
    4 device_type one-hot             esp32_sensor, ip_camera, gateway, other
   --
   24

Rules (contract):
  - Windows are 10 s, aligned to the clock: 14:10:00, 14:10:10, 14:10:20, ...
  - Inside a capture, EVERY window of every device exists. A window where nothing happened is real silence
    (all counts 0), and silence is information: a DoS'd sensor goes quiet. Outside captures nothing is made up.
  - A window is an attack (label 1) if any attack flow or event touches the device in it.

Two places where the contract had to be read carefully (both are in TEAM_NOTES.md for Task C to confirm):
  - mqtt_publish "excluding the device's own telemetry": a publish is left out when the PUBLISHER is one of our
    own devices (the sensor sending its readings). Leaving out by topic instead would hide mqtt_spoofing, where an
    attacker publishes on the sensor's topic.
  - sensor "max change between consecutive readings": the ESP32 sends one reading every 10 s, so a 10 s window
    almost never has two. Each reading is compared with the device's previous reading (even if that was in an
    earlier window), and the window keeps its biggest change.
"""
from __future__ import annotations

import math
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

import psycopg

from ingest.event import CONTRACT

FEATURE_VERSION: str = CONTRACT["feature_version"]
SPEC = CONTRACT["window_features"]
WINDOW_SECONDS: int = SPEC["window_seconds"]
WINDOW = timedelta(seconds=WINDOW_SECONDS)
DEVICE_TYPES: list[str] = CONTRACT["categorical_vocabularies"]["device_type"]

NUMERIC: list[str] = [f["name"] for f in SPEC["numeric"]]
TRANSFORM: dict[str, str] = {f["name"]: f["transform"] for f in SPEC["numeric"]}
FEATURE_NAMES: list[str] = NUMERIC + [f"device_type_{t}" for t in DEVICE_TYPES]
assert len(FEATURE_NAMES) == SPEC["dimension"], f"contract says {SPEC['dimension']} window features, built {len(FEATURE_NAMES)}"

FAILED_STATES = ("S0", "REJ", "RSTOS0", "RSTRH", "SH", "SHR", "OTH")   # no proper answer from the device
SSH_TELNET_PORTS = (22, 23, 2222, 2223)
SENSOR_FIELDS = {"sensor_smoke_delta_max": "smoke", "sensor_temp_delta_max": "temperature_c",
                 "sensor_humidity_delta_max": "humidity_pct"}


# ------------------------------------------------------------------------------------------- time
def window_start(ts: datetime) -> datetime:
    """The start of the 10 s window that holds ts, aligned to the clock (epoch)."""
    epoch = ts.timestamp()
    return datetime.fromtimestamp(epoch - epoch % WINDOW_SECONDS, tz=timezone.utc)


def capture_windows(start: datetime, end: datetime) -> list[datetime]:
    """Every window start from the one holding `start` up to (not including) `end`."""
    out, ws = [], window_start(start)
    while ws < end:
        out.append(ws)
        ws += WINDOW
    return out


# The same rounding in SQL: seconds since 1970, rounded down to a multiple of 10.
def _bucket(col: str) -> str:
    return f"to_timestamp(floor(extract(epoch FROM {col}) / {WINDOW_SECONDS}) * {WINDOW_SECONDS})"


# ------------------------------------------------------------------------------------------- gathering
# Which rows belong to a device? Flows: "into the device" = the device is the destination (contract).
# Events: the event was logged by the device, or the device's IP is on either end.
TOUCHES = "(t.device_id = d.device_id OR t.src_ip = d.ip OR t.dst_ip = d.ip)"

FLOW_SQL = f"""
SELECT d.device_id, {_bucket('f.ts_start')} AS ws,
       count(*)::float8                                                         AS n_conn_in,
       count(DISTINCT f.src_ip)::float8                                         AS n_unique_src_ip,
       count(DISTINCT f.dst_port)::float8                                       AS n_unique_dst_port,
       avg((COALESCE(f.conn_state, '') IN {FAILED_STATES})::int)::float8        AS ratio_failed_conn,
       sum(COALESCE(f.orig_bytes, 0))::float8                                   AS bytes_in_total,
       sum(COALESCE(f.resp_bytes, 0))::float8                                   AS bytes_out_total,
       sum(COALESCE(f.orig_pkts, 0))::float8                                    AS pkts_in_total,
       avg(COALESCE(f.duration_s, 0))::float8                                   AS mean_conn_duration,
       (count(*) FILTER (WHERE split_part(lower(COALESCE(f.service, '')), ',', 1) IN ('ssh', 'telnet')
                            OR f.dst_port IN {SSH_TELNET_PORTS}))::float8       AS n_ssh_telnet_conn
  FROM flows f JOIN devices d ON f.dst_ip = d.ip
 WHERE f.capture_id = %(cap)s
 GROUP BY 1, 2
"""

EVENT_SQL = f"""
SELECT d.device_id, {_bucket('t.ts')} AS ws,
       (count(*) FILTER (WHERE t.event_type = 'login_failed'))::float8          AS n_login_failed,
       (count(*) FILTER (WHERE t.event_type = 'login_success'))::float8         AS n_login_success,
       (count(*) FILTER (WHERE t.event_type = 'command'))::float8               AS n_commands,
       (count(*) FILTER (WHERE t.event_type = 'mqtt_connect'))::float8          AS n_mqtt_connect,
       (count(*) FILTER (WHERE t.event_type = 'mqtt_publish'
                           AND (t.src_ip IS NULL                     -- not published by one of our devices
                                OR t.src_ip NOT IN (SELECT ip FROM devices WHERE ip IS NOT NULL))
                        ))::float8                                              AS n_mqtt_publish,
       (count(*) FILTER (WHERE t.event_type = 'mqtt_subscribe'))::float8        AS n_mqtt_subscribe,
       (count(*) FILTER (WHERE t.event_type IN ('http_request', 'media_stream')))::float8 AS n_http_rtsp_req
  FROM events t JOIN devices d ON {TOUCHES}
 WHERE t.capture_id = %(cap)s
 GROUP BY 1, 2
"""

# Every flow and event touching a device, grouped by label: gives the window's label and how busy it was.
LABEL_SQL = f"""
SELECT d.device_id, {_bucket('t.ts')} AS ws, t.label, t.scenario, t.run_id, count(*)
  FROM (SELECT ts_start AS ts, src_ip, dst_ip, device_id, label, scenario, run_id FROM flows  WHERE capture_id = %(cap)s
        UNION ALL
        SELECT ts,             src_ip, dst_ip, device_id, label, scenario, run_id FROM events WHERE capture_id = %(cap)s) t
  JOIN devices d ON {TOUCHES}
 GROUP BY 1, 2, 3, 4, 5
"""

SENSOR_SQL = """
SELECT device_id, ts, payload FROM events
 WHERE capture_id = %(cap)s AND event_type = 'sensor_reading' AND device_id IS NOT NULL
 ORDER BY device_id, ts
"""


def _sensor_features(rows: list[tuple]) -> dict[tuple[str, datetime], dict[str, float]]:
    """Readings per window, and the biggest change from the previous valid reading, per sensor field."""
    out: dict[tuple[str, datetime], dict[str, float]] = defaultdict(lambda: defaultdict(float))
    previous: dict[tuple[str, str], float] = {}                  # (device, field) -> last valid value
    for device, ts, payload in rows:
        key = (device, window_start(ts))
        out[key]["sensor_n_readings"] += 1
        for feature, fld in SENSOR_FIELDS.items():
            value = payload.get(fld)
            if not isinstance(value, (int, float)) or not math.isfinite(value):
                continue                                          # bad reading ("ERR"): skip, keep the previous one
            if (device, fld) in previous:
                out[key][feature] = max(out[key][feature], abs(value - previous[(device, fld)]))
            previous[(device, fld)] = float(value)
    return out


# ------------------------------------------------------------------------------------------- one window
@dataclass
class Window:
    device_id: str
    window_start: datetime
    features_raw: dict[str, float]          # counts as counted, for people (dashboard, E's explanations)
    features: dict[str, float]              # after log1p where the contract says so; NOT scaled (step 9)
    n_events: int                           # flows + events touching the device (0 = a silent window)
    label: int | None
    scenario: str | None
    run_id: str | None

    @property
    def window_end(self) -> datetime:
        return self.window_start + WINDOW


def transform(raw: dict[str, float]) -> dict[str, float]:
    out = {}
    for name in FEATURE_NAMES:
        kind = TRANSFORM.get(name, "none")           # the device_type columns have no transform
        if kind == "log1p":
            out[name] = math.log1p(raw[name])
        elif kind == "none":
            out[name] = float(raw[name])
        else:
            raise ValueError(f"unknown transform {kind!r} for {name} in the contract")
    return out


def _window_label(groups: list[tuple], labeled: bool) -> tuple[int | None, str | None, str | None]:
    """groups = [(label, scenario, run_id, count)] of the rows touching the device in this window.
    Attack if any attack row; scenario/run = the one with the most attack rows (ties: alphabetical, so it's repeatable).
    Unknown (None) if the capture isn't labeled yet."""
    attack = Counter()
    for label, scenario, run_id, n in groups:
        if label == 1:
            attack[(scenario or "other", run_id)] += n
    if attack:
        (scenario, run_id), _ = sorted(attack.items(), key=lambda kv: (-kv[1], kv[0][0], kv[0][1] or ""))[0]
        return 1, scenario, run_id
    if not labeled or any(label is None for label, *_ in groups):
        return None, None, None
    return 0, None, None


# ------------------------------------------------------------------------------------------- one capture
class WindowError(Exception):
    pass


def capture_window_features(conn: psycopg.Connection, capture_id: str) -> list[Window]:
    """All windows of every device for one capture."""
    row = conn.execute("SELECT start_ts, end_ts, kind FROM captures WHERE capture_id = %s", (capture_id,)).fetchone()
    if row is None:
        raise WindowError(f"capture {capture_id!r} does not exist")
    start, end, kind = row
    params = {"cap": capture_id}
    if end is None:                                       # still recording: go up to the newest data
        last = conn.execute("SELECT max(ts) FROM (SELECT max(ts_start) AS ts FROM flows WHERE capture_id = %(cap)s "
                            "UNION ALL SELECT max(ts) FROM events WHERE capture_id = %(cap)s) x", params).fetchone()[0]
        if last is None:
            return []
        end = window_start(last) + WINDOW

    devices = conn.execute("SELECT device_id, device_type FROM devices WHERE monitored ORDER BY device_id").fetchall()
    flow_agg = {(r[0], r[1]): dict(zip(NUMERIC[:9], r[2:])) for r in conn.execute(FLOW_SQL, params)}
    event_agg = {(r[0], r[1]): dict(zip(NUMERIC[9:16], r[2:])) for r in conn.execute(EVENT_SQL, params)}
    sensor_agg = _sensor_features(conn.execute(SENSOR_SQL, params).fetchall())
    label_groups: dict[tuple[str, datetime], list[tuple]] = defaultdict(list)
    for device, ws, label, scenario, run_id, n in conn.execute(LABEL_SQL, params):
        label_groups[(device, ws)].append((label, scenario, run_id, n))
    # A capture counts as labeled once label_capture ran: no flow or event in it is still unlabeled. A live
    # capture only once it is closed (end_ts set): while it records, new unlabeled data can still arrive.
    closed = row[1] is not None
    labeled = (kind != "live" or closed) and not conn.execute(
        "SELECT EXISTS (SELECT 1 FROM flows WHERE capture_id = %(cap)s AND label IS NULL) "
        "    OR EXISTS (SELECT 1 FROM events WHERE capture_id = %(cap)s AND label IS NULL)", params).fetchone()[0]

    windows = []
    for ws in capture_windows(start, end):
        for device, device_type in devices:
            key = (device, ws)
            raw = dict.fromkeys(NUMERIC, 0.0)                # silence = real zeros
            raw.update(flow_agg.get(key, {}))
            raw.update(event_agg.get(key, {}))
            raw.update(sensor_agg.get(key, {}))
            for t in DEVICE_TYPES:
                raw[f"device_type_{t}"] = 1.0 if (device_type if device_type in DEVICE_TYPES else "other") == t else 0.0
            groups = label_groups.get(key, [])
            label, scenario, run_id = _window_label(groups, labeled)
            windows.append(Window(device, ws, {n: float(raw[n]) for n in FEATURE_NAMES}, transform(raw),
                                  sum(g[3] for g in groups), label, scenario, run_id))
    return windows


# If someone edits the numeric list in the contract, the SQL above must be edited too. Fail loudly at import.
assert NUMERIC[:9] == ["n_conn_in", "n_unique_src_ip", "n_unique_dst_port", "ratio_failed_conn", "bytes_in_total",
                       "bytes_out_total", "pkts_in_total", "mean_conn_duration", "n_ssh_telnet_conn"] \
       and NUMERIC[9:16] == ["n_login_failed", "n_login_success", "n_commands", "n_mqtt_connect", "n_mqtt_publish",
                             "n_mqtt_subscribe", "n_http_rtsp_req"] \
       and NUMERIC[16:] == ["sensor_n_readings", *SENSOR_FIELDS], \
    "the contract's window features changed: update features/window.py"
