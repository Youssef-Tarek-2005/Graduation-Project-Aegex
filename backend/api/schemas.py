"""The shapes of what the API accepts and returns (pydantic models).

FastAPI checks every request against these before our code runs: a missing field, a time without a time zone,
a port above 65535 or an unknown field is answered with 422 and an explanation. They also become the
documentation and the examples in Swagger (/docs).
"""
from __future__ import annotations

from datetime import datetime
from typing import Annotated, Any, Generic, Literal, TypeVar

from pydantic import AwareDatetime, BaseModel, BeforeValidator, ConfigDict, Field, IPvAnyAddress

from ingest.attacks import SCENARIOS
from ingest.captures import KINDS
from ingest.event import SEVERITIES

Severity = Literal[SEVERITIES]                       # type: ignore[valid-type]
Scenario = Literal[SCENARIOS]                        # type: ignore[valid-type]
Kind = Literal[KINDS]                                # type: ignore[valid-type]


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")        # a misspelled field is an error, not silently ignored


# ------------------------------------------------------------------------------------------- in
class EventIn(Strict):
    """One event, in the contract's ingestion format (contracts/TASK_B_CONTRACT.md, section 3)."""
    model_config = ConfigDict(extra="forbid", json_schema_extra={"examples": [{
        "ts": "2026-11-22T12:00:03.120Z", "source": "cowrie", "event_type": "login_failed", "device_id": "gw-01",
        "src_ip": "192.168.56.99", "src_port": 51234, "dst_ip": "192.168.56.10",
        "dst_port": 22, "proto": "tcp", "payload": {"username": "root", "password": "admin", "session": "swagger1"}}]})

    ts: AwareDatetime = Field(description="when it happened, with a time zone: ...Z or +02:00")
    source: str = Field(description="who reports it: cowrie, mosquitto, esp32, zeek, camera, ...")
    event_type: str = Field(description="from the contract: login_failed, mqtt_publish, sensor_reading, ...")
    device_id: str | None = Field(None, description="honeypot device involved (must exist)")
    capture_id: str | None = Field(None, description="leave out: the capture running at `ts` is used, if any")
    src_ip: IPvAnyAddress | None = None
    src_port: int | None = Field(None, ge=0, le=65535)
    dst_ip: IPvAnyAddress | None = None
    dst_port: int | None = Field(None, ge=0, le=65535)
    proto: str | None = None
    severity: Severity | None = None
    payload: dict[str, Any] = Field(default_factory=dict, description="everything source-specific")
    dedup_key: str | None = Field(None, max_length=128, description="optional: your own unique id for this event. "
                                  "Without it, the same event content sent twice is saved once.")


class SensorIn(Strict):
    """One ESP32 reading, sent directly by the sensor."""
    model_config = ConfigDict(extra="forbid", json_schema_extra={"examples": [{
        "device_id": "esp32-smoke-01", "ts": "2026-11-22T12:00:10Z", "smoke": 12.3, "temperature_c": 24.1,
        "humidity_pct": 41.0, "esp_ms": 1503664}]})

    device_id: str
    ts: AwareDatetime | None = Field(None, description="leave out if the ESP32 has no clock: the server's time is "
                                     "used and payload.ts_source says 'server'")
    smoke: float | None = None
    temperature_c: float | None = None
    humidity_pct: float | None = None
    esp_ms: int | None = Field(None, description="milliseconds since the ESP32 started")
    capture_id: str | None = None


HONEYPOT_EVENTS = {"connect": "session_open", "login_failed": "login_failed", "login_success": "login_success",
                   "command": "command", "http_request": "http_request", "disconnect": "session_close"}


class HoneypotIn(Strict):
    """One thing that happened on a fake service of the ESP32-S3 honeypot, sent by the ESP32 itself."""
    model_config = ConfigDict(extra="forbid", json_schema_extra={"examples": [{
        "device_id": "esp32s3-01", "event": "login_failed", "service": "telnet", "src_ip": "192.168.137.50",
        "src_port": 51234, "dst_port": 23, "session": "a1f3", "username": "root", "password": "admin",
        "esp_ms": 1503664}]})

    device_id: str
    event: Literal["connect", "login_failed", "login_success", "command", "http_request", "disconnect"] = Field(
        description="connect / disconnect = a client opened / closed a connection to the fake service")
    service: Literal["telnet", "http", "ssh", "mqtt", "other"] = Field(description="which fake service was hit")
    src_ip: IPvAnyAddress = Field(description="the client's address (the attacker, during an attack)")
    src_port: int | None = Field(None, ge=0, le=65535)
    dst_port: int | None = Field(None, ge=0, le=65535, description="the fake service's port on the ESP32, e.g. 23")
    ts: AwareDatetime | None = Field(None, description="leave out if the ESP32 has no clock: the server's time is used")
    session: str | None = Field(None, max_length=64, description="the same id on every event of one connection")
    username: str | None = Field(None, max_length=256)
    password: str | None = Field(None, max_length=256)
    input: str | None = Field(None, max_length=2000, description="command: what the client typed")
    method: str | None = Field(None, max_length=16, description="http_request: GET, POST, ...")
    path: str | None = Field(None, max_length=2000, description="http_request: the requested URL path")
    esp_ms: int | None = Field(None, description="milliseconds since the ESP32 started (tells apart two "
                               "identical events in the same second)")
    capture_id: str | None = None


class CaptureIn(Strict):
    model_config = ConfigDict(extra="forbid", json_schema_extra={"examples": [{
        "capture_id": "cap-2026-11-27-a", "start_ts": "2026-11-27T09:00:00Z", "end_ts": "2026-11-27T10:00:00Z",
        "kind": "attack", "notes": "hydra + nmap session"}]})

    capture_id: str = Field(min_length=1, max_length=100)
    start_ts: AwareDatetime
    end_ts: AwareDatetime | None = Field(None, description="leave out while still recording (live)")
    kind: Kind = "mixed"
    pcap_path: str | None = None
    notes: str | None = None


class AttackRunIn(Strict):
    """One row of Task A's attack log."""
    model_config = ConfigDict(extra="forbid", json_schema_extra={"examples": [{
        "run_id": "run-017", "capture_id": "cap-2026-11-20-a", "scenario": "vulnerability_scanning", "tool": "nmap",
        "command": "nmap -sS 192.168.56.30", "attacker_ip": "192.168.56.99", "target_device": "cam-01",
        "start_ts": "2026-11-20T14:45:00Z", "end_ts": "2026-11-20T14:47:00Z"}]})

    run_id: str = Field(min_length=1)
    capture_id: str
    scenario: Scenario
    tool: str | None = None
    command: str | None = None
    attacker_ip: IPvAnyAddress
    target_device: str | None = None
    start_ts: AwareDatetime
    end_ts: AwareDatetime
    notes: str | None = None


def _one_or_many(value: Any) -> Any:
    """Accept a single object as a list of one, so both go through the same checks and errors say which item."""
    return [value] if isinstance(value, dict) else value


EventList = Annotated[list[EventIn], BeforeValidator(_one_or_many)]
AttackRunList = Annotated[list[AttackRunIn], BeforeValidator(_one_or_many)]


# ------------------------------------------------------------------------------------------- out
class Health(BaseModel):
    status: Literal["ok", "degraded"]
    database: str
    database_name: str | None = Field(None, description="which database the API uses: aegex (sample lab) or "
                                      "aegex_poc (laptop + ESP32-S3)")
    timescaledb: str | None = None
    feature_version: str
    server_time: datetime
    counts: dict[str, int] = {}


class IngestResult(BaseModel):
    received: int = Field(description="items in the request")
    inserted: int = Field(description="new rows saved")
    duplicates: int = Field(description="already in the database, skipped")
    captures: dict[str, int] = Field(default_factory=dict, description="how many items went to which capture "
                                     "('(none)' = outside every capture: saved, but never labeled)")


class LogIngestResult(BaseModel):
    lines: int
    parsed: int = Field(description="events or flows produced by the parser")
    ignored: int = Field(description="valid lines the backend doesn't need")
    broken: int = Field(description="lines that couldn't be read; skipped")
    inserted: int
    duplicates: int


class CaptureOut(BaseModel):
    capture_id: str
    created: bool = Field(description="false = the exact same capture already existed")


class AttackRunsResult(BaseModel):
    runs: int
    inserted: list[str]
    updated: dict[str, list[str]] = Field(description="run_id -> changed fields")
    unchanged: list[str]
    labeled_captures: list[str] = Field(default_factory=list)


class Problems(BaseModel):
    """422 answer when our own checks refuse a request. Nothing was saved."""
    message: str
    problems: list[str]


# ------------------------------------------------------------------------------------------- read (step 11)
T = TypeVar("T")


class Page(BaseModel, Generic[T]):
    """One page of a list. If `next_cursor` is not null, send it back as `?cursor=...` for the next page."""
    items: list[T]
    count: int = Field(description="items on this page")
    next_cursor: str | None = Field(description="null = this was the last page")


class DeviceOut(BaseModel):
    device_id: str
    device_type: str
    ip: str | None
    mac: str | None
    is_virtual: bool
    platform: str | None
    description: str | None
    monitored: bool = Field(description="false: a known lab machine (e.g. the laptop hotspot), no feature windows")


class CaptureRow(BaseModel):
    capture_id: str
    start_ts: datetime
    end_ts: datetime | None = Field(description="null = still recording (live)")
    kind: str
    pcap_path: str | None
    notes: str | None


class AttackRunOut(BaseModel):
    run_id: str
    capture_id: str | None
    scenario: str
    tool: str | None
    command: str | None
    attacker_ip: str
    target_device: str | None
    start_ts: datetime
    end_ts: datetime
    notes: str | None


class EventOut(BaseModel):
    event_id: str
    ts: datetime
    source: str
    event_type: str
    layer: str
    device_id: str | None
    capture_id: str | None
    src_ip: str | None
    src_port: int | None
    dst_ip: str | None
    dst_port: int | None
    proto: str | None
    severity: str | None
    label: int | None = Field(description="1 attack, 0 normal, null = not labeled (live, or outside every capture)")
    scenario: str | None
    run_id: str | None
    payload: dict[str, Any]


class FlowOut(BaseModel):
    flow_id: str
    zeek_uid: str | None
    ts_start: datetime
    ts_end: datetime | None
    capture_id: str | None
    device_id: str | None
    src_ip: str
    src_port: int | None
    dst_ip: str
    dst_port: int | None
    proto: str
    service: str | None
    conn_state: str | None
    history: str | None
    duration_s: float | None
    orig_bytes: int | None
    resp_bytes: int | None
    orig_pkts: int | None
    resp_pkts: int | None
    label: int | None
    scenario: str | None
    run_id: str | None
    feature_version: str | None
    features: dict[str, float] | None = Field(None, description="only with ?include_features=true")


class WindowOut(BaseModel):
    entity_type: str
    entity_id: str
    window_start: datetime
    window_end: datetime
    capture_id: str | None
    feature_version: str
    n_events: int = Field(description="flows + events in this window (0 = silent)")
    label: int | None
    scenario: str | None
    run_id: str | None
    features: dict[str, float] = Field(description="the 24 window features after log1p, NOT scaled: apply "
                                       "artifacts/features/<version>/window_scaler.joblib in contract order")
    features_raw: dict[str, float] | None = Field(None, description="the counts as counted; only with ?include_raw=true")


class EdgeOut(BaseModel):
    flow_id: str
    ts: datetime
    src_node: str = Field(description="'dev:<device_id>' for our devices, else 'ip:<address>'")
    dst_node: str
    src_ip: str
    src_port: int | None
    dst_ip: str
    dst_port: int | None
    proto: str
    label: int | None
    scenario: str | None
    features: dict[str, float] = Field(description="the 41 flow features, NOT scaled (flow_scaler.joblib)")


# ------------------------------------------------------------------------------------------- dashboard summaries
class Series(BaseModel):
    name: str
    unit: str | None = None
    data: list[float | None]


class ChartOut(BaseModel):
    """Ready for a chart: `labels` is the time axis (bucket starts), each series is one line or bar stack."""
    bucket_seconds: int | None = Field(description="null = raw readings, not averaged")
    labels: list[datetime]
    series: list[Series]


class SummaryOut(BaseModel):
    events: int
    flows: int
    attack_flows: int
    layers: dict[str, int] = Field(description="events per collection layer (flows are counted in `flows`)")
    sources: dict[str, int]
    labels: dict[str, int] = Field(description="events: attack / normal / unlabeled")
    scenarios: dict[str, dict[str, int]] = Field(description="per scenario: attack events and attack flows")
    runs: dict[str, dict[str, int]] = Field(description="per attack run: attack events and attack flows")
