"""Shared data structures passed between pipeline stages."""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Iterator


class EventType(str, Enum):
    """The telemetry / event categories collected from the honeypot (system architecture, stage 1)."""
    NETWORK_TRAFFIC = "network_traffic"
    LOGIN_ATTEMPT = "login_attempt"
    FAILED_LOGIN = "failed_login"
    SESSION_INFO = "session_info"
    PACKET_CHARACTERISTICS = "packet_characteristics"
    SOURCE_IP = "source_ip"
    COMMAND_REQUEST = "command_request"
    MQTT_EVENT = "mqtt_event"
    BLE_EVENT = "ble_event"
    DEVICE_INTERACTION = "device_interaction"
    SENSOR_READING = "sensor_reading"
    DEVICE_LOG = "device_log"                    # syslog / service log lines (level, service, message)
    MEDIA_TELEMETRY = "media_telemetry"          # video / image / audio stream metadata from the camera honeypot


# The four collection layers of the "Multi-Layer Event Collection & Preprocessing" block.
LAYER_OF: dict[str, str] = {
    "network_traffic": "network_traffic", "packet_characteristics": "network_traffic", "source_ip": "network_traffic",
    "device_log": "device_service_logs", "mqtt_event": "device_service_logs", "ble_event": "device_service_logs",
    "login_attempt": "session_interaction", "failed_login": "session_interaction", "session_info": "session_interaction",
    "command_request": "session_interaction", "device_interaction": "session_interaction",
    "sensor_reading": "telemetry_media", "media_telemetry": "telemetry_media",
}
LAYERS = ("network_traffic", "device_service_logs", "session_interaction", "telemetry_media")

# Attack scenarios of the "Physical IoT Deception Testbed" block (ground-truth labels in the simulator).
SCENARIOS = ("vulnerability_scanning", "ddos", "mirai_botnet", "ransomware",
             "sensor_manipulation", "unauthorized_camera_access", "zero_day_exploit")
ENTRY_VECTORS = ("wifi", "bluetooth")                 # "Attacker Entry Layer"
HONEYPOTS = {"smoke_detector": "sensor_honeypot", "ip_camera": "camera_honeypot"}


def layer_of(event_type: str) -> str:
    return LAYER_OF.get(event_type, "network_traffic")


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


@dataclass
class RawEvent:
    """One uncleaned event exactly as collected (values may be strings / missing / malformed)."""
    event_type: EventType
    timestamp: str                          # ISO-8601 UTC
    source: str                             # 'csv' | 'honeypot-sim' | 'external'
    payload: dict[str, Any]
    event_id: str = field(default_factory=lambda: uuid.uuid4().hex)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["event_type"] = self.event_type.value
        return d


@dataclass
class TelemetryBatch:
    """One sensor row plus every network/security event observed in the same window."""
    timestamp: datetime
    sensor_event: RawEvent
    network_events: list[RawEvent] = field(default_factory=list)
    batch_id: str = field(default_factory=lambda: uuid.uuid4().hex)

    def all_events(self) -> Iterator[RawEvent]:
        yield self.sensor_event
        yield from self.network_events
