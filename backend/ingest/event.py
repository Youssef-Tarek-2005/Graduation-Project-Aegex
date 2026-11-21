"""The Event: one row of the `events` table, as a Python object.

Every parser (Cowrie, Mosquitto, ESP32, ...) returns Event objects. Because they all return the same shape,
the loader in step 4 only has to know how to save one kind of thing.

The allowed event types, and which layer each one belongs to, are NOT written here. They are read from
contracts/feature_contract.json, so the contract stays the single source of truth for the whole team.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

CONTRACT_PATH = Path(__file__).resolve().parents[2] / "contracts" / "feature_contract.json"
CONTRACT: dict[str, Any] = json.loads(CONTRACT_PATH.read_text(encoding="utf-8"))
EVENT_TYPES: dict[str, dict[str, Any]] = {k: v for k, v in CONTRACT["event_types"].items() if not k.startswith("_")}

SEVERITIES = ("info", "low", "medium", "high", "critical")


class ContractError(Exception):
    """A parser produced something the contract does not allow. That is a bug in our code, not a bad log
    line, so it is never silently skipped. (Deliberately not a ValueError, so parsers can't swallow it.)"""


@dataclass
class Event:
    ts: datetime                      # when it happened, always timezone-aware UTC
    source: str                       # who reported it: cowrie | mosquitto | esp32 | ...
    event_type: str                   # what happened: login_failed | mqtt_publish | sensor_reading | ...
    dedup_key: str                    # fingerprint of the original line, so loading a file twice adds nothing
    payload: dict[str, Any] = field(default_factory=dict)   # everything source-specific
    device_id: str | None = None      # which honeypot device was involved
    capture_id: str | None = None     # filled in by the loader (step 4), not by the parser
    src_ip: str | None = None
    src_port: int | None = None
    dst_ip: str | None = None
    dst_port: int | None = None
    proto: str | None = None
    severity: str | None = None

    def __post_init__(self) -> None:
        # Fail loudly on a programming mistake in a parser, instead of saving a row the database or the
        # feature code would trip over later.
        spec = EVENT_TYPES.get(self.event_type)
        if spec is None:
            raise ContractError(f"event_type {self.event_type!r} is not in the feature contract")
        if self.source not in spec["sources"]:
            raise ContractError(f"source {self.source!r} is not allowed for event_type {self.event_type!r}")
        if self.ts.tzinfo is None or self.ts.utcoffset() is None:
            raise ContractError("ts must be timezone-aware (UTC)")
        if self.severity is not None and self.severity not in SEVERITIES:
            raise ContractError(f"severity {self.severity!r} is not one of {SEVERITIES}")

    @property
    def layer(self) -> str:
        """The collection layer comes from the contract, never from the parser."""
        return EVENT_TYPES[self.event_type]["layer"]

    def to_row(self) -> dict[str, Any]:
        """The exact column -> value mapping for an INSERT into the events table."""
        row = asdict(self)
        row["layer"] = self.layer
        return row


def make_dedup_key(source: str, raw_line: str, occurrence: int = 0) -> str:
    """Fingerprint of one original log line.

    `occurrence` tells apart two lines that are exactly identical in the same file (for example two MQTT
    subscribes in the same second, because Mosquitto only logs whole seconds). Reading the same file again
    gives the same occurrence numbers, so the keys come out the same and the loader skips them.
    """
    h = hashlib.sha256(f"{source}|{occurrence}|{raw_line.rstrip(chr(13) + chr(10))}".encode("utf-8"))
    return h.hexdigest()[:32]
