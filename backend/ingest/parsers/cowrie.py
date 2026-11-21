"""Cowrie (SSH/Telnet honeypot) -> Events.

Cowrie writes one JSON object per line to cowrie.json, for example:
  {"eventid": "cowrie.login.failed", "timestamp": "2026-11-20T14:10:04.120000Z", "session": "a1b2c3",
   "src_ip": "192.168.56.99", "username": "root", "password": "1234", ...}

Only the first event of a session ("cowrie.session.connect") has the ports, so we remember them per
session and copy them onto the later events of that session. (Idea reused from the old CowrieParser.)
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from ..event import Event
from .base import Parser

# Cowrie eventid -> (our event_type, severity). Anything not listed is a valid line we don't need.
EVENT_MAP: dict[str, tuple[str, str]] = {
    "cowrie.session.connect":       ("session_open",  "low"),
    "cowrie.login.failed":          ("login_failed",  "medium"),
    "cowrie.login.success":         ("login_success", "high"),
    "cowrie.command.input":         ("command",       "high"),
    "cowrie.command.failed":        ("command",       "high"),
    "cowrie.session.file_download": ("file_download", "critical"),
    "cowrie.session.file_upload":   ("file_download", "critical"),
    "cowrie.session.closed":        ("session_close", "info"),
}

# Fields that become real columns, or that we already used. Everything else goes into payload.
_NOT_PAYLOAD = {"eventid", "timestamp", "src_ip", "src_port", "dst_ip", "dst_port", "message", "sensor", "uuid"}


def parse_cowrie_time(value: str) -> datetime:
    # "2026-11-20T14:10:04.120000Z" -> aware UTC datetime
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)


class CowrieParser(Parser):
    source = "cowrie"

    def __init__(self, device_id: str | None = None) -> None:
        super().__init__(device_id)
        self.sessions: dict[str, dict[str, Any]] = {}

    def _parse(self, line: str) -> list[Event] | None:
        try:
            d = json.loads(line)
        except json.JSONDecodeError:
            return None
        if not isinstance(d, dict) or "eventid" not in d or "timestamp" not in d:
            return None

        eventid = str(d["eventid"])
        session = str(d.get("session", ""))
        ts = parse_cowrie_time(str(d["timestamp"]))

        if eventid == "cowrie.session.connect":
            if len(self.sessions) > 10_000:          # keep memory bounded if "closed" lines go missing
                self.sessions.clear()
            self.sessions[session] = {
                "src_ip": d.get("src_ip"), "src_port": d.get("src_port"),
                "dst_ip": d.get("dst_ip"), "dst_port": d.get("dst_port"),
                "protocol": str(d.get("protocol", "ssh")).lower(),
            }

        if eventid not in EVENT_MAP:
            return []                                # e.g. cowrie.client.version, cowrie.client.size
        event_type, severity = EVENT_MAP[eventid]

        known = self.sessions.get(session, {})
        src_ip = d.get("src_ip") or known.get("src_ip")
        if not src_ip:
            return None                              # an attack event without an attacker IP is useless

        payload = {k: v for k, v in d.items() if k not in _NOT_PAYLOAD}
        payload["cowrie_eventid"] = eventid
        payload.setdefault("protocol", known.get("protocol", "ssh"))
        if eventid == "cowrie.command.failed":
            payload["failed"] = True
        if eventid == "cowrie.session.file_upload":
            payload["direction"] = "upload"

        if eventid == "cowrie.session.closed":
            self.sessions.pop(session, None)

        return [Event(
            ts=ts, source=self.source, event_type=event_type, severity=severity,
            dedup_key=self.dedup_key(line), device_id=self.device_id,
            src_ip=src_ip, src_port=_int(d.get("src_port", known.get("src_port"))),
            dst_ip=d.get("dst_ip") or known.get("dst_ip"), dst_port=_int(d.get("dst_port", known.get("dst_port"))),
            proto="tcp",                             # SSH and Telnet both run over TCP
            payload=payload,
        )]


def _int(x: Any) -> int | None:
    try:
        return int(x)
    except (TypeError, ValueError):
        return None
