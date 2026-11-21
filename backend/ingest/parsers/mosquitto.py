"""Mosquitto (MQTT broker honeypot) log -> Events.

Every Mosquitto log line starts with a Unix timestamp (seconds), because mosquitto.conf has
`log_timestamp true`. The lines we use:

  1793196300: New client connected from 192.168.56.20:50112 as esp32-smoke-01 (p2, c1, k60).   -> mqtt_connect
  1793196301: esp32-smoke-01 0 aegex/cmd/#                                                      -> mqtt_subscribe
  1793196302: Received PUBLISH from esp32-smoke-01 (d0, q0, r0, m0, 'aegex/sensors/smoke', ... (58 bytes))
                                                                                                -> mqtt_publish
  1793196400: Client esp32-smoke-01 disconnected.                                               -> (forget the client)

The subscribe and publish lines only name the client, not its IP, so we remember client -> IP from the
connect line. (Idea and regexes reused from the old MosquittoLogParser.)

"Received PUBLISH" lines only appear when mosquitto.conf has `log_type debug`. Task A must turn that on,
otherwise publishes are not in the log at all.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone

from ..event import Event
from .base import Parser

_LINE = re.compile(r"^(\d{9,11}): (.*)$")
_CONNECT = re.compile(r"^New client connected from (\S+):(\d+) as (\S+) \(p(\d), c(\d), k(\d+)(?:, u'([^']*)')?\)\.?$")
_SUBSCRIBE = re.compile(r"^(\S+) ([012]) (\S+)$")
_PUBLISH = re.compile(r"^Received PUBLISH from (\S+) \(d(\d), q(\d), r(\d), m(\d+), '([^']*)', \.\.\. \((\d+) bytes\)\)$")
_BYE = re.compile(r"^Client (\S+) (?:disconnected|closed its connection)")


class MosquittoLogParser(Parser):
    source = "mosquitto"

    def __init__(self, device_id: str | None = None, broker_ip: str | None = None, broker_port: int = 1883,
                 ignore_clients: tuple[str, ...] = ()) -> None:
        super().__init__(device_id)
        self.broker_ip, self.broker_port = broker_ip, broker_port
        self.ignore_clients = set(ignore_clients)       # e.g. our own monitoring client
        self.client_addr: dict[str, tuple[str, int]] = {}

    def _event(self, line: str, ts: datetime, event_type: str, client: str, payload: dict) -> list[Event]:
        ip, port = self.client_addr.get(client, (None, None))
        return [Event(
            ts=ts, source=self.source, event_type=event_type, severity="info",
            dedup_key=self.dedup_key(line), device_id=self.device_id,
            src_ip=ip, src_port=port, dst_ip=self.broker_ip, dst_port=self.broker_port, proto="tcp",
            payload={"client_id": client, **payload},
        )]

    def _parse(self, line: str) -> list[Event] | None:
        m = _LINE.match(line.strip())
        if not m:
            return None
        ts = datetime.fromtimestamp(int(m.group(1)), tz=timezone.utc)
        msg = m.group(2)

        if c := _CONNECT.match(msg):
            ip, port, client, proto_level, clean, keepalive, username = c.groups()
            if client in self.ignore_clients:
                return []
            if len(self.client_addr) > 10_000:
                self.client_addr.clear()
            self.client_addr[client] = (ip, int(port))
            payload = {"protocol_level": int(proto_level), "clean_session": clean == "1", "keepalive_s": int(keepalive)}
            if username is not None:
                payload["username"] = username
            return self._event(line, ts, "mqtt_connect", client, payload)

        if p := _PUBLISH.match(msg):
            client, dup, qos, retain, mid, topic, size = p.groups()
            if client in self.ignore_clients:
                return []
            return self._event(line, ts, "mqtt_publish", client,
                               {"topic": topic, "qos": int(qos), "retain": retain == "1", "payload_bytes": int(size)})

        if b := _BYE.match(msg):
            self.client_addr.pop(b.group(1), None)
            return []

        # The subscribe line is just "<client> <qos> <topic>". Only trust it for a client we saw connect,
        # otherwise ordinary log text that happens to have 3 words would be read as a subscribe.
        if (s := _SUBSCRIBE.match(msg)) and s.group(1) in self.client_addr:
            client, qos, topic = s.groups()
            if client in self.ignore_clients:
                return []
            return self._event(line, ts, "mqtt_subscribe", client, {"topic": topic, "qos": int(qos)})

        return []        # valid line we don't need: "mosquitto version ...", "New connection from ...", ...
