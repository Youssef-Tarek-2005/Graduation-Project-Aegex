"""Collection - real honeypot feeds. Each honeypot runs in its OWN container and only writes logs / speaks MQTT;
this module turns those into AEGEX events and pushes them through TelemetryCollector.submit_event().

  Cowrie     SSH/Telnet honeypot   -> tails cowrie.json (JSON lines)
  Zeek       network monitor       -> tails conn.log and notice.log (must be JSON: LogAscii::use_json=T)
  Mosquitto  MQTT honeypot broker  -> tails mosquitto.log (connections, subscriptions) + subscribes to the broker (publishes)

The parse_* functions are pure (no I/O) so they can be unit-tested. Unknown / malformed lines are skipped, never fatal."""
from __future__ import annotations

import asyncio
import json
import logging
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from ..config import Settings
from ..models import EventType
from .collector import TelemetryCollector

log = logging.getLogger(__name__)
Emit = Callable[[EventType, dict[str, Any], str, str | None], None]    # (type, payload, source, iso_timestamp)


def _iso_from_epoch(x: Any) -> str | None:
    try:
        return datetime.fromtimestamp(float(x), tz=timezone.utc).isoformat()
    except (TypeError, ValueError, OverflowError, OSError):
        return None


def _num(x: Any) -> float | None:
    try:
        return float(x)
    except (TypeError, ValueError):
        return None


# ----------------------------------------------------------------------------- Cowrie
class CowrieParser:
    """Maps Cowrie JSON events to AEGEX events. Keeps session id -> (ip, protocol) because only the connect event has them."""

    def __init__(self) -> None:
        self.sessions: dict[str, tuple[str, str]] = {}

    def parse(self, line: str, emit: Emit) -> None:
        try:
            d = json.loads(line)
        except json.JSONDecodeError:
            return
        if not isinstance(d, dict):
            return
        eid, sid, ts = str(d.get("eventid", "")), str(d.get("session", "")), d.get("timestamp")
        base = {"honeypot": "cowrie_honeypot"}
        if eid == "cowrie.session.connect":
            ip, proto = d.get("src_ip"), str(d.get("protocol", "ssh")).lower()
            if len(self.sessions) > 5000:                      # bound memory if close events are lost
                self.sessions.clear()
            self.sessions[sid] = (ip, proto)
            emit(EventType.SOURCE_IP, {"src_ip": ip, "first_seen": ts, "dst_port": d.get("dst_port"), "protocol": proto, **base}, "cowrie", ts)
            return
        cached_ip, cached_proto = self.sessions.get(sid, (None, "ssh"))
        ip = cached_ip or d.get("src_ip")
        proto = cached_proto or str(d.get("protocol", "ssh")).lower()
        if not ip:
            return
        common = {"src_ip": ip, "protocol": proto, "session_id": sid, **base}
        if eid in ("cowrie.login.failed", "cowrie.login.success"):
            ok = eid.endswith("success")
            user = d.get("username")
            emit(EventType.LOGIN_ATTEMPT, {**common, "username": user, "success": ok}, "cowrie", ts)
            if not ok:
                emit(EventType.FAILED_LOGIN, {**common, "username": user, "reason": "bad_credentials"}, "cowrie", ts)
        elif eid in ("cowrie.command.input", "cowrie.command.failed"):
            emit(EventType.COMMAND_REQUEST, {**common, "command": str(d.get("input", ""))}, "cowrie", ts)
        elif eid in ("cowrie.session.file_download", "cowrie.session.file_upload"):
            emit(EventType.DEVICE_INTERACTION, {**common, "device": "cowrie_honeypot", "action": "file_download",
                                                "url": d.get("url"), "sha256": d.get("shasum")}, "cowrie", ts)
        elif eid == "cowrie.session.closed":
            emit(EventType.SESSION_INFO, {**common, "duration_s": d.get("duration")}, "cowrie", ts)
            self.sessions.pop(sid, None)


# ----------------------------------------------------------------------------- Zeek
def parse_zeek_conn(line: str, emit: Emit) -> None:
    try:
        d = json.loads(line)
    except json.JSONDecodeError:
        return
    if not isinstance(d, dict) or "id.orig_h" not in d:
        return
    ob, rb = _num(d.get("orig_bytes")), _num(d.get("resp_bytes"))
    op, rp = _num(d.get("orig_pkts")), _num(d.get("resp_pkts"))
    emit(EventType.NETWORK_TRAFFIC, {
        "src_ip": d["id.orig_h"], "src_port": d.get("id.orig_p"), "dst_ip": d.get("id.resp_h"), "dst_port": d.get("id.resp_p"),
        "protocol": d.get("proto"), "service": d.get("service"), "conn_state": d.get("conn_state"),
        "bytes": (ob or 0) + (rb or 0) if (ob is not None or rb is not None) else None,
        "packets": (op or 0) + (rp or 0) if (op is not None or rp is not None) else None,
        "duration_s": d.get("duration"), "zeek_uid": d.get("uid"), "honeypot": "zeek_monitor"}, "zeek", _iso_from_epoch(d.get("ts")))


def parse_zeek_notice(line: str, emit: Emit) -> None:
    try:
        d = json.loads(line)
    except json.JSONDecodeError:
        return
    if not isinstance(d, dict) or "note" not in d:
        return
    p = {"source": "zeek", "level": "warning", "service": "zeek", "message": f"{d.get('note')}: {d.get('msg', '')}".strip(),
         "honeypot": "zeek_monitor"}
    if d.get("src"):
        p["src_ip"] = d["src"]
    emit(EventType.DEVICE_LOG, p, "zeek", _iso_from_epoch(d.get("ts")))


# ----------------------------------------------------------------------------- Mosquitto (log file)
_MQ_CONN = re.compile(r"^(\d+): New client connected from (\S+):(\d+) as (\S+) \(")
_MQ_SUB = re.compile(r"^(\d+): (\S+) (\d) (\S+)$")
_MQ_BYE = re.compile(r"^(\d+): Client (\S+) (?:disconnected|closed its connection)")


class MosquittoLogParser:
    """Mosquitto's log line has the client id, IP and subscriptions but not publishes (those come from the MQTT subscription)."""

    def __init__(self, ignore_client: str = "") -> None:
        self.ip_of: dict[str, str] = {}
        self.ignore = ignore_client

    def parse(self, line: str, emit: Emit) -> None:
        line = line.strip()
        if m := _MQ_CONN.match(line):
            ts, ip, port, cid = m.groups()
            if cid == self.ignore:
                return
            if len(self.ip_of) > 5000:
                self.ip_of.clear()
            self.ip_of[cid] = ip
            emit(EventType.MQTT_EVENT, {"src_ip": ip, "src_port": int(port), "action": "connect", "client_id": cid, "honeypot": "mqtt_broker"},
                 "mosquitto", _iso_from_epoch(ts))
        elif (m := _MQ_SUB.match(line)) and m.group(2) in self.ip_of:      # only lines whose first token is a known client
            ts, cid, qos, topic = m.groups()
            emit(EventType.MQTT_EVENT, {"src_ip": self.ip_of[cid], "action": "subscribe", "client_id": cid, "topic": topic, "qos": int(qos),
                                        "honeypot": "mqtt_broker"}, "mosquitto", _iso_from_epoch(ts))
        elif m := _MQ_BYE.match(line):
            self.ip_of.pop(m.group(2), None)


# ----------------------------------------------------------------------------- file tailing
class FileTailer:
    """Async `tail -F` for one file. Starts at the end of a file that already exists (unless from_start), at the start of
    one that appears later, and re-opens after truncation or rotation. Partial last lines wait for their newline."""

    def __init__(self, path: Path, on_line: Callable[[str], None], poll: float, from_start: bool):
        self.path, self.on_line, self.poll, self.from_start = Path(path), on_line, poll, from_start

    async def run(self) -> None:
        fh, inode, first, buf = None, None, True, ""
        try:
            while True:
                try:
                    st = os.stat(self.path)
                except OSError:
                    if fh:
                        fh.close(); fh = None
                    first = False                                  # file not there yet: read it from the start when it appears
                    await asyncio.sleep(self.poll)
                    continue
                if fh is None or st.st_ino != inode or st.st_size < fh.tell():
                    if fh:
                        fh.close()
                    fh, inode, buf = open(self.path, "r", encoding="utf-8", errors="replace"), st.st_ino, ""
                    if first and not self.from_start:
                        fh.seek(0, os.SEEK_END)
                    first = False
                chunk = fh.read()
                if chunk:
                    buf += chunk
                    *lines, buf = buf.split("\n")
                    for ln in lines:
                        if ln.strip():
                            try:
                                self.on_line(ln)
                            except Exception:                      # noqa: BLE001 - one bad line must not stop the feed
                                log.exception("feed parser error on %s", self.path.name)
                else:
                    await asyncio.sleep(self.poll)
        finally:
            if fh:
                fh.close()


# ----------------------------------------------------------------------------- MQTT subscription (publishes)
class MqttSubscriber:
    """Subscribes to the honeypot broker and emits one mqtt_event per PUBLISH. paho runs its own thread, so events are
    handed to the asyncio loop with call_soon_threadsafe. The broker does not tell subscribers who published, so these
    events carry topic / size / qos / retain but no src_ip."""

    def __init__(self, s: Settings, loop: asyncio.AbstractEventLoop, emit: Emit):
        self.s, self.loop, self.emit, self.client = s, loop, emit, None

    def start(self) -> None:
        import paho.mqtt.client as mqtt
        c = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id=self.s.mqtt_client_id)

        def on_connect(cl, _ud, _flags, rc, _props=None):
            if getattr(rc, "is_failure", rc != 0):
                log.warning("MQTT connect refused: %s", rc)
                return
            cl.subscribe(self.s.mqtt_topic)
            log.info("MQTT feed subscribed to %r on %s:%s", self.s.mqtt_topic, self.s.mqtt_host, self.s.mqtt_port)

        def on_message(_cl, _ud, msg):
            if msg.topic.startswith("$SYS"):
                return
            payload = {"action": "publish", "topic": msg.topic, "payload_size": len(msg.payload), "qos": msg.qos,
                       "retain": bool(msg.retain), "honeypot": "mqtt_broker"}
            self.loop.call_soon_threadsafe(self.emit, EventType.MQTT_EVENT, payload, "mosquitto", None)

        c.on_connect, c.on_message = on_connect, on_message
        c.reconnect_delay_set(min_delay=1, max_delay=30)
        c.connect_async(self.s.mqtt_host, self.s.mqtt_port, keepalive=60)    # does not block or raise if the broker is still starting
        c.loop_start()
        self.client = c

    def stop(self) -> None:
        if self.client:
            self.client.loop_stop()
            self.client.disconnect()


# ----------------------------------------------------------------------------- wiring
class HoneypotFeeds:
    def __init__(self, s: Settings, collector: TelemetryCollector):
        self.s, self.collector = s, collector
        self.tasks: list[asyncio.Task] = []
        self.mqtt: MqttSubscriber | None = None
        self.counts: dict[str, int] = {}

    def _emit(self, t: EventType, payload: dict[str, Any], source: str, ts: str | None) -> None:
        self.counts[source] = self.counts.get(source, 0) + 1
        self.collector.submit_event(t, payload, source, ts)

    def start(self) -> None:
        s, loop = self.s, asyncio.get_running_loop()
        cow, mq = CowrieParser(), MosquittoLogParser(ignore_client=s.mqtt_client_id)
        tail = lambda path, fn: asyncio.create_task(FileTailer(Path(path), fn, s.feeds_poll_interval, s.feeds_from_start).run())  # noqa: E731
        self.tasks = [
            tail(s.cowrie_log_path, lambda ln: cow.parse(ln, self._emit)),
            tail(Path(s.zeek_log_dir) / "conn.log", lambda ln: parse_zeek_conn(ln, self._emit)),
            tail(Path(s.zeek_log_dir) / "notice.log", lambda ln: parse_zeek_notice(ln, self._emit)),
            tail(s.mosquitto_log_path, lambda ln: mq.parse(ln, self._emit)),
        ]
        if s.mqtt_host:
            self.mqtt = MqttSubscriber(s, loop, self._emit)
            self.mqtt.start()
        log.info("Honeypot feeds started: cowrie=%s zeek=%s mosquitto=%s mqtt=%s", s.cowrie_log_path, s.zeek_log_dir,
                 s.mosquitto_log_path, f"{s.mqtt_host}:{s.mqtt_port}" if s.mqtt_host else "off")

    def stop(self) -> None:
        for t in self.tasks:
            t.cancel()
        if self.mqtt:
            self.mqtt.stop()
