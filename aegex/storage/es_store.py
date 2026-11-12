"""Task 3 (Elasticsearch) - high-velocity event search for the dashboard.

Two daily indices:
  <prefix>-raw-events-YYYY.MM.dd       every collected event
  <prefix>-security-events-YYYY.MM.dd  only events with severity > info (failed logins, malicious commands, ...)
Every document is tagged with its collection layer and, for testbed traffic, label / actor / entry_vector / honeypot
(the "Unified Event Store: time-ordered, labeled"). Documents use event_id as _id, so re-indexing the same event is idempotent."""
from __future__ import annotations

import logging
import re
import threading
import time
from typing import Any

from elasticsearch import Elasticsearch, helpers

from ..config import Settings
from ..models import LAYERS, layer_of

log = logging.getLogger(__name__)

_SUSPICIOUS_CMD = re.compile(r"(wget|curl|busybox|\bnc\b|netcat|/etc/passwd|chmod\s+7|rm\s+-rf|tftp|mirai|\|\s*sh|encrypt|\.locked|ransom|openssl\s+enc)", re.I)
_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
_LABEL_FLOOR = {"vulnerability_scanning": "low", "ddos": "medium", "mirai_botnet": "medium", "ransomware": "high",
                "sensor_manipulation": "medium", "unauthorized_camera_access": "medium", "zero_day_exploit": "high"}

_MAPPINGS = {"properties": {
    "@timestamp": {"type": "date"}, "event_id": {"type": "keyword"}, "event_type": {"type": "keyword"},
    "severity": {"type": "keyword"}, "reasons": {"type": "keyword"}, "source": {"type": "keyword"},
    "batch_id": {"type": "keyword"}, "src_ip": {"type": "ip", "ignore_malformed": True},
    "username": {"type": "keyword"}, "layer": {"type": "keyword"}, "label": {"type": "keyword"},
    "actor": {"type": "keyword"}, "entry_vector": {"type": "keyword"}, "honeypot": {"type": "keyword"},
    "command": {"type": "text", "fields": {"keyword": {"type": "keyword", "ignore_above": 512}}},
    "payload": {"type": "flattened"},
}}


def classify(event: dict[str, Any]) -> tuple[str, list[str]]:
    """Rule-based severity for dashboard triage (the ML layers do the real detection)."""
    t, p = event["event_type"], event.get("payload", {})
    sev, why = "info", []

    def bump(level: str, reason: str) -> None:
        nonlocal sev
        why.append(reason)
        if _RANK[level] > _RANK[sev]:
            sev = level

    if t == "failed_login":
        bump("medium", "failed_login")
    if t == "login_attempt":
        if p.get("success"):
            bump("medium", "successful_honeypot_login")
        else:
            bump("low", "login_attempt")
    if t == "command_request":
        if _SUSPICIOUS_CMD.search(str(p.get("command", ""))):
            bump("high", "malicious_command")
        else:
            bump("low", "command_execution")
    if t == "mqtt_event" and str(p.get("topic", "")).startswith("$SYS"):
        bump("medium", "mqtt_sys_topic_probe")
    if t == "ble_event" and p.get("action") in {"pair_attempt", "gatt_write"}:
        bump("medium", "ble_pairing_or_write")
    if t == "device_interaction":
        act = p.get("action")
        if act in {"firmware_download", "file_download"}:
            bump("high", f"device_tamper_{act}")
        elif act == "config_change":
            bump("medium", "device_tamper_config_change")
    if t == "device_log":
        lvl = {"warning": "low", "error": "medium", "critical": "high"}.get(str(p.get("level", "")).lower())
        if lvl:
            bump(lvl, f"device_log_{str(p['level']).lower()}")
    if t == "network_traffic" and ((p.get("packets") or 0) >= 800 or (p.get("bytes") or 0) >= 300_000):
        bump("medium", "traffic_flood")
    if t == "media_telemetry" and p.get("authenticated") is False:
        bump("high", "unauthenticated_media_access")
    if t == "source_ip" and p.get("honeypot") == "cowrie_honeypot":
        bump("low", "honeypot_connection")
    label = p.get("label")                                  # labeled testbed traffic: floor severity by scenario
    if label in _LABEL_FLOOR:
        bump(_LABEL_FLOOR[label], f"scenario:{label}")
    return sev, why


class ElasticStore:
    def __init__(self, s: Settings):
        self.s = s
        self.es = Elasticsearch(s.es_url, api_key=s.es_api_key or None, request_timeout=15, max_retries=2)
        self.raw_prefix, self.sec_prefix = f"{s.es_prefix}-raw-events", f"{s.es_prefix}-security-events"
        self._lock = threading.Lock()
        self._buf: list[dict] = []
        self._last_flush = time.monotonic()

    def init_indices(self) -> None:
        for name, prefix in (("raw", self.raw_prefix), ("security", self.sec_prefix)):
            self.es.indices.put_index_template(
                name=f"{self.s.es_prefix}-{name}", index_patterns=[f"{prefix}-*"], priority=200,
                template={"settings": {"number_of_shards": 1, "number_of_replicas": 0, "refresh_interval": "2s"},
                          "mappings": _MAPPINGS})

    def _to_doc(self, ev: dict[str, Any], batch_id: str) -> dict[str, Any]:
        p = ev.get("payload", {})
        sev, why = classify(ev)
        return {"@timestamp": ev["timestamp"], "event_id": ev["event_id"], "event_type": ev["event_type"],
                "severity": sev, "reasons": why, "source": ev.get("source"), "batch_id": batch_id,
                "src_ip": p.get("src_ip"), "username": p.get("username"), "command": p.get("command"),
                "layer": layer_of(ev["event_type"]), "label": p.get("label"), "actor": p.get("actor"),
                "entry_vector": p.get("entry_vector"), "honeypot": p.get("honeypot"), "payload": p}

    def index_events(self, events: list[dict[str, Any]], batch_id: str) -> None:
        actions = []
        for ev in events:
            doc = self._to_doc(ev, batch_id)
            day = str(doc["@timestamp"])[:10].replace("-", ".")
            actions.append({"_op_type": "index", "_index": f"{self.raw_prefix}-{day}", "_id": doc["event_id"], "_source": doc})
            if doc["severity"] != "info":
                actions.append({"_op_type": "index", "_index": f"{self.sec_prefix}-{day}", "_id": doc["event_id"], "_source": doc})
        with self._lock:
            self._buf.extend(actions)
            due = len(self._buf) >= self.s.es_batch_size or time.monotonic() - self._last_flush >= self.s.es_flush_seconds
        if due:
            self.flush()

    def flush(self) -> None:
        with self._lock:
            batch, self._buf, self._last_flush = self._buf, [], time.monotonic()
        if not batch:
            return
        ok, errors = helpers.bulk(self.es, batch, raise_on_error=False, stats_only=False)
        if errors:
            log.error("ES bulk: %d indexed, %d failed (first error: %s)", ok, len(errors), errors[0])

    # ---- dashboard queries --------------------------------------------------
    def recent_security_events(self, minutes: int = 60, limit: int = 50, min_severity: str = "low",
                               event_type: str | None = None, src_ip: str | None = None,
                               source: str | None = None, honeypot: str | None = None) -> dict[str, Any]:
        sev = [k for k, v in _RANK.items() if v >= _RANK[min_severity]]
        filt: list[dict] = [{"range": {"@timestamp": {"gte": f"now-{minutes}m"}}}, {"terms": {"severity": sev}}]
        if event_type:
            filt.append({"term": {"event_type": event_type}})
        if src_ip:
            filt.append({"term": {"src_ip": src_ip}})
        if source:
            filt.append({"term": {"source": source}})
        if honeypot:
            filt.append({"term": {"honeypot": honeypot}})
        r = self.es.search(index=f"{self.sec_prefix}-*", query={"bool": {"filter": filt}},
                           sort=[{"@timestamp": "desc"}], size=limit, track_total_hits=True,
                           ignore_unavailable=True, allow_no_indices=True)
        hits = r.get("hits", {})
        total = hits.get("total", 0)
        total = total.get("value", 0) if isinstance(total, dict) else total
        return {"total": int(total or 0), "hits": [h.get("_source", {}) for h in hits.get("hits", [])]}

    def layer_counts(self, minutes: int = 60) -> dict[str, Any]:
        """Collected events per collection layer, plus the labeled scenario / entry-vector split of the same window."""
        r = self.es.search(index=f"{self.raw_prefix}-*", size=0, ignore_unavailable=True, allow_no_indices=True,
                           query={"range": {"@timestamp": {"gte": f"now-{minutes}m"}}},
                           aggs={"layers": {"terms": {"field": "layer", "size": 10}},
                                 "labels": {"terms": {"field": "label", "size": 20}},
                                 "vectors": {"terms": {"field": "entry_vector", "size": 5}},
                                 "actors": {"terms": {"field": "actor", "size": 5}}})
        agg = lambda k: {
    b["key"]: b["doc_count"]
    for b in r.get("aggregations", {}).get(k, {}).get("buckets", [])
}
        layers = agg("layers")
        total = r.get("hits", {}).get("total", 0)
        total = total.get("value", 0) if isinstance(total, dict) else total
        return {"total": int(total or 0),
                "layers": {k: layers.get(k, 0) for k in LAYERS}, "labels": agg("labels"),
                "entry_vectors": agg("vectors"), "actors": agg("actors")}

    def event_histogram(self, minutes: int = 60, interval: str = "1m") -> dict[str, Any]:
        r = self.es.search(index=f"{self.sec_prefix}-*", size=0, ignore_unavailable=True, allow_no_indices=True,
                           query={"range": {"@timestamp": {"gte": f"now-{minutes}m", "lte": "now"}}},
                           aggs={"t": {"date_histogram": {"field": "@timestamp", "fixed_interval": interval,
                                                            "min_doc_count": 0,
                                                            "extended_bounds": {"min": f"now-{minutes}m", "max": "now"}},
                                       "aggs": {"types": {"terms": {"field": "event_type", "size": 20}}}}})
        return r.get("aggregations", {}).get("t", {}).get("buckets", [])
