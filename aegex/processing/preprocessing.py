"""Task 2 - Preprocessing: Raw IoT Events -> Cleaning -> Normalization -> Feature Extraction -> Sequence & Graph Construction."""
from __future__ import annotations

import hashlib
import ipaddress
import logging
import math
import random
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from ..config import MOCK_BAD_IPS, Settings
from ..models import EventType, TelemetryBatch
from ..detection.attack_analysis import AttackAnalyzer
from .sequence_graph import SequenceGraphBuilder

log = logging.getLogger(__name__)

SENSOR_FIELDS = ("smoke", "tempeture", "humidity_pct")
FEATURE_ORDER = ["smoke", "tempeture", "humidity_pct", "network_packet_size", "login_attempts",
                 "session_duration", "ip_reputation_score", "failed_logins"]
PACKET_CAP, SESSION_CAP, COUNT_CAP = 65535.0, 3600.0, 50.0   # normalisation ceilings
_PRIVATE = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8")]
_NUMERIC_EVENT_FIELDS = ("bytes", "packets", "packet_size", "duration_s", "payload_size", "frame_rate", "bitrate_kbps", "size_bytes", "payload_entropy")
_VALID_TYPES = {t.value for t in EventType}


# ----------------------------------------------------------------------------- data containers
@dataclass
class CleanedBatch:
    batch_id: str
    timestamp: datetime
    sensor: dict[str, Any]                  # smoke, tempeture, humidity_pct, esp_ms, source_time, was_imputed
    events: list[dict[str, Any]]            # cleaned network events (flat dicts)
    quality: dict[str, Any]


@dataclass
class NormalizedBatch:
    cleaned: CleanedBatch
    sensor_norm: dict[str, float]
    events: list[dict[str, Any]]            # same events with *_norm fields added


@dataclass
class FeatureVector:
    batch_id: str
    timestamp: datetime
    sensor: dict[str, Any]
    features: dict[str, float]              # the 5 requested features, real units
    features_normalized: dict[str, float]   # all 8 model inputs scaled to 0..1
    feature_source: str                     # 'observed' | 'mock'
    quality: dict[str, Any]
    graph_edges: list[dict[str, Any]] = field(default_factory=list)
    window: list[list[float]] = field(default_factory=list)       # last N feature vectors (sequence construction)
    analysis: dict[str, Any] | None = None                        # rule-based attack analysis, None = nothing detected

    def to_payload(self) -> dict[str, Any]:
        """JSON-serialisable message for the detection layer / webhooks."""
        return {
            "schema_version": "1.0",
            "batch_id": self.batch_id,
            "timestamp": self.timestamp.isoformat(),
            "sensor": self.sensor,
            "features": self.features,
            "features_normalized": self.features_normalized,
            "feature_order": FEATURE_ORDER,
            "vector": [self.features_normalized[k] for k in FEATURE_ORDER],
            "feature_source": self.feature_source,
            "quality": self.quality,
            "graph_edges": self.graph_edges,
            "window": self.window,
            "attack_analysis": self.analysis,
        }


def _to_float(v: Any) -> float | None:
    try:
        x = float(str(v).strip().replace(",", "."))
    except (TypeError, ValueError):
        return None
    return x if math.isfinite(x) else None


def _minmax(x: float, lo: float, hi: float) -> float:
    return 0.0 if hi <= lo else min(1.0, max(0.0, (x - lo) / (hi - lo)))


def _logscale(x: float, cap: float) -> float:
    return min(1.0, math.log1p(max(x, 0.0)) / math.log1p(cap))


# ----------------------------------------------------------------------------- step 2: cleaning
class Cleaner:
    def __init__(self, s: Settings):
        self.s = s
        self.bounds = {"smoke": (0.0, s.smoke_max), "tempeture": (s.temp_min, s.temp_max), "humidity_pct": (0.0, 100.0)}
        self.defaults = {"smoke": 0.0, "tempeture": 25.0, "humidity_pct": 50.0}   # used only before any good row exists
        self.last_good: dict[str, float] = {}

    def clean(self, batch: TelemetryBatch) -> CleanedBatch | None:
        raw = batch.sensor_event.payload
        sensor: dict[str, Any] = {}
        issues: list[str] = []
        bad: set[str] = set()
        for f in SENSOR_FIELDS:
            v, (lo, hi) = _to_float(raw.get(f)), self.bounds[f]
            if v is None or not (lo <= v <= hi):
                bad.add(f)
                issues.append(f"{f}:{'missing' if v is None else 'out_of_range'}")
                v = self.last_good.get(f)                       # forward-fill from last valid reading
                if v is None:
                    v = self.defaults[f]
                    issues.append(f"{f}:default_used")
            sensor[f] = float(v)
        invalid = len(bad)
        if invalid == len(SENSOR_FIELDS) and not self.last_good:
            log.warning("Dropping unusable CSV row (no valid fields, no history): %s", raw)
            return None
        for f in SENSOR_FIELDS:                                 # remember only genuinely valid values
            if f not in bad:
                self.last_good[f] = sensor[f]
        esp = _to_float(raw.get("esp_ms"))
        sensor["esp_ms"] = int(esp) if esp is not None else None
        sensor["source_time"] = raw.get("time")
        sensor["was_imputed"] = invalid > 0 or bool(raw.get("_malformed"))

        events, dropped = [], 0
        for ev in batch.network_events:
            if ev.event_type.value not in _VALID_TYPES:
                dropped += 1
                continue
            p = dict(ev.payload)
            if "src_ip" in p:
                try:
                    p["src_ip"] = str(ipaddress.ip_address(str(p["src_ip"]).strip()))
                except ValueError:
                    dropped += 1
                    continue
            for f in _NUMERIC_EVENT_FIELDS:
                if f in p:
                    x = _to_float(p[f])
                    p[f] = x if (x is not None and x >= 0) else None
            events.append({"event_type": ev.event_type.value, "timestamp": ev.timestamp, **p})
        quality = {"issues": issues, "malformed_row": bool(raw.get("_malformed")), "dropped_events": dropped}
        return CleanedBatch(batch.batch_id, batch.timestamp, sensor, events, quality)


# ----------------------------------------------------------------------------- step 3: normalisation
class Normalizer:
    def __init__(self, s: Settings):
        self.bounds = {"smoke": (0.0, s.smoke_max), "tempeture": (s.temp_min, s.temp_max), "humidity_pct": (0.0, 100.0)}

    def normalize(self, c: CleanedBatch) -> NormalizedBatch:
        sensor_norm = {f: _minmax(c.sensor[f], *self.bounds[f]) for f in SENSOR_FIELDS}   # fixed physical ranges: no data leakage
        events = []
        for e in c.events:
            e = dict(e)
            if e.get("packet_size") is not None:
                e["packet_size_norm"] = _logscale(e["packet_size"], PACKET_CAP)
            if e.get("duration_s") is not None:
                e["duration_norm"] = _logscale(e["duration_s"], SESSION_CAP)
            events.append(e)
        return NormalizedBatch(c, sensor_norm, events)


# ----------------------------------------------------------------------------- IP reputation (mock-able)
class IPReputation:
    """0 = clean, 1 = known malicious. Blocklist hit -> 0.9+, RFC1918 -> ~0, other public IPs -> stable pseudo-score.
    Replace `score()` with an AbuseIPDB / threat-feed lookup when available."""

    def __init__(self, blocklist_path: str = ""):
        self.bad = set(MOCK_BAD_IPS)
        if blocklist_path and Path(blocklist_path).exists():
            self.bad |= {l.strip() for l in Path(blocklist_path).read_text().splitlines() if l.strip() and not l.startswith("#")}

    def score(self, ip: str) -> float:
        if ip in self.bad:
            return 0.9 + (int(hashlib.md5(ip.encode()).hexdigest(), 16) % 10) / 100
        addr = ipaddress.ip_address(ip)
        if any(addr in n for n in _PRIVATE):
            return 0.02
        return 0.05 + (int(hashlib.md5(ip.encode()).hexdigest(), 16) % 30) / 100


# ----------------------------------------------------------------------------- step 4: feature extraction
class FeatureExtractor:
    def __init__(self, s: Settings):
        self.s = s
        self.rep = IPReputation(s.ip_blocklist_path)

    def extract(self, nb: NormalizedBatch) -> FeatureVector:
        c, ev = nb.cleaned, nb.events
        by = lambda t: [e for e in ev if e["event_type"] == t.value]  # noqa: E731

        sizes = [e["packet_size"] for e in by(EventType.PACKET_CHARACTERISTICS) if e.get("packet_size") is not None]
        sizes += [e["bytes"] / max(e.get("packets") or 1, 1) for e in by(EventType.NETWORK_TRAFFIC) if e.get("bytes") is not None]
        durs = [e["duration_s"] for e in by(EventType.SESSION_INFO) if e.get("duration_s") is not None]
        ips = {e["src_ip"] for e in ev if "src_ip" in e}
        login_n = len(by(EventType.LOGIN_ATTEMPT))
        failed_n = max(len(by(EventType.FAILED_LOGIN)), sum(1 for e in by(EventType.LOGIN_ATTEMPT) if e.get("success") is False))
        login_n = max(login_n, failed_n)

        observed = bool(ev)
        if observed:
            pkt = sum(sizes) / len(sizes) if sizes else 0.0
            sess = max(durs) if durs else 0.0
            rep = max((self.rep.score(i) for i in ips), default=0.0)
            pkt_norm = (sum(_logscale(x, PACKET_CAP) for x in sizes) / len(sizes)) if sizes else 0.0
            sess_norm = _logscale(sess, SESSION_CAP)
        else:                                   # no network telemetry: deterministic mock keyed on the sensor row
            r = random.Random(int(hashlib.md5(f"{c.sensor.get('esp_ms')}{c.batch_id[:8]}".encode()).hexdigest(), 16))
            pkt, sess = r.gauss(512, 120), r.uniform(1, 45)
            pkt = max(pkt, 40.0)
            login_n, failed_n = r.randint(0, 2), 0
            rep = r.uniform(0.02, 0.2)
            pkt_norm, sess_norm = _logscale(pkt, PACKET_CAP), _logscale(sess, SESSION_CAP)

        features = {"network_packet_size": round(pkt, 3), "login_attempts": float(login_n),
                    "session_duration": round(sess, 3), "ip_reputation_score": round(rep, 4), "failed_logins": float(failed_n)}
        normalized = {**nb.sensor_norm, "network_packet_size": pkt_norm, "login_attempts": min(1.0, login_n / COUNT_CAP),
                      "session_duration": sess_norm, "ip_reputation_score": rep, "failed_logins": min(1.0, failed_n / COUNT_CAP)}

        sensor_out = {k: c.sensor[k] for k in (*SENSOR_FIELDS, "esp_ms", "source_time", "was_imputed")}
        return FeatureVector(c.batch_id, c.timestamp, sensor_out, features,
                             {k: round(float(normalized[k]), 6) for k in FEATURE_ORDER},
                             "observed" if observed else "mock", c.quality)


# ----------------------------------------------------------------------------- the 5-step pipeline
class PreprocessingPipeline:
    def __init__(self, s: Settings):
        self.cleaner, self.normalizer, self.extractor = Cleaner(s), Normalizer(s), FeatureExtractor(s)
        self.sequence_graph = SequenceGraphBuilder(s)
        self.analyzer = AttackAnalyzer(self.extractor.rep)

    def process(self, batch: TelemetryBatch) -> FeatureVector | None:
        raw = batch                                    # step 1: Raw IoT Events (intake from Task 1)
        cleaned = self.cleaner.clean(raw)              # step 2: Cleaning
        if cleaned is None:
            return None
        normalized = self.normalizer.normalize(cleaned)  # step 3: Normalization
        fv = self.extractor.extract(normalized)          # step 4: Feature Extraction
        vec = [fv.features_normalized[k] for k in FEATURE_ORDER]
        fv.window, fv.graph_edges = self.sequence_graph.build(vec, normalized.events)   # step 5: Sequence & Graph Construction
        fv.analysis = self.analyzer.analyze(normalized.events)                          # rule-based attack analysis
        return fv
