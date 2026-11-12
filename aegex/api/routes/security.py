from datetime import datetime, timezone
import logging
from typing import Literal

from fastapi import APIRouter, HTTPException, Query

from ..deps import es
from ..schemas import EventsResponse, HistogramResponse

router = APIRouter(prefix="/api/v1/security", tags=["Security events"])
log = logging.getLogger(__name__)


@router.get("/events", response_model=EventsResponse, summary="Recent security events (newest first)",
            description=("Events the honeypot flagged as suspicious: failed logins, malicious commands, MQTT probes, BLE pairing attempts, "
                         "device tampering. Read from Elasticsearch.\n\nAn empty list is normal for the first minute or two."))
def security_events(
    minutes: int = Query(60, ge=1, le=10080, description="How far back to look, in minutes."),
    limit: int = Query(50, ge=1, le=500, description="Maximum number of events to return."),
    min_severity: Literal["info", "low", "medium", "high", "critical"] = Query("low", description="Hide events below this severity."),
    event_type: str | None = Query(None, description="Optional. Only this type, e.g. failed_login or command_request."),
    src_ip: str | None = Query(None, description="Optional. Only events from this IP address."),
    source: str | None = Query(None, description="Optional. Event source e.g. cowrie, zeek, mosquitto."),
    honeypot: str | None = Query(None, description="Optional. Only events targeting this honeypot."),
) -> dict:
    try:
        r = es.recent_security_events(minutes, limit, min_severity, event_type, src_ip, source=source, honeypot=honeypot)
    except Exception as e:  # noqa: BLE001
        log.exception("Failed to query recent security events")
        raise HTTPException(503, f"Elasticsearch unavailable: {type(e).__name__}") from e
    events = []
    for h in r.get("hits", []):
        events.append({"id": h.get("event_id", "unknown"), "timestamp": h.get("@timestamp", ""),
                       "event_type": h.get("event_type", "unknown"), "severity": h.get("severity", "info"),
                       "reasons": h.get("reasons", []), "src_ip": h.get("src_ip"), "source": h.get("source"),
                       "honeypot": h.get("honeypot"), "details": h.get("payload", {})})
    return {
        "meta": {"total": r.get("total", 0), "returned": len(events), "window_minutes": minutes,
                 "generated_at": datetime.now(timezone.utc).isoformat()},
        "events": events,
    }


@router.get("/events/histogram", response_model=HistogramResponse, summary="Event counts over time (for a bar chart)",
            description="How many security events happened in each time bucket, split by event type.")
def security_histogram(
    minutes: int = Query(60, ge=1, le=10080, description="How far back to look, in minutes."),
    interval: str = Query("1m", pattern=r"^\d+[smhd]$", description="Bucket size: 30s, 1m, 5m, 1h, 1d ..."),
) -> dict:
    try:
        buckets = es.event_histogram(minutes, interval)
    except Exception as e:  # noqa: BLE001
        log.exception("Failed to query security-event histogram")
        raise HTTPException(503, f"Elasticsearch unavailable: {type(e).__name__}") from e
    types = sorted({t["key"] for b in buckets for t in b.get("types", {}).get("buckets", [])})
    counts = [{t["key"]: t["doc_count"] for t in b.get("types", {}).get("buckets", [])} for b in buckets]
    return {"meta": {"interval": interval, "window_minutes": minutes},
            "labels": [b["key_as_string"] for b in buckets],
            "series": [{"name": t, "data": [c.get(t, 0) for c in counts]} for t in types]}


@router.get("/layers", summary="Collected events per collection layer",
            description="Network traffic, device & service logs, session & interaction, telemetry & media - plus the labeled split by scenario, entry vector (Wi-Fi / Bluetooth) and actor (attacker / normal user).")
def collection_layers(minutes: int = Query(60, ge=1, le=10080, description="How far back to look, in minutes.")) -> dict:
    try:
        r = es.layer_counts(minutes)
    except Exception as e:  # noqa: BLE001
        log.exception("Failed to query collection-layer counts")
        raise HTTPException(503, f"Elasticsearch unavailable: {type(e).__name__}") from e
    return {"meta": {"window_minutes": minutes, "generated_at": datetime.now(timezone.utc).isoformat()}, **r}
