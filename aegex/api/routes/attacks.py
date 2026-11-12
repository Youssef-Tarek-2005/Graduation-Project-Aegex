from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException, Query

from ...models import SCENARIOS
from ..deps import pg

router = APIRouter(prefix="/api/v1/attacks", tags=["Attack analysis"])


def _db(fn, *a):
    try:
        return fn(*a)
    except Exception as e:  # noqa: BLE001
        raise HTTPException(503, f"PostgreSQL unavailable: {type(e).__name__}") from e


@router.get("", summary="Detected attacks (newest first)",
            description="Rule-based attack analysis per telemetry window: category, severity, confidence, source IPs, entry vector (Wi-Fi / Bluetooth), "
                        "targeted honeypot (camera / sensor), the signals that fired and the MITRE ATT&CK techniques.")
def attacks(minutes: int = Query(60, ge=1, le=10080), limit: int = Query(50, ge=1, le=500),
            category: str | None = Query(None, description="One of: " + ", ".join(SCENARIOS))) -> dict:
    rows = _db(pg.recent_attacks, minutes, limit, category)
    return {"meta": {"returned": len(rows), "window_minutes": minutes, "generated_at": datetime.now(timezone.utc).isoformat()}, "attacks": rows}


@router.get("/summary", summary="Attack counts by scenario, severity, entry vector and honeypot",
            description="Aggregates for the dashboard cards and charts.")
def attack_summary(minutes: int = Query(60, ge=1, le=10080)) -> dict:
    return {"meta": {"window_minutes": minutes, "generated_at": datetime.now(timezone.utc).isoformat()}, **_db(pg.attack_summary, minutes)}
