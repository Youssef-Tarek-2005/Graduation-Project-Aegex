from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException, Query

from ..deps import pg
from ..schemas import TimeseriesResponse

router = APIRouter(prefix="/api/v1/sensors", tags=["Sensors"])
UNITS = {"tempeture": "°C", "smoke": "ADC", "humidity_pct": "%"}


def _iso(v) -> str:
    return v.astimezone(timezone.utc).isoformat() if isinstance(v, datetime) else str(v)


@router.get("/timeseries", response_model=TimeseriesResponse,
            summary="Temperature, smoke and humidity over time",
            description=("Returns the sensor readings from your CSV (stored in PostgreSQL), oldest first, ready to draw as a line chart.\n\n"
                         "**Try it:** press **Execute**. In the response, `labels` is the time axis and each entry of `series` is one sensor line."))
def sensor_timeseries(
    minutes: int = Query(60, ge=1, le=10080, description="How far back to look, in minutes. 60 = last hour, 1440 = last 24 hours."),
    limit: int = Query(1000, ge=1, le=20000, description="Maximum number of data points to return."),
    bucket_seconds: int | None = Query(None, ge=1, description="Optional. Average the readings into buckets of this many seconds "
                                                               "(60 = one point per minute). Leave empty for raw readings."),
) -> dict:
    try:
        rows = pg.sensor_timeseries(minutes, limit, bucket_seconds)
    except Exception as e:  # noqa: BLE001
        raise HTTPException(503, f"PostgreSQL unavailable: {type(e).__name__}") from e
    return {
        "meta": {"count": len(rows), "window_minutes": minutes, "bucket_seconds": bucket_seconds,
                 "generated_at": datetime.now(timezone.utc).isoformat()},
        "labels": [_iso(r["t"]) for r in rows],
        "series": [{"name": k, "unit": u, "data": [round(float(r[k]), 3) for r in rows]} for k, u in UNITS.items()],
        "points": [{"t": _iso(r["t"]), **{k: round(float(r[k]), 3) for k in UNITS}} for r in rows],
    }
