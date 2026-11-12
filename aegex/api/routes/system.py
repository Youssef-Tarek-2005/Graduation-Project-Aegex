from fastapi import APIRouter

from ..deps import es, pg
from ..schemas import HealthResponse

router = APIRouter(tags=["System"])


@router.get("/health", response_model=HealthResponse, summary="Are the databases connected?",
            description="Quick check. Both values should say **up**. If one says down, that service is still starting or has crashed.")
def health() -> dict:
    out = {}
    try:
        pg.sensor_timeseries(1, 1)
        out["postgres"] = "up"
    except Exception as e:  # noqa: BLE001
        out["postgres"] = f"down: {type(e).__name__}"
    try:
        out["elasticsearch"] = "up" if es.es.ping() else "down"
    except Exception as e:  # noqa: BLE001
        out["elasticsearch"] = f"down: {type(e).__name__}"
    return out
