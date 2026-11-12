from typing import Literal

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import PlainTextResponse

from ...intel.report import build_report, to_markdown
from ..deps import pg

router = APIRouter(prefix="/api/v1/reports", tags=["Reports"])


@router.get("/blue-team", summary="Blue team report: findings, recommendations, mitigation steps",
            description="Built from stored attack analyses and linked to the knowledge base. `format=markdown` returns a downloadable text report.")
def blue_team(minutes: int = Query(60, ge=1, le=10080), format: Literal["json", "markdown"] = Query("json")):
    try:
        rows = pg.recent_attacks(minutes, 5000)
    except Exception as e:  # noqa: BLE001
        raise HTTPException(503, f"PostgreSQL unavailable: {type(e).__name__}") from e
    rep = build_report(rows, minutes)
    if format == "markdown":
        return PlainTextResponse(to_markdown(rep), media_type="text/markdown; charset=utf-8",
                                 headers={"Content-Disposition": "attachment; filename=aegex-blue-team-report.md"})
    return rep
