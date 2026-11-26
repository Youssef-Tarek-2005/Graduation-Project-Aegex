"""The FastAPI app: wires the pieces together.

    cd backend
    .venv/Scripts/python -m api                # then open http://localhost:8001/docs
"""
from __future__ import annotations

from contextlib import asynccontextmanager
from datetime import datetime, timezone

import psycopg
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from psycopg_pool import PoolTimeout

from ingest.event import CONTRACT

from . import db, ingest, lab, read, stats
from .schemas import Health

DESCRIPTION = """
The AEGEX backend (Task B). One database for everything the honeypot lab records, and the place
where the other tasks send and fetch data. The agreement behind it: `contracts/TASK_B_CONTRACT.md`.

**Try it:** open an endpoint, press **Try it out**, edit the example, press **Execute**.

All times are UTC and must say so (`...Z` or `+02:00`). If our checks refuse a request, the answer is 422 with
every problem listed, and **nothing is saved**.
"""


@asynccontextmanager
async def lifespan(app: FastAPI):
    db.open_pool()                 # at start: open the connection pool
    yield
    db.close_pool()                # at stop: close it


app = FastAPI(title="AEGEX backend", version=CONTRACT["feature_version"], description=DESCRIPTION, lifespan=lifespan,
              openapi_tags=[{"name": "System", "description": "Is everything running?"},
                            {"name": "Ingest", "description": "Send events, sensor readings and log lines in."},
                            {"name": "Lab: captures and attack log", "description": "Task A's recording sessions "
                             "and attack log, which drive the labels."},
                            {"name": "Data", "description": "Read events and flows back (dashboard, E)."},
                            {"name": "Features (for the models)", "description": "Window features and graph "
                             "edges for C and D. Not scaled: apply the step 9 scalers."},
                            {"name": "Dashboard", "description": "Counts and chart-ready series for "
                             "frontend/dashboard.html."}])

# The dashboard is a plain HTML file in the browser; this lets it call the API. (Step 12 adds the API key.)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["GET", "POST", "PATCH"], allow_headers=["*"])

app.include_router(ingest.router)
app.include_router(lab.router)
app.include_router(read.router)
app.include_router(stats.router)


@app.exception_handler(PoolTimeout)
@app.exception_handler(psycopg.OperationalError)
async def database_down(request: Request, exc: Exception) -> JSONResponse:
    return JSONResponse(status_code=503, content={"detail": "The database is not reachable. Is Docker running?"})


@app.get("/health", response_model=Health, tags=["System"], summary="Is the API and its database OK?")
def health() -> Health | JSONResponse:
    now = datetime.now(timezone.utc)
    try:
        with db.connection() as conn:
            version = conn.execute("SELECT extversion FROM pg_extension WHERE extname = 'timescaledb'").fetchone()
            counts = dict(conn.execute("""
                SELECT 'events', count(*) FROM events UNION ALL SELECT 'flows', count(*) FROM flows
                UNION ALL SELECT 'captures', count(*) FROM captures UNION ALL SELECT 'attack_runs', count(*) FROM attack_runs
                UNION ALL SELECT 'feature_windows', count(*) FROM feature_windows""").fetchall())
            name = conn.info.dbname
        return Health(status="ok", database="ok", database_name=name, timescaledb=version[0] if version else None,
                      feature_version=CONTRACT["feature_version"], server_time=now, counts=counts)
    except (PoolTimeout, psycopg.Error) as exc:
        body = Health(status="degraded", database=f"not reachable: {type(exc).__name__}",
                      feature_version=CONTRACT["feature_version"], server_time=now)
        return JSONResponse(status_code=503, content=body.model_dump(mode="json"))
