"""GET endpoints for the 8-step plan's pieces (Step 5): datasets, pipeline runs, the datastore.

    GET /api/v1/datasets                 the catalogue (Step 1) + what is loaded in this database (Step 2)
    GET /api/v1/datasets/{id}            one dataset: its captures, flows per class, caveats
    GET /api/v1/pipeline/runs            the pipeline's run reports (Step 3), newest first
    GET /api/v1/pipeline/runs/{run_id}   one report, stage by stage
    GET /api/v1/datastore                size, rows and compression of this database (Step 4)

The API reads ONE database (AEGEX_DB_URL). Point it at aegex_datasets to browse the public datasets with every
endpoint (flows, captures, ...); /datasets always shows the whole catalogue, with `loaded` = 0 for datasets
that are not in the database the API reads.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Annotated

import psycopg
from fastapi import APIRouter, Depends, HTTPException, Query

from datasets import analyze
from ingest import datastore, pipeline

from .db import get_conn
from .ingest import REFUSED
from .schemas import DatasetDetail, DatasetOut, DatastoreOut, PipelineRunOut, PipelineRunSummary

router = APIRouter(prefix="/api/v1", responses=REFUSED)
Conn = Annotated[psycopg.Connection, Depends(get_conn)]
RUN_ID = re.compile(r"^[A-Za-z0-9_.-]{1,120}$")
REPORT = analyze.REPORT_DIR / "datasets_report.json"


# ------------------------------------------------------------------------------------------- datasets
def _measured() -> dict:
    """Step 1 totals per dataset id, from the last `python -m datasets.analyze` (empty if it never ran)."""
    try:
        report = json.loads(REPORT.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return {d["id"]: d["total"] for d in report.get("datasets", []) if d.get("total")}


def _loaded(conn: psycopg.Connection) -> dict:
    rows = conn.execute(
        "SELECT c.dataset, count(DISTINCT c.capture_id), count(f.flow_id), count(*) FILTER (WHERE f.label = 1) "
        "FROM captures c LEFT JOIN flows f ON f.capture_id = c.capture_id "
        "WHERE c.dataset IS NOT NULL GROUP BY c.dataset").fetchall()
    return {d: {"captures": c, "flows": f, "attack_flows": a} for d, c, f, a in rows}


def _dataset(ds: dict, loaded: dict, measured: dict) -> dict:
    return {"id": ds["id"], "name": ds["name"], "host": ds["host"], "url": ds["url"],
            "download_bytes": sum(f.get("size_bytes") or 0 for f in analyze.used_files(ds))
            or ds.get("total_size_bytes_approx"),
            "label_method": ds["labelling"]["method"], "used_by_models": ds.get("used_by_models", []),
            "loaded": loaded.get(ds["id"], {"captures": 0, "flows": 0, "attack_flows": 0}),
            "measured": measured.get(ds["id"])}


@router.get("/datasets", response_model=list[DatasetOut], tags=["Datasets"],
            summary="The public dataset catalogue, what is loaded here and what Step 1 measured")
def list_datasets(conn: Conn) -> list[dict]:
    loaded, measured = _loaded(conn), _measured()
    return [_dataset(ds, loaded, measured) for ds in analyze.load_catalogue()["datasets"]]


@router.get("/datasets/{dataset_id}", response_model=DatasetDetail, tags=["Datasets"],
            summary="One dataset: its captures in this database, flows per attack class")
def get_dataset(conn: Conn, dataset_id: str) -> dict:
    cat = {d["id"]: d for d in analyze.load_catalogue()["datasets"]}
    if dataset_id not in cat:
        raise HTTPException(404, f"unknown dataset {dataset_id!r}; the catalogue has: {', '.join(cat)}")
    caps = []
    for cid, kind, start, end, notes in conn.execute(
            "SELECT capture_id, kind, start_ts, end_ts, notes FROM captures WHERE dataset = %s ORDER BY start_ts",
            (dataset_id,)).fetchall():
        classes = dict(conn.execute("SELECT coalesce(attack_class, 'unlabelled'), count(*) FROM flows "
                                    "WHERE capture_id = %s GROUP BY 1 ORDER BY 2 DESC", (cid,)).fetchall())
        flows = sum(classes.values())
        caps.append({"capture_id": cid, "kind": kind, "start_ts": start, "end_ts": end, "notes": notes,
                     "flows": flows, "attack_flows": flows - classes.get("benign", 0) - classes.get("unlabelled", 0),
                     "classes": classes})
    out = _dataset(cat[dataset_id], _loaded(conn), _measured())
    return {**out, "captures": caps, "caveats": cat[dataset_id].get("caveats", [])}


# ------------------------------------------------------------------------------------------- pipeline runs
def _runs_dir() -> Path:
    return pipeline.RUNS_DIR


def _read_run(path: Path) -> dict | None:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


@router.get("/pipeline/runs", response_model=list[PipelineRunSummary], tags=["Pipeline"],
            summary="Run reports of python -m ingest.pipeline, newest first")
def list_runs(limit: Annotated[int, Query(ge=1, le=500)] = 50) -> list[dict]:
    files = sorted(_runs_dir().glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True) \
        if _runs_dir().is_dir() else []
    out = []
    for path in files:
        r = _read_run(path)
        if r is None:
            continue
        out.append({"run_id": path.stem, "session": r.get("session", ""), "kind": r.get("kind", ""),
                    "started": r.get("started", ""), "ok": bool(r.get("ok")),
                    "stages": {s["name"]: s["status"] for s in r.get("stages", [])}})
        if len(out) >= limit:
            break
    return out


@router.get("/pipeline/runs/{run_id}", response_model=PipelineRunOut, tags=["Pipeline"],
            summary="One pipeline run, stage by stage, with its counts")
def get_run(run_id: str) -> dict:
    if not RUN_ID.match(run_id):                    # a file name only: no folders, no "..", no drive letters
        raise HTTPException(404, "no such run")
    path = _runs_dir() / f"{run_id}.json"
    r = _read_run(path) if path.is_file() else None
    if r is None:
        raise HTTPException(404, "no such run")
    return {"run_id": run_id, **{k: r.get(k) for k in ("session", "kind", "started", "ok", "stages")}}


# ------------------------------------------------------------------------------------------- datastore
@router.get("/datastore", response_model=DatastoreOut, tags=["Datastore"],
            summary="Size, rows, chunks and compression of the database the API reads")
def get_datastore(conn: Conn) -> dict:
    s = datastore.status(conn)
    return {**{k: s[k] for k in ("database", "bytes", "hypertables", "tables", "flows_from", "flows_to")},
            "captures_by_source": dict(s["datasets"])}
