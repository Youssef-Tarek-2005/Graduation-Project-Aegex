"""POST endpoints for the lab bookkeeping that Task A sends: captures and the attack log.

Same checks as the command-line tools (step 6): the attack log is refused as a whole if any row is wrong.
"""
from __future__ import annotations

from typing import Annotated

import psycopg
from fastapi import APIRouter, Body, Depends, HTTPException, Response, status

from ingest.attacks import AttackLogError, db_problems, parse_run, save_runs
from ingest.captures import CaptureError, add_capture
from ingest.loader import label_capture

from .db import get_conn
from .ingest import REFUSED, refuse
from .schemas import AttackRunList, AttackRunsResult, CaptureIn, CaptureOut

router = APIRouter(prefix="/api/v1", tags=["Lab: captures and attack log"])
Conn = Annotated[psycopg.Connection, Depends(get_conn)]


@router.post("/captures", response_model=CaptureOut, status_code=status.HTTP_201_CREATED,
             responses={200: {"model": CaptureOut, "description": "the exact same capture already existed"},
                        409: {"description": "a capture with this id exists with different values"}, **REFUSED},
             summary="Register a recording session")
def create_capture(conn: Conn, capture: CaptureIn, response: Response) -> CaptureOut:
    """Must exist before its events, flows and attack runs arrive. Sending the same capture again is fine (200)."""
    try:
        created = add_capture(conn, capture.capture_id, capture.start_ts, capture.end_ts, capture.kind,
                              capture.pcap_path, capture.notes)
    except CaptureError as exc:
        if "already exists" in str(exc):
            raise HTTPException(status_code=409, detail=str(exc)) from None
        raise refuse([str(exc)]) from None
    if not created:
        response.status_code = status.HTTP_200_OK
    return CaptureOut(capture_id=capture.capture_id, created=created)


@router.post("/attack-runs", response_model=AttackRunsResult, responses=REFUSED,
             summary="Send Task A's attack log (one run, or a list)")
def create_attack_runs(conn: Conn, items: Annotated[AttackRunList, Body()],
                       label: bool = False) -> AttackRunsResult:
    """All rows are checked together (capture exists and contains the run, device exists, the attacker isn't a
    honeypot, no overlap with the same attacker's other runs). Any problem: nothing saved, all problems listed.

    Sending a corrected run with the same run_id updates it. `?label=true` re-labels the touched captures."""
    runs, problems = [], []
    for i, item in enumerate(items):
        run, row_problems = parse_run(f"item {i}", item.model_dump(mode="json"))
        problems += row_problems
        if run:
            runs.append(run)
    ids = [r.run_id for r in runs]
    problems += [f"run_id {rid} is used twice in this request" for rid in sorted({x for x in ids if ids.count(x) > 1})]
    problems += db_problems(conn, runs)
    if problems or not runs:
        raise refuse(problems or ["the list is empty"], "The attack log was refused. Nothing was saved.")
    try:
        result = save_runs(conn, runs)
    except AttackLogError as exc:
        raise refuse(exc.problems) from None
    if label:
        for cid in result.captures:
            label_capture(conn, cid)
    return AttackRunsResult(runs=result.runs, inserted=result.inserted, updated=result.updated,
                            unchanged=result.unchanged, labeled_captures=result.captures if label else [])
