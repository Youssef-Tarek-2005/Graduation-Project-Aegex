"""Task A's attack log -> attack_runs table -> labels.

Every label in the dataset comes from this file, so it is treated much more strictly than the honeypot logs:
  - a honeypot log: a broken line is skipped and the rest is saved (one bad line in a million can't stop us)
  - the attack log: ANY problem refuses the whole file and lists every problem at once
    (one wrong row = thousands of wrong labels, and a model trained on wrong labels learns the wrong thing)

    cd backend
    .venv/Scripts/python -m ingest.attacks samples/attack_log.csv --check     # only check, save nothing
    .venv/Scripts/python -m ingest.attacks samples/attack_log.csv --label     # save, label, print the report
    .venv/Scripts/python -m ingest.attacks --report cap-2026-11-20-a          # just the labeling report

File formats: CSV with a header row, a JSON list of objects, or one JSON object per line.
Fields (contracts/TASK_B_CONTRACT.md): run_id, capture_id, scenario, tool, command, attacker_ip,
target_device, start_ts, end_ts, and an optional notes.

Loading the same file again changes nothing. Loading a corrected file updates the changed runs; run with
--label afterwards and the labels move with them (label_capture resets a capture's labels before applying).
"""
from __future__ import annotations

import csv
import io
import ipaddress
import json
from dataclasses import dataclass, field, fields
from datetime import datetime
from pathlib import Path
from typing import Any

import psycopg

from .captures import parse_utc

SCENARIOS = ("vulnerability_scanning", "bruteforce", "dos", "mirai_botnet", "mqtt_spoofing",
             "sensor_manipulation", "unauthorized_camera_access", "ransomware", "other")
REQUIRED = ("run_id", "capture_id", "scenario", "attacker_ip", "start_ts", "end_ts")


class AttackLogError(Exception):
    """The attack log has problems. Holds all of them, so A can fix everything in one go."""

    def __init__(self, problems: list[str]):
        self.problems = problems
        super().__init__(f"{len(problems)} problem(s) in the attack log. Nothing was saved.\n"
                         + "\n".join(f"  - {p}" for p in problems))


@dataclass
class AttackRun:
    run_id: str
    capture_id: str
    scenario: str
    attacker_ip: str
    start_ts: datetime
    end_ts: datetime
    tool: str | None = None
    command: str | None = None
    target_device: str | None = None
    notes: str | None = None
    where: str = field(default="", compare=False)     # "line 3": where it came from, for error messages

    def to_row(self) -> dict[str, Any]:
        return {f.name: getattr(self, f.name) for f in fields(self) if f.name != "where"}

    def overlaps(self, other: AttackRun) -> bool:
        return self.start_ts < other.end_ts and other.start_ts < self.end_ts


COLUMNS = tuple(f.name for f in fields(AttackRun) if f.name != "where")


# ------------------------------------------------------------------------------------------- reading
def read_rows(path: str | Path) -> list[tuple[str, Any]]:
    """The file's rows as (where, dict). Accepts CSV, a JSON list, or JSON lines."""
    text = Path(path).read_text(encoding="utf-8-sig")
    start = text.lstrip()[:1]
    try:
        if start == "[":
            return [(f"item {i}", d) for i, d in enumerate(json.loads(text), 1)]
        if start == "{":
            return [(f"line {n}", json.loads(line)) for n, line in enumerate(text.splitlines(), 1) if line.strip()]
    except json.JSONDecodeError as exc:
        raise AttackLogError([f"not valid JSON: {exc}"]) from None
    reader = csv.DictReader(io.StringIO(text))
    return [(f"line {reader.line_num}", row) for row in reader]


def parse_run(where: str, raw: Any) -> tuple[AttackRun | None, list[str]]:
    """One row -> AttackRun, or None plus the list of what's wrong with it."""
    if not isinstance(raw, dict):
        return None, [f"{where}: expected an object with named fields, got {type(raw).__name__}"]
    d = {str(k).strip().lower(): (v.strip() if isinstance(v, str) else v) for k, v in raw.items() if k is not None}
    d = {k: (None if v == "" else v) for k, v in d.items()}
    name = f"{where} ({d['run_id']})" if d.get("run_id") else where
    problems = []

    unknown = sorted(set(d) - set(COLUMNS))
    if unknown:
        problems.append(f"{name}: unknown column(s) {', '.join(unknown)}. Allowed: {', '.join(COLUMNS)}")
    missing = [k for k in REQUIRED if d.get(k) is None]
    if missing:
        problems.append(f"{name}: missing {', '.join(missing)}")
    if d.get("scenario") is not None and d["scenario"] not in SCENARIOS:
        problems.append(f"{name}: scenario {d['scenario']!r} is not one of {', '.join(SCENARIOS)}")
    if d.get("attacker_ip") is not None:
        try:
            d["attacker_ip"] = str(ipaddress.ip_address(str(d["attacker_ip"])))
        except ValueError:
            problems.append(f"{name}: attacker_ip {d['attacker_ip']!r} is not an IP address")
    for key in ("start_ts", "end_ts"):
        if d.get(key) is not None:
            try:
                d[key] = parse_utc(str(d[key]), key)
            except ValueError as exc:
                problems.append(f"{name}: {exc}")
    if isinstance(d.get("start_ts"), datetime) and isinstance(d.get("end_ts"), datetime) and d["end_ts"] <= d["start_ts"]:
        problems.append(f"{name}: ends ({d['end_ts']:%H:%M:%S}) before it starts ({d['start_ts']:%H:%M:%S})")

    if problems:
        return None, problems
    return AttackRun(**{k: d.get(k) for k in COLUMNS}, where=name), []


def file_problems(path: str | Path, default_capture: str | None = None) -> tuple[list[AttackRun], list[str]]:
    """Read the file and check it on its own (no database). Returns the good runs and every problem found."""
    runs, problems = [], []
    for where, raw in read_rows(path):
        if default_capture and isinstance(raw, dict) and not raw.get("capture_id"):
            raw = {**raw, "capture_id": default_capture}
        run, row_problems = parse_run(where, raw)
        problems += row_problems
        if run:
            runs.append(run)
    if not runs and not problems:
        problems.append("the file has no attack runs")

    seen: dict[str, AttackRun] = {}
    for r in runs:
        if r.run_id in seen:
            problems.append(f"{r.where}: run_id {r.run_id} is used twice (also {seen[r.run_id].where})")
        seen.setdefault(r.run_id, r)
    problems += _overlaps(runs, runs)
    return runs, problems


def parse_attack_log(path: str | Path, default_capture: str | None = None) -> list[AttackRun]:
    """File checks only. Raises AttackLogError listing every problem."""
    runs, problems = file_problems(path, default_capture)
    if problems:
        raise AttackLogError(problems)
    return runs


def check_attack_log(conn: psycopg.Connection, path: str | Path, default_capture: str | None = None) -> list[AttackRun]:
    """File checks + database checks, all reported together, so A can fix everything in one round."""
    runs, problems = file_problems(path, default_capture)
    problems += db_problems(conn, runs)
    if problems:
        raise AttackLogError(sorted(problems, key=_line_no))
    return runs


def _line_no(problem: str) -> int:
    """'line 7 (run-106): ...' -> 7, so problems print in file order (sorted() keeps a line's own order)."""
    word, _, rest = problem.partition(" ")
    number = rest.split(" ", 1)[0].rstrip(":")
    return int(number) if word in ("line", "item") and number.isdigit() else 0


def _overlaps(new: list[AttackRun], against: list[AttackRun]) -> list[str]:
    """Two runs from the same attacker at the same time: a flow in the overlap would match both, and the
    database would pick one of the two scenarios at random. Different attackers at the same time are fine."""
    problems = []
    for i, a in enumerate(new):
        others = new[i + 1:] if new is against else against      # inside one file: check each pair once
        for b in others:
            if a.run_id != b.run_id and a.attacker_ip == b.attacker_ip and a.overlaps(b):
                problems.append(f"{a.where}: overlaps {b.run_id} ({b.start_ts:%H:%M:%S}-{b.end_ts:%H:%M:%S}) from the "
                                f"same attacker {a.attacker_ip}. Traffic in the overlap can't get one scenario. "
                                f"Split the times, or log it as one run.")
    return problems


# ------------------------------------------------------------------------------------------- checking against the database
SELECT_RUNS = f"SELECT {', '.join(COLUMNS).replace('attacker_ip', 'host(attacker_ip)')} FROM attack_runs"


def db_problems(conn: psycopg.Connection, runs: list[AttackRun]) -> list[str]:
    """The checks that need the database: capture, device, attacker IP, overlaps with runs already saved."""
    problems = []
    captures = {cid: (s, e) for cid, s, e in conn.execute("SELECT capture_id, start_ts, end_ts FROM captures")}
    devices = {dev: ip for dev, ip in conn.execute("SELECT device_id, host(ip) FROM devices")}
    device_by_ip = {ip: dev for dev, ip in devices.items() if ip}

    for r in runs:
        if r.capture_id not in captures:
            problems.append(f"{r.where}: capture {r.capture_id!r} does not exist. "
                            f"Add it first: python -m ingest.captures add {r.capture_id} --start ... --end ...")
        else:
            c_start, c_end = captures[r.capture_id]
            if r.start_ts < c_start or (c_end is not None and r.end_ts > c_end):
                c_end_s = f"{c_end:%H:%M:%S}" if c_end else "(still recording)"
                problems.append(f"{r.where}: runs {r.start_ts:%Y-%m-%d %H:%M:%S}-{r.end_ts:%H:%M:%S} UTC, outside capture "
                                f"{r.capture_id} ({c_start:%Y-%m-%d %H:%M:%S}-{c_end_s}). Wrong capture, or times not in UTC?")
        if r.target_device is not None and r.target_device not in devices:
            problems.append(f"{r.where}: target_device {r.target_device!r} does not exist. Known: {', '.join(sorted(devices))}")
        if r.attacker_ip in device_by_ip:
            problems.append(f"{r.where}: attacker_ip {r.attacker_ip} is our own lab device {device_by_ip[r.attacker_ip]}. "
                            f"Every connection of that device would be labeled attack. Use the attacker machine's IP "
                            f"(a separate laptop/phone/Kali box on the network). If NAT hid it, switch the VM to "
                            f"bridged networking. Attacking from the hotspot laptop itself can't be labeled.")

    file_ids = {r.run_id for r in runs}
    saved = [AttackRun(*row, where=row[0]) for row in conn.execute(SELECT_RUNS) if row[0] not in file_ids]
    return problems + _overlaps(runs, saved)


def check_against_db(conn: psycopg.Connection, runs: list[AttackRun]) -> None:
    problems = db_problems(conn, runs)
    if problems:
        raise AttackLogError(problems)


# ------------------------------------------------------------------------------------------- saving
UPSERT_SQL = """
INSERT INTO attack_runs (run_id, capture_id, scenario, tool, command, attacker_ip, target_device, start_ts, end_ts, notes)
VALUES (%(run_id)s, %(capture_id)s, %(scenario)s, %(tool)s, %(command)s, %(attacker_ip)s::inet, %(target_device)s,
        %(start_ts)s, %(end_ts)s, %(notes)s)
ON CONFLICT (run_id) DO UPDATE SET
    capture_id = EXCLUDED.capture_id, scenario = EXCLUDED.scenario, tool = EXCLUDED.tool, command = EXCLUDED.command,
    attacker_ip = EXCLUDED.attacker_ip, target_device = EXCLUDED.target_device, start_ts = EXCLUDED.start_ts,
    end_ts = EXCLUDED.end_ts, notes = EXCLUDED.notes
"""


@dataclass
class AttackLoadResult:
    runs: int = 0
    inserted: list[str] = field(default_factory=list)
    updated: dict[str, list[str]] = field(default_factory=dict)     # run_id -> names of the changed fields
    unchanged: list[str] = field(default_factory=list)
    captures: list[str] = field(default_factory=list)                # captures this file touches (to re-label)

    def __str__(self) -> str:
        lines = [f"{self.runs} attack runs: {len(self.inserted)} new, {len(self.updated)} changed, "
                 f"{len(self.unchanged)} already saved"]
        lines += [f"  new:     {rid}" for rid in self.inserted]
        lines += [f"  changed: {rid} ({', '.join(f)})" for rid, f in self.updated.items()]
        return "\n".join(lines)


def save_runs(conn: psycopg.Connection, runs: list[AttackRun]) -> AttackLoadResult:
    """Check against the database, then save every run in one transaction (all or nothing)."""
    check_against_db(conn, runs)
    result = AttackLoadResult(runs=len(runs), captures=sorted({r.capture_id for r in runs}))
    with conn.transaction():
        for r in runs:
            row = conn.execute(SELECT_RUNS + " WHERE run_id = %s", (r.run_id,)).fetchone()
            if row is None:
                result.inserted.append(r.run_id)
            else:
                changed = [name for name, old in zip(COLUMNS, row) if old != getattr(r, name)]
                if not changed:
                    result.unchanged.append(r.run_id)
                    continue
                result.updated[r.run_id] = changed
            conn.execute(UPSERT_SQL, r.to_row())
    return result


def load_attack_log(conn: psycopg.Connection, path: str | Path, default_capture: str | None = None) -> AttackLoadResult:
    return save_runs(conn, check_attack_log(conn, path, default_capture))


# ------------------------------------------------------------------------------------------- labeling report
@dataclass
class RunCoverage:
    run_id: str
    scenario: str
    attacker_ip: str
    start_ts: datetime
    end_ts: datetime
    flows: int
    events: int


@dataclass
class LabelReport:
    capture_id: str
    runs: list[RunCoverage]
    flows: dict[int, int]            # label -> count
    events: dict[int, int]
    leftovers: list[tuple]           # attacker traffic labeled normal: (kind, ts, src, dst, what)
    warnings: list[str]

    def __str__(self) -> str:
        out = [f"capture {self.capture_id}",
               f"  flows:  {self.flows.get(1, 0):>5} attack  {self.flows.get(0, 0):>5} normal",
               f"  events: {self.events.get(1, 0):>5} attack  {self.events.get(0, 0):>5} normal"]
        if self.runs:
            out.append(f"  {'run':<10} {'scenario':<24} {'attacker':<16} {'time (UTC)':<19} flows  events")
            for r in self.runs:
                out.append(f"  {r.run_id:<10} {r.scenario:<24} {r.attacker_ip:<16} "
                           f"{r.start_ts:%H:%M:%S}-{r.end_ts:%H:%M:%S}   {r.flows:>5}  {r.events:>6}")
        else:
            out.append("  no attack runs (a normal-only capture: everything is labeled normal)")
        for kind, ts, src, dst, what in self.leftovers[:10]:
            out.append(f"    attacker traffic labeled normal: {kind:<5} {ts:%H:%M:%S}  {src} -> {dst}  {what}")
        if len(self.leftovers) > 10:
            out.append(f"    ... and {len(self.leftovers) - 10} more")
        out += [f"  WARNING: {w}" for w in self.warnings]
        if not self.warnings:
            out.append("  OK: every run matched traffic, and no attacker traffic is outside the runs")
        return "\n".join(out)


def label_report(conn: psycopg.Connection, capture_id: str) -> LabelReport:
    """What labeling did for one capture, and the two mistakes it can't see by itself:
       1. a run that matched no traffic (wrong attacker_ip, NAT, times not in UTC, or the attack never ran)
       2. traffic from the attacker outside every run, which got labeled normal (end_ts too early?)"""
    runs = [RunCoverage(*row) for row in conn.execute("""
        SELECT r.run_id, r.scenario, host(r.attacker_ip), r.start_ts, r.end_ts,
               (SELECT count(*) FROM flows f  WHERE f.capture_id = r.capture_id AND f.run_id = r.run_id),
               (SELECT count(*) FROM events e WHERE e.capture_id = r.capture_id AND e.run_id = r.run_id)
          FROM attack_runs r WHERE r.capture_id = %s ORDER BY r.start_ts""", (capture_id,))]
    flows = dict(conn.execute("SELECT label, count(*) FROM flows WHERE capture_id = %s AND label IS NOT NULL "
                              "GROUP BY label", (capture_id,)).fetchall())
    events = dict(conn.execute("SELECT label, count(*) FROM events WHERE capture_id = %s AND label IS NOT NULL "
                               "GROUP BY label", (capture_id,)).fetchall())
    leftovers = conn.execute("""
        WITH attackers AS (SELECT DISTINCT attacker_ip FROM attack_runs WHERE capture_id = %(c)s)
        SELECT 'flow', f.ts_start, host(f.src_ip), host(f.dst_ip), concat(f.proto, '/', f.dst_port)
          FROM flows f WHERE f.capture_id = %(c)s AND f.label = 0
           AND (f.src_ip IN (SELECT attacker_ip FROM attackers) OR f.dst_ip IN (SELECT attacker_ip FROM attackers))
        UNION ALL
        SELECT 'event', e.ts, host(e.src_ip), host(e.dst_ip), e.event_type
          FROM events e WHERE e.capture_id = %(c)s AND e.label = 0
           AND (e.src_ip IN (SELECT attacker_ip FROM attackers) OR e.dst_ip IN (SELECT attacker_ip FROM attackers))
        ORDER BY 2""", {"c": capture_id}).fetchall()

    warnings = []
    for r in runs:
        if r.flows == 0 and r.events == 0:
            warnings.append(f"{r.run_id} matched no traffic. Check attacker_ip {r.attacker_ip} (NAT changes it), check the "
                            f"times are UTC, check the data for this capture is loaded, and check the attack really ran.")
    if leftovers:
        warnings.append(f"{len(leftovers)} rows from an attacker IP are outside every run and were labeled normal. "
                        f"If they belong to an attack, fix that run's start_ts/end_ts and load the log again. "
                        f"If the attacker machine really did something normal then, this is fine.")
    if not flows and not events:
        warnings.append(f"capture {capture_id} has no labeled data yet: load its logs/pcap, then label it")
    return LabelReport(capture_id, runs, flows, events, leftovers, warnings)


# ------------------------------------------------------------------------------------------- command line
def main() -> int:
    import argparse
    import sys

    from .db import connect, db_url
    from .loader import label_capture

    ap = argparse.ArgumentParser(prog="python -m ingest.attacks", description="Load Task A's attack log and label the data.")
    ap.add_argument("file", nargs="?", help="attack log: CSV, JSON list, or JSON lines")
    ap.add_argument("--capture", help="capture_id for rows that leave it empty")
    ap.add_argument("--check", action="store_true", help="only check the file (and the database), save nothing")
    ap.add_argument("--label", action="store_true", help="after saving, re-label every capture in the file and print the report")
    ap.add_argument("--report", metavar="CAPTURE", help="print the labeling report for a capture")
    ap.add_argument("--label-capture", metavar="CAPTURE", help="label one capture now (e.g. a normal-only recording "
                    "with no attack runs: everything in it becomes normal) and print the report")
    a = ap.parse_args()
    if not a.file and not a.report and not a.label_capture:
        ap.error("give an attack log file, --report CAPTURE, or --label-capture CAPTURE")

    try:
        with connect() as conn:
            if a.file:
                runs = check_attack_log(conn, a.file, a.capture)
                if a.check:
                    print(f"{a.file}: {len(runs)} attack runs, no problems found. Nothing was saved (--check).")
                    return 0
                result = save_runs(conn, runs)
                print(f"{a.file}:\n{result}")
                if a.label:
                    for cid in result.captures:
                        label_capture(conn, cid)
                        print(f"\nlabeled {label_report(conn, cid)}")
                elif result.inserted or result.updated:
                    print(f"run again with --label (or CALL label_capture(...)) so the labels follow the changes")
            if a.label_capture:
                if not conn.execute("SELECT 1 FROM captures WHERE capture_id = %s", (a.label_capture,)).fetchone():
                    raise AttackLogError(f"capture {a.label_capture!r} does not exist")
                label_capture(conn, a.label_capture)
                print(f"labeled {label_report(conn, a.label_capture)}")
            if a.report:
                print(label_report(conn, a.report))
    except AttackLogError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    except psycopg.OperationalError as exc:
        print(f"ERROR: can't reach the database at {db_url()}. Is Docker running?\n{exc}", file=sys.stderr)
        return 1
    except FileNotFoundError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
