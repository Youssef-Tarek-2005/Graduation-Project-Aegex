"""Step 3 - the pipeline: raw files -> checked -> unified format -> labels -> features, in one command.

    cd backend
    .venv\\Scripts\\python -m ingest.pipeline run sessions\\sample-lab.json            # one recording session
    .venv\\Scripts\\python -m ingest.pipeline run sessions\\sample-lab.json --check    # check the inputs only
    .venv\\Scripts\\python -m ingest.pipeline run sessions\\datasets-small.json        # public datasets

A session file (JSON) says what was recorded; paths are relative to the session file:

    {"capture":    {"id": "cap-2026-11-20-a", "start": "2026-11-20T14:00:00Z", "end": "2026-11-20T15:00:00Z",
                    "kind": "mixed", "notes": "..."},
     "pcap":       "../samples/cap-2026-11-20-a.pcap",       (or "conn_log": a conn.log Zeek already wrote)
     "logs":       [{"source": "cowrie", "path": "../samples/cowrie.json", "device": "gw-01"}, ...],
     "attack_log": "../samples/attack_log.csv",               (optional: none = a normal-only capture)
     "features":   true,                                       (optional, default true)
     "detect":     {"normal": "../pcaps/poc-normal.pcap", "gat": false}}   (optional: run the AI models)

A datasets file: {"datasets": ["kitsune", "xiiotid"], "data": "C:\\\\aegex_data", "max_rows": 1000000}

The stages, in order. Each prints PASS / WARN / FAIL with its counts; the first FAIL stops the run, because
every later stage needs the earlier ones. A WARN (e.g. attacker traffic outside every attack run) goes on.

  session:   1 check      every file exists, times have a time zone, sources are known, the attack log is valid
                          (nothing is saved if anything is wrong, and every problem is listed at once)
             2 capture    the captures row (already there with the same values = fine)
             3 flows      pcap -> Zeek (Docker) -> conn.log -> flows          (step 2's unified record)
             4 logs       Cowrie / Mosquitto / ESP32 -> events
             5 labels     attack log -> attack_runs -> label_capture() -> label report
             6 features   41 numbers per flow, 24 per device per 10 s
             7 detect     LSTM-AE + VAE (+ GAT) on the pcap -> alerts         (only with "detect")
  datasets:  1 check      the original files are in the data folder (sizes)
             2 load       AI team's adapter -> flows rows in aegex_datasets   (datasets.to_unified)

Running the same session again is safe: every stage skips what is already saved. The run report is also saved
as JSON in backend/pipeline_runs/ (one file per run), so a run can be looked at later.
The session pipeline writes to the database in AEGEX_DB_URL; datasets always go to aegex_datasets.
"""
from __future__ import annotations

import argparse
import json
import sys
import tempfile
import time
import traceback
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path

import psycopg

from .db import connect

RUNS_DIR = Path(__file__).resolve().parents[1] / "pipeline_runs"
SOURCES = ("cowrie", "mosquitto", "esp32")


class SessionError(Exception):
    """The session file itself is wrong (problems listed in .problems)."""

    def __init__(self, problems: list[str]):
        super().__init__("; ".join(problems))
        self.problems = problems


# --------------------------------------------------------------------------- results
@dataclass
class Stage:
    name: str
    status: str = "PASS"                   # PASS | WARN | FAIL | SKIP
    counts: dict = field(default_factory=dict)
    lines: list[str] = field(default_factory=list)
    seconds: float = 0.0

    def warn(self, text: str) -> None:
        self.lines.append(f"WARNING: {text}")
        if self.status == "PASS":
            self.status = "WARN"

    def fail(self, text: str) -> None:
        self.lines.append(text)
        self.status = "FAIL"


@dataclass
class RunReport:
    session: str
    kind: str                              # session | datasets
    started: str
    stages: list[Stage] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return all(s.status in ("PASS", "WARN", "SKIP") for s in self.stages)

    def to_dict(self) -> dict:
        return {"session": self.session, "kind": self.kind, "started": self.started, "ok": self.ok,
                "stages": [asdict(s) for s in self.stages]}


def run_stages(report: RunReport, stages: list[tuple[str, callable]], log=print) -> RunReport:
    """Run the stages in order; stop at the first FAIL (a crash counts as FAIL, with its message)."""
    for name, fn in stages:
        st = Stage(name)
        t = time.time()
        log(f"\n[{len(report.stages) + 1}/{len(stages)}] {name}")
        try:
            fn(st)
        except Exception as exc:
            st.fail(f"crashed: {type(exc).__name__}: {exc}")
            traceback.print_exc(limit=2)
        st.seconds = round(time.time() - t, 1)
        for line in st.lines:
            log(f"    {line}")
        log(f"  -> {st.status}  {json.dumps(st.counts)}  ({st.seconds} s)")
        report.stages.append(st)
        if st.status == "FAIL":
            log(f"\nSTOPPED: stage '{name}' failed; the later stages need it.")
            break
    return report


# --------------------------------------------------------------------------- session file
def read_session(path: Path) -> dict:
    """Load a session file and resolve its paths (relative to the file). Raises SessionError."""
    try:
        s = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SessionError([f"cannot read {path}: {exc}"]) from None
    base = path.resolve().parent
    fix = lambda p: str((base / p).resolve()) if p else p
    for key in ("pcap", "conn_log", "attack_log"):
        if s.get(key):
            s[key] = fix(s[key])
    for log in s.get("logs", []):
        if isinstance(log, dict) and log.get("path"):
            log["path"] = fix(log["path"])
    if isinstance(s.get("detect"), dict) and s["detect"].get("normal"):
        s["detect"]["normal"] = fix(s["detect"]["normal"])
    return s


def session_problems(s: dict) -> list[str]:
    """Everything wrong with a session file, all at once (empty = fine). Reads files, saves nothing."""
    from .attacks import AttackLogError, parse_attack_log
    from .captures import CaptureError, KINDS, parse_utc

    p: list[str] = []
    cap = s.get("capture") or {}
    if not cap.get("id"):
        p.append("capture.id is missing")
    if not cap.get("start"):
        p.append("capture.start is missing")
    else:
        try:
            start = parse_utc(cap["start"], "capture.start")
            end = parse_utc(cap["end"], "capture.end") if cap.get("end") else None
            if end is not None and end <= start:
                p.append("capture.end is not after capture.start")
        except (CaptureError, ValueError) as exc:
            p.append(str(exc))
    if cap.get("kind", "mixed") not in KINDS:
        p.append(f"capture.kind {cap.get('kind')!r} is not one of {', '.join(KINDS)}")
    if s.get("pcap") and s.get("conn_log"):
        p.append("give pcap OR conn_log, not both")
    for key in ("pcap", "conn_log", "attack_log"):
        if s.get(key) and not Path(s[key]).is_file():
            p.append(f"{key}: file not found: {s[key]}")
    for i, log in enumerate(s.get("logs", [])):
        where = f"logs[{i}]"
        if not isinstance(log, dict):
            p.append(f"{where} must be an object")
            continue
        if log.get("source") not in SOURCES:
            p.append(f"{where}.source {log.get('source')!r} is not one of {', '.join(SOURCES)}")
        if not log.get("path") or not Path(log["path"]).is_file():
            p.append(f"{where}: file not found: {log.get('path')}")
    if s.get("attack_log") and Path(s["attack_log"]).is_file():
        try:
            parse_attack_log(s["attack_log"], cap.get("id"))
        except AttackLogError as exc:
            p += [f"attack_log: {x}" for x in getattr(exc, "problems", [str(exc)])]
    det = s.get("detect")
    if det:
        if not s.get("pcap"):
            p.append("detect needs a pcap (the AI models read the recording itself)")
        if not isinstance(det, dict) or not det.get("normal") or not Path(det["normal"]).is_file():
            p.append("detect.normal: a recording of normal traffic on the same network is needed (file not found)")
    if not (s.get("pcap") or s.get("conn_log") or s.get("logs")):
        p.append("nothing to load: give a pcap, a conn_log or logs")
    return p


# --------------------------------------------------------------------------- session stages
def session_stages(conn: psycopg.Connection, s: dict, check_only: bool = False) -> list[tuple[str, callable]]:
    cap_id = (s.get("capture") or {}).get("id")

    def check(st: Stage) -> None:
        problems = session_problems(s)
        st.counts = {"files": sum(bool(s.get(k)) for k in ("pcap", "conn_log", "attack_log")) + len(s.get("logs", []))}
        for x in problems:
            st.fail(x)
        if not problems:
            st.lines.append("session file OK: every file found, times have a time zone, attack log valid")

    def capture(st: Stage) -> None:
        from .captures import add_capture, parse_utc
        c = s["capture"]
        new = add_capture(conn, cap_id, parse_utc(c["start"]), parse_utc(c["end"]) if c.get("end") else None,
                          c.get("kind", "mixed"), s.get("pcap"), c.get("notes"))
        st.counts = {"new": int(new)}
        st.lines.append(f"capture {cap_id}: {'added' if new else 'already saved with the same values'}")

    def flows(st: Stage) -> None:
        from .flows import load_conn_log
        if not (s.get("pcap") or s.get("conn_log")):
            st.status = "SKIP"
            st.lines.append("no pcap or conn_log in this session")
            return
        with tempfile.TemporaryDirectory() as tmp:
            if s.get("pcap"):
                from .zeek import run_zeek
                conn_log = run_zeek(s["pcap"], tmp)
                st.lines.append(f"Zeek read {Path(s['pcap']).name}")
            else:
                conn_log = Path(s["conn_log"])
            r = load_conn_log(conn, conn_log, cap_id)
        st.counts = {"lines": r.parse.lines, "flows": r.parse.events, "saved": r.inserted,
                     "already_saved": r.duplicates, "broken_lines": r.parse.skipped, "touch_device": r.with_device}
        if r.parse.skipped:
            st.warn(f"{r.parse.skipped} broken conn.log lines were skipped")

    def logs(st: Stage) -> None:
        from .loader import load_file
        from .parsers import build_parser
        if not s.get("logs"):
            st.status = "SKIP"
            st.lines.append("no logs in this session")
            return
        tot = {"lines": 0, "events": 0, "saved": 0, "already_saved": 0, "broken_lines": 0}
        for log in s["logs"]:
            opts = {k: log[k] for k in ("broker_ip", "device_ip", "tz") if log.get(k)}
            r = load_file(conn, build_parser(log["source"], log.get("device"), **opts), log["path"], cap_id)
            st.lines.append(f"{log['source']:<9} {Path(log['path']).name}: {r.parse}; saved {r.inserted}")
            for k, v in (("lines", r.parse.lines), ("events", r.parse.events), ("saved", r.inserted),
                         ("already_saved", r.duplicates), ("broken_lines", r.parse.skipped)):
                tot[k] += v
        st.counts = tot
        if tot["broken_lines"]:
            st.warn(f"{tot['broken_lines']} broken log lines were skipped")

    def labels(st: Stage) -> None:
        from .attacks import label_report, load_attack_log
        from .loader import label_capture
        if s.get("attack_log"):
            r = load_attack_log(conn, s["attack_log"], cap_id)
            st.lines.append(str(r).splitlines()[0])
            st.counts["attack_runs"] = r.runs
        else:
            st.lines.append("no attack log: a normal-only capture, everything is labelled normal")
        label_capture(conn, cap_id)
        rep = label_report(conn, cap_id)
        st.counts.update(attack_flows=rep.flows.get(1, 0), normal_flows=rep.flows.get(0, 0),
                         attack_events=rep.events.get(1, 0), normal_events=rep.events.get(0, 0))
        for w in rep.warnings:
            st.warn(w)

    def features(st: Stage) -> None:
        if s.get("features") is False:
            st.status = "SKIP"
            st.lines.append('"features": false in the session file')
            return
        from features.build import build_flow_features, build_window_features
        f = build_flow_features(conn, cap_id)
        w = build_window_features(conn, cap_id)
        st.counts = {"flow_features": f.computed, "flow_features_already": f.already_done, "windows": w.windows,
                     "active_windows": w.active, "attack_windows": w.attack}
        st.lines += [str(f), str(w).splitlines()[0]]

    def detect(st: Stage) -> None:
        det = s.get("detect")
        if not det:
            st.status = "SKIP"
            st.lines.append("no \"detect\" in the session file")
            return
        import detect as d
        results = d.run_models(Path(s["pcap"]), Path(det["normal"]), cap_id, gat=bool(det.get("gat")))
        st.counts = {"alerts": d.save_alerts(results, cap_id)}
        if det.get("gat"):
            st.counts["gat_incidents"] = d.save_gat_alerts(results, cap_id)

    stages = [("check inputs", check)]
    if not check_only:
        stages += [("capture", capture), ("flows (pcap -> Zeek -> flows)", flows), ("logs -> events", logs),
                   ("attack log + labels", labels), ("features", features), ("detect (AI models)", detect)]
    return stages


# --------------------------------------------------------------------------- dataset stages
def dataset_stages(s: dict, check_only: bool = False) -> list[tuple[str, callable]]:
    from datasets import analyze, to_unified
    data = Path(s.get("data") or analyze.DEFAULT_DATA)
    names = s.get("datasets") or []
    cat = {d["id"]: d for d in analyze.load_catalogue()["datasets"]}

    def check(st: Stage) -> None:
        unknown = [n for n in names if n not in cat]
        if not names or unknown:
            st.fail(f"unknown datasets {unknown} (catalogue: {', '.join(cat)})" if unknown else "no datasets listed")
            return
        if not data.is_dir():
            st.fail(f"data folder {data} does not exist")
            return
        have = 0
        for n in names:
            files = [analyze.check_file(data, f, quick=True) for f in analyze.used_files(cat[n])]
            ok = [f for f in files if f["status"] in ("present", "unpacked", "verified")]
            bad = [f for f in files if f["status"] == "size mismatch"]
            have += len(ok)
            st.lines.append(f"{n}: {len(ok)} / {len(files)} files in {data}")
            if not ok:
                st.warn(f"{n}: no files yet, it will be skipped (download list: datasets/report/datasets_report.md)")
            for f in bad:
                st.fail(f"{n}: {f['file']} has the wrong size (broken download?)")
        st.counts = {"datasets": len(names), "files_here": have}
        if not have and st.status != "FAIL":
            st.fail("none of the listed datasets' files are in the data folder")

    def load(st: Stage) -> None:
        url = to_unified.setup()
        reg = analyze.load_adapters(data)
        total = {"captures": 0, "flows": 0, "attacks": 0, "dropped": 0}
        with connect(url) as dconn:
            for n in names:
                for cap, r in to_unified.load_dataset(dconn, reg, n, int(s.get("max_rows") or to_unified.DEFAULT_MAX_ROWS),
                                                      log=st.lines.append).items():
                    total["captures"] += 1
                    total["flows"] += r["loaded"]
                    total["attacks"] += r["attacks"]
                    total["dropped"] += r["bad_ip"] + r["bad_time"] + r["duplicate"]
        st.counts = total
        if not total["captures"]:
            st.fail("no capture could be loaded")

    return [("check dataset files", check)] + ([] if check_only else [("load into aegex_datasets", load)])


# --------------------------------------------------------------------------- main
def run(path: Path, check_only: bool = False, save: bool = True, conn: psycopg.Connection | None = None,
        log=print) -> RunReport:
    s = read_session(path)
    kind = "datasets" if "datasets" in s else "session"
    report = RunReport(str(path), kind, datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"))
    if kind == "datasets":
        run_stages(report, dataset_stages(s, check_only), log)
    else:
        own = conn is None
        conn = conn or connect()
        try:
            run_stages(report, session_stages(conn, s, check_only), log)
        finally:
            if own:
                conn.close()
    if save and not check_only:
        RUNS_DIR.mkdir(exist_ok=True)
        name = (s.get("capture") or {}).get("id") or "datasets"
        out = RUNS_DIR / f"{name}_{datetime.now(timezone.utc):%Y%m%d-%H%M%S}.json"
        out.write_text(json.dumps(report.to_dict(), indent=1, default=str), encoding="utf-8")
        log(f"\nrun report: {out}")
    return report


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Step 3 pipeline: one recording session (or datasets) end to end.")
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run", help="run every stage of a session file")
    r.add_argument("session", type=Path)
    r.add_argument("--check", action="store_true", help="only check the inputs; save nothing")
    a = ap.parse_args(argv)
    try:
        report = run(a.session, a.check)
    except SessionError as exc:
        print("ERROR: " + "\n       ".join(exc.problems))
        return 2
    except psycopg.OperationalError as exc:
        print(f"ERROR: the database server is not reachable ({exc.__class__.__name__}). Start Docker first.")
        return 1
    print("\nRESULT: " + ("OK" if report.ok else "FAILED") + " - " +
          ", ".join(f"{s.name.split(' ')[0]} {s.status}" for s in report.stages))
    return 0 if report.ok else 1


if __name__ == "__main__":
    sys.exit(main())
