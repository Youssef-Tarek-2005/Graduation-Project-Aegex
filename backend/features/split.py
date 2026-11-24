"""Train / validation / test split, by WHOLE captures, in time order (contract -> splits).

Why not just shuffle the rows and take 70 / 15 / 15?
  Window 14:10:00 and window 14:10:10 of the same attack are almost identical. With a random split, one lands in
  train and its twin in test, the model "recognises" the test rows it has nearly seen, and the score is fake.
  The PoC reported 100% that way. Splitting whole captures means test data is from sessions the model never saw.

Why in time order?
  In real life the model is trained on the past and used on the future. Test = the last recorded captures.

The automatic proposal:
  captures sorted by start time; a capture goes to train if its middle lies in the first 70% of all recorded time,
  to validation if in the next 15%, else to test. Then it's checked: the test split must contain every scenario.
  If the automatic proposal can't satisfy that, write splits.json by hand (same format) and pass it with --splits.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

import psycopg

from .window import FEATURE_VERSION

SPLITS = ("train", "val", "test")


@dataclass
class CaptureInfo:
    capture_id: str
    start: datetime
    end: datetime
    windows: int                    # windows of the current feature version
    attack_windows: int
    unlabeled_windows: int
    scenarios: set[str] = field(default_factory=set)

    @property
    def seconds(self) -> float:
        return (self.end - self.start).total_seconds()


def capture_infos(conn: psycopg.Connection) -> list[CaptureInfo]:
    """Every capture that has windows, oldest first, with what's in it."""
    rows = conn.execute("""
        SELECT c.capture_id, c.start_ts, COALESCE(c.end_ts, max(w.window_end)),
               count(*), count(*) FILTER (WHERE w.label = 1), count(*) FILTER (WHERE w.label IS NULL),
               COALESCE(array_agg(DISTINCT w.scenario) FILTER (WHERE w.scenario IS NOT NULL), '{}')
          FROM captures c JOIN feature_windows w ON w.capture_id = c.capture_id AND w.feature_version = %s
         GROUP BY c.capture_id, c.start_ts, c.end_ts
         ORDER BY c.start_ts""", (FEATURE_VERSION,)).fetchall()
    return [CaptureInfo(cid, start, end, n, n_attack, n_unlabeled, set(scen))
            for cid, start, end, n, n_attack, n_unlabeled, scen in rows]


def propose_split(captures: list[CaptureInfo], train: float = 0.70, val: float = 0.15,
                  zero_day: str | None = None) -> dict[str, list[str]]:
    """Captures (labeled ones only) -> {"train": [...], "val": [...], "test": [...]} by the middle-of-capture rule.
    zero_day: every capture containing that scenario goes to test, so the model never sees it before testing."""
    usable = sorted((c for c in captures if c.unlabeled_windows == 0), key=lambda c: c.start)
    total = sum(c.seconds for c in usable) or 1.0
    split: dict[str, list[str]] = {s: [] for s in SPLITS}
    done = 0.0
    for c in usable:
        middle = (done + c.seconds / 2) / total
        done += c.seconds
        if zero_day and zero_day in c.scenarios:
            split["test"].append(c.capture_id)
        elif middle < train:
            split["train"].append(c.capture_id)
        elif middle < train + val:
            split["val"].append(c.capture_id)
        else:
            split["test"].append(c.capture_id)
    return split


@dataclass
class SplitCheck:
    problems: list[str] = field(default_factory=list)       # the dataset is not exported
    warnings: list[str] = field(default_factory=list)       # exported, but read these

    @property
    def ok(self) -> bool:
        return not self.problems


def check_split(split: dict[str, list[str]], captures: list[CaptureInfo], zero_day: str | None = None) -> SplitCheck:
    info = {c.capture_id: c for c in captures}
    check = SplitCheck()
    seen: dict[str, str] = {}
    for name in SPLITS:
        for cid in split.get(name, []):
            if cid not in info:
                check.problems.append(f"{name}: capture {cid!r} has no windows (unknown capture, or step 8 not run for it)")
            elif cid in seen:
                check.problems.append(f"capture {cid} is in both {seen[cid]} and {name}. A capture belongs to one split only.")
            elif info[cid].unlabeled_windows:
                check.problems.append(f"{name}: capture {cid} isn't fully labeled ({info[cid].unlabeled_windows} windows "
                                      f"without a label). Label it (step 6) and rebuild its windows (step 8).")
            seen.setdefault(cid, name)
    for name in SPLITS:
        if not split.get(name):
            check.problems.append(f"the {name} split is empty. Record more captures, or assign them by hand with --splits.")
    if check.problems:
        return check

    def scenarios(name: str) -> set[str]:
        return set().union(*(info[c].scenarios for c in split[name]))

    every = set().union(*(c.scenarios for c in captures if c.capture_id in seen))
    missing = every - scenarios("test")
    if missing:
        check.problems.append(f"the test split ({', '.join(split['test'])}) has no {', '.join(sorted(missing))}. The "
                              f"contract wants every scenario in test. Record a last capture with every scenario, "
                              f"or assign captures by hand with --splits.")
    if zero_day:
        leaked = [c for c in split["train"] + split["val"] if zero_day in info[c].scenarios]
        if leaked:
            check.problems.append(f"zero-day scenario {zero_day} appears in train/val captures {', '.join(leaked)}")
        if zero_day not in every:
            check.problems.append(f"zero-day scenario {zero_day} is in no capture")
    if not any(info[c].windows - info[c].attack_windows for c in split["train"]):
        check.problems.append("train has no normal windows: the autoencoders (Task C) have nothing to learn from")

    if not any(info[c].attack_windows for c in split["val"]):
        check.warnings.append("validation has no attack windows, so thresholds can't be checked against attacks")
    if not any(info[c].attack_windows for c in split["train"]):
        check.warnings.append("train has no attack windows: fine for C's autoencoders, but D's supervised model needs some")
    last_train = max(info[c].start for c in split["train"])
    if any(info[c].start < last_train for c in split["val"] + split["test"]):
        check.warnings.append("not in time order: a val/test capture is older than a train capture (OK if on purpose)")
    unused = [c.capture_id for c in captures if c.capture_id not in seen]
    if unused:
        check.warnings.append(f"not in any split (unlabeled, e.g. live): {', '.join(unused)}")
    return check


def read_splits(path: str | Path) -> dict[str, list[str]]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    return {s: list(data.get(s, [])) for s in SPLITS}


def describe(split: dict[str, list[str]], captures: list[CaptureInfo]) -> str:
    info = {c.capture_id: c for c in captures}
    lines = [f"{'split':<6} {'captures':<9} {'windows':>8} {'attack':>7}  scenarios"]
    for name in SPLITS:
        cs = [info[c] for c in split[name] if c in info]
        lines.append(f"{name:<6} {len(cs):<9} {sum(c.windows for c in cs):>8} {sum(c.attack_windows for c in cs):>7}  "
                     f"{', '.join(sorted(set().union(*(c.scenarios for c in cs)))) or '-'}")
        lines += [f"         {c.capture_id}" for c in cs]
    return "\n".join(lines)
