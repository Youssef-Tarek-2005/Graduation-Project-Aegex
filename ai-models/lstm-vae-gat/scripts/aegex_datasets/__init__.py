"""
Aegex dataset plug-ins - the ONLY place that knows about individual datasets.

Every dataset is one module (``<name>.py``) or one folder (``<name>/__init__.py``) in this package.
The pipeline finds them automatically:

    add a dataset      copy _template.py to <name>.py, fill it in       (nothing else to edit)
    remove a dataset   delete its file / folder                         (nothing else to edit)
    switch it off      ACTIVE = False  (still usable with --datasets <name>)

Steps 1-5, the models, the benchmark and the results summary all read their per-dataset settings
from here:

    module attribute    used by                         meaning
    NAME                everything                      short id; folder names under preprocessed/
    TITLE, SOURCE       docs, results                   human name, where to download it
    ORDER               everything                      position in ALL / ACTIVE lists (lower first)
    ACTIVE              steps 1-5, train_*.py, bench    True = in the default run
    ORIGINALS           step 1 / step 4                 original files, checked against ORIGINALS_SHA256.txt
    captures()          step 1                          capture names, in the order they are processed
    build(capture)      step 1                          -> (flows DataFrame in aegex_prep.FLOW_COLUMNS, stats)
    run(report, log)    step 1 (optional)               streaming alternative to captures()/build()
    BENCH               aegex_bench.py                  realistic-benchmark case (bases, attacks, ...)
    QUOTED_RUN          export_results_summary.py       benchmark folder whose numbers are quoted
    BASELINE_NOTE       step5_baseline.py               one sentence printed with the baseline
    CROSS_CAPTURE       step5_baseline.py               captures for the leave-one-capture-out test

Modules whose name starts with "_" (e.g. _template.py) are ignored.
"""
import importlib
import os
import pkgutil
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_PREP = os.path.join(os.path.dirname(_HERE), "preprocessing")
if _PREP not in sys.path:                       # adapters use the shared library aegex_prep
    sys.path.insert(0, _PREP)

REQUIRED = ("NAME", "TITLE", "ORDER", "ORIGINALS")
_registry = None


def _load():
    global _registry
    if _registry is None:
        mods = {}
        for info in pkgutil.iter_modules([_HERE]):
            if info.name.startswith("_"):
                continue
            mod = importlib.import_module(f"{__name__}.{info.name}")
            missing = [a for a in REQUIRED if not hasattr(mod, a)]
            if missing:
                raise ImportError(f"aegex_datasets.{info.name} is missing {missing}")
            if not (hasattr(mod, "run") or (hasattr(mod, "captures") and hasattr(mod, "build"))):
                raise ImportError(f"aegex_datasets.{info.name} needs captures()+build() or run()")
            if mod.NAME in mods:
                raise ImportError(f"dataset name {mod.NAME!r} defined twice")
            mods[mod.NAME] = mod
        _registry = dict(sorted(mods.items(), key=lambda kv: (kv[1].ORDER, kv[0])))
    return _registry


def names():
    """Every installed dataset, in ORDER."""
    return list(_load())


def active():
    """Datasets in the default run (ACTIVE = True), in ORDER."""
    return [n for n, m in _load().items() if getattr(m, "ACTIVE", False)]


def get(name):
    try:
        return _load()[name]
    except KeyError:
        raise KeyError(f"unknown dataset {name!r}; installed: {names()}") from None


def bench_cases():
    """{dataset: benchmark case} for datasets that define BENCH."""
    return {n: m.BENCH for n, m in _load().items() if getattr(m, "BENCH", None)}


def quoted_runs():
    """{benchmark folder: {datasets quoted from it}} for the results summary."""
    out = {}
    for n, m in _load().items():
        if getattr(m, "QUOTED_RUN", None):
            out.setdefault(m.QUOTED_RUN, set()).add(n)
    return out


def baseline_notes():
    return {n: m.BASELINE_NOTE for n, m in _load().items() if getattr(m, "BASELINE_NOTE", "")}


def cross_capture():
    return {n: list(m.CROSS_CAPTURE) for n, m in _load().items() if getattr(m, "CROSS_CAPTURE", None)}


def originals(datasets):
    """Original file names of the given datasets (keys of ORIGINALS_SHA256.txt)."""
    return [f for d in datasets for f in get(d).ORIGINALS]


def describe():
    """One line per dataset - `python -I -m aegex_datasets` from the scripts folder prints it."""
    rows = []
    for n, m in _load().items():
        rows.append(f"{n:<10} {'active' if getattr(m, 'ACTIVE', False) else 'off':<7} {m.TITLE:<22} "
                    f"bench={'yes' if getattr(m, 'BENCH', None) else 'no':<3} quoted={getattr(m, 'QUOTED_RUN', None) or '-'}")
    return "\n".join(rows)
