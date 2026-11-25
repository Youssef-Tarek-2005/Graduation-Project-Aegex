"""
Make the NVD enrichment usable.

The loader is already in the project and already wired into the ingest script,
but it sends no API key and sleeps 0.6 s between requests. NVD allows
5 requests per 30 seconds without a key — one per six seconds — so at 0.6 s
almost every call comes back 403 or 429. Those are caught, logged as
warnings, and the loop continues, so the run *looks* fine and quietly brings
back a handful of CVEs instead of hundreds.

0.6 s is the correct pace *with* a key (50 requests per 30 seconds), which is
what the loader was written for. So this adds the missing key.

    1  config/settings.py          += nvd_api_key, nvd_sleep_seconds
    2  src/loaders/nvd_cve.py      sends the key header
    3  src/ingestion/normalize.py  passes both through

Get a free key (email only, arrives in minutes):
    https://nvd.nist.gov/developers/request-an-api-key

Then in the project's .env:
    NVD_API_KEY=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx

Safe to run twice. Run:
    python enable_nvd.py --dry-run
    python enable_nvd.py
"""
from __future__ import annotations

import argparse
import os
import shutil
from pathlib import Path

RAG_DIR = Path(os.environ.get(
    "RAG_DIR",
    str(Path(__file__).resolve().parents[2] / "threat-intelligence-assistant")))

# ---- 1. settings: the key and a pace that is safe without one --------------
SET_OLD = "    nvd_enrich_limit: int = Field(default=100, ge=0, le=2000)"
SET_NEW = """    nvd_enrich_limit: int = Field(default=100, ge=0, le=2000)
    # NVD allows 5 requests / 30 s anonymously and 50 / 30 s with a key.
    # Without a key the safe pace is one request every 6 seconds.
    nvd_api_key: str = ""
    nvd_sleep_seconds: float = Field(default=6.0, ge=0.0, le=30.0)"""

# ---- 2. the loader: send the key, take the pace as an argument -------------
LOAD_OLD = """    session = requests.Session()
    session.headers.update({"User-Agent": "Threat-Intel-Rag/1.0"})"""
LOAD_NEW = """    session = requests.Session()
    session.headers.update({"User-Agent": "Threat-Intel-Rag/1.0"})
    if api_key:
        # NVD reads the key from this header; with it the quota is 50/30s.
        session.headers.update({"apiKey": api_key})"""

SIG_OLD = """    limit: int | None = None,
    sleep_seconds: float = 0.6,
) -> list[ThreatDocument]:"""
SIG_NEW = """    limit: int | None = None,
    sleep_seconds: float = 6.0,
    api_key: str = "",
) -> list[ThreatDocument]:"""

# the warning-only except is what hides a throttled run; count the failures
FAIL_OLD = """        except requests.RequestException as exc:
            logger.warning("NVD fetch failed for %s: %s", cve_id, exc)"""
FAIL_NEW = """        except requests.RequestException as exc:
            failures += 1
            logger.warning("NVD fetch failed for %s: %s", cve_id, exc)"""

INIT_OLD = """    cache = _load_cache(cache_path)
    documents: list[ThreatDocument] = []"""
INIT_NEW = """    cache = _load_cache(cache_path)
    failures = 0
    documents: list[ThreatDocument] = []"""

REPORT_OLD = """    logger.info("NVD loader: %d documents (%d cached)", len(documents), len(cache))
    return documents"""
REPORT_NEW = """    logger.info("NVD loader: %d documents (%d cached)", len(documents), len(cache))
    if failures:
        # Loud, because a throttled run otherwise looks like a successful one.
        print(f"  !! {failures} of {len(to_fetch)} NVD fetches failed. "
              f"{'Slow nvd_sleep_seconds down' if not api_key else 'Check the key'}"
              f" — without an API key NVD allows one request every 6 seconds.")
    return documents"""

# ---- 3. normalize: pass both through ---------------------------------------
NORM_OLD = """            cve_ids,
            settings.nvd_cache_path,
            limit=settings.nvd_enrich_limit,
        )"""
NORM_NEW = """            cve_ids,
            settings.nvd_cache_path,
            limit=settings.nvd_enrich_limit,
            sleep_seconds=settings.nvd_sleep_seconds,
            api_key=settings.nvd_api_key,
        )"""

EDITS = [
    ("config/settings.py",          [(SET_OLD, SET_NEW)],                 "settings"),
    ("src/loaders/nvd_cve.py",      [(SIG_OLD, SIG_NEW), (LOAD_OLD, LOAD_NEW),
                                     (INIT_OLD, INIT_NEW), (FAIL_OLD, FAIL_NEW),
                                     (REPORT_OLD, REPORT_NEW)],           "nvd loader"),
    ("src/ingestion/normalize.py",  [(NORM_OLD, NORM_NEW)],               "normalize"),
]


def apply(rel: str, pairs: list[tuple[str, str]], label: str, dry: bool) -> str:
    path = RAG_DIR / rel
    if not path.exists():
        raise SystemExit(f"not found: {path}")
    text = original = path.read_text(encoding="utf-8")

    done = sum(1 for _, new in pairs if new in text)
    if done == len(pairs):
        return f"  {label:12} already patched"

    for old, new in pairs:
        if new in text:
            continue
        if old not in text:
            raise SystemExit(
                f"  {label}: could not find a block to replace in {rel}.\n"
                f"       Upstream has changed; patch it by hand.")
        text = text.replace(old, new, 1)

    if dry:
        return f"  {label:12} would patch ({len(pairs)} edit(s))"
    shutil.copy2(path, path.with_suffix(path.suffix + ".bak"))
    path.write_text(text, encoding="utf-8")
    return f"  {label:12} patched ({len(pairs)} edit(s), backup: {path.name}.bak)"


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--dry-run", action="store_true")
    a = p.parse_args()

    print(f"RAG project: {RAG_DIR}\n")
    for rel, pairs, label in EDITS:
        print(apply(rel, pairs, label, a.dry_run))

    if a.dry_run:
        print("\n--dry-run: nothing written.")
        return

    print("""
Next:
  1  get a free key (email only)   https://nvd.nist.gov/developers/request-an-api-key
  2  add it to the project's .env  NVD_API_KEY=...
     and speed the pace back up    NVD_SLEEP_SECONDS=0.6
  3  try ten first
     python scripts/ingest.py --validate-only --enrich-nvd --nvd-limit 10
  4  then the rest, in runs of 100 — the cache makes each run resume
     python scripts/ingest.py --build-index --enrich-nvd --nvd-limit 100

Without a key, leave NVD_SLEEP_SECONDS at 6.0: 100 CVEs then takes ten minutes.""")


if __name__ == "__main__":
    main()
