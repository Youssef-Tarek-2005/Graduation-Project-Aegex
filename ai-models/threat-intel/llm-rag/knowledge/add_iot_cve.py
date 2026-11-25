"""
Add IoT-relevant CVEs to the knowledge base.

The CISA KEV set is the vulnerabilities proven to be exploited in the wild, but
it is small and not IoT-specific. The full NVD is 300,000+ CVEs — mostly noise
for an IoT honeypot, and ten-plus hours to embed locally. This takes the useful
middle: the CVEs whose descriptions mention IoT technology.

It searches NVD by keyword — MQTT, router, IP camera, firmware, embedded — with
pagination (up to 2000 per request), so it is a handful of requests, not one
call per CVE. CVEs already in the index (from KEV) are skipped.

No source code is patched: the project already has an "nvd_cve" source type and
already recognises CVE-… citations. This only adds documents.

    python add_iot_cve.py --dry-run            # show the plan, hit nothing
    python add_iot_cve.py --fetch              # download to a local cache
    python add_iot_cve.py --build-index        # embed the cache into the index

Needs the same NVD setup as enable_nvd.py: run enable_nvd.py first, get a free
key, and put NVD_API_KEY in the project's .env (the key is read from there).
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
CACHE = HERE / "iot_cve_cache.json"

RAG_DIR = Path(os.environ.get(
    "RAG_DIR",
    str(Path(__file__).resolve().parents[2] / "threat-intelligence-assistant")))

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CVE_URL = "https://nvd.nist.gov/vuln/detail/{}"
PAGE = 2000  # NVD maximum per request

# Each term is one NVD keyword search. Kept specific on purpose: broad words
# ("device", "network") would drag in most of NVD and defeat the point.
KEYWORDS = [
    "MQTT", "CoAP", "Modbus", "Zigbee", "BACnet",
    "IP camera", "router firmware", "smart home",
    "embedded device", "IoT device", "firmware update",
    "SCADA", "industrial control",
]


# --------------------------------------------------------------------------
def api_key() -> str:
    """Read NVD_API_KEY from the RAG project's .env, if present."""
    env = RAG_DIR / ".env"
    if env.exists():
        for line in env.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line.startswith("NVD_API_KEY=") and not line.startswith("#"):
                return line.split("=", 1)[1].strip()
    return os.environ.get("NVD_API_KEY", "")


def fetch() -> dict:
    """Search NVD for every keyword, page through, merge, cache by CVE id."""
    import requests

    key = api_key()
    sleep = 0.6 if key else 6.0
    print(f"     API key: {'yes' if key else 'no — pacing at 6 s/request'}")

    session = requests.Session()
    session.headers.update({"User-Agent": "Threat-Intel-Rag/1.0"})
    if key:
        session.headers.update({"apiKey": key})

    merged: dict[str, dict] = {}
    if CACHE.exists():
        merged = json.loads(CACHE.read_text(encoding="utf-8"))
        print(f"     resuming — {len(merged)} CVE(s) already cached")

    for term in KEYWORDS:
        start, total = 0, None
        got = 0
        while total is None or start < total:
            params = {"keywordSearch": term, "resultsPerPage": PAGE,
                      "startIndex": start}
            try:
                r = session.get(NVD_API, params=params, timeout=40)
                r.raise_for_status()
            except requests.RequestException as exc:
                print(f"     ! '{term}' failed at index {start}: {exc}")
                break
            body = r.json()
            total = body.get("totalResults", 0)
            for v in body.get("vulnerabilities", []):
                cve = v.get("cve", {})
                cid = cve.get("id")
                if cid and cid not in merged:
                    merged[cid] = cve
                    got += 1
            start += PAGE
            time.sleep(sleep)
        print(f"     {term:22} {total or 0:>6} match(es), {got} new")
        CACHE.write_text(json.dumps(merged, indent=2), encoding="utf-8")

    print(f"\n     cache now holds {len(merged)} unique CVE(s)")
    return merged


# --------------------------------------------------------------------------
def to_document(cid: str, cve: dict) -> dict:
    """Turn one NVD CVE record into a chunk for the vector store."""
    desc = next((d.get("value", "") for d in cve.get("descriptions", [])
                 if d.get("lang") == "en"), "")
    cvss = ""
    metrics = cve.get("metrics", {})
    for k in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        items = metrics.get(k, [])
        if items:
            d = items[0].get("cvssData", {})
            cvss = f"{d.get('baseScore', 'N/A')} ({d.get('baseSeverity', 'UNKNOWN')})"
            break
    content = (f"{cid}: {desc}"
               + (f"\n\nCVSS base score: {cvss}." if cvss else ""))
    return {
        "text": content,
        "id": f"nvd_cve:{cid}",
        "metadata": {
            "source_id": cid,
            "source_type": "nvd_cve",
            "title": cid,
            "url": CVE_URL.format(cid),
            "retrieved_at": datetime.now(timezone.utc).isoformat(),
            "tactics": [],
            "platforms": ["IoT"],
            "extra": {"origin": "iot_keyword_search", "cvss": cvss},
        },
    }


# --------------------------------------------------------------------------
def build_index(cache: dict) -> None:
    sys.path.insert(0, str(RAG_DIR))
    os.chdir(RAG_DIR)
    from config.settings import get_settings
    from src.embeddings.factory import get_embeddings
    from langchain_community.vectorstores import FAISS

    settings = get_settings()
    emb = get_embeddings(settings)
    index_dir = Path(settings.indices_dir)
    vs = FAISS.load_local(str(index_dir), emb,
                          allow_dangerous_deserialization=True)

    present = {d.metadata.get("source_id") for d in vs.docstore._dict.values()}
    before = len(vs.docstore._dict)
    print(f"     index holds {before:,} chunks  "
          f"(embeddings: {settings.embedding_model})")

    # skip CVEs already indexed (KEV enrichment may have added some)
    new = [to_document(cid, cve) for cid, cve in cache.items()
           if cid not in present]
    skipped = len(cache) - len(new)
    if skipped:
        print(f"     {skipped} already in the index (from KEV) — skipped")
    if not new:
        print("     nothing new to add."); return

    print(f"     embedding {len(new)} IoT CVE(s) one at a time — slower, but "
          f"it dodges Ollama's large-batch /tokenize bug ...")

    # Why one at a time: Ollama's batch embed path makes the client call an
    # internal /tokenize endpoint on a model-runner port that is unreachable
    # on this host, so a 2,900-text add_texts() dies instantly. A single-text
    # embed goes straight to the main server and works. embed_query is a batch
    # of one, so the vectors are identical to the rest of the index. We flush
    # to disk every FLUSH docs, so a crash resumes from the cache.
    FLUSH = 200
    pairs, metas, ids = [], [], []
    done = 0

    def flush():
        if not pairs:
            return
        vs.add_embeddings(text_embeddings=pairs, metadatas=metas, ids=ids)
        vs.save_local(str(index_dir))
        pairs.clear(); metas.clear(); ids.clear()

    for d in new:
        try:
            vec = emb.embed_query(d["text"])
        except Exception as exc:
            print(f"     ! skipped {d['metadata']['source_id']}: {str(exc)[:70]}")
            continue
        pairs.append((d["text"], vec))
        metas.append(d["metadata"])
        ids.append(d["id"])
        done += 1
        if done % 50 == 0:
            print(f"     embedded {done}/{len(new)} ...")
        if len(pairs) >= FLUSH:
            flush()
    flush()
    print(f"     {before:,} -> {len(vs.docstore._dict):,} chunks")

    manifest = index_dir / "manifest.json"
    if manifest.exists():
        m = json.loads(manifest.read_text(encoding="utf-8"))
        m["chunk_count"] = len(vs.docstore._dict)
        m.setdefault("added_sources", [])
        if "nvd_cve_iot" not in m["added_sources"]:
            m["added_sources"].append("nvd_cve_iot")
        m["last_modified"] = datetime.now(timezone.utc).isoformat()
        manifest.write_text(json.dumps(m, indent=2), encoding="utf-8")


# --------------------------------------------------------------------------
def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--dry-run", action="store_true",
                   help="show the keyword plan, touch nothing")
    p.add_argument("--fetch", action="store_true",
                   help="download IoT CVEs to the local cache")
    p.add_argument("--build-index", action="store_true",
                   help="embed the cached CVEs into the index")
    a = p.parse_args()

    print(f"RAG project: {RAG_DIR}\n")

    if a.dry_run or not (a.fetch or a.build_index):
        print("plan:")
        print(f"  search NVD for {len(KEYWORDS)} IoT keywords:")
        print("   ", ", ".join(KEYWORDS))
        print(f"  key in .env : {'yes' if api_key() else 'no (slower)'}")
        print(f"  cache file  : {CACHE}")
        print("\n  then:  python add_iot_cve.py --fetch")
        print("  then:  python add_iot_cve.py --build-index")
        if a.dry_run:
            return
        if not CACHE.exists():
            return

    if a.fetch:
        print("fetching ...")
        fetch()
        print("\ndone fetching. Next:  python add_iot_cve.py --build-index")
        return

    if a.build_index:
        if not CACHE.exists():
            raise SystemExit("no cache yet — run --fetch first")
        cache = json.loads(CACHE.read_text(encoding="utf-8"))
        print(f"building index from {len(cache)} cached CVE(s) ...")
        build_index(cache)
        print('\ndone. Check it:  python ask.py '
              '"What IoT CVEs affect MQTT brokers?"')


if __name__ == "__main__":
    main()
