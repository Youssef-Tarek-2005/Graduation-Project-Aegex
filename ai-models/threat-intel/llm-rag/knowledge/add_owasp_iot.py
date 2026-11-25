"""
Add the OWASP IoT Top 10 to the knowledge base.

This is not just a data load. The RAG project only knows five source types and
only recognises four shapes of citation ID, so dropping new documents in
without touching those two places gives the worst outcome: the documents are
retrieved, the model cites them, the citation checker does not recognise the
IDs, and confidence silently drops. The script therefore patches both before
embedding anything, and backs each file up first.

    1  src/models/document.py   SourceType      += "owasp_iot"
    2  src/rag/citations.py     CITATION_PATTERN += IOT-I<n>
    3  the ten documents are embedded and added to the FAISS index

Safe to run twice: existing OWASP entries are removed before the new ones go in.

Run:
    python add_owasp_iot.py --dry-run
    python add_owasp_iot.py
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
DATA = HERE / "owasp_iot_top10.json"
TAXONOMY = HERE / "attack_families.json"

RAG_DIR = Path(os.environ.get(
    "RAG_DIR",
    str(Path(__file__).resolve().parents[2] / "threat-intelligence-assistant")))

SOURCE_TYPE = "owasp_iot"

# ---- patch 1: the document model only allows five source types -------------
TYPE_OLD = '''    "cisa_kev",
    "nvd_cve",
]'''
TYPE_NEW = '''    "cisa_kev",
    "nvd_cve",
    "owasp_iot",
]'''

# ---- patch 2: the citation checker only knows four ID shapes ---------------
CITE_OLD = (
    r'    r"\[(T\d{4}(?:\.\d{3})?|G\d{4}|S\d{4}|CVE-\d{4}-\d{4,})\]"' "\n"
    r'    r"|(?<![A-Za-z0-9])(T\d{4}(?:\.\d{3})?|G\d{4}|S\d{4}|CVE-\d{4}-\d{4,})(?![A-Za-z0-9])",'
)
CITE_NEW = (
    r'    r"\[(T\d{4}(?:\.\d{3})?|G\d{4}|S\d{4}|CVE-\d{4}-\d{4,}|IOT-I\d{1,2})\]"' "\n"
    r'    r"|(?<![A-Za-z0-9])(T\d{4}(?:\.\d{3})?|G\d{4}|S\d{4}|CVE-\d{4}-\d{4,}|IOT-I\d{1,2})(?![A-Za-z0-9])",'
)


def patch(path: Path, old: str, new: str, label: str, dry: bool) -> str:
    """Apply one source edit, idempotently, keeping a .bak beside the file."""
    if not path.exists():
        raise SystemExit(f"not found: {path}")
    text = path.read_text(encoding="utf-8")
    if new in text:
        return f"  {label:22} already patched"
    if old not in text:
        raise SystemExit(
            f"  {label}: could not find the text to replace in {path}.\n"
            f"       The upstream project has changed. Patch it by hand:\n"
            f"       add {SOURCE_TYPE!r} / the IOT-I pattern, then re-run with "
            f"--skip-patch.")
    if dry:
        return f"  {label:22} would patch"
    shutil.copy2(path, path.with_suffix(path.suffix + ".bak"))
    path.write_text(text.replace(old, new), encoding="utf-8")
    return f"  {label:22} patched (backup: {path.name}.bak)"


def attack_types_line(keys: list[str], fams: dict) -> str:
    """Expand family keys into a text line rich with cross-dataset labels."""
    parts = []
    for k in keys:
        f = fams.get(k)
        if not f:
            continue
        parts.append(f"{f['name']} ({', '.join(f['labels'])})")
    return "; ".join(parts)


def build_documents() -> list[dict]:
    """The ten items, as chunks ready for the vector store."""
    data = json.loads(DATA.read_text(encoding="utf-8"))
    fams = json.loads(TAXONOMY.read_text(encoding="utf-8"))["families"]
    now = datetime.now(timezone.utc).isoformat()
    docs = []
    for item in data["items"]:
        keys = item["attack_families"]
        # The attack-type line is part of the embedded text on purpose: it is
        # what pulls the right OWASP item up when a question names a detected
        # attack. Families expand into cross-dataset label variants so retrieval
        # fires whatever exact label the detector emits.
        line = attack_types_line(keys, fams)
        content = (
            f"OWASP IoT Top 10 ({data['version']}) — {item['id']}: "
            f"{item['title']}.\n\n{item['text']}\n\n"
            f"Related detected attack types: {line}."
        )
        docs.append({
            "text": content,
            "metadata": {
                "source_id": item["id"],
                "source_type": SOURCE_TYPE,
                "title": f"OWASP IoT Top 10 — {item['title']}",
                "url": data["source_url"],
                "retrieved_at": now,
                "tactics": [],
                "platforms": ["IoT"],
                "extra": {"owasp_version": data["version"],
                          "attack_families": keys},
            },
            "id": f"{SOURCE_TYPE}:{item['id']}",
        })
    return docs


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--dry-run", action="store_true",
                   help="show what would change, touch nothing")
    p.add_argument("--skip-patch", action="store_true",
                   help="the two source edits are already in place")
    a = p.parse_args()

    print(f"RAG project: {RAG_DIR}\n")

    print("1/4  source edits")
    if a.skip_patch:
        print("     skipped on request")
    else:
        print(patch(RAG_DIR / "src" / "models" / "document.py",
                    TYPE_OLD, TYPE_NEW, "SourceType", a.dry_run))
        print(patch(RAG_DIR / "src" / "rag" / "citations.py",
                    CITE_OLD, CITE_NEW, "CITATION_PATTERN", a.dry_run))

    print("\n2/4  building documents")
    docs = build_documents()
    print(f"     {len(docs)} items  ({docs[0]['metadata']['source_id']} … "
          f"{docs[-1]['metadata']['source_id']})")

    if a.dry_run:
        print("\n     --dry-run: the index is not touched.")
        print("\n     first document preview:")
        for line in docs[0]["text"].splitlines()[:3]:
            print(f"       {line[:92]}")
        return

    print("\n3/4  loading the index")
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
    before = len(vs.docstore._dict)
    print(f"     {before:,} chunks  (embeddings: {settings.embedding_model})")

    # idempotent: drop any OWASP entries already present
    stale = [k for k, d in vs.docstore._dict.items()
             if d.metadata.get("source_type") == SOURCE_TYPE]
    if stale:
        vs.delete(stale)
        print(f"     removed {len(stale)} existing OWASP chunk(s)")

    print("\n4/4  embedding (one at a time) and saving")
    # One request per document — dodges Ollama's large-batch /tokenize bug.
    pairs, metas, ids = [], [], []
    for d in docs:
        pairs.append((d["text"], emb.embed_query(d["text"])))
        metas.append(d["metadata"])
        ids.append(d["id"])
    vs.add_embeddings(text_embeddings=pairs, metadatas=metas, ids=ids)
    vs.save_local(str(index_dir))
    after = len(vs.docstore._dict)
    print(f"     {before:,} -> {after:,} chunks")

    manifest = index_dir / "manifest.json"
    if manifest.exists():
        m = json.loads(manifest.read_text(encoding="utf-8"))
        m["chunk_count"] = after
        m.setdefault("added_sources", [])
        if SOURCE_TYPE not in m["added_sources"]:
            m["added_sources"].append(SOURCE_TYPE)
        m["last_modified"] = datetime.now(timezone.utc).isoformat()
        manifest.write_text(json.dumps(m, indent=2), encoding="utf-8")
        print(f"     manifest updated")

    print("\ndone. Check it worked:")
    print('  python ask.py "What does OWASP IoT Top 10 say about weak or '
          'hardcoded passwords on an IoT device?"')
    print("  the answer should cite [IOT-I1]")


if __name__ == "__main__":
    main()
