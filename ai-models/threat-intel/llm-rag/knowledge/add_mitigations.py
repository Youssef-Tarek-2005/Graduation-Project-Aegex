"""
Add MITRE ATT&CK mitigations (the M-series) to the knowledge base.

This is the defensive / blue-team layer. The corpus already explains what an
attack is (ATT&CK), which vulnerability it uses (CVE/KEV), which risk and
weakness it reflects (OWASP / CWE) and by what method (CAPEC). Mitigations add
the last piece: what the defender should DO about it, cited as [M####].

Like the others, this is NOT just a data load — the RAG project only accepts a
fixed set of source types and citation ID shapes, so the script patches both
first (backing each up), then embeds:

    1  src/models/document.py   SourceType      += "attack_mitigation"
    2  src/rag/citations.py     CITATION_PATTERN += M<n>
    3  the curated mitigations are embedded into the FAISS index

Embedding is one document at a time, which dodges Ollama's large-batch
/tokenize bug. Safe to run twice: existing mitigation entries are removed first,
and the source edits are idempotent.

Run:
    python add_mitigations.py --dry-run
    python add_mitigations.py
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
DATA = HERE / "attack_mitigations.json"
TAXONOMY = HERE / "attack_families.json"

RAG_DIR = Path(os.environ.get(
    "RAG_DIR",
    str(Path(__file__).resolve().parents[2] / "threat-intelligence-assistant")))

SOURCE_TYPE = "attack_mitigation"

# ---- patch 1: the document model only allows a fixed set of source types ----
# Anchored on whichever entry currently closes the Literal, so it works whether
# or not OWASP / CWE / CAPEC have already been added.
TYPE_ANCHORS = ('    "capec",\n]', '    "owasp_iot",\n]', '    "nvd_cve",\n]')
TYPE_ADD = '    "attack_mitigation",\n]'

# ---- patch 2: the citation checker only knows a fixed set of ID shapes -------
CITE_ADD = r"|M\d{4}"
CITE_ANCHORS = (r"CAPEC-\d{1,4})", r"IOT-I\d{1,2})", r"CVE-\d{4}-\d{4,})")


def patch_source_type(path: Path, dry: bool) -> str:
    if not path.exists():
        raise SystemExit(f"not found: {path}")
    text = path.read_text(encoding="utf-8")
    if '"attack_mitigation"' in text:
        return f"  {'SourceType':22} already patched"
    for anchor in TYPE_ANCHORS:
        if anchor in text:
            if dry:
                return f"  {'SourceType':22} would patch"
            shutil.copy2(path, path.with_suffix(path.suffix + ".bak"))
            path.write_text(text.replace(anchor, anchor[:-1] + TYPE_ADD),
                            encoding="utf-8")
            return f"  {'SourceType':22} patched (backup: {path.name}.bak)"
    raise SystemExit(
        f"  SourceType: could not find the Literal to extend in {path}.\n"
        f"       Add \"attack_mitigation\" to the SourceType list by hand,\n"
        f"       then re-run with --skip-patch.")


def patch_citations(path: Path, dry: bool) -> str:
    if not path.exists():
        raise SystemExit(f"not found: {path}")
    text = path.read_text(encoding="utf-8")
    if r"|M\d{4}" in text:
        return f"  {'CITATION_PATTERN':22} already patched"
    for anchor in CITE_ANCHORS:
        if anchor in text:
            if dry:
                return f"  {'CITATION_PATTERN':22} would patch"
            shutil.copy2(path, path.with_suffix(path.suffix + ".bak"))
            path.write_text(text.replace(anchor, anchor[:-1] + CITE_ADD + ")"),
                            encoding="utf-8")
            return f"  {'CITATION_PATTERN':22} patched (backup: {path.name}.bak)"
    raise SystemExit(
        f"  CITATION_PATTERN: could not find the pattern to extend in {path}.\n"
        f"       Add M\\d{{4}} to CITATION_PATTERN by hand, then --skip-patch.")


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
    """The curated mitigations, as chunks ready for the vector store."""
    data = json.loads(DATA.read_text(encoding="utf-8"))
    fams = json.loads(TAXONOMY.read_text(encoding="utf-8"))["families"]
    now = datetime.now(timezone.utc).isoformat()
    docs = []
    for item in data["items"]:
        keys = item["attack_families"]
        line = attack_types_line(keys, fams)
        # "Mitigation for" wording plus the attack-type line is what pulls the
        # right control up when a blue-team question names a detected attack.
        content = (
            f"{item['id']} (MITRE ATT&CK mitigation): {item['title']}.\n\n"
            f"{item['text']}\n\n"
            f"Mitigation for these detected attack types: {line}."
        )
        docs.append({
            "text": content,
            "metadata": {
                "source_id": item["id"],
                "source_type": SOURCE_TYPE,
                "title": f"ATT&CK Mitigation — {item['title']}",
                "url": f"https://attack.mitre.org/mitigations/{item['id']}/",
                "retrieved_at": now,
                "tactics": [],
                "platforms": ["IoT"],
                "extra": {"standard_version": data["version"],
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
        print(patch_source_type(RAG_DIR / "src" / "models" / "document.py",
                                a.dry_run))
        print(patch_citations(RAG_DIR / "src" / "rag" / "citations.py",
                              a.dry_run))

    print("\n2/4  building documents")
    docs = build_documents()
    print(f"     {len(docs)} mitigations  "
          f"({docs[0]['metadata']['source_id']} … "
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

    stale = [k for k, d in vs.docstore._dict.items()
             if d.metadata.get("source_type") == SOURCE_TYPE]
    if stale:
        vs.delete(stale)
        print(f"     removed {len(stale)} existing mitigation chunk(s)")

    print("\n4/4  embedding (one at a time) and saving")
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
        print("     manifest updated")

    print("\ndone. Check it worked:")
    print('  python ask.py "What blue-team mitigations defend an IoT device '
          'against a password brute-force attack?"')
    print("  the answer should cite something like [M1027] and [M1032]")


if __name__ == "__main__":
    main()
