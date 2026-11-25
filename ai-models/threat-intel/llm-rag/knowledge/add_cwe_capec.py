"""
Add MITRE CWE (weaknesses) and CAPEC (attack patterns) to the knowledge base.

This closes the last gap in the threat-intelligence corpus. The base already
answers "which technique / which exploited CVE"; CWE answers "which underlying
weakness" and CAPEC answers "by what method", so a detection can be explained
end to end: attack class -> ATT&CK technique -> CWE weakness -> CAPEC method.

Like OWASP, this is NOT just a data load. The RAG project only accepts a fixed
set of source types and only recognises a fixed set of citation ID shapes, so
new documents dropped in without touching those two places are retrieved and
cited but the citation checker does not recognise the IDs, and confidence
silently drops. The script therefore patches both first, backing each up, then
embeds.

    1  src/models/document.py   SourceType      += "cwe", "capec"
    2  src/rag/citations.py     CITATION_PATTERN += CWE-<n>, CAPEC-<n>
    3  the curated CWE + CAPEC items are embedded into the FAISS index

Embedding is done one document at a time on purpose: Ollama's large-batch embed
path calls an internal /tokenize endpoint on a model-runner port that is
unreachable on some Windows setups, so a single-request embed is the safe path.

Safe to run twice: existing cwe/capec entries are removed before the new ones go
in, and the two source edits are idempotent.

Run:
    python add_cwe_capec.py --dry-run
    python add_cwe_capec.py
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
CWE_DATA = HERE / "cwe_iot.json"
CAPEC_DATA = HERE / "capec_iot.json"
TAXONOMY = HERE / "attack_families.json"

RAG_DIR = Path(os.environ.get(
    "RAG_DIR",
    str(Path(__file__).resolve().parents[2] / "threat-intelligence-assistant")))

SOURCE_TYPES = ("cwe", "capec")

# ---- patch 1: the document model only allows a fixed set of source types ----
# Anchored on whichever entry currently closes the Literal, so it works whether
# or not the OWASP patch has already run.
TYPE_ANCHORS = ('    "owasp_iot",\n]', '    "nvd_cve",\n]')
TYPE_ADD = '    "cwe",\n    "capec",\n]'

# ---- patch 2: the citation checker only knows a fixed set of ID shapes -------
CITE_ADD = r"|CWE-\d{1,4}|CAPEC-\d{1,4}"
CITE_ANCHORS = (r"IOT-I\d{1,2})", r"CVE-\d{4}-\d{4,})")


def patch_source_type(path: Path, dry: bool) -> str:
    if not path.exists():
        raise SystemExit(f"not found: {path}")
    text = path.read_text(encoding="utf-8")
    if '"cwe"' in text and '"capec"' in text:
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
        f"       The upstream project changed. Add \"cwe\" and \"capec\" to the\n"
        f"       SourceType list by hand, then re-run with --skip-patch.")


def patch_citations(path: Path, dry: bool) -> str:
    if not path.exists():
        raise SystemExit(f"not found: {path}")
    text = path.read_text(encoding="utf-8")
    if r"|CWE-\d{1,4}" in text:
        return f"  {'CITATION_PATTERN':22} already patched"
    for anchor in CITE_ANCHORS:
        if anchor in text:
            if dry:
                return f"  {'CITATION_PATTERN':22} would patch"
            shutil.copy2(path, path.with_suffix(path.suffix + ".bak"))
            # insert the new alternatives just before each group's closing ")"
            path.write_text(text.replace(anchor, anchor[:-1] + CITE_ADD + ")"),
                            encoding="utf-8")
            return f"  {'CITATION_PATTERN':22} patched (backup: {path.name}.bak)"
    raise SystemExit(
        f"  CITATION_PATTERN: could not find the pattern to extend in {path}.\n"
        f"       Add CWE-\\d{{1,4}} and CAPEC-\\d{{1,4}} to CITATION_PATTERN by\n"
        f"       hand, then re-run with --skip-patch.")


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
    """The curated CWE + CAPEC items, as chunks ready for the vector store."""
    now = datetime.now(timezone.utc).isoformat()
    fams = json.loads(TAXONOMY.read_text(encoding="utf-8"))["families"]
    docs: list[dict] = []
    for data_file, source_type, standard in (
        (CWE_DATA, "cwe", "CWE"),
        (CAPEC_DATA, "capec", "CAPEC"),
    ):
        data = json.loads(data_file.read_text(encoding="utf-8"))
        for item in data["items"]:
            keys = item["attack_families"]
            # The attack-type line is embedded with the text on purpose: it is
            # what pulls the right weakness/pattern up when a question names a
            # detected attack. Families expand into cross-dataset label variants
            # so retrieval fires whatever exact label the detector emits.
            line = attack_types_line(keys, fams)
            content = (
                f"{item['id']} ({standard}): {item['title']}.\n\n{item['text']}\n\n"
                f"Related detected attack types: {line}."
            )
            docs.append({
                "text": content,
                "metadata": {
                    "source_id": item["id"],
                    "source_type": source_type,
                    "title": f"{standard} — {item['title']}",
                    "url": data["source_url"],
                    "retrieved_at": now,
                    "tactics": [],
                    "platforms": ["IoT"],
                    "extra": {"standard": standard,
                              "standard_version": data["version"],
                              "attack_families": keys},
                },
                "id": f"{source_type}:{item['id']}",
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
    cwe = sum(1 for d in docs if d["metadata"]["source_type"] == "cwe")
    capec = len(docs) - cwe
    print(f"     {len(docs)} items  ({cwe} CWE, {capec} CAPEC)")

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

    # idempotent: drop any cwe/capec entries already present
    stale = [k for k, d in vs.docstore._dict.items()
             if d.metadata.get("source_type") in SOURCE_TYPES]
    if stale:
        vs.delete(stale)
        print(f"     removed {len(stale)} existing CWE/CAPEC chunk(s)")

    print("\n4/4  embedding (one at a time) and saving")
    # One request per document — dodges Ollama's large-batch /tokenize bug.
    pairs, metas, ids = [], [], []
    for i, d in enumerate(docs, 1):
        pairs.append((d["text"], emb.embed_query(d["text"])))
        metas.append(d["metadata"])
        ids.append(d["id"])
        if i % 10 == 0:
            print(f"     embedded {i}/{len(docs)} ...")
    vs.add_embeddings(text_embeddings=pairs, metadatas=metas, ids=ids)
    vs.save_local(str(index_dir))
    after = len(vs.docstore._dict)
    print(f"     {before:,} -> {after:,} chunks")

    manifest = index_dir / "manifest.json"
    if manifest.exists():
        m = json.loads(manifest.read_text(encoding="utf-8"))
        m["chunk_count"] = after
        m.setdefault("added_sources", [])
        for st in SOURCE_TYPES:
            if st not in m["added_sources"]:
                m["added_sources"].append(st)
        m["last_modified"] = datetime.now(timezone.utc).isoformat()
        manifest.write_text(json.dumps(m, indent=2), encoding="utf-8")
        print("     manifest updated")

    print("\ndone. Check it worked:")
    print('  python ask.py "What weakness and attack pattern explain a '
          'brute-force Password attack on an IoT device?"')
    print("  the answer should cite something like [CWE-798] and [CAPEC-49]")


if __name__ == "__main__":
    main()
