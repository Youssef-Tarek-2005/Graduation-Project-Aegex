"""
Turn detections into grounded threat-intelligence reports.

This half of the AI stack stands on its own. It never imports TensorFlow or
PyTorch and never loads the autoencoder, E-GraphSAGE or the type classifier.
Its only input is a JSON file of detections, so whoever owns this part can
build and test it while the detection half is still being written — and the
two halves meet at a file format rather than at a function call.

    detections.json  ->  [ this ]  ->  reports.json  +  report.md

Run:
    python report.py --detections examples/detections.json --dry-run
    python report.py --detections examples/detections.json
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime
from pathlib import Path

# Where the RAG project lives. Override with RAG_DIR instead of editing this.
RAG_DIR = Path(os.environ.get(
    "RAG_DIR",
    str(Path(__file__).resolve().parents[1] / "threat-intelligence-assistant")))

REQUIRED = ("id", "attack_type", "source", "target")


# --------------------------------------------------------------------------
# Input
# --------------------------------------------------------------------------
def load_detections(path: Path) -> list[dict]:
    """Read and validate the detections file, failing with a useful message."""
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise SystemExit(f"no such file: {path}")
    except json.JSONDecodeError as e:
        raise SystemExit(f"{path} is not valid JSON — {e}")

    items = raw.get("detections") if isinstance(raw, dict) else raw
    if not isinstance(items, list):
        raise SystemExit('expected a list, or an object with a "detections" list')
    if not items:
        raise SystemExit("the file holds no detections")

    for n, d in enumerate(items, 1):
        if not isinstance(d, dict):
            raise SystemExit(f"detection {n} is not an object")
        missing = [k for k in REQUIRED if not str(d.get(k, "")).strip()]
        if missing:
            raise SystemExit(
                f"detection {n} (id={d.get('id', '?')}) is missing: "
                f"{', '.join(missing)}")
    return items


# --------------------------------------------------------------------------
# The bridge: a detection becomes an analyst's question
# --------------------------------------------------------------------------
def build_question(d: dict) -> str:
    """
    The RAG layer rejects anything that does not read as a threat-intelligence
    question, so a bare class name like "Port_Scanning" is refused. Every
    sentence built here carries the words MITRE ATT&CK.

    Evidence is optional: a detection that carries none still produces a valid
    question, which is what lets this half run before the detection half exists.
    """
    attack = str(d["attack_type"]).replace("_", " ")
    ev = d.get("evidence") or {}

    detail = ""
    err, thr = ev.get("reconstruction_error"), ev.get("threshold")
    if isinstance(err, (int, float)) and isinstance(thr, (int, float)):
        detail = f" (reconstruction error {err:.4f} vs threshold {thr:.4f})"
    elif isinstance(ev.get("graph_probability"), (int, float)):
        detail = f" (graph-model attack probability {ev['graph_probability']:.3f})"

    return (
        f"{attack} activity was detected from {d['source']} against IoT "
        f"honeypot {d['target']}{detail}. Which MITRE ATT&CK technique does "
        f"this map to, and what mitigation is recommended?"
    )


def build_mitigation_question(d: dict) -> str:
    """
    A second, defence-focused question. It is aimed squarely at the blue-team
    side so retrieval pulls the ATT&CK mitigations (M-series) and the OWASP/CWE
    controls for the detected attack, letting the report carry a grounded
    recommendations section separate from the assessment.
    """
    attack = str(d["attack_type"]).replace("_", " ")
    return (
        f"A {attack} attack was detected against an IoT honeypot. Based on "
        f"MITRE ATT&CK mitigations and IoT security best practice, what "
        f"defensive controls should the blue team apply to prevent, detect, "
        f"and respond to it? List the recommended mitigations."
    )


# --------------------------------------------------------------------------
# The RAG chain
# --------------------------------------------------------------------------
def load_chain(rag_dir: Path):
    if not (rag_dir / "config" / "settings.py").exists():
        raise SystemExit(
            f"the RAG project is not at {rag_dir}\n"
            f"       clone it and point RAG_DIR at it:\n"
            f"       git clone https://github.com/rvong65/"
            f"threat-intelligence-assistant")

    sys.path.insert(0, str(rag_dir))
    os.chdir(rag_dir)        # settings resolve .env and indices/ from here
    from config.settings import get_settings
    from src.embeddings.factory import get_embeddings
    from src.llm.factory import get_llm
    from src.rag.chain import ThreatIntelRAGChain
    from src.vectorstore.factory import load_vectorstore

    s = get_settings()
    return ThreatIntelRAGChain(vectorstore=load_vectorstore(get_embeddings(s), s),
                               llm=get_llm(s), settings=s)


# --------------------------------------------------------------------------
def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--detections", required=True, type=Path)
    p.add_argument("--out", default="report.md",
                   help="markdown report (a .json sibling is written too)")
    p.add_argument("--dry-run", action="store_true",
                   help="build and show the questions without calling the LLM")
    p.add_argument("--no-recommendations", action="store_true",
                   help="skip the blue-team recommendations section")
    a = p.parse_args()

    out_md = a.out if os.path.isabs(a.out) else str(Path.cwd() / a.out)
    out_json = str(Path(out_md).with_suffix(".json"))

    print("1/3  reading detections ...")
    dets = load_detections(a.detections)
    print(f"     {len(dets)} detection(s)")

    print("2/3  building questions ...")
    questions = [build_question(d) for d in dets]
    mit_questions = [build_mitigation_question(d) for d in dets]
    if a.dry_run:
        print("     --dry-run: the LLM is not called\n")
        for d, q, mq in zip(dets, questions, mit_questions):
            print(f"  [{d['id']}] {d['attack_type']}")
            print(f"      assessment : {q}")
            if not a.no_recommendations:
                print(f"      blue team  : {mq}")
            print()
        print("Questions look right? Drop --dry-run to generate the reports.")
        return

    print("3/3  loading the RAG chain (the first call is slow) ...")
    chain = load_chain(RAG_DIR)

    results, md = [], [
        "# Threat Intelligence Report", "",
        f"- Generated: {datetime.now():%Y-%m-%d %H:%M}",
        f"- Detections: {len(dets)}",
        "- Knowledge base: ATT&CK, CISA KEV, IoT CVEs, OWASP IoT Top 10, CWE, "
        "CAPEC, ATT&CK mitigations — retrieved locally",
        "",
    ]

    for n, (d, q, mq) in enumerate(zip(dets, questions, mit_questions), 1):
        r = chain.invoke(q)
        sources = [{"id": s.source_id, "url": s.url}
                   for s in (r.citations.sources or [])]

        rec = None if a.no_recommendations else chain.invoke(mq)
        rec_sources = ([{"id": s.source_id, "url": s.url}
                        for s in (rec.citations.sources or [])] if rec else [])

        results.append({
            "id": d["id"],
            "attack_type": d["attack_type"],
            "question": q,
            "answer": r.answer,
            "confidence": r.confidence.overall,
            "abstained": bool(r.hard_abstained),
            "sources": sources,
            "recommendations": ({
                "question": mq,
                "answer": rec.answer,
                "confidence": rec.confidence.overall,
                "abstained": bool(rec.hard_abstained),
                "sources": rec_sources,
            } if rec else None),
        })

        md += [f"## {n}. {str(d['attack_type']).replace('_', ' ')}", "",
               f"- Detection id: `{d['id']}`",
               f"- Source: `{d['source']}`  ->  Target: `{d['target']}`", ""]
        if d.get("evidence"):
            md.append("<details><summary>Evidence from the detection half"
                      "</summary>\n")
            md.append("```json")
            md.append(json.dumps(d["evidence"], indent=2))
            md += ["```", "</details>", ""]
        md += ["**Query**", "", f"> {q}", "",
               "**Grounded assessment**", "", r.answer, "",
               f"- Confidence: **{r.confidence.overall}/100**",
               f"- Abstained: {bool(r.hard_abstained)}", ""]
        if sources:
            md.append("- Sources: " + ", ".join(
                f"[{s['id']}]({s['url']})" for s in sources))
        md.append("")

        if rec is not None:
            md += ["**Blue Team recommendations**", "", rec.answer, "",
                   f"- Confidence: **{rec.confidence.overall}/100**",
                   f"- Abstained: {bool(rec.hard_abstained)}", ""]
            if rec_sources:
                md.append("- Sources: " + ", ".join(
                    f"[{s['id']}]({s['url']})" for s in rec_sources))
            md.append("")

        flag = "abstained" if r.hard_abstained else f"{r.confidence.overall}/100"
        extra = "" if rec is None else (
            " | rec " + ("abstained" if rec.hard_abstained
                         else f"{rec.confidence.overall}/100"))
        print(f"     [{d['id']}] {d['attack_type']} -> {flag}{extra}")

    Path(out_md).write_text("\n".join(md), encoding="utf-8")
    Path(out_json).write_text(json.dumps(results, indent=2), encoding="utf-8")
    print(f"\ndone -> {out_md}")
    print(f"     -> {out_json}")


if __name__ == "__main__":
    main()
