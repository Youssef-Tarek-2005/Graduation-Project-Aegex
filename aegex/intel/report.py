"""Threat Intelligence - "Blue Team Report" (findings, recommendations, mitigation steps).

Template-based and grounded: every finding is built from stored attack analyses and linked to knowledge-base entries
(MITRE ATT&CK, OWASP IoT, CWE/CAPEC). No LLM is involved; the RAG-LLM stage of the diagram is intentionally omitted."""
from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from typing import Any

from .knowledge_base import CATEGORY_PROFILE, references_for

_SEV = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def build_report(attacks: list[dict[str, Any]], minutes: int) -> dict[str, Any]:
    """`attacks` = rows from PostgresStore.recent_attacks()."""
    groups: dict[str, list[dict]] = {}
    for a in attacks:
        groups.setdefault(a["category"], []).append(a)
    findings = []
    for cat, rows in groups.items():
        prof = CATEGORY_PROFILE.get(cat, {})
        ips = Counter(ip for r in rows for ip in (r.get("src_ips") or []))
        sigs = Counter(sg for r in rows for sg in (r.get("signals") or []))
        findings.append({
            "category": cat, "title": prof.get("title", cat), "count": len(rows),
            "max_severity": max((r["severity"] for r in rows), key=lambda x: _SEV.get(x, 0)),
            "avg_confidence": round(sum(r["confidence"] for r in rows) / len(rows), 2),
            "first_seen": min(r["ts"] for r in rows), "last_seen": max(r["ts"] for r in rows),
            "top_sources": [{"ip": ip, "events": n} for ip, n in ips.most_common(5)],
            "entry_vectors": dict(Counter(r["entry_vector"] for r in rows)),
            "targets": dict(Counter(r["honeypot"] for r in rows)),
            "evidence": [{"signal": k, "seen": n} for k, n in sigs.most_common(6)],
            "references": references_for(cat),
            "mitigations": prof.get("mitigations", []),
        })
    findings.sort(key=lambda f: (-_SEV.get(f["max_severity"], 0), -f["count"]))
    # prioritised, de-duplicated recommendations (highest-severity findings first)
    recs: list[str] = []
    for f in findings:
        for m in f["mitigations"]:
            if m not in recs:
                recs.append(m)
    blocklist = sorted({s["ip"] for f in findings for s in f["top_sources"]})
    if blocklist:
        recs.append("Add these sources to the network blocklist: " + ", ".join(blocklist) + ".")
    return {"generated_at": datetime.now(timezone.utc).isoformat(), "window_minutes": minutes,
            "total_detections": len(attacks), "findings": findings, "recommendations": recs}


def to_markdown(r: dict[str, Any]) -> str:
    L = ["# AEGEX Blue Team Report", "",
         f"Generated: {r['generated_at']}  ", f"Window: last {r['window_minutes']} minutes  ",
         f"Detections: {r['total_detections']}", ""]
    if not r["findings"]:
        return "\n".join(L + ["No attacks detected in this window."])
    L += ["## Executive summary", ""]
    for f in r["findings"]:
        L.append(f"- **{f['title']}**: {f['count']} detection{'s' if f['count'] != 1 else ''}, max severity {f['max_severity']}, avg confidence {f['avg_confidence']}")
    L += ["", "## Findings", ""]
    for f in r["findings"]:
        L += [f"### {f['title']} ({f['max_severity']})", "",
              f"- Detections: {f['count']}, between {f['first_seen']} and {f['last_seen']}",
              "- Entry vector: " + ", ".join(f"{k} ({v})" for k, v in f["entry_vectors"].items()),
              "- Targeted honeypot: " + ", ".join(f"{k} ({v})" for k, v in f["targets"].items()),
              "- Top sources: " + (", ".join(f"{s['ip']} ({s['events']})" for s in f["top_sources"]) or "none identified"),
              "- Evidence: " + ", ".join(f"{e['signal'].replace('_', ' ')} x{e['seen']}" for e in f["evidence"])]
        refs = [f"{e['id']} {e['title']}" for layer in f["references"].values() for e in layer]
        if refs:
            L.append("- References: " + "; ".join(refs))
        L += ["", "Mitigation steps:", *[f"{i}. {m}" for i, m in enumerate(f["mitigations"], 1)], ""]
    L += ["## Recommendations (priority order)", "", *[f"{i}. {m}" for i, m in enumerate(r["recommendations"], 1)], ""]
    return "\n".join(L)
