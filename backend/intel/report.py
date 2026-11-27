"""Threat intelligence from what WE detected: every incident linked to real, cited knowledge. No LLM needed.

    GET /api/v1/intel/live-report?minutes=60               (JSON, the dashboard's threat-intelligence page)
    GET /api/v1/intel/live-report?minutes=60&format=markdown

For the chosen time range it takes the incidents our detectors raised (rule baseline, temporal GAT, LSTM-AE / VAE)
and groups them per attacker and attack type. For each group it adds:

  - what we saw: when, which detectors agreed, which devices were hit, the rule evidence, and the usernames /
    passwords the attacker tried on the honeypot (captured by us, not taken from a feed)
  - MITRE ATT&CK techniques for that behaviour (fixed, well-known mapping, with links)
  - from Task E's verified knowledge base (ai-models/threat-intel/llm-rag/knowledge, each item mapped to attack
    families): OWASP IoT Top 10, CWE weaknesses, CAPEC attack patterns, ATT&CK mitigations, and the most severe
    related IoT CVEs from the NVD cache

Grounded on purpose: every line is either our own measurement or an entry of a named public catalogue, with its
id. Task E's LLM + RAG (report.py, Groq or Ollama) can write prose on top of exactly this when a model is set up.
"""
from __future__ import annotations

import json
import re
from collections import Counter
from datetime import datetime, timedelta, timezone
from functools import lru_cache
from pathlib import Path

import psycopg

KB = Path(__file__).resolve().parents[2] / "ai-models" / "threat-intel" / "llm-rag" / "knowledge"

SCENARIOS = {   # our scenario -> (name, attack families in Task E's knowledge base, ATT&CK techniques, CVE words)
    "vulnerability_scanning": ("Reconnaissance / port scanning", ["scanning", "vuln_scan", "fingerprint"],
                               [("T1595", "Active Scanning"), ("T1046", "Network Service Discovery")],
                               ["unauthenticated", "information disclosure", "exposed"]),
    "dos": ("Denial of service (flood)", ["dos", "ddos"],
            [("T1498", "Network Denial of Service"), ("T1499.002", "Endpoint Denial of Service: Service Exhaustion Flood")],
            ["denial of service", "crash", "exhaust"]),
    "bruteforce": ("Password brute force", ["password"],
                   [("T1110.001", "Brute Force: Password Guessing"), ("T1078.001", "Valid Accounts: Default Accounts")],
                   ["default password", "hard-coded", "hardcoded", "brute"]),
    "mirai_botnet": ("Mirai-style botnet spreading over Telnet", ["botnet", "password", "scanning"],
                     [("T1018", "Remote System Discovery"), ("T1110.001", "Brute Force: Password Guessing"),
                      ("T1078.001", "Valid Accounts: Default Accounts"), ("T1584.005", "Compromise Infrastructure: Botnet")],
                     ["telnet", "default password", "hard-coded", "hardcoded"]),
}
AI_CLASS = {"scanning": "vulnerability_scanning", "ddos": "dos", "mirai": "mirai_botnet"}   # VAE closest class
DETECTOR = {"rules": "Rule baseline", "lstm_ae": "LSTM-AE", "vae": "VAE", "temporal_gat": "Temporal GAT"}
SEVERITY = ["low", "medium", "high", "critical"]
NEW_INCIDENT = timedelta(minutes=10)      # the same attacker + type after 10 quiet minutes = a new incident


# --------------------------------------------------------------------------- knowledge base
@lru_cache(maxsize=1)
def knowledge() -> dict:
    def items(name):
        try:
            d = json.loads((KB / name).read_text(encoding="utf-8"))
            return d.get("items", []), d.get("source_url")
        except (OSError, ValueError):
            return [], None
    out = {k: items(f) for k, f in (("owasp", "owasp_iot_top10.json"), ("cwe", "cwe_iot.json"),
                                    ("capec", "capec_iot.json"), ("mitigations", "attack_mitigations.json"))}
    try:
        out["cves"] = list(json.loads((KB / "iot_cve_cache.json").read_text(encoding="utf-8")).values())
    except (OSError, ValueError):
        out["cves"] = []
    return out


def _for_families(kind: str, families: list[str], limit: int) -> list[dict]:
    items, _ = knowledge()[kind]
    hits = [i for i in items if set(i.get("attack_families", [])) & set(families)]
    hits.sort(key=lambda i: -len(set(i.get("attack_families", [])) & set(families)))
    return [{"id": i["id"], "title": i["title"], "text": i.get("text", "")} for i in hits[:limit]]


def _cvss(cve: dict) -> float:
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        for m in (cve.get("metrics") or {}).get(key, []):
            score = (m.get("cvssData") or {}).get("baseScore")
            if score is not None:
                return float(score)
    return 0.0


def _cves(words: list[str], limit: int = 3) -> list[dict]:
    pat = re.compile("|".join(re.escape(w) for w in words), re.I)
    found = []
    for c in knowledge()["cves"]:
        desc = next((d["value"] for d in c.get("descriptions", []) if d.get("lang") == "en"), "")
        if desc and pat.search(desc):
            found.append({"id": c["id"], "cvss": _cvss(c), "summary": desc[:240] + ("..." if len(desc) > 240 else ""),
                          "url": f"https://nvd.nist.gov/vuln/detail/{c['id']}"})
    found.sort(key=lambda x: (-x["cvss"], x["id"]))
    return found[:limit]


def intel_for(scenario: str) -> dict:
    name, families, techniques, words = SCENARIOS[scenario]
    return {"scenario_name": name,
            "attack_techniques": [{"id": t, "name": n, "url": f"https://attack.mitre.org/techniques/{t.replace('.', '/')}/"}
                                  for t, n in techniques],
            "owasp_iot": _for_families("owasp", families, 3), "cwe": _for_families("cwe", families, 3),
            "capec": _for_families("capec", families, 3), "mitigations": _for_families("mitigations", families, 4),
            "cves": _cves(words)}


# --------------------------------------------------------------------------- our detections
def build(conn: psycopg.Connection, minutes: int, now: datetime | None = None) -> dict:
    now = now or datetime.now(timezone.utc)
    since = now - timedelta(minutes=minutes)
    ips = dict(conn.execute("SELECT device_id, host(ip) FROM devices WHERE ip IS NOT NULL").fetchall())
    rows = conn.execute(
        "SELECT model_name, entity_id, predicted_scenario, severity, window_start, window_end, evidence, device_id "
        "FROM alerts WHERE window_end >= %s AND window_start <= %s ORDER BY window_start", (since, now)).fetchall()
    groups: dict = {}
    seen_by: dict = {}                                    # attacker ip -> detectors that flagged it at all
    pad = timedelta(minutes=2)
    # The rule baseline names the attack type most precisely, so its incidents come first; a GAT or AI alert on
    # the same attacker at the same time joins that incident. The GAT's type is a behaviour rule and the VAE's
    # "closest known class" only a hint, so they name an incident only when no rule incident covers it.
    rows = sorted(rows, key=lambda r: (r[0] != "rules", {"temporal_gat": 0}.get(r[0], 1), r[4]))
    for model, entity, scen, sev, ws, we, ev, dev in rows:
        ip = ips.get(entity, entity)
        seen_by.setdefault(ip, Counter())[DETECTOR.get(model, model)] += 1
        ev = ev or {}
        if ip in ips.values():                            # our own devices are victims here, not attackers
            continue
        same = [g for (gip, _, _), g in groups.items() if gip == ip and ws <= g["last_seen"] + pad and we >= g["first_seen"] - pad]
        if model != "rules" and same:
            g = same[0]
        else:
            if model in ("lstm_ae", "vae"):
                scen = AI_CLASS.get(str(ev.get("closest_known_class")))
            if scen not in SCENARIOS:
                continue
            # the same attacker and type again after a quiet gap is a new incident, not the old one going on
            near = [k for k, g in groups.items() if k[:2] == (ip, scen) and ws <= g["last_seen"] + NEW_INCIDENT]
            key = near[-1] if near else (ip, scen, sum(1 for k in groups if k[:2] == (ip, scen)))
            g = groups.setdefault(key, {"attacker": ip, "scenario": scen, "first_seen": ws, "last_seen": we,
                                        "severity": "low", "alerts": 0, "targets": Counter(), "evidence": []})
        g["first_seen"], g["last_seen"] = min(g["first_seen"], ws), max(g["last_seen"], we)
        g["alerts"] += 1
        if SEVERITY.index(sev or "low") > SEVERITY.index(g["severity"]):
            g["severity"] = sev
        for t in (ev.get("devices") or []) + ([dev] if dev else []) + (ev.get("targets") or [])[:3]:
            g["targets"][t] += 1
        if model == "rules" and ev.get("summary") and len(g["evidence"]) < 3:
            g["evidence"].append(ev["summary"])
    incidents = []
    for (ip, scen, _), g in sorted(groups.items(), key=lambda kv: kv[1]["last_seen"], reverse=True):
        creds = conn.execute(
            "SELECT payload->>'username', payload->>'password', count(*) FROM events WHERE event_type = 'login_failed' "
            "AND src_ip = %s::inet AND ts BETWEEN %s AND %s GROUP BY 1, 2 ORDER BY 3 DESC LIMIT 5",
            (ip, g["first_seen"] - timedelta(minutes=2), g["last_seen"] + timedelta(minutes=2))).fetchall()
        incidents.append({**{k: g[k] for k in ("attacker", "scenario", "severity", "alerts", "evidence")},
                          "first_seen": g["first_seen"].isoformat(), "last_seen": g["last_seen"].isoformat(),
                          "detectors": dict(seen_by.get(ip, {})),
                          "targets": [t for t, _ in g["targets"].most_common(4)],
                          "credentials_tried": [{"username": u, "password": p, "times": n} for u, p, n in creds if u],
                          **intel_for(scen)})
    by = Counter(i["scenario"] for i in incidents)
    k = knowledge()
    return {"generated": now.isoformat(), "minutes": minutes,
            "summary": {"incidents": len(incidents), "attackers": len({i["attacker"] for i in incidents}),
                        "by_scenario": dict(by), "alerts": len(rows),
                        "worst": max((i["severity"] for i in incidents), key=SEVERITY.index, default=None)},
            "incidents": incidents,
            "sources": {"MITRE ATT&CK": "https://attack.mitre.org/", "OWASP IoT Top 10": k["owasp"][1],
                        "CWE": k["cwe"][1], "CAPEC": k["capec"][1], "ATT&CK mitigations": k["mitigations"][1],
                        "NVD (cached IoT CVEs)": "https://nvd.nist.gov/"}}


def markdown(r: dict) -> str:
    s = r["summary"]
    L = [f"# AEGEX threat-intelligence report", "",
         f"Last {r['minutes']} minutes, generated {r['generated'][:19].replace('T', ' ')} UTC. "
         f"{s['incidents']} incident(s) from {s['attackers']} attacker(s), built from {s['alerts']} detector alerts.", ""]
    if not r["incidents"]:
        L.append("No attacks detected in this period.")
    for n, i in enumerate(r["incidents"], 1):
        L += [f"## {n}. {i['scenario_name']} from {i['attacker']} ({i['severity']})", "",
              f"- **When:** {i['first_seen'][11:19]} to {i['last_seen'][11:19]} UTC",
              f"- **Detected by:** " + ", ".join(f"{d} ({c})" for d, c in i["detectors"].items()),
              f"- **Targets:** {', '.join(i['targets']) or '-'}"]
        L += [f"- **Evidence:** {e}" for e in i["evidence"]]
        if i["credentials_tried"]:
            L.append("- **Credentials tried on the honeypot:** " +
                     ", ".join(f"{c['username']} / {c['password']} (x{c['times']})" for c in i["credentials_tried"]))
        L.append("- **MITRE ATT&CK:** " + ", ".join(f"{t['id']} {t['name']}" for t in i["attack_techniques"]))
        L.append("- **OWASP IoT Top 10:** " + ", ".join(f"{x['id']} {x['title']}" for x in i["owasp_iot"]))
        L.append("- **Weaknesses (CWE):** " + ", ".join(f"{x['id']} {x['title']}" for x in i["cwe"]))
        L.append("- **Attack patterns (CAPEC):** " + ", ".join(f"{x['id']} {x['title']}" for x in i["capec"]))
        L += ["- **What to do (ATT&CK mitigations):**"] + [f"  - {m['id']} {m['title']}: {m['text']}" for m in i["mitigations"]]
        if i["cves"]:
            L += ["- **Related IoT CVEs (highest CVSS):**"] + [f"  - {c['id']} (CVSS {c['cvss']}): {c['summary']}"
                                                              for c in i["cves"]]
        L.append("")
    L += ["## Sources", ""] + [f"- {k}: {v}" for k, v in r["sources"].items()]
    return "\n".join(L) + "\n"
