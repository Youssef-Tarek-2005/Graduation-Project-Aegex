import collections
import datetime as dt

from aegex.testbed import HoneypotEventSimulator
from aegex.config import get_settings
from aegex.intel.report import build_report, to_markdown
from aegex.intel.retriever import KnowledgeRetriever
from aegex.models import SCENARIOS, EventType, RawEvent, TelemetryBatch
from aegex.processing.preprocessing import FEATURE_ORDER, PreprocessingPipeline


def _run(n=600, p=0.4, seed=3):
    s, sim, pipe = get_settings(), HoneypotEventSimulator(seed, p), None
    pipe = PreprocessingPipeline(s)
    t0 = dt.datetime(2026, 1, 1, tzinfo=dt.timezone.utc)
    for i in range(n):
        ts = (t0 + dt.timedelta(seconds=5 * i)).isoformat()
        evs = sim.generate_window(ts)
        sensor = RawEvent(EventType.SENSOR_READING, ts, "csv", {"smoke": 300, "tempeture": 27.0, "humidity_pct": 55, "esp_ms": i, "time": ts})
        fv = pipe.process(TelemetryBatch(t0 + dt.timedelta(seconds=5 * i), sensor, evs))
        yield evs, fv


def test_all_scenarios_generated_and_detected():
    seen, hit, false_pos = set(), collections.Counter(), 0
    for evs, fv in _run():
        truth = {e.payload["label"] for e in evs if e.payload.get("actor") == "attacker"}
        if truth:
            t = next(iter(truth)); seen.add(t); hit[t] += bool(fv.analysis and fv.analysis["category"] == t)
        else:
            false_pos += fv.analysis is not None
    assert seen == set(SCENARIOS)
    assert all(hit[t] > 0 for t in SCENARIOS) and false_pos == 0


def test_vector_window_and_payload():
    last = None
    for _, fv in _run(40):
        last = fv
    p = last.to_payload()
    assert len(p["vector"]) == len(FEATURE_ORDER) and 1 <= len(p["window"]) <= get_settings().window_size
    assert all(0.0 <= x <= 1.0 for x in p["vector"])


def test_report_and_retriever():
    rows = [{"category": "mirai_botnet", "severity": "high", "confidence": 0.9, "src_ips": ["203.0.113.5"], "entry_vector": "wifi",
             "honeypot": "camera_honeypot", "signals": ["dropper_command"], "ts": "t1"}]
    md = to_markdown(build_report(rows, 60))
    assert "Mirai" in md and "T1110.001" in md and "203.0.113.5" in md
    assert KnowledgeRetriever().search("mirai")[0]["id"].startswith(("IOC", "I1", "CVE", "T1"))
    assert {l["layer"] for l in KnowledgeRetriever().layers()} == {"mitre_attack", "owasp_iot_top10", "cve_nvd", "cwe_capec", "threat_feeds"}
