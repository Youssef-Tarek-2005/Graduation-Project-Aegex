"""Attack analysis (category, severity, confidence) - RULE-BASED, no machine learning.

Looks at the behaviour inside one batch (ports touched, commands run, log messages, entropy, who connected) and
checks it against a signature list per attack scenario. confidence = share of that scenario's signatures observed.
The AI detection stage in the architecture diagram is intentionally not implemented; this gives the dashboard and
the blue-team report real categories without it, and can be replaced by model output later."""
from __future__ import annotations

import re
from collections import Counter
from typing import Any

from ..intel.knowledge_base import CATEGORY_PROFILE
from ..models import EventType

_SEV = ["low", "medium", "high", "critical"]
_DROPPER = re.compile(r"wget |curl |busybox|mirai|nc -e|chmod 777|tftp ", re.I)
_RANSOM = re.compile(r"encrypt|\.locked|ransom|openssl\s+enc|rm -rf /data", re.I)
_CRASH = re.compile(r"segfault|crash|overflow|core dumped", re.I)
_DEGRADE = re.compile(r"queue full|dropping|cpu load|watchdog", re.I)
_SMOKE_TOPIC = "smoke"
MIN_SIGNALS = 2


class AttackAnalyzer:
    def __init__(self, reputation):
        self.rep = reputation

    def analyze(self, events: list[dict[str, Any]]) -> dict[str, Any] | None:
        if not events:
            return None
        t = lambda et: [e for e in events if e["event_type"] == et.value]  # noqa: E731
        bad = {e["src_ip"] for e in events if "src_ip" in e and self.rep.score(e["src_ip"]) >= 0.5}
        from_bad = lambda evs: [e for e in evs if e.get("src_ip") in bad]  # noqa: E731

        net, pkts, logs = t(EventType.NETWORK_TRAFFIC), t(EventType.PACKET_CHARACTERISTICS), t(EventType.DEVICE_LOG)
        logins, fails = t(EventType.LOGIN_ATTEMPT), t(EventType.FAILED_LOGIN)
        cmds, inter = t(EventType.COMMAND_REQUEST), t(EventType.DEVICE_INTERACTION)
        mqtt, ble, media = t(EventType.MQTT_EVENT), t(EventType.BLE_EVENT), t(EventType.MEDIA_TELEMETRY)

        ports_by_ip: dict[str, set] = {}
        for e in net:
            if (e.get("bytes") or 0) < 200 and e.get("dst_port") is not None:
                ports_by_ip.setdefault(e["src_ip"], set()).add(e["dst_port"])
        flood = [e for e in net if (e.get("packets") or 0) >= 800 or (e.get("bytes") or 0) >= 300_000]
        cmd_text = lambda evs: [str(e.get("command", "")) for e in evs]  # noqa: E731
        n_failed = max(len(fails), sum(1 for e in logins if e.get("success") is False))

        sig: dict[str, list[tuple[str, bool]]] = {
            "vulnerability_scanning": [
                ("many_ports_probed", any(len(p) >= 6 for p in ports_by_ip.values())),
                ("syn_probe_packets", any("S" == str(e.get("tcp_flags")) and (e.get("packet_size") or 0) <= 100 for e in pkts)),
                ("probe_in_device_log", any("probe" in str(e.get("message", "")).lower() for e in logs)),
                ("known_bad_source", bool(bad))],
            "ddos": [
                ("flood_volume", bool(flood)),
                ("multiple_sources", len({e["src_ip"] for e in flood}) >= 2),
                ("service_degradation_log", any(_DEGRADE.search(str(e.get("message", ""))) for e in logs)),
                ("syn_flood_packets", any(e.get("tcp_flags") == "S" and (e.get("packet_size") or 0) >= 1000 for e in pkts))],
            "mirai_botnet": [
                ("repeated_failed_logins", n_failed >= 4),
                ("telnet_or_ssh_bruteforce", any(e.get("protocol") in ("telnet", "ssh") for e in fails + logins)),
                ("dropper_command", any(_DROPPER.search(c) for c in cmd_text(cmds))),
                ("known_bad_source", bool(bad))],
            "ransomware": [
                ("encryption_or_ransom_command", any(_RANSOM.search(c) for c in cmd_text(cmds))),
                ("successful_root_login", any(e.get("success") is True and e.get("username") == "root" for e in logins)),
                ("config_change", any(e.get("action") == "config_change" for e in from_bad(inter))),
                ("storage_write_storm_log", any("locked" in str(e.get("message", "")).lower() or "write storm" in str(e.get("message", "")).lower() for e in logs))],
            "sensor_manipulation": [
                ("mqtt_publish_from_bad_source", any(e.get("action") == "publish" and _SMOKE_TOPIC in str(e.get("topic", "")) for e in from_bad(mqtt))),
                ("alarm_config_change", any(e.get("action") == "config_change" and e.get("device") == "smoke_detector" for e in from_bad(inter))),
                ("ble_gatt_write", any(e.get("action") == "gatt_write" for e in ble)),
                ("threshold_modified_log", any("threshold" in str(e.get("message", "")).lower() for e in logs))],
            "unauthorized_camera_access": [
                ("camera_access_from_bad_source", any(e.get("device") == "ip_camera" for e in from_bad(inter))),
                ("unauthenticated_media_stream", any(e.get("authenticated") is False for e in media)),
                ("rtsp_port_from_bad_source", any(e.get("dst_port") == 554 for e in from_bad(net))),
                ("snapshot_request", any("snapshot" in c.lower() for c in cmd_text(from_bad(cmds))))],
            "zero_day_exploit": [
                ("crash_in_device_log", any(_CRASH.search(str(e.get("message", ""))) for e in logs)),
                ("high_entropy_payload", any((e.get("payload_entropy") or 0) >= 7.5 for e in pkts)),
                ("firmware_download_from_bad_source", any(e.get("action") == "firmware_download" for e in from_bad(inter))),
                ("oversized_command", any(len(c) >= 64 for c in cmd_text(cmds)))],
        }
        best = None
        for cat, checks in sig.items():
            hits = [n for n, ok in checks if ok]
            if len(hits) >= MIN_SIGNALS and (best is None or (len(hits) / len(checks), len(hits)) > best[1:3]):
                best = (cat, len(hits) / len(checks), len(hits), hits)
        if best is None:
            return None
        cat, share, _n, hits = best
        sev = CATEGORY_PROFILE[cat]["base_severity"]
        conf = round(min(0.99, 0.3 + 0.7 * share), 2)
        if sev == "low" and conf >= 0.9:
            sev = "medium"
        meta = [e for e in events if e.get("src_ip") in bad]
        vec = Counter(e["entry_vector"] for e in meta if e.get("entry_vector")).most_common(1)
        hp = Counter(e["honeypot"] for e in meta if e.get("honeypot")).most_common(1)
        truth = Counter(e["label"] for e in meta if e.get("label") not in (None, "benign")).most_common(1)
        return {"category": cat, "severity": sev, "confidence": conf, "signals": hits,
                "src_ips": sorted(bad), "mitre": CATEGORY_PROFILE[cat]["mitre"],
                "entry_vector": vec[0][0] if vec else "unknown", "honeypot": hp[0][0] if hp else "unknown",
                "ground_truth": truth[0][0] if truth else None}
