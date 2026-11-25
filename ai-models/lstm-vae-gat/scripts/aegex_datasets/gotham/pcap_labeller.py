"""
Aegex preprocessing - Gotham Dataset 2025 adapter (Belarbi et al., Zenodo 10.5281/zenodo.14502760, CC BY 4.0).

Layout inside GothamDataset2025.zip (read-only, streamed, never extracted):
    raw/benign/iotsim-<device>-<n>_0-0_to_OpenvSwitch-<s>_<p>-0.pcap          78 devices, 2 h benign
    raw/malicious/<scenario>/iotsim-<device>-<n>_..._.pcap                     8 devices per scenario
    processed/iotsim-<device>-<n>.csv                                          official per-packet labels

Each pcap is captured on ONE device's link to its switch, so a packet between two monitored devices is in
both captures (with a different TTL / IP checksum / MACs after routing). One scenario = one capture:
    1. k-way merge of the scenario's per-device pcaps by timestamp,
    2. duplicate removal: same IP packet (src, dst, proto, IP id, length, first 16 L4 bytes; TTL and
       checksum ignored) seen in a DIFFERENT device capture within DEDUP_WINDOW s is dropped,
    3. per-packet labels = the official rules of github.com/othmbela/gotham-network-packet-labeller
       (metadata/*.json, transcribed below), applied in the same order (benign device<->server first,
       then malicious rules, first match wins, everything else "Unknown"),
    4. FlowBuilder -> flows; the flow's fine label = most frequent malicious packet label, else Benign,
       else Unknown.

Deviation from the official labeller, on purpose: the official code turns "192.168.33.10" into a regex,
so it would also match 192.168.33.100 etc.; here IPs match exactly and "192.168.x.x" means 192.168.*.
`validate_against_official()` measures how far our labels are from the official processed CSVs.
"""
import heapq
import io
import os
import re
import zipfile

import numpy as np
import pandas as pd

import aegex_prep as ap

ZIP = os.path.join("gotham_2025", "GothamDataset2025.zip")
ORIGINAL_NAME = "gotham_2025/GothamDataset2025.zip"     # key in ORIGINALS_SHA256.txt
DEDUP_WINDOW = 0.5                                      # seconds

# scenario folder in the zip -> capture name
SCENARIOS = {
    "benign": "benign",
    "mirai-infection": "mirai_infection",
    "mirai-dos": "mirai_dos",
    "merlin": "merlin",
    "network-scanning": "network_scanning",
    "coap-amplificator": "coap_amplification",
}
# scenario -> official metadata file (network-scanning uses the masscan rules)
RULE_FILE = {"mirai-infection": "mirai-infection", "mirai-dos": "mirai-dos", "merlin": "merlin",
             "network-scanning": "masscan", "coap-amplificator": "coap-amplificator"}

# ------------------------------------------------------------------ metadata-benign.json (device IPs, servers)
def _rng(prefix, a, b):
    return [f"{prefix}.{i}" for i in range(a, b + 1)]


DEVICES = {   # device: (device IPs by instance number 1..n, server IPs)
    "iotsim-air-quality": (["192.168.18.17"], ["192.168.2.1", "192.168.0.2", "192.168.0.3"]),
    "iotsim-building-monitor": (_rng("192.168.17", 10, 14), ["192.168.1.1", "192.168.0.2", "192.168.0.3"]),
    "iotsim-city-power": (["192.168.18.18"], ["192.168.2.3", "192.168.0.2", "192.168.0.3"]),
    "iotsim-combined-cycle": (_rng("192.168.20", 10, 19), ["192.168.4.1", "192.168.0.2", "192.168.0.3"]),
    "iotsim-combined-cycle-tls": (_rng("192.168.20", 20, 24), ["192.168.4.3", "192.168.0.2", "192.168.0.3"]),
    "iotsim-cooler-motor": (_rng("192.168.19", 10, 19) + _rng("192.168.19", 30, 34),
                            ["192.168.3.1", "192.168.0.2", "192.168.0.3", "192.168.0.4"]),
    "iotsim-domotic-monitor": (_rng("192.168.18", 10, 14), ["192.168.2.1", "192.168.0.2", "192.168.0.3"]),
    "iotsim-hydraulic-system": (_rng("192.168.20", 30, 44),
                                ["192.168.4.2", "192.168.0.2", "192.168.0.3", "192.168.0.4"]),
    "iotsim-ip-camera-museum": (["192.168.17.15", "192.168.17.16"], ["192.168.1.2", "192.168.0.2", "192.168.0.3"]),
    "iotsim-ip-camera-street": (["192.168.18.15", "192.168.18.16"], ["192.168.2.2", "192.168.0.2", "192.168.0.3"]),
    "iotsim-predictive-maintenance": (_rng("192.168.19", 20, 29) + _rng("192.168.19", 40, 44),
                                      ["192.168.3.1", "192.168.0.2", "192.168.0.3", "192.168.0.4"]),
    "iotsim-stream-consumer": (["192.168.17.17", "192.168.17.18"], ["192.168.1.2", "192.168.0.2", "192.168.0.3"]),
}
DEVICE_OF_IP = {ip: d for d, (ips, _) in DEVICES.items() for ip in ips}
SERVERS = {d: set(s) for d, (_, s) in DEVICES.items()}
ANY = "192.168.x.x"


# ------------------------------------------------------------------ malicious rules (metadata-<event>.json)
def _both(a, b, label, proto=None):
    return [(a, b, None, None, proto, label), (b, a, None, None, proto, label)]


def _flood(prefix, protos):
    pairs = [("192.168.20.10", "192.168.18.18"), ("192.168.17.10", "192.168.18.10"),
             ("192.168.17.15", "192.168.18.15")]
    out = []
    for a, b in pairs:
        for proto, kind in protos:
            out += _both(a, b, f"{prefix} {kind} Flooding", proto)
    return out


# rule = (src, dst, sport, dport, ip_proto, label); first match wins
RULES = {
    "mirai-dos": _both("192.168.33.10", ANY, "Mirai C&C Communication")
                 + _flood("Mirai", [(17, "UDP"), (1, "UDP"), (6, "TCP"), (47, "GRE")]),
    "mirai-infection": [("192.168.0.100", ANY, 65148, 23, None, "TCP Scan"),
                        (ANY, "192.168.0.100", 23, 65148, None, "TCP Scan"),
                        ("192.168.0.100", ANY, 65148, 2323, None, "TCP Scan"),
                        (ANY, "192.168.0.100", 2323, 65148, None, "TCP Scan")]
                       + _both("192.168.0.100", ANY, "Telnet Brute Force")
                       + _both("192.168.33.11", ANY, "Reporting")
                       + _both("192.168.33.10", ANY, "Mirai C&C Communication")
                       + _both("192.168.33.12", ANY, "Ingress Tool Transfer")
                       + _both("192.168.33.13", ANY, "File Download")
                       + [(ANY, ANY, None, None, None, "TCP Scan")],
    "merlin": _both(ANY, "192.168.34.10", "Merlin C&C Communication")
              + _flood("Merlin", [(1, "ICMP")]) + _flood("Merlin", [(17, "UDP")]) + _flood("Merlin", [(6, "TCP")]),
    "masscan": _both("192.168.35.10", ANY, "TCP Scan"),
    "coap-amplificator": _both("192.168.35.10", "192.168.20.10", "UDP Scan")
                         + _both("192.168.0.200", "192.168.20.10", "CoAP Amplification"),
}

# official grouped label (config.py) and our project taxonomy, per scenario
GROUP = {"Benign": "Benign", "TCP Scan": "Network Scanning", "UDP Scan": "Network Scanning",
         "Telnet Brute Force": "Brute Force", "Reporting": "Infection", "Ingress Tool Transfer": "Infection",
         "File Download": "Infection", "CoAP Amplification": "DoS", "Merlin TCP Flooding": "DoS",
         "Merlin UDP Flooding": "DoS", "Merlin ICMP Flooding": "DoS", "Mirai TCP Flooding": "DoS",
         "Mirai UDP Flooding": "DoS", "Mirai GRE Flooding": "DoS",
         "Merlin C&C Communication": "C&C Communication", "Mirai C&C Communication": "C&C Communication"}


def project_class(scenario, label):
    """-> (attack_class, campaign). Mirai lifecycle before the floods = 'mirai'; any flood = 'ddos'."""
    if label in ("Benign", "Unknown"):
        return "benign", ""
    if label.startswith("Mirai") and label.endswith("Flooding"):
        return "ddos", "mirai"
    if label.startswith("Merlin"):
        return ("ddos" if label.endswith("Flooding") else "other"), "merlin"
    if scenario in ("mirai-infection", "mirai-dos"):
        return "mirai", "mirai"                   # telnet scan, brute force, loader, reporting, C&C
    if label == "CoAP Amplification":
        return "ddos", ""
    return "scanning", ""                          # masscan / UDP scan


def _ip_match(pattern, ip):
    return ip.startswith("192.168.") if pattern == ANY else ip == pattern


class Labeller:
    def __init__(self, scenario):
        self.rules = RULES.get(RULE_FILE.get(scenario, ""), [])
        self.cache = {}

    def __call__(self, src, dst, ipproto, sport, dport):
        k = (src, dst, ipproto, sport, dport)
        lab = self.cache.get(k)
        if lab is not None:
            return lab
        lab = self._label(src, dst, ipproto, sport, dport)
        if len(self.cache) > 1_000_000:          # floods with random ports
            self.cache.clear()
        self.cache[k] = lab
        return lab

    def _label(self, src, dst, ipproto, sport, dport):
        if ipproto is None:                      # ARP / non-IP: no rule in the official labeller
            return "Unknown"
        d = DEVICE_OF_IP.get(src)
        if d is not None and dst in SERVERS[d]:
            return "Benign"
        d = DEVICE_OF_IP.get(dst)
        if d is not None and src in SERVERS[d]:
            return "Benign"
        for rs, rd, rsp, rdp, rp, label in self.rules:
            if rp is not None and ipproto != rp:
                continue
            if rsp is not None and (ipproto != 6 or sport != rsp or dport != rdp):
                continue
            if _ip_match(rs, src) and _ip_match(rd, dst):
                return label
        return "Unknown"


def reduce_tags(d):
    mal = {k: v for k, v in d.items() if k not in ("Benign", "Unknown")}
    if mal:
        return max(mal, key=mal.get)
    return "Benign" if "Benign" in d else "Unknown"


# ------------------------------------------------------------------ zip layout
_MEMBER = re.compile(r"(?:^|/)raw/(?:benign|malicious/([^/]+))/(iotsim-[a-z\-]+?-\d+)_[^/]*\.pcap$")


def list_members(zip_path):
    """-> {scenario: [(device_instance, member), ...]}"""
    out = {}
    with zipfile.ZipFile(zip_path) as z:
        for n in z.namelist():
            m = _MEMBER.search(n)
            if m:
                out.setdefault(m.group(1) or "benign", []).append((m.group(2), n))
    return {k: sorted(v) for k, v in out.items()}


def device_ip(instance):
    """'iotsim-combined-cycle-10' -> '192.168.20.19' (official rule: n-th IP of the device list)."""
    name, n = instance.rsplit("-", 1)
    return DEVICES[name][0][int(n) - 1]


# ------------------------------------------------------------------ packet helpers
def dedup_key(frame, linktype):
    """(key bytes, ip_proto or None). Key ignores MACs, TTL and IP checksum (changed by routing)."""
    off = None
    if linktype == 1 and len(frame) >= 14:
        et, off = (frame[12] << 8) | frame[13], 14
        while et in (0x8100, 0x88A8) and len(frame) >= off + 4:
            et, off = (frame[off + 2] << 8) | frame[off + 3], off + 4
    elif linktype == 113 and len(frame) >= 16:
        et, off = (frame[14] << 8) | frame[15], 16
    elif linktype in (101, 228):
        et, off = 0x0800, 0
    if off is None:
        return bytes(frame), None
    if et != 0x0800 or len(frame) < off + 20:
        return bytes(frame[off:]), None               # ARP etc.: whole L2 payload
    ihl = (frame[off] & 0x0F) * 4
    l4 = off + ihl
    key = bytes(frame[off + 2:off + 6]) + bytes(frame[off + 9:off + 10]) + bytes(frame[off + 12:off + 20]) \
        + bytes(frame[l4:l4 + 16])
    return key, frame[off + 9]


def _stream(zip_path, member, idx):
    z = zipfile.ZipFile(zip_path)
    fh = z.open(member)
    try:
        for t, frame, lt in ap.read_capture(fh):
            if t is not None:
                yield t, idx, frame, lt
    finally:
        fh.close()
        z.close()


def merged_packets(zip_path, members, stats):
    """k-way timestamp merge of the per-device captures with cross-capture duplicate removal."""
    streams = [_stream(zip_path, m, i) for i, (_, m) in enumerate(members)]
    seen, last_purge = {}, None
    for t, idx, frame, lt in heapq.merge(*streams, key=lambda x: (x[0], x[1])):
        stats["packets_read"] += 1
        key, ipproto = dedup_key(frame, lt)
        prev = seen.get(key)
        if prev is not None and prev[1] != idx and t - prev[0] <= DEDUP_WINDOW:
            stats["duplicates_removed"] += 1
            continue
        seen[key] = (t, idx)
        if last_purge is None:
            last_purge = t
        elif t - last_purge > 2.0:
            cut = t - DEDUP_WINDOW
            seen = {k: v for k, v in seen.items() if v[0] >= cut}
            last_purge = t
        yield t, frame, lt, ipproto


def build_scenario_flows(zip_path, scenario, members, log=print):
    stats = {"packets_read": 0, "duplicates_removed": 0, "skipped_non_ipv4": 0,
             "devices": [d for d, _ in members], "packet_labels": {}}
    lab = Labeller(scenario)
    fb = ap.FlowBuilder(tag_reducer=reduce_tags)
    counts = stats["packet_labels"]
    last_expire, n = None, 0
    for t, frame, lt, ipproto in merged_packets(zip_path, members, stats):
        p = ap.parse_packet(frame, lt)
        if p is None:
            stats["skipped_non_ipv4"] += 1
            continue
        proto, src, sp, dst, dp = p[0], p[1], p[2], p[3], p[4]
        label = lab(src, dst, ipproto, sp, dp) if proto != "arp" else "Unknown"
        counts[label] = counts.get(label, 0) + 1
        fb.add(t, p, int(label not in ("Benign", "Unknown")), label)
        n += 1
        if last_expire is None:
            last_expire = t
        elif t - last_expire > 30:
            fb.expire(t)
            last_expire = t
        if n % 2_000_000 == 0:
            log(f"    {n:,} packets, {fb.n_flows():,} flows, {stats['duplicates_removed']:,} duplicates")
    df = fb.finish()
    if "tag" not in df.columns:
        df["tag"] = "Unknown"
    cls = [project_class(scenario, x) for x in df.tag]
    df["attack_class"] = [c for c, _ in cls]
    df["campaign"] = [c for _, c in cls]
    df["is_attack"] = (df.attack_class != "benign").astype("int8")
    df["original_label"] = df.tag.map(lambda x: f"{x} ({GROUP.get(x, x)})")
    df["label_note"] = np.where(df.tag == "Unknown", "no official Gotham rule matched; treated as benign", "")
    stats["flows"] = len(df)
    stats["unknown_flows"] = int((df.tag == "Unknown").sum())
    return df.drop(columns=["tag"]), stats


# ------------------------------------------------------------------ check against the official labels
def validate_against_official(zip_path, flows_by_capture, max_rows_per_device=2_000_000):
    """Compare packet-label counts: our rules vs processed/iotsim-<device>.csv (official, tab-separated).
    Returns a DataFrame of official grouped label counts per device. Read-only."""
    rows = []
    with zipfile.ZipFile(zip_path) as z:
        for n in z.namelist():
            if "/processed/" not in "/" + n or not n.endswith(".csv"):
                continue
            with z.open(n) as fh:
                head = fh.read(4096).decode("utf-8", "replace")
            sep = "\t" if head.count("\t") > head.count(",") else ","
            with z.open(n) as fh:
                df = pd.read_csv(io.TextIOWrapper(fh, "utf-8"), sep=sep, nrows=max_rows_per_device,
                                 usecols=lambda c: c in ("label", "label_category"), dtype=str)
            col = "label" if "label" in df.columns else df.columns[-1]
            for k, v in df[col].value_counts().items():
                rows.append({"device": os.path.basename(n)[:-4], "label": k, "packets": int(v)})
    return pd.DataFrame(rows)
