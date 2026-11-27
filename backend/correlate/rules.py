"""The correlation baseline: simple, explainable rules that turn flows + events into incidents.

No machine learning. It is the yardstick for the AI models (Step 8): they count for what they find beyond it.

Every rule looks at ONE source address in ONE minute (fixed 60-second buckets):

    rule          fires when, in one minute from one source                         scenario
    port_scan     >= 20 different ports tried on one host                           vulnerability_scanning
    host_sweep    >= 20 different hosts tried, mostly unanswered (or ARP requests)  vulnerability_scanning
    telnet_scan   Telnet (23 / 2323) tried on >= 5 different hosts                  mirai_botnet
    flood         >= 100 connections to one service (same host and port)            dos
    brute_force   >= 5 failed logins (Cowrie / honeypot login_failed events)        bruteforce
                  within 10 minutes (fail2ban's defaults: maxretry 5, findtime 10 min)

The thresholds are round numbers fixed before any evaluation, not tuned on the test data, so the baseline is
honest. Change them here only, and say so in the results.

Correlation: hits of the same source less than MERGE_GAP minutes apart become ONE incident, even when different
rules fired (e.g. an ARP sweep, then Telnet scans = one Mirai incident). The incident then collects everything
else that source did in its time span: flows, the hosts and honeypot devices it reached, and its events from
the other sources (Cowrie logins, honeypot page hits, ...).

Rates are per minute of the traffic's OWN clock. A replay sped up 4x (Step 6) packs four minutes into one, so the
flow rules see four times the rate and fire more; score the baseline on traffic at its original speed.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta

import pandas as pd

BUCKET = 60                     # seconds per bucket
LOGIN_WINDOW = 600              # seconds: failed logins are counted over 10 minutes (fail2ban's default findtime)
MERGE_GAP = 2                   # buckets: hits closer than this belong to one incident
RST = 4
FAILED_STATES = {"S0", "REJ", "RSTOS0", "RSTR", "SH", "SHR", "OTH"}
TELNET = {23, 2323}

RULES = {   # name: (threshold, scenario, what the number means)
    "port_scan": (20, "vulnerability_scanning", "ports tried on one host"),
    "host_sweep": (20, "vulnerability_scanning", "hosts tried, mostly unanswered"),
    "telnet_scan": (5, "mirai_botnet", "hosts tried on Telnet"),
    "flood": (100, "dos", "connections to one service"),
    "brute_force": (5, "bruteforce", "failed logins in 10 minutes"),
}
PRIORITY = ["mirai_botnet", "dos", "bruteforce", "vulnerability_scanning"]   # an incident's scenario: the first hit


@dataclass
class Incident:
    src_ip: str
    start: datetime
    end: datetime
    rules: dict = field(default_factory=dict)          # rule -> highest value in one minute
    flows: int = 0
    failed_share: float = 0.0
    targets: list = field(default_factory=list)        # most-contacted hosts
    devices: list = field(default_factory=list)        # our honeypot devices it reached
    events: dict = field(default_factory=dict)         # event_type -> count
    flow_ids: list = field(default_factory=list)       # a sample, for the evidence

    @property
    def scenario(self) -> str:
        found = {RULES[r][1] for r in self.rules}
        return next(s for s in PRIORITY if s in found)

    @property
    def score(self) -> float:
        """How far over the line the strongest rule went: 1.0 = exactly at its threshold."""
        return round(max(v / RULES[r][0] for r, v in self.rules.items()), 2)

    @property
    def severity(self) -> str:
        s = self.score
        return "critical" if s >= 10 else "high" if s >= 3 else "medium" if s >= 1.5 else "low"

    @property
    def summary(self) -> str:
        parts = [f"{r.replace('_', ' ')}: {v:,} {RULES[r][2]}" + ("" if r == "brute_force" else " in a minute")
                 for r, v in
                 sorted(self.rules.items(), key=lambda kv: -kv[1] / RULES[kv[0]][0])]
        return f"{self.src_ip} -> " + "; ".join(parts)


# --------------------------------------------------------------------------- per-minute numbers
def _prepare(flows: pd.DataFrame) -> pd.DataFrame:
    f = flows.copy()
    f["bucket"] = (pd.to_datetime(f["ts"], utc=True).astype("int64") // 10**9 // BUCKET).astype("int64")
    resp = pd.to_numeric(f.get("resp_pkts"), errors="coerce")
    bwd = pd.to_numeric(f.get("bwd_flags"), errors="coerce").fillna(0).astype(int)
    state = f.get("conn_state", pd.Series(index=f.index, dtype=object)).fillna("")
    f["failed"] = (f["proto"] == "tcp") & ((resp.fillna(-1) == 0) | ((bwd & RST) > 0) | state.isin(FAILED_STATES))
    f["dst_port"] = pd.to_numeric(f["dst_port"], errors="coerce")
    return f


def minute_numbers(flows: pd.DataFrame) -> pd.DataFrame:
    """One row per (source, minute) with the numbers the flow rules compare."""
    if flows.empty:
        return pd.DataFrame(columns=["src_ip", "bucket", "port_scan", "host_sweep", "telnet_scan", "flood"])
    f = _prepare(flows)
    g = f.groupby(["src_ip", "bucket"])
    out = pd.DataFrame({"flows": g.size(), "hosts": g["dst_ip"].nunique(), "failed_share": g["failed"].mean()})
    out["port_scan"] = f.groupby(["src_ip", "bucket", "dst_ip"])["dst_port"].nunique().groupby(level=[0, 1]).max()
    # a flood hammers ONE service (host + port); a scan touches many ports, so it must not count as a flood
    out["flood"] = f.groupby(["src_ip", "bucket", "dst_ip", "dst_port"], dropna=False).size().groupby(level=[0, 1]).max()
    arp = f[f["proto"] == "arp"].groupby(["src_ip", "bucket"])["dst_ip"].nunique()
    tel = f[f["dst_port"].isin(TELNET) & (f["proto"] == "tcp")].groupby(["src_ip", "bucket"])["dst_ip"].nunique()
    out["arp_hosts"] = arp.reindex(out.index).fillna(0)
    out["telnet_scan"] = tel.reindex(out.index).fillna(0)
    unanswered = out["hosts"].where(out["failed_share"] >= 0.5, 0)
    out["host_sweep"] = pd.concat([unanswered, out["arp_hosts"]], axis=1).max(axis=1)
    return out.reset_index()


def login_numbers(events: pd.DataFrame) -> pd.DataFrame:
    """Failed logins of each source in the LOGIN_WINDOW before each failed login, per (source, minute).
    Logins use a longer window than the flow rules: fail2ban's default (5 failures within 10 minutes)."""
    empty = pd.DataFrame(columns=["src_ip", "bucket", "brute_force"])
    if events.empty:
        return empty
    e = events[(events["event_type"] == "login_failed") & events["src_ip"].notna()].copy()
    if e.empty:
        return empty
    e["ts"] = pd.to_datetime(e["ts"], utc=True)
    e = e.sort_values("ts")
    e["n"] = 1
    e["brute_force"] = (e.set_index("ts").groupby("src_ip")["n"].rolling(f"{LOGIN_WINDOW}s").sum()
                        .reset_index(level=0, drop=True).to_numpy())
    e["bucket"] = (e["ts"].astype("int64") // 10**9 // BUCKET).astype("int64")
    return e.groupby(["src_ip", "bucket"])["brute_force"].max().astype(int).reset_index()


# --------------------------------------------------------------------------- rules -> incidents
def hits(flows: pd.DataFrame, events: pd.DataFrame) -> list[tuple[str, int, str, int]]:
    """Every (source, minute, rule, value) where a rule reached its threshold."""
    out = []
    m = minute_numbers(flows)
    for rule in ("port_scan", "host_sweep", "telnet_scan", "flood"):
        hit = m[m[rule] >= RULES[rule][0]]
        out += [(r.src_ip, int(r.bucket), rule, int(getattr(r, rule))) for r in hit.itertuples(index=False)]
    lg = login_numbers(events)
    hit = lg[lg["brute_force"] >= RULES["brute_force"][0]]
    out += [(r.src_ip, int(r.bucket), "brute_force", int(r.brute_force)) for r in hit.itertuples(index=False)]
    return sorted(out, key=lambda h: (h[0], h[1]))


def correlate(flows: pd.DataFrame, events: pd.DataFrame | None = None) -> list[Incident]:
    """Rules on flows (+ events) -> incidents, one per source and burst of activity."""
    events = events if events is not None else pd.DataFrame(columns=["ts", "src_ip", "event_type"])
    groups: list[list] = []
    for h in hits(flows, events):
        if groups and groups[-1][0][0] == h[0] and h[1] - groups[-1][-1][1] <= MERGE_GAP:
            groups[-1].append(h)
        else:
            groups.append([h])
    if not groups:
        return []
    f = _prepare(flows) if not flows.empty else flows
    ev = events.copy()
    if not ev.empty:
        ev["ts"] = pd.to_datetime(ev["ts"], utc=True)
    out = []
    for grp in groups:
        src = grp[0][0]
        b0, b1 = grp[0][1], grp[-1][1]
        rules: dict = {}
        for _, _, rule, value in grp:
            rules[rule] = max(rules.get(rule, 0), value)
        mine = f[(f["src_ip"] == src) & f["bucket"].between(b0, b1)] if not f.empty else f
        if not mine.empty:
            start, end = pd.to_datetime(mine["ts"], utc=True).min(), pd.to_datetime(mine["ts"], utc=True).max()
        else:
            start = pd.Timestamp(b0 * BUCKET, unit="s", tz="UTC")
            end = pd.Timestamp((b1 + 1) * BUCKET, unit="s", tz="UTC")
        inc = Incident(src, start.to_pydatetime(), end.to_pydatetime(), rules)
        if not mine.empty:
            inc.flows = len(mine)
            inc.failed_share = round(float(mine["failed"].mean()), 3)
            inc.targets = mine["dst_ip"].value_counts().head(10).index.tolist()
            if "device_id" in mine:
                inc.devices = sorted({d for d in mine["device_id"].dropna() if d})
            if "flow_id" in mine:
                inc.flow_ids = mine["flow_id"].head(20).tolist()
        if not ev.empty:
            pad = timedelta(seconds=BUCKET)
            near = ev[(ev["src_ip"] == src) & (ev["ts"] >= start - pad) & (ev["ts"] <= end + pad)]
            inc.events = {k: int(v) for k, v in near["event_type"].value_counts().items()}
            if "device_id" in near:
                inc.devices = sorted(set(inc.devices) | {d for d in near["device_id"].dropna() if d})
        out.append(inc)
    return out
