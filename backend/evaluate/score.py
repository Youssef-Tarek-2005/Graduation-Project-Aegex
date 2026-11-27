"""Scoring: how good is a detector on a labelled capture? Pure functions, no database.

Detectors give different kinds of alerts, so every alert is turned into the same thing first: the FLOWS it
covers. An alert covers a flow when the flow is inside the alert's time window and involves the alert's host:

    alert entity_type   covers the flows ...                                      used by
    src_ip              SENT by that address                                      rules, temporal GAT
    device              that BELONG to that device, by the AI team's own rule     LSTM-AE + VAE
                        (aegex_prep.assign_device): the originator if it is a local device (a LAN address in
                        >= 3 flows), else the responder if that one is local, else the originator

Then two levels, because each answers a different question:

  flow level      Of all attack flows, how many were covered (recall)? Of all covered flows, how many were really
                  attacks (precision)? How many normal flows were covered (false alarm rate)?
  attacker level  Of the hosts that sent attack traffic, how many were flagged at all? How many normal hosts were
                  flagged? And how long after a host's first attack flow came its first alert (time to detect)?

Ground truth = flows.label (1 = attack), from the dataset (Step 2) or from Task A's attack log (label_capture).
"""
from __future__ import annotations

import ipaddress

import numpy as np
import pandas as pd

SLACK = pd.Timedelta(seconds=1)       # AI windows are written to the second: don't lose the flow at its edge
MIN_DEVICE_FLOWS = 3                  # same as aegex_prep.MIN_DEVICE_FLOWS
LAN = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16")]


def _private(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(a in n for n in LAN)


def device_of(flows: pd.DataFrame) -> np.ndarray:
    """The device each flow belongs to, exactly as the AI team's aegex_prep.assign_device decides it."""
    count = pd.concat([flows["src_ip"], flows["dst_ip"]], ignore_index=True).value_counts()
    local = {ip: n >= MIN_DEVICE_FLOWS and _private(ip) for ip, n in count.items()}
    sp = flows["src_ip"].map(local).fillna(False).to_numpy(bool)
    dp = flows["dst_ip"].map(local).fillna(False).to_numpy(bool)
    return np.where(sp, flows["src_ip"], np.where(dp, flows["dst_ip"], flows["src_ip"]))


def covered(flows: pd.DataFrame, alerts: pd.DataFrame) -> np.ndarray:
    """True for every flow that at least one alert covers. flows: ts, src_ip, dst_ip.
    alerts: entity_type, ip (the host's address), window_start, window_end."""
    hit = np.zeros(len(flows), dtype=bool)
    if flows.empty or alerts.empty:
        return hit
    ts = pd.to_datetime(flows["ts"], utc=True).astype("int64").to_numpy()          # nanoseconds since 1970
    src, dev = flows["src_ip"].to_numpy(), device_of(flows)
    for a in alerts.itertuples(index=False):
        start = (pd.Timestamp(a.window_start).tz_convert("UTC") - SLACK).value
        end = (pd.Timestamp(a.window_end).tz_convert("UTC") + SLACK).value
        inside = (ts >= start) & (ts <= end)
        mine = (dev == a.ip) if a.entity_type == "device" else (src == a.ip)
        hit |= inside & mine
    return hit


def flow_metrics(truth: np.ndarray, pred: np.ndarray) -> dict:
    truth, pred = np.asarray(truth, bool), np.asarray(pred, bool)
    tp, fp = int((truth & pred).sum()), int((~truth & pred).sum())
    fn, tn = int((truth & ~pred).sum()), int((~truth & ~pred).sum())
    precision = tp / (tp + fp) if tp + fp else None
    recall = tp / (tp + fn) if tp + fn else None
    f1 = 2 * precision * recall / (precision + recall) if precision and recall else (0.0 if tp + fn else None)
    return {"tp": tp, "fp": fp, "fn": fn, "tn": tn, "precision": _r(precision), "recall": _r(recall),
            "f1": _r(f1), "false_alarm_rate": _r(fp / (fp + tn) if fp + tn else None)}


def attacker_metrics(flows: pd.DataFrame, alerts: pd.DataFrame) -> dict:
    """Hosts that sent attack flows vs hosts the detector flagged, and time to detect."""
    attack = flows[flows["label"] == 1]
    attackers = set(attack["src_ip"])
    hosts = set(flows["src_ip"]) | set(flows["dst_ip"])
    flagged = set(alerts["ip"]) if not alerts.empty else set()
    found = attackers & flagged
    first_attack = pd.to_datetime(attack["ts"], utc=True).groupby(attack["src_ip"]).min()
    delays = {}
    for ip in sorted(found):
        first_alert = pd.to_datetime(alerts.loc[alerts["ip"] == ip, "window_start"], utc=True).min()
        delays[ip] = round(max(0.0, (first_alert - first_attack[ip]).total_seconds()), 1)
    return {"attackers": len(attackers), "attackers_found": len(found), "attackers_missed": sorted(attackers - found),
            "normal_hosts": len(hosts - attackers), "normal_hosts_flagged": len((flagged & hosts) - attackers),
            "flagged_normal": sorted((flagged & hosts) - attackers)[:10],
            "time_to_detect_s": delays}


def evaluate(flows: pd.DataFrame, alerts: pd.DataFrame) -> dict:
    """Both levels for one detector. flows need label; alerts as in covered()."""
    pred = covered(flows, alerts)
    return {"alerts": int(len(alerts)), "flow": flow_metrics(flows["label"].to_numpy() == 1, pred),
            "attacker": attacker_metrics(flows, alerts)}


def _r(x):
    return None if x is None else round(float(x), 4)
