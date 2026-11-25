"""
Aegex realistic benchmark - shared scenario builder + scorer for every model stage (LSTM-AE, VAE, GAT).

Why: the datasets' own test splits are not realistic. Edge-IIoTset recorded each attack in a separate
file with no normal traffic, so 100 % of its test attack windows are pure attack and a one-line rule
already detects 99.9 %. In a real network an attack happens on a device that is ALSO doing its normal
work, so attack flows are mixed into normal ones. This module builds such mixed scenarios from the
real captures and measures every stage on them.

Scenario = one normal capture ("base") + one attack (capture, class) injected into it
  base period   chronological period of the base capture's clean benign flows matching the phase:
                train = first 70 %, val = next 15 %, test = last 15 %  (same as the dataset splits)
  attack flows  the attack's flows from the SAME split of the attack capture (test scenarios use only
                test-split attack flows -> never seen by any model), up to n_attack, original timing
                stretched by `slowdown` (1 = original speed, 10 / 100 = low-and-slow)
  identities    attacker IP -> a busy device of the base network (the "compromised" device);
                the attack's main target IP (if a LAN address) -> another base device (the "target")
  placement     the attack starts at a time the compromised device is active, so its attack flows
                are interleaved with its normal flows (not placed in an empty gap)
  train/val     the base is cropped to the attack time +- CROP_MARGIN (enough normal context, smaller)
  test          the WHOLE test period of the base is kept -> false alarms are measured on hours of
                real normal traffic, not on a few minutes

Then the UNCHANGED pipeline runs on the merged traffic: engineer_features (device context recomputed),
the dataset's scaler, windows_for, graphs_for.
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import numpy as np
import pandas as pd

import aegex_models as am
from aegex_models import ap, s3

BENCH_DIR = os.path.join(am.PREPROCESSED, "benchmark")
CROP_MARGIN = 1200.0          # seconds of normal traffic kept around the attack in train / val scenarios
PHASE_RANGE = {"train": (0.0, 0.70), "val": (0.70, 0.85), "test": (0.85, 1.0)}
MIN_ATTACK_FLOWS = 20

# Normal captures used as bases, attack captures injected into them (classes are discovered per capture).
# Each case lives in its dataset plug-in (scripts/aegex_datasets/<name>.py, attribute BENCH) with the
# reasons for its choices. Keys:
#   bases / attacks            capture names
#   classes                    in-scope attack classes injected (default: all found)
#   same_capture               normal traffic and attacks are in ONE continuous capture (split by time)
#   attacker_min_flows         a host counts as attacker only with >= this many attack flows
#   drop_compromised_sources   drop flows ORIGINATED by any host that sends attack flows of any class
import aegex_datasets as reg

CASES = reg.bench_cases()


def compromised_sources(ds, A, min_flows=20):
    """Hosts that originate attack flows of ANY class (>= min_flows)."""
    n = A.src_ip.value_counts()
    return set(n.index[n >= min_flows])


def _case(ds):
    return CASES.get(ds, {})


def attacker_ips(ds, A):
    """Hosts whose traffic is excluded from the normal base: sources of attack flows (of the case's
    classes, with at least attacker_min_flows flows if set)."""
    c = _case(ds)
    if c.get("classes"):
        A = A[A.attack_class.isin(c["classes"])]
    n = A.src_ip.value_counts()
    return set(n.index[n >= c.get("attacker_min_flows", 1)])

_flow_cache = {}


def _flows(ds, cap):
    k = (ds, cap)
    if k not in _flow_cache:
        if len(_flow_cache) > 6:
            _flow_cache.pop(next(iter(_flow_cache)))
        p = os.path.join(am.PREPROCESSED, "flows", ds, f"{cap}.parquet")
        if not os.path.exists(p):                  # large captures are stored as <cap>\part-NNNN.parquet
            p = os.path.join(am.PREPROCESSED, "flows", ds, cap)
        _flow_cache[k] = pd.read_parquet(p)
    return _flow_cache[k]


_base_cache, _attack_cache = {}, {}


def base_period(ds, cap, phase):
    """Clean benign flows of the base capture in the phase's chronological period (no attacker IPs)."""
    k = (ds, cap, phase)
    if k not in _base_cache:
        B = _flows(ds, cap)
        attackers = attacker_ips(ds, B[B.is_attack == 1])
        keep = (B.is_attack == 0) & ~B.src_ip.isin(attackers) & ~B.dst_ip.isin(attackers)
        if _case(ds).get("drop_compromised_sources"):
            keep &= ~B.src_ip.isin(compromised_sources(ds, B[B.is_attack == 1]))
        B = B[keep]
        lo, hi = PHASE_RANGE[phase]
        q = B.ts.quantile([lo, hi]).to_numpy()
        m = (B.ts >= q[0]) & ((B.ts < q[1]) if hi < 1 else (B.ts <= q[1]))
        _base_cache[k] = B[m].sort_values("ts", kind="stable").reset_index(drop=True)
    return _base_cache[k]


def attack_pool(ds, cap, phase):
    """{attack_class: attack flows of that class in the phase's split (chronological per class)}."""
    k = (ds, cap, phase)
    if k not in _attack_cache:
        A = _flows(ds, cap)
        A = A[A.is_attack == 1].reset_index(drop=True)
        sp = ap.chronological_split(A)
        A = A[sp == phase]
        keep = _case(ds).get("classes")
        _attack_cache[k] = {c: g.sort_values("ts", kind="stable").reset_index(drop=True)
                            for c, g in A.groupby("attack_class")
                            if len(g) >= MIN_ATTACK_FLOWS and (keep is None or c in keep)}
    return _attack_cache[k]


# Control injections (shortcut check): NORMAL flows pushed through exactly the same injection procedure
# as an attack (identity remapping, time shift, merge, feature recomputation). They are labelled as
# "attack" so every metric is computed the same way, but a perfect detector should flag them only at
# the false-alarm rate. Anything above that is detection of the injection itself, not of attacks.
#   self        the victim's OWN normal flows from the train period, replayed later (target remapped like attacks)
#   self_nomap  same, without remapping the main peer to another base device
#   other       normal flows of the busiest device of ANOTHER normal capture of the same dataset
CONTROL_KINDS = ("self", "self_nomap", "other")


def control_pool(ds, base, kind, victim):
    if kind in ("self", "self_nomap"):
        B = base_period(ds, base, "train")
        P = B[B.src_ip == victim]
        if len(P) < MIN_ATTACK_FLOWS:
            P = B[(B.src_ip == victim) | (B.dst_ip == victim)]
    else:
        P = pd.DataFrame()
        for ob in CASES[ds]["bases"]:
            if ob == base:
                continue
            B = base_period(ds, ob, "test")
            d = busy_devices(B, 1)
            if d:
                P = B[B.src_ip == d[0]]
                break
        if P.empty:
            # single-capture dataset: another busy device of the same network (its own test-period traffic)
            B = base_period(ds, base, "test")
            d = [x for x in busy_devices(B, 4) if x != victim]
            if d:
                P = B[B.src_ip == d[0]]
    P = P.sort_values("ts", kind="stable").copy()
    P["is_attack"] = 1
    P["attack_class"] = f"control_{kind}"
    return P.reset_index(drop=True)


def busy_devices(B, k=3):
    priv = B.src_ip[B.src_ip.map(ap.is_private).astype(bool)]
    return list(priv.value_counts().index[:k])


def scenario_specs(phase, datasets=None, slowdowns=(1, 10, 100), reps=2, n_attack=300, seed=0,
                   controls=(), attacks=True):
    """All scenario definitions of a phase (cheap: no feature engineering yet).
    controls: CONTROL_KINDS to add (normal traffic injected like an attack); attacks=False -> controls only."""
    rng = np.random.default_rng(seed + {"train": 0, "val": 1, "test": 2}[phase])
    specs = []
    for ds in datasets or ap.ACTIVE_DATASETS:
        if ds not in CASES:
            continue
        for base in CASES[ds]["bases"]:
            B = base_period(ds, base, phase)
            if len(B) < 30:
                continue
            blen = float(B.ts.max() - B.ts.min())
            for kind in controls:
                for r in range(reps):
                    specs.append({"phase": phase, "dataset": ds, "base": base, "attack_capture": f"control:{kind}",
                                  "attack_class": f"control_{kind}", "slowdown": 1.0, "rep": r, "n_attack": n_attack,
                                  "seed": int(rng.integers(1 << 30))})
            for acap in (CASES[ds]["attacks"] if attacks else []):
                if acap == base and not CASES[ds].get("same_capture"):
                    continue
                for cls, pool in attack_pool(ds, acap, phase).items():
                    orig = float(pool.ts.iloc[:n_attack].max() - pool.ts.iloc[:n_attack].min())
                    done = []
                    for slow in sorted(slowdowns):
                        eff = min(slow, 0.6 * blen / orig) if orig > 0 else slow
                        if done and eff < 2 * done[-1]:      # does not fit the base period -> not a new speed
                            continue
                        done.append(eff)
                        for r in range(reps):
                            specs.append({"phase": phase, "dataset": ds, "base": base, "attack_capture": acap,
                                          "attack_class": cls, "slowdown": float(slow), "rep": r, "n_attack": n_attack,
                                          "seed": int(rng.integers(1 << 30))})
            specs.append({"phase": phase, "dataset": ds, "base": base, "attack_capture": None, "attack_class": None,
                          "slowdown": 0.0, "rep": 0, "n_attack": 0, "seed": 0})          # clean: no injection
    for s in specs:
        s["id"] = (f"{s['dataset']}__{s['base']}__clean" if s["attack_capture"] is None else
                   f"{s['dataset']}__{s['base']}__{s['attack_capture'].replace(':', '-')}__{s['attack_class']}"
                   f"__x{int(s['slowdown'])}__r{s['rep']}")
    return specs


def build_scenario(spec, scaler, window, stride, snapshot_seconds):
    """spec -> dict(feat (scaled, sorted by device+ts), windows, edges, nodes, info)."""
    rng = np.random.default_rng(spec["seed"])
    B = base_period(spec["dataset"], spec["base"], spec["phase"]).copy()
    devs = busy_devices(B)
    info = dict(spec)
    if spec["attack_capture"] is None:
        M = B
        info.update(victim=None, target=None, attack_start=None, attack_end=None, n_injected=0, slowdown_effective=0.0)
    else:
        victim = devs[spec["rep"] % len(devs)]
        is_control = str(spec["attack_capture"]).startswith("control:")
        if is_control:
            kind = spec["attack_capture"].split(":", 1)[1]
            pool = control_pool(spec["dataset"], spec["base"], kind, victim)
        else:
            pool = attack_pool(spec["dataset"], spec["attack_capture"], spec["phase"])[spec["attack_class"]]
        n = min(spec["n_attack"], len(pool))
        off = 0 if spec["phase"] == "test" else int(rng.integers(0, len(pool) - n + 1))
        A = pool.iloc[off:off + n].copy()
        attacker = victim if is_control and kind != "other" else A.src_ip.value_counts().index[0]
        tgt_counts = A.dst_ip[A.dst_ip != attacker].value_counts()
        main_target = tgt_counts.index[0] if len(tgt_counts) and not (is_control and kind == "self_nomap") else None
        others = [d for d in devs if d != victim]
        target = others[0] if others else None
        b0, b1 = B.ts.min(), B.ts.max()
        orig = float(A.ts.max() - A.ts.min())
        slow, room = spec["slowdown"], 0.6 * (b1 - b0)
        if orig > 0 and orig * slow > room:            # does not fit: slow down less (never speed it up) ...
            slow = max(1.0, room / orig)
            rel = (A.ts - A.ts.min()) * slow
            A = A[(rel <= room).to_numpy()].copy()    # ... and at x1 keep only the part that fits in time
            n = len(A)
            orig = float(A.ts.max() - A.ts.min())
        span = orig * slow
        vt = B.ts[(B.src_ip == victim) | (B.dst_ip == victim)].to_numpy()
        vt = vt[vt <= b1 - span] if (vt <= b1 - span).any() else vt
        lo_q, hi_q = (0.1, 0.9) if spec["phase"] != "test" else (0.2 + 0.4 * (spec["rep"] % 2), 0.2 + 0.4 * (spec["rep"] % 2))
        start = float(np.quantile(vt, rng.uniform(lo_q, hi_q))) if len(vt) else b0 + 0.25 * (b1 - b0)
        A["ts"] = start + (A.ts - A.ts.min()) * slow
        A["ts_end"] = A.ts + A.duration
        for col in ("src_ip", "dst_ip"):
            v = A[col].to_numpy(object).copy()
            v[v == attacker] = victim
            if main_target is not None and target is not None and ap.is_private(str(main_target)):
                v[v == main_target] = target
            A[col] = v
        if spec["phase"] != "test":
            B = B[(B.ts >= start - CROP_MARGIN) & (B.ts <= start + span + CROP_MARGIN)]
        M = pd.concat([B, A], ignore_index=True)
        info.update(victim=victim, target=target if main_target is not None and ap.is_private(str(main_target)) else None,
                    attack_start=start, attack_end=start + span, n_injected=int(n), slowdown_effective=float(slow))
    M = ap.to_schema(M)
    M["capture"] = spec["id"]
    feat = ap.engineer_features(M)
    feat = scaler.transform(feat)
    feat["split"] = spec["phase"]
    feat = feat.sort_values(["device", "ts"], kind="stable").reset_index(drop=True)
    W = s3.windows_for(feat, spec["id"], window, stride)
    edges, nodes = s3.graphs_for(feat, snapshot_seconds)
    info["t0"] = float(feat.ts.min())
    info["base_hours"] = float((B.ts.max() - B.ts.min()) / 3600.0)
    info["n_flows"] = int(len(feat))
    return {"feat": feat, "windows": W, "edges": edges, "nodes": nodes, "info": info}


# ------------------------------------------------------------------------------------------ scoring
def score_scenario(sc, lstm, vae, device, rules=None, device_thr=None):
    """LSTM-AE + VAE (+ trivial-rule) outputs for every window of a built scenario.
    device_thr: optional per-device thresholds (see aegex_models.apply_device_thresholds)."""
    feat, W = sc["feat"], sc["windows"]
    T = int(lstm.meta["window"])
    F = feat[ap.FEATURES].to_numpy(np.float32)
    ds = sc["info"]["dataset"]
    S = am.score_windows(lstm.model, F, W, T, device, threshold=am.threshold_for(lstm.meta, ds),
                         score_agg=am.score_agg_of(lstm.meta))
    out = S
    if vae is not None:
        err, mu = am.vae_score_windows(vae, S, F, W, device)
        out = pd.concat([S, am.vae_outputs(vae.meta, err, mu, dataset=ds)], axis=1)
    if device_thr:
        out = am.apply_device_thresholds(out, device_thr)
    if rules and sc["info"]["dataset"] in rules:
        r = rules[sc["info"]["dataset"]]
        names = am.window_stat_names(am.VAE_STAT_BLOCKS)
        st = am.window_stats(F, W, T, am.VAE_STAT_BLOCKS)[:, names.index(r["stat"])]
        out["rule_anomaly"] = ((st > r["threshold"]) if r["higher"] else (st < r["threshold"])).astype(np.int8)
    return out


def trivial_rules(datasets, window, fpr=0.01):
    """Per dataset: the single window statistic that best separates attack from benign on the dataset's
    own VAL split (pure windows), thresholded at the val-benign 99th percentile. This is the 'no model'
    reference: a model that does not beat it adds nothing."""
    from sklearn.metrics import roc_auc_score
    names = am.window_stat_names(am.VAE_STAT_BLOCKS)
    rules = {}
    for ds in datasets:
        W = pd.read_parquet(os.path.join(am.PREPROCESSED, "windows", f"{ds}.parquet"))
        W = W[(W.split == "val") & W.split_pure & ~((W.label == 0) & (W.device_compromised == 1))]
        if W.label.nunique() < 2:
            continue
        stats, y = [], []
        for cap, g in W.groupby("capture"):
            F = pd.read_parquet(os.path.join(am.PREPROCESSED, "features", ds, f"{cap}.parquet"),
                                columns=ap.FEATURES).to_numpy(np.float32)
            stats.append(am.window_stats(F, g, window, am.VAE_STAT_BLOCKS)); y.append(g.label.to_numpy())
        X, y = np.concatenate(stats), np.concatenate(y)
        best = (0.5, None, True)
        for j, nm in enumerate(names):
            if np.std(X[:, j]) < 1e-9:
                continue
            auc = roc_auc_score(y, X[:, j])
            if max(auc, 1 - auc) > best[0]:
                best = (max(auc, 1 - auc), j, auc >= 0.5)
        auc, j, up = best
        xb = X[y == 0, j]
        thr = float(np.quantile(xb, 1 - fpr) if up else np.quantile(xb, fpr))
        rules[ds] = {"stat": names[j], "higher": bool(up), "threshold": thr, "val_auc": float(auc)}
    return rules


# ------------------------------------------------------------------------------------------ metrics
METHODS = {"lstm": "lstm_anomaly", "vae": "vae_anomaly", "either": None, "rule": "rule_anomaly"}


def flags(scored, method):
    if method == "either":
        return ((scored.lstm_anomaly == 1) | (scored.vae_anomaly == 1)).to_numpy()
    col = METHODS[method]
    return scored[col].to_numpy() == 1 if col in scored else None


def scenario_metrics(scored, info, methods=("lstm", "vae", "either", "rule")):
    """Window- and incident-level numbers of one scenario for every method."""
    att = scored.n_attack.to_numpy() > 0
    frac = scored.attack_frac.to_numpy()
    # false alarms are counted on devices that carry NO attack flow; normal windows of the device that IS
    # attacking / being flooded are neither clean normal nor attack and are left out of both rates
    involved = scored.device.isin(set(scored.device[att])).to_numpy()
    benign = ~att & ~involved
    hours = max(info["base_hours"], 1e-6)
    rows = []
    for m in methods:
        f = flags(scored, m)
        if f is None:
            continue
        r = {"id": info["id"], "dataset": info["dataset"], "base": info["base"], "attack": info["attack_class"],
             "attack_capture": info["attack_capture"], "slowdown": info["slowdown"], "rep": info["rep"],
             "speed": info.get("slowdown_effective"), "n_injected": info.get("n_injected"),
             "method": m, "attack_windows": int(att.sum()), "attack_windows_mixed": int((att & (frac < 1)).sum()),
             "detected_windows": int(f[att].sum()),
             "low_share_windows": int((att & (frac < 0.5)).sum()), "low_share_detected": int(f[att & (frac < 0.5)].sum()),
             "benign_windows": int(benign.sum()), "false_alarm_windows": int(f[benign].sum()),
             "base_hours": hours, "incident_detected": None, "time_to_detect_s": None}
        if att.any():
            r["incident_detected"] = bool(f[att].any())
            if r["incident_detected"]:
                r["time_to_detect_s"] = float(scored.t_end.to_numpy()[att & f].min() - info["attack_start"])
        rows.append(r)
    return rows
