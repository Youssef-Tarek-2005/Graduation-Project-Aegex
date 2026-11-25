"""
Aegex models - shared code for every model stage (LSTM-AE now; VAE and GAT plug into the same pieces).

What lives here
  * LSTMAutoencoder              the stage-1 sequence model (PyTorch)
  * ModelBundle                  a self-describing saved model: weights + the exact feature order,
                                 window size, scalers, threshold and flow-builder settings it was
                                 trained with. Loading checks these against the current pipeline,
                                 so a model can never silently be fed differently-built inputs.
  * window_batches / score_windows   turn feature rows + window index into scores
  * traffic_to_inputs            the SAME preprocessing for real/live traffic (pcap -> flows ->
                                 features -> windows -> graph snapshots) as for the datasets
  * OUTPUT CONTRACT              column names the VAE / GAT / attack-analysis stages consume

Output contract (stage 1 -> later stages)
  window table  (one row per LSTM window)
      capture, device, row_start, row_end, n_flows, t_start, t_end,
      [split, label, window_class, attack_frac]      (only for labelled datasets)
      lstm_error        mean reconstruction error of the window
      lstm_score        lstm_error / threshold   (>= 1  ->  anomaly)   <- scale-free, use this
      lstm_anomaly      0/1
      lstm_top_features the 3 features reconstructed worst (for the attack analysis / RAG report)
      z_0 .. z_{k-1}    latent vector of the window (VAE input / GAT node embedding)
  node-snapshot table  (one row per device per GAT snapshot, keyed exactly like graph nodes)
      capture, snapshot, node, lstm_max_score, lstm_mean_score, lstm_n_windows, lstm_any_anomaly, z_0..
      A window is assigned to the snapshot in which it ENDS (its evidence is complete then), which
      is also what a live system can compute.

Output contract (stage 2 = VAE, same window keys as stage 1)
  window columns
      vae_error           negative ELBO (reconstruction + KL) of the window's input vector
      vae_score           vae_error / threshold   (>= 1 -> anomaly)
      vae_anomaly         0/1
      vae_confidence      share of normal (validation) windows that are LESS unusual; 0.99 = more unusual
                          than 99 % of normal traffic  (calibrated confidence for the attack analysis)
      vae_class_hint      closest KNOWN class in latent space (benign / scanning / ddos / mirai / ...)
      vae_class_distance  distance to it in units of that class's radius (< 1 = inside the class)
      vae_novelty         distance to the closest known class (same units)
      zero_day_candidate  vae_anomaly AND vae_novelty > 1  (unlike normal traffic AND every known attack)
      mu_0 .. mu_{k-1}    latent mean (GAT node embedding)
  node-snapshot table: vae_max_score, vae_mean_score, vae_n_windows, vae_any_anomaly, mu_*,
                       zero_day_candidate (max), vae_confidence (max)

Nothing here hard-codes a dataset or a feature: datasets come from aegex_prep.ACTIVE_DATASETS / the
bundle, features from aegex_prep.FEATURES (USE_DEVICE_CONTEXT switch), and every bundle refuses to load
if the preprocessing that built its inputs has changed.
"""
import datetime as _dt
import hashlib
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
PREP = os.path.abspath(os.path.join(HERE, "..", "preprocessing"))
sys.path.insert(0, PREP)

import numpy as np
import pandas as pd
import torch
import torch.nn as nn
from torch.nn.utils.rnn import pack_padded_sequence

import aegex_prep as ap
import step3_sequences_graphs as s3

DATA_ROOT = ap.OUT_DIR                       # where results are written (AEGEX_OUT, default: project folder)
PREPROCESSED = ap.PREPROCESSED_DIR
MODELS_DIR = os.path.join(DATA_ROOT, "models")
BUNDLE_FORMAT = 1


def pipeline_fingerprint():
    """Everything that changes what a model input means. Stored in every bundle."""
    return {"feature_order": list(ap.FEATURES), "continuous": list(ap.CONT_FEATURES),
            "binary": list(ap.BIN_FEATURES), "tcp_udp_icmp_timeouts": dict(ap.TIMEOUT),
            "active_timeout": ap.ACTIVE_TIMEOUT, "service_ports": {k: sorted(v) for k, v in ap.SERVICE_PORTS.items()},
            "min_device_flows": ap.MIN_DEVICE_FLOWS, "scaler_min_scale": ap.MIN_SCALE,
            "scaler_tail_start": ap.TAIL_START,
            "device_context": {"enabled": ap.USE_DEVICE_CONTEXT, "new_peer_gap": ap.NEW_PEER_GAP,
                               "rate_window": ap.RATE_WINDOW, "context_window": ap.CONTEXT_WINDOW}}


def fingerprint_hash(fp):
    return hashlib.sha256(json.dumps(fp, sort_keys=True).encode()).hexdigest()[:16]


def pick_device(name="auto"):
    if name == "auto":
        return torch.device("cuda" if torch.cuda.is_available() else "cpu")
    return torch.device(name)


# =============================================================================================
# Models (registry: a bundle's "model_type" names the class, its "init" holds the constructor args,
# so ONE loader serves the LSTM-AE, the VAE and later the GAT)
# =============================================================================================
MODEL_REGISTRY = {}


def register(name):
    def deco(cls):
        MODEL_REGISTRY[name] = cls
        return cls
    return deco


@register("lstm_autoencoder")
class LSTMAutoencoder(nn.Module):
    """Sequence-to-sequence LSTM autoencoder over windows of flows.

    encoder LSTM -> last hidden state -> latent z (k dims) -> repeated over time -> decoder LSTM
    -> per-step reconstruction of all 45 features. Trained on BENIGN windows only, so attacks
    reconstruct badly. Variable-length windows are handled with packing + a mask.
    """

    def __init__(self, n_features, hidden=64, latent=16, layers=1, dropout=0.0):
        super().__init__()
        d = dropout if layers > 1 else 0.0
        self.enc = nn.LSTM(n_features, hidden, layers, batch_first=True, dropout=d)
        self.to_z = nn.Linear(hidden, latent)
        self.from_z = nn.Linear(latent, hidden)
        self.dec = nn.LSTM(hidden, hidden, layers, batch_first=True, dropout=d)
        self.out = nn.Linear(hidden, n_features)

    def encode(self, x, mask):
        lengths = mask.sum(1).clamp(min=1).cpu()
        packed = pack_padded_sequence(x, lengths, batch_first=True, enforce_sorted=False)
        _, (h, _) = self.enc(packed)
        return self.to_z(h[-1])

    def decode(self, z, T):
        y, _ = self.dec(self.from_z(z).unsqueeze(1).expand(-1, T, -1).contiguous())
        return self.out(y)

    def forward(self, x, mask):
        z = self.encode(x, mask)
        return self.decode(z, x.shape[1]), z


def masked_errors(recon, x, mask):
    """-> (window error [B], per-feature window error [B, F]) using only real (unpadded) steps."""
    se = (recon - x) ** 2                                   # [B, T, F]
    m = mask.unsqueeze(-1).float()
    n = m.sum(1).clamp(min=1)                               # [B, 1]
    per_feat = (se * m).sum(1) / n                          # [B, F]
    return per_feat.mean(1), per_feat


# How a window's per-flow errors become ONE window score.
#   mean     average over the window's flows (v1-v7). A few attack flows among many normal ones are
#            diluted: 1 bad flow in 32 moves the mean by 1/32 of its error -> diluted attacks are missed.
#   max      the single worst flow. Catches one bad flow, but is noisier on normal traffic.
#   topk:K   mean of the K worst flows (default topk:4): needs a few unusual flows, robust to one odd one.
SCORE_AGGS = ("mean", "max", "topk:2", "topk:4", "topk:8")


def flow_errors(recon, x, mask):
    """Per-flow reconstruction error [B, T] (mean over features); padded steps -> 0."""
    return ((recon - x) ** 2).mean(-1) * mask.float()


def aggregate_flow_errors(fe, mask, how="mean"):
    """[B, T] per-flow errors -> [B] window score (see SCORE_AGGS)."""
    m = mask.float()
    n = m.sum(1).clamp(min=1)
    if how == "mean":
        return fe.sum(1) / n
    neg = fe.masked_fill(~mask, float("-inf"))
    if how == "max":
        return neg.max(1).values
    if how.startswith("topk:"):
        k = min(int(how.split(":")[1]), fe.shape[1])
        top = neg.topk(k, dim=1).values                                     # [B, k], -inf where window shorter
        valid = torch.isfinite(top)
        return torch.where(valid, top, torch.zeros_like(top)).sum(1) / valid.sum(1).clamp(min=1)
    raise ValueError(f"unknown score aggregation {how!r}; use one of {SCORE_AGGS}")


@torch.no_grad()
def lstm_batch_scores(model, x, m, how="mean"):
    """One forward pass -> dict of numpy arrays: error (aggregated), error_mean, error_peak, peak_pos,
    peak_feat_err [B, F] (per-feature error of the worst flow), z."""
    recon, z = model(x, m)
    fe = flow_errors(recon, x, m)
    peak, pos = fe.masked_fill(~m, float("-inf")).max(1)
    pf = ((recon - x) ** 2)[torch.arange(len(x), device=x.device), pos]
    return {"error": aggregate_flow_errors(fe, m, how).cpu().numpy(), "error_mean": aggregate_flow_errors(fe, m, "mean").cpu().numpy(),
            "error_peak": peak.cpu().numpy(), "peak_pos": pos.cpu().numpy(), "peak_feat_err": pf.cpu().numpy(),
            "z": z.cpu().numpy()}


def score_agg_of(meta):
    """Window-score aggregation a bundle was thresholded with (bundles before v8: mean)."""
    return meta.get("score_agg", "mean")


# A network gets its own threshold only if its val split has at least this many clean normal windows;
# a 99th percentile of fewer windows is noise (IoT-23 has 10), so such networks use the pooled threshold.
MIN_CALIBRATION_WINDOWS = 200


def threshold_for(meta, dataset=None):
    """Alarm threshold of a bundle for traffic of `dataset` (= one network). Bundles with
    threshold_mode 'per_dataset' hold one threshold per training network, each the 99th pct of THAT
    network's own val normal traffic (a deployment calibrates its own the same way: score_traffic.py
    --calibrate). Unknown networks get the pooled threshold."""
    if dataset and meta.get("threshold_mode") == "per_dataset" and dataset in meta.get("per_dataset_thresholds", {}):
        return float(meta["per_dataset_thresholds"][dataset])
    return float(meta["threshold"])


# =============================================================================================
# Bundle (save / load with compatibility checks)
# =============================================================================================
class ModelBundle:
    def __init__(self, model, meta):
        self.model, self.meta = model, meta

    @property
    def threshold(self):
        return float(self.meta["threshold"])

    def save(self, path):
        os.makedirs(path, exist_ok=True)
        torch.save(self.model.state_dict(), os.path.join(path, "model.pt"))
        json.dump(self.meta, open(os.path.join(path, "bundle.json"), "w"), indent=1)

    @classmethod
    def load(cls, path, device="cpu", strict=True):
        meta = json.load(open(os.path.join(path, "bundle.json")))
        if meta.get("bundle_format") != BUNDLE_FORMAT:
            raise RuntimeError(f"bundle format {meta.get('bundle_format')} != {BUNDLE_FORMAT}")
        now = pipeline_fingerprint()
        if meta["pipeline"]["feature_order"] != now["feature_order"]:
            raise RuntimeError("Model was trained with a different feature list/order than the current "
                               "preprocessing code. Retrain the model or check out the matching code version.")
        if strict and fingerprint_hash(meta["pipeline"]) != fingerprint_hash(now):
            raise RuntimeError("Preprocessing settings changed since this model was trained "
                               f"(bundle {fingerprint_hash(meta['pipeline'])} vs code {fingerprint_hash(now)}). "
                               "Retrain, or load with strict=False if the change is known to be harmless.")
        if "init" in meta:
            model = MODEL_REGISTRY[meta["model_type"]](**meta["init"])
        else:   # bundles written before the registry existed (LSTM-AE only)
            h = meta["hparams"]
            model = LSTMAutoencoder(len(meta["pipeline"]["feature_order"]), h["hidden"], h["latent"], h["layers"], h["dropout"])
        model.load_state_dict(torch.load(os.path.join(path, "model.pt"), map_location=device, weights_only=True))
        model.to(device).eval()
        return cls(model, meta)


# =============================================================================================
# Windows -> batches -> scores
# =============================================================================================
def window_batches(F, rs, re_, window, batch_size):
    """F: float32 [n_rows, n_features] (rows sorted by device, ts). Yields (idx, X, mask) numpy."""
    for b in range(0, len(rs), batch_size):
        a_, e_ = rs[b:b + batch_size], re_[b:b + batch_size]
        n = len(a_)
        X = np.zeros((n, window, F.shape[1]), np.float32)
        M = np.zeros((n, window), bool)
        for i, (a, e) in enumerate(zip(a_, e_)):
            X[i, :e - a], M[i, :e - a] = F[a:e], True
        yield slice(b, b + n), X, M


@torch.no_grad()
def score_windows(model, F, windows, window, device, batch_size=1024, threshold=None, score_agg="mean"):
    """Score a window table against feature matrix F. Returns a DataFrame following the contract.
    lstm_error is the window score under `score_agg` (the bundle's setting: score_agg_of(meta));
    lstm_error_mean / lstm_error_peak are always added, lstm_peak_row is the row of F holding the
    window's most unusual flow (lets the attack analysis point at ONE connection)."""
    model.eval()
    rs, re_ = windows.row_start.to_numpy(), windows.row_end.to_numpy()
    n = len(rs)
    err, emean, epeak = (np.zeros(n, np.float32) for _ in range(3))
    prow = np.zeros(n, np.int64)
    lat = None
    top = np.empty(n, dtype=object)
    names = np.array(ap.FEATURES)
    for sl, X, M in window_batches(F, rs, re_, window, batch_size):
        r = lstm_batch_scores(model, torch.from_numpy(X).to(device), torch.from_numpy(M).to(device), score_agg)
        err[sl], emean[sl], epeak[sl] = r["error"], r["error_mean"], r["error_peak"]
        prow[sl] = rs[sl] + r["peak_pos"]
        if lat is None:
            lat = np.zeros((n, r["z"].shape[1]), np.float32)
        lat[sl] = r["z"]
        t3 = np.argsort(-r["peak_feat_err"], axis=1)[:, :3]
        top[sl] = [",".join(names[i]) for i in t3]
    out = windows.reset_index(drop=True).copy()
    out["lstm_error"] = err
    out["lstm_error_mean"], out["lstm_error_peak"], out["lstm_peak_row"] = emean, epeak, prow
    if threshold is not None:
        out["lstm_score"] = (err / threshold).astype(np.float32)
        out["lstm_anomaly"] = (out.lstm_score >= 1.0).astype(np.int8)
    out["lstm_top_features"] = top          # worst-reconstructed features of the window's most unusual flow
    if lat is not None:
        out = pd.concat([out, pd.DataFrame(lat, columns=[f"z_{i}" for i in range(lat.shape[1])])], axis=1)
    return out


def node_snapshot_table(scored, t0, snapshot_seconds, stage="lstm", latent_prefix="z_", extra_max=()):
    """Aggregate one stage's window outputs per (capture, snapshot, device) so they join onto the GAT
    node tables (keys snapshot + node). Expects columns <stage>_score and <stage>_anomaly.
    A window belongs to the snapshot in which it ENDS (what a live system knows at that moment).
    Output: capture, snapshot, node, <stage>_max_score, <stage>_mean_score, <stage>_n_windows,
            <stage>_any_anomaly, mean of the latent columns, max of every column in extra_max."""
    s = scored.copy()
    s["snapshot"] = ((s.t_end - t0) // snapshot_seconds).astype("int64")
    zc = [c for c in s.columns if c.startswith(latent_prefix)]
    g = s.groupby(["capture", "snapshot", "device"], sort=True)
    sc, an = f"{stage}_score", f"{stage}_anomaly"
    out = g.agg(**{f"{stage}_max_score": (sc, "max"), f"{stage}_mean_score": (sc, "mean"),
                   f"{stage}_n_windows": (sc, "size"), f"{stage}_any_anomaly": (an, "max")})
    out = out.join(g[zc].mean())
    for c in extra_max:
        out[c] = g[c].max()
    return out.reset_index().rename(columns={"device": "node"})


def attach_to_graph_nodes(nodes, *node_tables):
    """Left-join stage node tables onto GAT graph nodes (keys snapshot + node); missing -> 0."""
    for t in node_tables:
        t = t.drop(columns=[c for c in ("capture",) if c in t.columns])
        nodes = nodes.merge(t, on=["snapshot", "node"], how="left")
        fill = [c for c in t.columns if c not in ("snapshot", "node")]
        nodes[fill] = nodes[fill].fillna(0)
    return nodes


# =============================================================================================
# Stage 2: VAE over windows (density / calibrated confidence / zero-day candidates)
# =============================================================================================
@register("window_vae")
class WindowVAE(nn.Module):
    """MLP variational autoencoder over one vector per window.
    Anomaly score = reconstruction error + KL term (negative ELBO, per input dimension), computed
    deterministically at the posterior mean. Its latent mean (mu_*) is exported for the GAT."""

    def __init__(self, n_in, hidden=(128, 64), latent=8, dropout=0.0):
        super().__init__()
        h1, h2 = hidden
        self.n_in = n_in
        self.enc = nn.Sequential(nn.Linear(n_in, h1), nn.ReLU(), nn.Dropout(dropout), nn.Linear(h1, h2), nn.ReLU())
        self.mu, self.logvar = nn.Linear(h2, latent), nn.Linear(h2, latent)
        self.dec = nn.Sequential(nn.Linear(latent, h2), nn.ReLU(), nn.Linear(h2, h1), nn.ReLU(), nn.Linear(h1, n_in))

    def encode(self, x):
        h = self.enc(x)
        return self.mu(h), self.logvar(h).clamp(-10, 10)

    def forward(self, x):
        mu, logvar = self.encode(x)
        z = mu + torch.randn_like(mu) * torch.exp(0.5 * logvar) if self.training else mu
        return self.dec(z), mu, logvar

    def elbo_terms(self, x, recon, mu, logvar):
        rec = ((recon - x) ** 2).mean(1)
        kl = (-0.5 * (1 + logvar - mu ** 2 - logvar.exp()).sum(1)) / self.n_in
        return rec, kl


# Input blocks of the VAE (a bundle stores the blocks it was trained with, so old bundles keep working)
#   lstm_latent   z_*                       LSTM-AE window embedding
#   lstm_error    log_lstm_error            LSTM-AE window score (bundle's aggregation)
#   window_stats  mean_* (all), std_* (cont) average behaviour of the window
#   window_max    max_* (all), min_* (cont) the most extreme flow per feature - NOT diluted by the
#                                           normal flows around it (one telnet probe -> max_svc_telnet = 1)
#   lstm_peak     log_lstm_error_peak       error of the window's single most unusual flow
VAE_INPUT_BLOCKS = ("lstm_latent", "lstm_error", "lstm_peak", "window_stats", "window_max")
VAE_STAT_BLOCKS = ("window_stats", "window_max")


def window_stat_names(blocks=("window_stats",)):
    names = []
    if "window_stats" in blocks:
        names += [f"mean_{f}" for f in ap.FEATURES] + [f"std_{f}" for f in ap.CONT_FEATURES]
    if "window_max" in blocks:
        names += [f"max_{f}" for f in ap.FEATURES] + [f"min_{f}" for f in ap.CONT_FEATURES]
    return names


def batch_window_stats(X, M, blocks=("window_stats",)):
    """X [B, T, F], M [B, T] -> [B, n_stats] in window_stat_names(blocks) order (masked, any length)."""
    nc = len(ap.CONT_FEATURES)
    m = M[..., None].astype(np.float32)
    parts = []
    if "window_stats" in blocks:
        n = np.maximum(m.sum(1), 1)
        mean = (X * m).sum(1) / n
        var = ((X[..., :nc] - mean[:, None, :nc]) ** 2 * m).sum(1) / n
        parts += [mean, np.sqrt(np.maximum(var, 0))]
    if "window_max" in blocks:
        parts += [np.where(M[..., None], X, -np.inf).max(1), np.where(M[..., None], X[..., :nc], np.inf).min(1)]
    if not parts:
        return np.zeros((len(X), 0), np.float32)
    out = np.concatenate(parts, axis=1).astype(np.float32)
    out[~np.isfinite(out)] = 0.0
    return out


def window_stats(F, windows, window, blocks=("window_stats",), batch_size=8192):
    """Per-window statistics of the flow features (see batch_window_stats). Names follow
    window_stat_names(blocks), so they track the current feature list automatically."""
    rs, re_ = windows.row_start.to_numpy(), windows.row_end.to_numpy()
    out = np.zeros((len(rs), len(window_stat_names(blocks))), np.float32)
    for sl, X, M in window_batches(F, rs, re_, window, batch_size):
        out[sl] = batch_window_stats(X, M, blocks)
    return out


def vae_input_names(blocks, lstm_latent_dim):
    names = []
    if "lstm_latent" in blocks:
        names += [f"z_{i}" for i in range(lstm_latent_dim)]
    if "lstm_error" in blocks:
        names += ["log_lstm_error"]
    if "lstm_peak" in blocks:
        names += ["log_lstm_error_peak"]
    names += window_stat_names(blocks)
    return names


def build_vae_inputs(lstm_scored, stats, blocks):
    """lstm_scored: window table with z_*, lstm_error (+ lstm_error_peak); stats: window_stats(.., blocks)."""
    parts = []
    if "lstm_latent" in blocks:
        parts.append(lstm_scored[[c for c in lstm_scored.columns if c.startswith("z_")]].to_numpy(np.float32))
    if "lstm_error" in blocks:
        parts.append(np.log1p(lstm_scored.lstm_error.to_numpy(np.float32))[:, None])
    if "lstm_peak" in blocks:
        parts.append(np.log1p(lstm_scored.lstm_error_peak.to_numpy(np.float32))[:, None])
    if any(b in blocks for b in VAE_STAT_BLOCKS):
        parts.append(stats)
    return np.concatenate(parts, axis=1)


class LatentPrototypes:
    """Gaussian prototype per KNOWN class in the VAE latent space (Mahalanobis distance, shrunk
    covariance). distance / class radius (99th pct of the class's own training windows) < 1 means
    'looks like this known class'. A window far from every known class (benign included) that the VAE
    also finds anomalous is a ZERO-DAY CANDIDATE."""

    def __init__(self, d=None):
        self.classes, self.means, self.icov, self.radius = [], [], [], []
        if d:
            self.classes, self.means = d["classes"], [np.asarray(m) for m in d["means"]]
            self.icov, self.radius = [np.asarray(c) for c in d["icov"]], d["radius"]

    def fit(self, mu, labels, shrink=0.1, max_per_class=50_000, rng=None):
        rng = rng or np.random.default_rng(0)
        for c in sorted(set(labels)):
            m = mu[labels == c]
            if len(m) < 20:
                continue
            if len(m) > max_per_class:
                m = m[rng.choice(len(m), max_per_class, replace=False)]
            mean = m.mean(0)
            cov = np.cov(m, rowvar=False)
            cov = (1 - shrink) * cov + shrink * np.eye(len(mean)) * np.trace(cov) / len(mean) + 1e-6 * np.eye(len(mean))
            icov = np.linalg.inv(cov)
            d = np.sqrt(np.einsum("ij,jk,ik->i", m - mean, icov, m - mean))
            self.classes.append(c); self.means.append(mean); self.icov.append(icov)
            self.radius.append(float(np.quantile(d, 0.99)))
        return self

    def distances(self, mu):
        """-> [n, n_classes] distance / radius."""
        D = np.zeros((len(mu), len(self.classes)), np.float32)
        for j, (m, ic, r) in enumerate(zip(self.means, self.icov, self.radius)):
            diff = mu - m
            D[:, j] = np.sqrt(np.maximum(np.einsum("ij,jk,ik->i", diff, ic, diff), 0)) / r
        return D

    def to_dict(self):
        return {"classes": self.classes, "means": [m.tolist() for m in self.means],
                "icov": [c.tolist() for c in self.icov], "radius": self.radius}


@torch.no_grad()
def vae_score_matrix(model, Xn, device, batch_size=8192):
    """Standardised input matrix -> (negative-ELBO score, latent mean)."""
    model.eval()
    errs, mus = [], []
    for b in range(0, len(Xn), batch_size):
        x = torch.from_numpy(Xn[b:b + batch_size]).to(device)
        recon, mu, logvar = model(x)
        rec, kl = model.elbo_terms(x, recon, mu, logvar)
        errs.append((rec + kl).cpu().numpy()); mus.append(mu.cpu().numpy())
    return np.concatenate(errs), np.concatenate(mus)


MIN_DEVICE_WINDOWS = 50     # a device needs this many normal calibration windows to get its own threshold


def device_thresholds(devices, err, network_thr, q=0.99, min_windows=MIN_DEVICE_WINDOWS):
    """Per-device alarm thresholds from NORMAL calibration windows: max(network threshold, the device's own
    q-quantile), only for devices with >= min_windows windows. Never lower than the network threshold, so a
    noisy estimate on a quiet device cannot create a hair trigger; only devices that are noisy by nature
    get more room. Returns {device: threshold}."""
    s = pd.Series(np.asarray(err, dtype=float), index=pd.Index(np.asarray(devices), name="device"))
    g = s.groupby(level=0)
    n = g.size()
    qs = g.quantile(q)
    return {d: max(float(network_thr), float(qs[d])) for d in n.index[n >= min_windows]}


def apply_device_thresholds(out, device_thr):
    """Re-flag scored windows with per-device thresholds {"lstm": {ip: thr}, "vae": {ip: thr}}. Devices
    without their own threshold keep the threshold already applied. Idempotent; also refreshes the
    zero-day flag, which depends on vae_anomaly."""
    for stage, err_col in (("lstm", "lstm_error"), ("vae", "vae_error")):
        thr = (device_thr or {}).get(stage) or {}
        if err_col not in out or not thr:
            continue
        cur = (out[err_col] / out[f"{stage}_score"]).replace([np.inf, -np.inf], np.nan)   # threshold in use
        t = out.device.map(thr).astype(float).fillna(cur).to_numpy()
        out[f"{stage}_score"] = (out[err_col] / t).astype(np.float32)
        out[f"{stage}_anomaly"] = (out[f"{stage}_score"] >= 1.0).astype(np.int8)
    if "vae_novelty" in out and "vae_anomaly" in out:
        out["zero_day_candidate"] = ((out.vae_anomaly == 1) & (out.vae_novelty > 1.0)).astype(np.int8)
    return out


def vae_outputs(meta, err, mu, dataset=None):
    """Turn raw VAE scores into the output-contract columns (threshold, confidence, class hint, zero-day).
    dataset: use that network's own threshold / normal reference (threshold_mode per_dataset)."""
    thr = threshold_for(meta, dataset)
    refs = meta.get("per_dataset_reference_scores", {})
    ref = np.asarray(refs[dataset] if dataset in refs and meta.get("threshold_mode") == "per_dataset"
                     else meta["benign_reference_scores"])     # sorted val-benign scores
    p = 1.0 - np.searchsorted(ref, err, side="left") / len(ref)  # share of normal windows at least this unusual
    out = pd.DataFrame({"vae_error": err.astype(np.float32), "vae_score": (err / thr).astype(np.float32)})
    out["vae_anomaly"] = (out.vae_score >= 1.0).astype(np.int8)
    out["vae_confidence"] = (1.0 - p).astype(np.float32)        # 0.99 = more unusual than 99 % of normal windows
    protos = LatentPrototypes(meta["prototypes"])
    D = protos.distances(mu)
    near = D.argmin(1)
    out["vae_class_hint"] = np.array(protos.classes, dtype=object)[near]
    out["vae_class_distance"] = D[np.arange(len(D)), near]
    out["vae_novelty"] = D.min(1)
    out["zero_day_candidate"] = ((out.vae_anomaly == 1) & (out.vae_novelty > 1.0)).astype(np.int8)
    for i in range(mu.shape[1]):
        out[f"mu_{i}"] = mu[:, i].astype(np.float32)
    return out


def vae_normalise(meta, X):
    mean, std = np.asarray(meta["input_mean"], np.float32), np.asarray(meta["input_std"], np.float32)
    c = float(meta.get("input_clip", 20.0))          # bundles before vae_v5 used +-20
    return np.clip((X - mean) / std, -c, c).astype(np.float32)


def vae_score_windows(vbundle, lstm_scored, F, windows, device, meta=None):
    """Full stage-2 scoring of windows already scored by the matching LSTM-AE (same row order).
    meta: optionally a recalibrated copy of the bundle meta (threshold / reference scores)."""
    meta = meta or vbundle.meta
    stats = window_stats(F, windows, int(meta["window"]), meta["input_blocks"])
    X = build_vae_inputs(lstm_scored, stats, meta["input_blocks"])
    if X.shape[1] != len(meta["input_names"]):
        raise RuntimeError("VAE input layout differs from training (feature list or LSTM latent size changed)")
    err, mu = vae_score_matrix(vbundle.model, vae_normalise(meta, X), device)
    return err, mu


def check_vae_matches_lstm(vae_meta, lstm_dir):
    sha = file_sha256(os.path.join(lstm_dir, "model.pt"))
    if vae_meta["upstream"]["lstm_model_sha256"] != sha:
        raise RuntimeError(f"VAE '{vae_meta['run']}' was trained on LSTM run '{vae_meta['upstream']['lstm_run']}', "
                           "not on the LSTM model given. Use the matching LSTM bundle or retrain the VAE.")


def balanced_quantile(values, groups, q):
    """Quantile where every group (capture) carries equal total weight - a threshold set this way gives
    roughly the target false-alarm rate in EVERY capture instead of only in the largest one."""
    values = np.asarray(values, np.float64)
    _, inv, counts = np.unique(np.asarray(groups).astype(str), return_inverse=True, return_counts=True)
    w = 1.0 / counts[inv]
    o = np.argsort(values)
    cw = np.cumsum(w[o]) / w.sum()
    idx = np.minimum(np.searchsorted(cw, np.atleast_1d(q)), len(o) - 1)
    res = values[o][idx]
    return float(res[0]) if np.ndim(q) == 0 else res


def to_csv_safe(df, path):
    """CSV copy of an output table: list / array cells become 'a|b|c' strings, floats keep 6 decimals."""
    d = df.copy()
    for c in d.columns:
        if d[c].dtype == object:
            d[c] = d[c].map(lambda v: "|".join(map(str, v)) if isinstance(v, (list, tuple, np.ndarray)) else v)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    d.to_csv(tmp, index=False, float_format="%.6g", encoding="utf-8")
    os.replace(tmp, path)


def write_output(df, parquet_path, csv=True):
    """Model output = parquet (fast, typed; what the next stage reads) + the same table as CSV (Excel,
    reports, other tools). Same name, '.csv' extension."""
    ap.write_parquet(df, parquet_path)
    if csv:
        to_csv_safe(df, os.path.splitext(parquet_path)[0] + ".csv")


def file_sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


# =============================================================================================
# Real / live traffic: identical preprocessing to the datasets
# =============================================================================================
def traffic_to_inputs(pcap_path, capture_name, scaler, member=None, log=print):
    """pcap/pcapng (optionally zipped) -> (flows, scaled features sorted by device+ts, stats).
    Uses exactly the dataset code paths: FlowBuilder, engineer_features, RobustScaler."""
    flows, st = ap.build_flows_from_pcap(pcap_path, member=member, log=log)
    flows["is_attack"], flows["mal_frac"] = 0, 0.0
    flows["attack_class"], flows["campaign"], flows["original_label"] = "unlabeled", "", ""
    flows["label_note"] = "live traffic (no ground truth)"
    flows["dataset"], flows["capture"] = "live", capture_name
    flows = ap.to_schema(flows)
    feat = ap.engineer_features(flows)
    feat["split"] = "live"
    if scaler is not None:
        feat = scaler.transform(feat)
    feat = feat.sort_values(["device", "ts"], kind="stable").reset_index(drop=True)
    return flows, feat, st


def fit_scaler_on(feat_unscaled):
    """Calibrate the robust scaler on a capture of the deployment's OWN normal traffic."""
    return ap.RobustScaler().fit(feat_unscaled[ap.CONT_FEATURES])


def now_iso():
    return _dt.datetime.now().isoformat(timespec="seconds")
