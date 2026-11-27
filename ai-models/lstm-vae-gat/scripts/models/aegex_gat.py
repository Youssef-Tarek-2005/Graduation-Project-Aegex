"""
Aegex stage 3 - temporal graph attention network (GAT) over the 60 s network snapshots.

What it adds on top of the LSTM-AE / VAE (which look at ONE device's flows at a time)
  * relations: who talks to whom in each snapshot, with what kind of traffic (edge features)
  * roles: is a host the SOURCE of an attack (compromised / attacking) or its TARGET (victim)?
  * time: a per-host memory (GRU) carried from snapshot to snapshot, so slow multi-minute behaviour
    and spreading over time can build up evidence

Model (pure PyTorch, no graph library needed)
  node encoder   MLP over node inputs (traffic aggregates + stage-1/2 outputs, see NODE_BLOCKS)
  2 x EdgeGAT    GATv2-style attention, messages along both directions of every edge, edge features
                 enter the attention and the message (multi-head)
  memory         GRUCell per host, updated each snapshot the host appears in
  heads          node: P(attack source), P(attack target);  edge: P(edge carries attack traffic)

Inputs per snapshot (built by snapshot_sequence from step-3 graph tables + stage node tables)
  node blocks    traffic  log in/out flows, peers, bytes, is_private, is_external, gap since last seen
                 stage    LSTM / VAE max + mean score, any-anomaly, #windows, confidence, zero-day flag
                 latent   VAE latent means mu_* (behaviour embedding of the host's windows)
  edge features  mean of the 50 flow features over the pair's flows + log #flows + direction flag
Labels (training / evaluation only, never inputs): node out_attack > 0 (source), in_attack > 0
(target), edge n_attack > 0.
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import numpy as np
import pandas as pd
import torch
import torch.nn as nn
import torch.nn.functional as Fn

import aegex_models as am
from aegex_models import ap

NODE_TRAFFIC = ["log_out_flows", "log_in_flows", "log_out_peers", "log_in_peers", "log_out_bytes", "log_in_bytes",
                "is_private", "is_external", "log_gap_snapshots"]
NODE_STAGE = ["lstm_max_score", "lstm_mean_score", "lstm_any_anomaly", "lstm_n_windows",
              "vae_max_score", "vae_mean_score", "vae_any_anomaly", "vae_confidence", "zero_day_candidate", "has_windows"]
NODE_BLOCKS = ("traffic", "stage", "latent")
ALL_NODE_BLOCKS = NODE_BLOCKS + ("deviation",)   # "deviation" needs train_gat.py --relative-inputs
# --relative-inputs (train_gat.py): each host's traffic vs ITS OWN recent history (EWMA z-score, 0 for a new host)
NODE_DEV_BASE = ["log_out_flows", "log_in_flows", "log_out_peers", "log_in_peers", "log_out_bytes", "log_in_bytes"]
NODE_DEV = [f"dev_{c}" for c in NODE_DEV_BASE]
EDGE_FEATURES = list(ap.FEATURES) + ["log_n_flows", "is_reverse"]


def node_feature_names(blocks, vae_latent):
    n = []
    if "traffic" in blocks:
        n += NODE_TRAFFIC
    if "stage" in blocks:
        n += NODE_STAGE
    if "latent" in blocks:
        n += [f"mu_{i}" for i in range(vae_latent)]
    if "deviation" in blocks:
        n += NODE_DEV
    return n


# ============================================================================================ data
def node_stage_table(scored, t0, snapshot_seconds):
    """Window table scored by LSTM-AE + VAE -> one row per (snapshot, device) (GAT node inputs)."""
    l = am.node_snapshot_table(scored, t0, snapshot_seconds, stage="lstm", latent_prefix="__none__")
    v = am.node_snapshot_table(scored, t0, snapshot_seconds, stage="vae", latent_prefix="mu_",
                               extra_max=("zero_day_candidate", "vae_confidence"))
    return l.merge(v.drop(columns=["capture"]), on=["snapshot", "node"], how="outer")


def snapshot_sequence(edges, nodes, stage, vae_latent, name, meta=None):
    """Step-3 graph tables (+ node stage table) of ONE capture/scenario -> dict with a list of snapshot
    graphs (numpy) in time order. Node ids are stable across snapshots (index into `hosts`)."""
    nodes = nodes.copy()
    if stage is not None and len(stage):
        nodes = nodes.merge(stage.drop(columns=[c for c in ("capture",) if c in stage.columns]),
                            on=["snapshot", "node"], how="left")
    nodes["has_windows"] = (nodes["lstm_n_windows"].notna().astype(np.float32) if "lstm_n_windows" in nodes
                            else np.float32(0.0))
    for c in NODE_STAGE + [f"mu_{i}" for i in range(vae_latent)]:
        if c not in nodes:
            nodes[c] = 0.0
    num = nodes.select_dtypes(include=[np.number]).columns
    nodes[num] = nodes[num].fillna(0.0)
    for c in ("lstm_max_score", "lstm_mean_score", "vae_max_score", "vae_mean_score"):
        nodes[c] = np.log1p(np.clip(nodes[c].to_numpy(np.float64), 0, None))
    nodes["lstm_n_windows"] = np.log1p(nodes["lstm_n_windows"].to_numpy(np.float64))
    nodes["is_external"] = (nodes.node == "EXTERNAL").astype(np.float32)
    hosts = pd.Index(pd.unique(nodes.node))
    nodes["nid"] = hosts.get_indexer(nodes.node)
    nodes = nodes.sort_values(["snapshot", "nid"])
    prev = nodes.groupby("nid").snapshot.shift()
    nodes["log_gap_snapshots"] = np.log1p((nodes.snapshot - prev).fillna(1000).clip(0, 1000))
    nodes["y_source"] = (nodes.out_attack > 0).astype(np.float32)
    nodes["y_target"] = (nodes.in_attack > 0).astype(np.float32)
    feat_cols = NODE_TRAFFIC + NODE_STAGE + [f"mu_{i}" for i in range(vae_latent)]
    ecols = list(ap.FEATURES) + ["log_n_flows"]
    snaps = []
    eg = {s: g for s, g in edges.groupby("snapshot", sort=True)}
    for s, g in nodes.groupby("snapshot", sort=True):
        e = eg.get(s)
        nid = g.nid.to_numpy(np.int64)
        local = {h: i for i, h in enumerate(nid)}
        if e is not None and len(e):
            si = hosts.get_indexer(e.src); di = hosts.get_indexer(e.dst)
            src = np.array([local[x] for x in si], np.int64); dst = np.array([local[x] for x in di], np.int64)
            ef = e[ecols].to_numpy(np.float32)
            ye = (e.n_attack.to_numpy() > 0).astype(np.float32)
            split = e.split.mode().iat[0] if "split" in e and e.split.notna().any() else None
        else:
            src = dst = np.zeros(0, np.int64); ef = np.zeros((0, len(ecols)), np.float32); ye = np.zeros(0, np.float32)
            split = None
        snaps.append({"snapshot": int(s), "nid": nid, "x": g[feat_cols].to_numpy(np.float32),
                      "src": src, "dst": dst, "e": ef, "y_node": g[["y_source", "y_target"]].to_numpy(np.float32),
                      "y_edge": ye, "split": split})
    return {"name": name, "hosts": list(hosts), "snaps": snaps, "feat_cols": feat_cols, "meta": meta or {}}


def select_blocks(x, feat_cols, blocks, vae_latent):
    keep = node_feature_names(blocks, vae_latent)
    idx = [feat_cols.index(c) for c in keep]
    return x[:, idx]


# ============================================================================================ model
def segment_softmax(score, index, n):
    """softmax of score [E, H] over edges sharing the same index (destination node)."""
    mx = torch.full((n, score.shape[1]), float("-inf"), device=score.device, dtype=score.dtype)
    mx = mx.scatter_reduce(0, index[:, None].expand_as(score), score, reduce="amax", include_self=True)
    ex = torch.exp(score - mx[index])
    den = torch.zeros((n, score.shape[1]), device=score.device, dtype=score.dtype).index_add_(0, index, ex)
    return ex / den[index].clamp(min=1e-12)


class EdgeGAT(nn.Module):
    """GATv2-style layer with edge features: a_ij = softmax_j( att . LeakyReLU(Ws h_j + Wd h_i + We e_ij) )."""

    def __init__(self, d_in, d_edge, d_out, heads=4, dropout=0.1):
        super().__init__()
        self.h, self.d = heads, d_out // heads
        self.ws, self.wd, self.we = nn.Linear(d_in, d_out), nn.Linear(d_in, d_out), nn.Linear(d_edge, d_out)
        self.att = nn.Parameter(torch.randn(heads, self.d) * 0.1)
        self.self_ = nn.Linear(d_in, d_out)
        self.norm = nn.LayerNorm(d_out)
        self.drop = nn.Dropout(dropout)

    def forward(self, h, src, dst, e):
        n = h.shape[0]
        out = self.self_(h)
        if len(src):
            xs = self.ws(h)[src].view(-1, self.h, self.d)
            xd = self.wd(h)[dst].view(-1, self.h, self.d)
            xe = self.we(e).view(-1, self.h, self.d)
            score = (Fn.leaky_relu(xs + xd + xe, 0.2) * self.att).sum(-1)          # [E, H]
            alpha = self.drop(segment_softmax(score, dst, n))
            msg = ((xs + xe) * alpha[..., None]).reshape(-1, self.h * self.d)
            out = out + torch.zeros_like(out).index_add_(0, dst, msg)
        return self.norm(Fn.elu(out))


@am.register("temporal_gat")
class TemporalGAT(nn.Module):
    def __init__(self, n_node, n_edge, hidden=64, heads=4, layers=2, dropout=0.1):
        super().__init__()
        self.hidden = hidden
        self.enc = nn.Sequential(nn.Linear(n_node, hidden), nn.ReLU(), nn.Linear(hidden, hidden))
        self.eenc = nn.Sequential(nn.Linear(n_edge, hidden), nn.ReLU())
        self.gat = nn.ModuleList([EdgeGAT(hidden, hidden, hidden, heads, dropout) for _ in range(layers)])
        self.gru = nn.GRUCell(hidden, hidden)
        self.node_head = nn.Sequential(nn.Linear(2 * hidden, hidden), nn.ReLU(), nn.Linear(hidden, 2))
        self.edge_head = nn.Sequential(nn.Linear(3 * hidden, hidden), nn.ReLU(), nn.Linear(hidden, 1))

    def step(self, x, src, dst, e, mem):
        """One snapshot. x [N, n_node], e [E, n_edge] (already incl. reversed copies), mem [N, H]."""
        h = self.enc(x)
        ee = self.eenc(e) if len(e) else e.new_zeros((0, self.hidden))
        for layer in self.gat:
            h = h + layer(h, src, dst, ee)
        m = self.gru(h, mem)
        z = torch.cat([h, m], 1)
        return self.node_head(z), m, h, ee


def add_reverse(src, dst, e):
    """Messages flow both ways along each edge; the copy is marked with is_reverse = 1."""
    f = np.concatenate([e, np.zeros((len(e), 1), np.float32)], 1)
    r = np.concatenate([e, np.ones((len(e), 1), np.float32)], 1)
    return np.r_[src, dst], np.r_[dst, src], np.concatenate([f, r], 0)


def run_sequence(model, seq, norm, device, train=False, chunk=32, loss_fn=None, opt=None, blocks=NODE_BLOCKS,
                 vae_latent=8):
    """Run the model over one snapshot sequence (memory carried across snapshots).
    Training: truncated back-propagation every `chunk` snapshots. Returns per-snapshot outputs."""
    nmean, nstd, emean, estd = norm
    H = model.hidden
    mem = torch.zeros((len(seq["hosts"]), H), device=device)
    outs, total, pending = [], 0.0, []
    for i, s in enumerate(seq["snaps"]):
        x = select_blocks(s["x"], seq["feat_cols"], blocks, vae_latent)
        x = torch.from_numpy(np.clip((x - nmean) / nstd, -10, 10).astype(np.float32)).to(device)
        src, dst, e = add_reverse(s["src"], s["dst"], s["e"])
        e = torch.from_numpy(np.clip((e - emean) / estd, -10, 10).astype(np.float32)).to(device)
        src_t, dst_t = torch.from_numpy(src).to(device), torch.from_numpy(dst).to(device)
        nid = torch.from_numpy(s["nid"]).to(device)
        logits, m, h, ee = model.step(x, src_t, dst_t, e, mem[nid])
        mem = mem.index_copy(0, nid, m)
        ne = len(s["src"])
        if ne:
            z = torch.cat([h, m], 1)
            zs = model.node_head[0](z)
            el = model.edge_head(torch.cat([zs[src_t[:ne]], zs[dst_t[:ne]], ee[:ne]], 1)).squeeze(1)
        else:
            el = logits.new_zeros(0)
        if train:
            pending.append(loss_fn(logits, el, s))
            if len(pending) == chunk or i == len(seq["snaps"]) - 1:
                loss = torch.stack(pending).mean()
                opt.zero_grad(); loss.backward()
                torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0); opt.step()
                total += loss.item() * len(pending); pending = []
                mem = mem.detach()
        else:
            outs.append((torch.sigmoid(logits).detach().cpu().numpy(), torch.sigmoid(el).detach().cpu().numpy()))
    return total if train else outs
