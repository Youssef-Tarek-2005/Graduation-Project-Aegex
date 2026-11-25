"""
Aegex preprocessing - shared library.

Every dataset is converted to ONE unified, bidirectional flow schema (FLOW_COLUMNS) so the
same feature/normalisation/sequence/graph code runs on all of them:

    raw source                 adapter (scripts/aegex_datasets/<name>.py)     unified flow table
    pcaps (Kitsune, Edge)   -> build_flows_from_pcap (here)          ->   ts, src/dst ip+port, proto,
    Zeek conn.log (IoT-23)  -> aegex_datasets.iot23.to_flows         ->   duration, fwd/bwd pkts+bytes,
    NetFlow (NF-ToN-IoT)    -> aegex_datasets.nf_toniot.to_flows     ->   fwd/bwd TCP flags, labels
    CICFlowMeter CSV (ACI)  -> cicflowmeter_to_flows (here)          ->

Dataset-specific code (file names, labels, captures, benchmark cases) lives ONLY in the
aegex_datasets package; this module holds the format readers and everything shared.

Conventions
  * "fwd" = originator -> responder (the host that sent the first packet), "bwd" = reply direction.
  * bytes are IP-layer bytes (IP total length); ARP counts 28 bytes per packet.
  * TCP flags are the OR of all flags seen per direction, standard bits:
        FIN=1 SYN=2 RST=4 PSH=8 ACK=16 URG=32
  * attack_class taxonomy (project scope): benign, scanning, ddos, ransomware, mirai, other
    (other = attacks outside the project scope that cannot be cut out of a continuous capture).
  * Original labels are always kept in `original_label`.

Nothing in this module writes to the original dataset files.
"""
import hashlib
import io
import ipaddress
import os
import struct
import sys
import time
import zipfile

import numpy as np
import pandas as pd

# --------------------------------------------------------------------------------------------
# Unified schema
# --------------------------------------------------------------------------------------------
FLOW_COLUMNS = {
    "ts": "float64", "ts_end": "float64",
    "src_ip": "string", "src_port": "int32", "dst_ip": "string", "dst_port": "int32",
    "proto": "string",                      # tcp / udp / icmp / arp / other
    "duration": "float64",
    "fwd_pkts": "int64", "bwd_pkts": "int64", "fwd_bytes": "int64", "bwd_bytes": "int64",
    "fwd_flags": "int16", "bwd_flags": "int16",
    "mal_frac": "float32",                  # share of malicious packets (packet-labelled sources), else 0/1
    "is_attack": "int8", "attack_class": "string", "campaign": "string", "original_label": "string",
    "label_note": "string",                 # empty, or why our label differs from / refines the original one
    "dataset": "string", "capture": "string",
}
ATTACK_CLASSES = ["benign", "scanning", "ddos", "ransomware", "mirai", "other"]

# Datasets are plug-ins in scripts/aegex_datasets (one file each). ALL_DATASETS / ACTIVE_DATASETS are
# read from there on first use (module __getattr__ below): add / delete a plug-in file, or set its
# ACTIVE flag, and every step, model and benchmark follows.
SCRIPTS_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if SCRIPTS_DIR not in sys.path:
    sys.path.insert(0, SCRIPTS_DIR)


def __getattr__(name):
    if name in ("ALL_DATASETS", "ACTIVE_DATASETS"):
        import aegex_datasets
        return aegex_datasets.names() if name == "ALL_DATASETS" else aegex_datasets.active()
    raise AttributeError(f"module 'aegex_prep' has no attribute {name!r}")


def log(*a):
    print(time.strftime("%H:%M:%S"), *a, flush=True)


FIN, SYN, RST, PSH, ACK, URG = 1, 2, 4, 8, 16, 32
PROTO_NAME = {1: "icmp", 6: "tcp", 17: "udp"}

# Zeek-like inactivity timeouts (seconds)
TIMEOUT = {"tcp": 300.0, "udp": 60.0, "icmp": 60.0, "arp": 60.0, "other": 60.0}
# NetFlow-style active timeout: long-lived connections are exported every 120 s, so continuous
# streams (e.g. camera video) become a time series of records instead of one hour-long flow.
ACTIVE_TIMEOUT = 120.0


def to_schema(df):
    """Order columns and cast to the unified dtypes."""
    for c, t in FLOW_COLUMNS.items():
        if c not in df.columns:
            df[c] = "" if t == "string" else 0
    df = df[list(FLOW_COLUMNS)]
    return df.astype(FLOW_COLUMNS)


def write_parquet(df, path):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    df.to_parquet(tmp, index=False, compression="zstd")
    os.replace(tmp, path)


# --------------------------------------------------------------------------------------------
# Where the data is (one setting for every script)
# --------------------------------------------------------------------------------------------
# Default: everything in the project folder (two levels above this file), as on the author's PC.
# Override with environment variables, e.g. in a Kaggle notebook:
#     AEGEX_DATA=/kaggle/input        (original datasets; read-only, any sub-folders)
#     AEGEX_OUT=/kaggle/working       (preprocessed/, models/, model_results/, live_results/, ...)
# Kaggle unpacks uploaded archives, so locate() also finds an original as an unpacked file.
PROJECT_DIR = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
DATA_DIR = os.path.abspath(os.environ.get("AEGEX_DATA") or PROJECT_DIR)
OUT_DIR = os.path.abspath(os.environ.get("AEGEX_OUT") or PROJECT_DIR)
PREPROCESSED_DIR = os.path.join(OUT_DIR, "preprocessed")
_SKIP_DIRS = {".venv", "__pycache__", "preprocessed", "models", "model_results", "live_results",
              "results_summary", ".git"}
_file_index = {}


def _index(root):
    """[(relative path lower case with '/', absolute path)] of every file under root (cached)."""
    if root not in _file_index:
        out = []
        for d, dirs, files in os.walk(root):
            dirs[:] = [x for x in dirs if x not in _SKIP_DIRS]
            for f in files:
                p = os.path.join(d, f)
                out.append((os.path.relpath(p, root).replace(os.sep, "/").lower(), p))
        _file_index[root] = out
    return _file_index[root]


def locate(name, member=None):
    """Find an original dataset file -> (path, member) for open_maybe_zip().

    Searched root by root: AEGEX_DATA first, then the project folder (derived inputs such as
    kitsune_mirai_relabeled\\ live there). In each root:
    1. root/name exists: use it as is (a zip is read with `member`).
    2. an UNPACKED copy (Kaggle unpacks archives): the file whose path ends with `member`, or, without a
       member, with `name` minus a trailing '.zip' (Mirai_pcap.pcap.zip -> Mirai_pcap.pcap); member is then
       None. Matching ignores case; the shortest matching path wins."""
    tail = member or (name[:-4] if name.lower().endswith(".zip") else name)
    tail = tail.replace("\\", "/").strip("/").lower()
    for root in dict.fromkeys([DATA_DIR, PROJECT_DIR]):
        p = os.path.join(root, name)
        if os.path.exists(p):
            return p, member
        hits = [p for rel, p in _index(root) if rel == tail or rel.endswith("/" + tail)]
        if hits:
            return min(hits, key=len), None
    raise FileNotFoundError(f"original '{name}'" + (f" [{member}]" if member else "") +
                            f" not found in AEGEX_DATA={DATA_DIR} (neither as file nor unpacked)")


def read_original_bytes(name, member=None):
    """Whole content of an original (zip member or unpacked file) - for small tables such as parquet."""
    path, mem = locate(name, member)
    with open_maybe_zip(path, mem) as fh:
        return fh.read()


# --------------------------------------------------------------------------------------------
# Provenance: originals must stay byte-identical
# --------------------------------------------------------------------------------------------
def sha256(path, block=1 << 22):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(block), b""):
            h.update(b)
    return h.hexdigest().upper()


def check_originals(data_dir, names):
    """Verify the named originals against ORIGINALS_SHA256.txt. Raises on any mismatch."""
    manifest = {}
    mpath = os.path.join(data_dir, "ORIGINALS_SHA256.txt")
    missing = [n for n in names if not os.path.exists(os.path.join(data_dir, n))]
    if not os.path.exists(mpath) or missing:
        raise RuntimeError(f"Cannot verify originals in {data_dir}: " +
                           ("no ORIGINALS_SHA256.txt" if not os.path.exists(mpath) else f"missing {missing}") +
                           ". Outside your own verified copy (e.g. on Kaggle) run with --skip-checksums.")
    with open(mpath, encoding="utf-8-sig") as f:
        for line in f:
            parts = line.split()
            if len(parts) >= 4 and len(parts[0]) == 64:
                manifest[" ".join(parts[3:]).split(" (added")[0].strip()] = parts[0].upper()
    bad = []
    for n in names:
        if n not in manifest:
            bad.append(f"{n}: not in manifest")
        elif sha256(os.path.join(data_dir, n)) != manifest[n]:
            bad.append(f"{n}: CHECKSUM MISMATCH")
    if bad:
        raise RuntimeError("Original dataset check failed:\n  " + "\n  ".join(bad))
    return True


# --------------------------------------------------------------------------------------------
# Packet capture reading (pcap + pcapng, optionally inside a .zip) - streaming, read-only
# --------------------------------------------------------------------------------------------
def open_maybe_zip(path, member=None):
    if path.lower().endswith(".zip"):
        z = zipfile.ZipFile(path)
        name = member or [n for n in z.namelist() if not n.endswith("/")][0]
        return z.open(name)
    return open(path, "rb")


def read_capture(fh):
    """Yield (timestamp_seconds, frame_bytes) from a pcap or pcapng stream."""
    f = io.BufferedReader(fh, buffer_size=1 << 22)
    magic = f.peek(4)[:4]
    if magic in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d"):
        gh = f.read(24)
        e = "<" if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1") else ">"
        div = 1e9 if magic in (b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d") else 1e6
        linktype = struct.unpack(e + "I", gh[20:24])[0]
        hdr = struct.Struct(e + "IIII")
        while True:
            h = f.read(16)
            if len(h) < 16:
                return
            s, frac, incl, _ = hdr.unpack(h)
            yield s + frac / div, f.read(incl), linktype
    e, ifaces = "<", []
    while True:
        bh = f.read(8)
        if len(bh) < 8:
            return
        if struct.unpack("<I", bh[:4])[0] == 0x0A0D0D0A:          # section header block
            bom = f.read(4)
            e = "<" if bom == b"\x4d\x3c\x2b\x1a" else ">"
            f.read(struct.unpack(e + "I", bh[4:8])[0] - 12)
            ifaces = []
            continue
        btype, blen = struct.unpack(e + "II", bh)
        body = f.read(blen - 8)
        if btype == 1:                                              # interface description
            linktype = struct.unpack(e + "H", body[:2])[0]
            div, opts, i = 1e6, body[8:-4], 0
            while i + 4 <= len(opts):
                code, ln = struct.unpack(e + "HH", opts[i:i + 4])
                if code == 0:
                    break
                if code == 9:
                    v = opts[i + 4]
                    div = float(2 ** (v & 0x7F)) if v & 0x80 else float(10 ** v)
                i += 4 + ((ln + 3) & ~3)
            ifaces.append((div, linktype))
        elif btype == 6:                                            # enhanced packet block
            iid, th, tl, cap, _ = struct.unpack(e + "IIIII", body[:20])
            div, lt = ifaces[iid]
            yield ((th << 32) | tl) / div, body[20:20 + cap], lt
        elif btype == 3:                                            # simple packet block
            yield None, body[4:4 + struct.unpack(e + "I", body[:4])[0]], ifaces[0][1] if ifaces else 1


def _ip(b):
    return f"{b[0]}.{b[1]}.{b[2]}.{b[3]}"


def parse_packet(frame, linktype=1):
    """Return (proto, src, sport, dst, dport, ip_bytes, tcp_flags) or None (non-IPv4/ARP)."""
    if linktype == 1:                       # Ethernet
        if len(frame) < 14:
            return None
        et, off = (frame[12] << 8) | frame[13], 14
        while et in (0x8100, 0x88A8) and len(frame) >= off + 4:    # VLAN tags
            et, off = (frame[off + 2] << 8) | frame[off + 3], off + 4
    elif linktype == 113:                   # Linux cooked capture (SLL)
        if len(frame) < 16:
            return None
        et, off = (frame[14] << 8) | frame[15], 16
    elif linktype in (101, 228):            # raw IPv4
        et, off = 0x0800, 0
    else:
        return None
    if et == 0x0806 and len(frame) >= off + 28:
        return ("arp", _ip(frame[off + 14:off + 18]), 0, _ip(frame[off + 24:off + 28]), 0, 28, 0)
    if et != 0x0800 or len(frame) < off + 20:
        return None
    ihl = (frame[off] & 0x0F) * 4
    total = (frame[off + 2] << 8) | frame[off + 3]
    p = frame[off + 9]
    src, dst = _ip(frame[off + 12:off + 16]), _ip(frame[off + 16:off + 20])
    l4 = off + ihl
    sport = dport = flags = 0
    if p in (6, 17) and len(frame) >= l4 + 4:
        sport, dport = (frame[l4] << 8) | frame[l4 + 1], (frame[l4 + 2] << 8) | frame[l4 + 3]
        if p == 6 and len(frame) >= l4 + 14:
            flags = frame[l4 + 13] & 0x3F
    elif p == 1 and len(frame) >= l4 + 2:
        sport, dport = frame[l4], frame[l4 + 1]        # ICMP type / code (Zeek convention)
    return (PROTO_NAME.get(p, "other"), src, sport, dst, dport, total, flags)


# --------------------------------------------------------------------------------------------
# Packets -> bidirectional flows
# --------------------------------------------------------------------------------------------
class FlowBuilder:
    """Zeek-style bidirectional flow assembly with inactivity + active timeouts.

    A flow key is the unordered pair of endpoints + protocol. The originator is the sender
    of the first packet. A TCP flow is closed when a fresh SYN (without ACK) arrives after the
    connection saw FIN or RST, or after the inactivity timeout. Flows longer than ACTIVE_TIMEOUT
    are exported and continued in a new record that keeps the original orientation.
    """

    COLS = ["ts", "ts_end", "src_ip", "src_port", "dst_ip", "dst_port", "proto", "fwd_pkts",
            "bwd_pkts", "fwd_bytes", "bwd_bytes", "fwd_flags", "bwd_flags", "_closed", "_mal", "_tags"]
    CHUNK = 500_000          # finished flows are compacted into DataFrames every CHUNK records

    def __init__(self, tag_reducer=None):
        """tag_reducer: optional fn(dict tag->packet count) -> str, used when add() gets tags
        (per-packet fine labels); the result is returned in a `tag` column."""
        self.active = {}
        self.done = []
        self.chunks = []
        self.tag_reducer = tag_reducer or (lambda d: max(d, key=d.get))

    def _close(self, key):
        self.done.append(self.active.pop(key))
        if len(self.done) >= self.CHUNK:
            self._compact()

    def _compact(self):
        if not self.done:
            return
        df = pd.DataFrame(self.done, columns=self.COLS)
        self.done = []
        df["_tags"] = [self.tag_reducer(d) if d else None for d in df._tags]
        self.chunks.append(df)

    def n_flows(self):
        return sum(len(c) for c in self.chunks) + len(self.done) + len(self.active)

    def add(self, t, pkt, mal, tag=None):
        proto, src, sp, dst, dp, nbytes, flags = pkt
        # ICMP: key on the host pair only, so an echo request (type 8) and its reply (type 0)
        # form ONE flow; the record keeps the first packet's type/code as src_port/dst_port.
        a, b = ((src, 0), (dst, 0)) if proto in ("icmp", "arp") else ((src, sp), (dst, dp))
        key = (proto, a, b) if a <= b else (proto, b, a)
        f = self.active.get(key)
        if f is not None:
            closed = f[13]
            if (t - f[1] > TIMEOUT[proto]) or (proto == "tcp" and closed and flags & SYN and not flags & ACK):
                self._close(key)
                f = None
            elif t - f[0] > ACTIVE_TIMEOUT:
                # long-lived connection: export a record and continue in a new one, same orientation
                self._close(key)
                f = [t, t, f[2], f[3], f[4], f[5], proto, 0, 0, 0, 0, 0, 0, False, 0, None]
                self.active[key] = f
        if f is None:
            # [ts, last, src, sport, dst, dport, proto, fp, bp, fb, bb, ff, bf, closed, malpkts, tags]
            f = [t, t, src, sp, dst, dp, proto, 0, 0, 0, 0, 0, 0, False, 0, None]
            self.active[key] = f
        f[1] = t
        if src == f[2] and (sp == f[3] or proto in ("icmp", "arp")):
            f[7] += 1; f[9] += nbytes; f[11] |= flags
        else:
            f[8] += 1; f[10] += nbytes; f[12] |= flags
        if flags & (FIN | RST):
            f[13] = True
        f[14] += mal
        if tag is not None:
            d = f[15]
            if d is None:
                d = f[15] = {}
            d[tag] = d.get(tag, 0) + 1

    def expire(self, now):
        for k in [k for k, f in self.active.items() if now - f[1] > TIMEOUT[k[0]]]:
            self._close(k)

    def finish(self):
        for k in list(self.active):
            self._close(k)
        self._compact()
        df = pd.concat(self.chunks, ignore_index=True) if self.chunks else pd.DataFrame(columns=self.COLS)
        self.chunks = []
        df["duration"] = df.ts_end - df.ts
        df["mal_frac"] = df._mal / (df.fwd_pkts + df.bwd_pkts)
        drop = ["_closed", "_mal"]
        if df._tags.notna().any():
            df = df.rename(columns={"_tags": "tag"})
        else:
            drop.append("_tags")
        return df.drop(columns=drop).sort_values("ts", kind="stable").reset_index(drop=True)


def build_flows_from_pcap(path, member=None, packet_labels=None, log=print):
    """Read one capture and return its flows. packet_labels: optional sequence of 0/1 per packet
    (same order as the capture, e.g. Kitsune labels); used to compute mal_frac per flow."""
    fb = FlowBuilder()
    n = skipped = 0
    last_expire = None
    with open_maybe_zip(path, member) as fh:
        for t, frame, lt in read_capture(fh):
            mal = int(packet_labels[n]) if packet_labels is not None else 0
            n += 1
            p = parse_packet(frame, lt)
            if p is None or t is None:
                skipped += 1
                continue
            fb.add(t, p, mal)
            if last_expire is None:
                last_expire = t
            elif t - last_expire > 30:
                fb.expire(t)
                last_expire = t
            if n % 2_000_000 == 0:
                log(f"    {n:,} packets, {fb.n_flows():,} flows")
    if packet_labels is not None and n != len(packet_labels):
        raise RuntimeError(f"{path}: {n} packets but {len(packet_labels)} labels")
    df = fb.finish()
    return df, {"packets": n, "skipped_non_ipv4": skipped, "flows": len(df)}


# --------------------------------------------------------------------------------------------
# Flow-record format readers shared by dataset plug-ins (Zeek history, CICFlowMeter)
# --------------------------------------------------------------------------------------------
_ZEEK_ORIG = {"S": SYN, "H": SYN | ACK, "A": ACK, "D": PSH, "F": FIN, "R": RST}


def _zeek_history_flags(h):
    """Zeek `history` -> (orig_flags, resp_flags). Upper case = originator, lower = responder.
    'D'/'d' (payload seen) is mapped to PSH, the closest NetFlow/pcap equivalent."""
    of = rf = 0
    if isinstance(h, str):
        for ch in h:
            if ch in _ZEEK_ORIG:
                of |= _ZEEK_ORIG[ch]
            elif ch.upper() in _ZEEK_ORIG:
                rf |= _ZEEK_ORIG[ch.upper()]
    return of, rf


# CICFlowMeter-V4 flow CSVs (e.g. ACI-IoT-2023) -------------------------------------------------------
CIC_COLS = ["Src IP", "Src Port", "Dst IP", "Dst Port", "Protocol", "Timestamp", "Flow Duration",
            "Total Fwd Packet", "Total Bwd packets", "Total Length of Fwd Packet", "Total Length of Bwd Packet",
            "Fwd Header Length", "Bwd Header Length", "Fwd PSH Flags", "Bwd PSH Flags", "FIN Flag Count",
            "SYN Flag Count", "RST Flag Count", "PSH Flag Count", "ACK Flag Count", "Label"]


def parse_timestamps(s, window):
    """CICFlowMeter timestamp strings -> unix seconds. Some tools write year-DAY-month ('2023-01-11' = 1 Nov);
    both orders are tried and the one falling inside `window` (start, end) dates is kept, row by row."""
    s = s.astype(str).str.strip()
    lo, hi = pd.Timestamp(window[0]), pd.Timestamp(window[1]) + pd.Timedelta(days=1)
    best = pd.Series(pd.NaT, index=s.index, dtype="datetime64[ns]")
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%d-%m %H:%M:%S", "%d/%m/%Y %I:%M:%S %p", "%d/%m/%Y %H:%M:%S",
                "%m/%d/%Y %I:%M:%S %p", "%Y-%m-%d %H:%M:%S.%f"):
        t = pd.to_datetime(s, format=fmt, errors="coerce")
        ok = best.isna() & t.notna() & (t >= lo) & (t < hi)
        best[ok] = t[ok]
    return (best - pd.Timestamp("1970-01-01")) / pd.Timedelta(seconds=1)


def cicflowmeter_to_flows(df, label_fn, window):
    """CICFlowMeter-V4 flow records -> unified flows. Returns (flows, stats).

      * time: `Timestamp` (1-s resolution, see parse_timestamps); duration: `Flow Duration` (microseconds).
      * bytes: payload (`Total Length of ... Packet`) + header bytes (`... Header Length`), clipped to >= 20 per
        packet; an approximation of IP-layer bytes (our convention).
      * protocol: CICFlowMeter writes 0 for ICMP and other non-TCP/UDP traffic -> 'icmp' (ping sweeps, ICMP floods).
      * flags: CICFlowMeter only counts SYN/ACK/FIN/RST over the whole flow (no direction; PSH has one per
        direction). Mapped as: SYN -> fwd SYN, plus bwd SYN|ACK when >= 2 SYNs and the responder answered;
        ACK -> bwd ACK if answered, fwd ACK if >= 2 ACKs or unanswered (a lone ACK is the reply's RST/ACK);
        FIN -> fwd FIN (+ bwd FIN when >= 2); RST -> from the
        responder if it answered without a handshake, else from the originator; PSH per direction.
      * label_fn(label string) -> attack_class."""
    st = {"rows_in": len(df)}
    ts = parse_timestamps(df["Timestamp"], window)
    st["bad_timestamps"] = int(ts.isna().sum())
    df = df[ts.notna()].copy()
    ts = ts[ts.notna()]
    num = lambda c: pd.to_numeric(df[c], errors="coerce").fillna(0)
    proto_n = num("Protocol").astype(int)
    proto = proto_n.map({6: "tcp", 17: "udp", 1: "icmp", 0: "icmp"}).fillna("other")
    fp, bp = num("Total Fwd Packet").astype("int64"), num("Total Bwd packets").astype("int64")
    fb = (num("Total Length of Fwd Packet") + num("Fwd Header Length").clip(lower=0)).clip(lower=20 * fp)
    bb = (num("Total Length of Bwd Packet") + num("Bwd Header Length").clip(lower=0)).clip(lower=20 * bp)
    syn, ack, fin, rst = (num(c).to_numpy() for c in ("SYN Flag Count", "ACK Flag Count", "FIN Flag Count", "RST Flag Count"))
    fpsh, bpsh, psh = (num(c).to_numpy() for c in ("Fwd PSH Flags", "Bwd PSH Flags", "PSH Flag Count"))
    tcp = (proto == "tcp").to_numpy()
    ans = (bp > 0).to_numpy()
    hs = (syn >= 2) & ans
    fwd_ack = (ack >= 2) | ((ack > 0) & ~ans)        # a single ACK on an answered flow is the reply's (RST/ACK)
    fwd = (np.where(syn > 0, SYN, 0) | np.where(fwd_ack, ACK, 0) | np.where(fin > 0, FIN, 0)
           | np.where((fpsh > 0) | ((psh > 0) & (bpsh == 0)), PSH, 0) | np.where((rst > 0) & ~(ans & ~hs), RST, 0))
    bwd = (np.where(hs, SYN | ACK, 0) | np.where((ack > 0) & ans, ACK, 0) | np.where((fin >= 2) & ans, FIN, 0)
           | np.where((bpsh > 0) & ans, PSH, 0) | np.where((rst > 0) & ans & ~hs, RST, 0))
    dur = num("Flow Duration").clip(lower=0).to_numpy() / 1e6
    lab = df["Label"].astype(str).str.strip()
    out = pd.DataFrame({
        "ts": ts.to_numpy(float), "ts_end": ts.to_numpy(float) + dur,
        "src_ip": df["Src IP"].astype(str).str.strip().to_numpy(), "src_port": num("Src Port").astype("int32").to_numpy(),
        "dst_ip": df["Dst IP"].astype(str).str.strip().to_numpy(), "dst_port": num("Dst Port").astype("int32").to_numpy(),
        "proto": proto.to_numpy(), "duration": dur,
        "fwd_pkts": fp.to_numpy(), "bwd_pkts": bp.to_numpy(),
        "fwd_bytes": fb.astype("int64").to_numpy(), "bwd_bytes": bb.astype("int64").to_numpy(),
        "fwd_flags": np.where(tcp, fwd, 0).astype("int16"), "bwd_flags": np.where(tcp, bwd, 0).astype("int16"),
        "original_label": lab.to_numpy(),
        "attack_class": lab.map(label_fn).to_numpy(),
    })
    out["is_attack"] = (out.attack_class != "benign").astype("int8")
    out["mal_frac"] = out.is_attack.astype("float32")
    out["campaign"], out["label_note"] = "", ""
    out = out.sort_values("ts", kind="stable").reset_index(drop=True)
    st["flows"] = len(out)
    st["labels"] = lab.value_counts().to_dict()
    st["classes"] = out.attack_class.value_counts().to_dict()
    return out, st


# --------------------------------------------------------------------------------------------
# Feature engineering (identical for every dataset)
# --------------------------------------------------------------------------------------------
SERVICE_PORTS = {
    "dns": {53}, "http": {80, 8080, 8000, 8081, 8008}, "https": {443, 8443},
    "telnet": {23, 2323}, "ssh": {22}, "smb_rpc": {135, 137, 138, 139, 445},
    "mqtt": {1883, 8883}, "modbus": {502}, "ssdp_mdns": {1900, 5353}, "ntp": {123},
    "ftp": {20, 21}, "smtp": {25, 465, 587}, "rdp": {3389}, "metasploit": {4444},
}
PORT_TO_SVC = {p: s for s, ps in SERVICE_PORTS.items() for p in ps}
SVC_COLS = [f"svc_{s}" for s in SERVICE_PORTS] + ["svc_wellknown_other", "svc_registered", "svc_ephemeral"]

# continuous features -> robust-scaled; binary features -> left as 0/1
# Device-context features (causal: only the device's own traffic up to this flow; IPs never used as values).
# ONE switch: set to False to remove them everywhere (features, scaler, models' compatibility fingerprint).
# After changing it, rerun preprocessing steps 2-5 and retrain the models.
USE_DEVICE_CONTEXT = True
DEVICE_CONTEXT_CONT = ["log_dev_flows_10s", "log_dev_new_peers_60s", "log_dev_new_ports_60s", "dev_reply_share_60s"]
DEVICE_CONTEXT_BIN = ["dev_new_peer"]
CONT_FEATURES = ["log_duration", "log_fwd_pkts", "log_bwd_pkts", "log_fwd_bytes", "log_bwd_bytes",
                 "fwd_mean_pkt", "bwd_mean_pkt", "log_pkt_rate", "log_byte_rate",
                 "fwd_byte_share", "fwd_pkt_share", "log_iat_device", "log_iat_pair"] + \
    (DEVICE_CONTEXT_CONT if USE_DEVICE_CONTEXT else [])
FLAG_FEATURES = [f"{d}_{n}" for d in ("fwd", "bwd") for n in ("syn", "ack", "fin", "rst", "psh")]
BIN_FEATURES = ["proto_tcp", "proto_udp", "proto_icmp", "proto_arp", "has_reply"] + \
    (DEVICE_CONTEXT_BIN if USE_DEVICE_CONTEXT else []) + FLAG_FEATURES + SVC_COLS
# device-context settings
NEW_PEER_GAP = 300.0     # a peer / port counts as "new" if the device has not used it for 300 s (or never)
RATE_WINDOW, CONTEXT_WINDOW = "10s", "60s"
FEATURES = CONT_FEATURES + BIN_FEATURES
IDENTITY = ["ts", "ts_end", "src_ip", "src_port", "dst_ip", "dst_port", "proto", "device",
            "dataset", "capture"]
RAW_COUNTERS = ["duration", "fwd_pkts", "bwd_pkts", "fwd_bytes", "bwd_bytes"]   # unscaled, for graph aggregates / reporting
LABELS = ["is_attack", "attack_class", "campaign", "original_label", "label_note", "mal_frac", "device_compromised"]
# device_compromised = 1 for every flow of a device that ORIGINATES attack flows in the capture.
# Its benign-labelled flows (background NTP/DNS of an infected bot) carry the attack's device context
# (IoT-23: ~2,900 new peers/min, same as the scans), so they are NOT a reference for normal behaviour:
# the scaler and the autoencoder use only clean benign traffic. Flood victims are not marked.

_LAN_NETS = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16")]
_PRIVATE_CACHE = {}
MIN_DEVICE_FLOWS = 3


def is_private(ip):
    """LAN address = RFC 1918 or link-local (NOT Python's broader is_private, which also
    includes reserved ranges such as 240.0.0.0/4 that spoofed floods hit at random)."""
    v = _PRIVATE_CACHE.get(ip)
    if v is None:
        try:
            a = ipaddress.ip_address(ip)
            v = a.version == 4 and any(a in n for n in _LAN_NETS)
        except ValueError:
            v = False
        if len(_PRIVATE_CACHE) < 2_000_000:
            _PRIVATE_CACHE[ip] = v
    return v


def assign_device(df):
    """The local device a flow belongs to (used for per-device LSTM sequences).
    A 'local device' is a LAN address seen in >= MIN_DEVICE_FLOWS flows of the capture (spoofed
    random sources appear once and are excluded). Device = originator if local, else responder if
    local, else originator. Spoofed-source floods therefore land in the VICTIM's sequence."""
    both = pd.concat([df.src_ip, df.dst_ip], ignore_index=True)
    cnt = both.value_counts()
    local = {ip: (n >= MIN_DEVICE_FLOWS and is_private(ip)) for ip, n in cnt.items()}
    sp, dp = df.src_ip.map(local).to_numpy(bool), df.dst_ip.map(local).to_numpy(bool)
    return np.where(sp, df.src_ip, np.where(dp, df.dst_ip, df.src_ip))


def device_context(df, has_reply):
    """Behaviour of the flow's DEVICE over its recent past (causal, so it works on live traffic too).
    Captures what single-flow features cannot see: floods (rate), scanning / worm spread (fan-out to
    new hosts and ports) and unanswered probing (reply share). IPs are only used as keys, never as values.
      log_dev_flows_10s       log1p(#flows of this device in the last 10 s, incl. this one)
      dev_new_peer            1 if the device has not talked to this peer for NEW_PEER_GAP s (or never)
      log_dev_new_peers_60s   log1p(#new-peer flows of the device in the last 60 s)
      log_dev_new_ports_60s   log1p(#flows to a service port the device has not used for NEW_PEER_GAP s)
      dev_reply_share_60s     share of the device's flows in the last 60 s that got any reply
    Input must be sorted by ts (engineer_features guarantees it)."""
    dev = pd.Series(df["device"].to_numpy(), index=df.index)
    peer = pd.Series(np.where(df.src_ip.to_numpy() == dev.to_numpy(), df.dst_ip.to_numpy(), df.src_ip.to_numpy()),
                     index=df.index)
    ts = df.ts
    gap_peer = ts.groupby([dev, peer], sort=False).diff()
    new_peer = (gap_peer.isna() | (gap_peer > NEW_PEER_GAP)).astype("float64")
    gap_port = ts.groupby([dev, df.dst_port], sort=False).diff()
    new_port = (gap_port.isna() | (gap_port > NEW_PEER_GAP)).astype("float64")
    # time-based rolling per device: work in (device, ts) order, then map back
    order = np.lexsort((ts.to_numpy(), dev.to_numpy()))
    tmp = pd.DataFrame({"device": dev.to_numpy()[order], "one": 1.0, "np": new_peer.to_numpy()[order],
                        "nport": new_port.to_numpy()[order], "rep": has_reply.to_numpy()[order].astype("float64")},
                       index=pd.to_datetime(ts.to_numpy()[order], unit="s"))
    g = tmp.groupby("device", sort=True)
    rate = g["one"].rolling(RATE_WINDOW).sum().to_numpy()
    r60 = g[["np", "nport", "rep", "one"]].rolling(CONTEXT_WINDOW).sum()
    out = np.empty((len(df), 5))
    out[order, 0] = np.log1p(rate)
    out[order, 1] = tmp["np"].to_numpy()
    out[order, 2] = np.log1p(r60["np"].to_numpy())
    out[order, 3] = np.log1p(r60["nport"].to_numpy())
    out[order, 4] = r60["rep"].to_numpy() / r60["one"].to_numpy()
    return pd.DataFrame(out, index=df.index, columns=["log_dev_flows_10s", "dev_new_peer", "log_dev_new_peers_60s",
                                                      "log_dev_new_ports_60s", "dev_reply_share_60s"])


def engineer_features(df):
    """Raw unified flows -> model features (unscaled). Input must be one capture."""
    df = df.sort_values("ts", kind="stable").reset_index(drop=True)
    df["device"] = assign_device(df)
    att = df.is_attack.to_numpy() == 1
    attackers = set(df.src_ip.to_numpy()[att]) & set(df.device.to_numpy()[att])
    df["device_compromised"] = df.device.isin(attackers).astype("int8")
    f = pd.DataFrame(index=df.index)
    fp, bp = df.fwd_pkts.astype("float64"), df.bwd_pkts.astype("float64")
    fbt, bbt = df.fwd_bytes.astype("float64"), df.bwd_bytes.astype("float64")
    dur = df.duration.clip(lower=0).astype("float64")
    f["log_duration"] = np.log1p(dur)
    f["log_fwd_pkts"], f["log_bwd_pkts"] = np.log1p(fp), np.log1p(bp)
    f["log_fwd_bytes"], f["log_bwd_bytes"] = np.log1p(fbt), np.log1p(bbt)
    f["fwd_mean_pkt"] = np.log1p(fbt / fp.where(fp > 0)).fillna(0)
    f["bwd_mean_pkt"] = np.log1p(bbt / bp.where(bp > 0)).fillna(0)
    f["log_pkt_rate"] = np.log1p((fp + bp) / (dur + 1e-3))
    f["log_byte_rate"] = np.log1p((fbt + bbt) / (dur + 1e-3))
    f["fwd_byte_share"] = (fbt / (fbt + bbt).where(fbt + bbt > 0)).fillna(0.5)
    f["fwd_pkt_share"] = (fp / (fp + bp).where(fp + bp > 0)).fillna(0.5)
    # temporal context: time since the previous flow of the same device / same host pair
    f["log_iat_device"] = np.log1p(df.groupby("device", sort=False).ts.diff().fillna(3600).clip(0, 3600))
    pair = df.src_ip.str.cat(df.dst_ip, sep=">")
    f["log_iat_pair"] = np.log1p(df.ts.groupby(pair, sort=False).diff().fillna(3600).clip(0, 3600))
    for p in ("tcp", "udp", "icmp", "arp"):
        f[f"proto_{p}"] = (df.proto == p).astype("int8")
    f["has_reply"] = (bp > 0).astype("int8")
    if USE_DEVICE_CONTEXT:
        ctx = device_context(df, f["has_reply"])
        for c in ctx.columns:
            f[c] = ctx[c].to_numpy()
    for d in ("fwd", "bwd"):
        fl = df[f"{d}_flags"].astype("int16")
        for n, bit in (("syn", SYN), ("ack", ACK), ("fin", FIN), ("rst", RST), ("psh", PSH)):
            f[f"{d}_{n}"] = ((fl & bit) > 0).astype("int8")
    port = df.dst_port.where(df.proto.isin(["tcp", "udp"]), -1)
    svc = port.map(PORT_TO_SVC)
    for s in SERVICE_PORTS:
        f[f"svc_{s}"] = (svc == s).astype("int8")
    rest = svc.isna() & (port >= 0)
    f["svc_wellknown_other"] = (rest & (port < 1024)).astype("int8")
    f["svc_registered"] = (rest & (port >= 1024) & (port < 49152)).astype("int8")
    f["svc_ephemeral"] = (rest & (port >= 49152)).astype("int8")
    out = pd.concat([df[[c for c in IDENTITY if c in df.columns] + RAW_COUNTERS + LABELS].reset_index(drop=True),
                     f[FEATURES].astype("float32")], axis=1)
    return out


def chronological_split(df, train=0.70, val=0.15):
    """Per (attack_class) chronological 70/15/15 split inside one capture.
    Every class keeps its time order (no random-row leakage) and every class appears in every split."""
    split = np.empty(len(df), dtype=object)
    for _, idx in df.groupby("attack_class", sort=False).indices.items():
        t = df.ts.values[idx]
        order = idx[np.argsort(t, kind="stable")]
        n = len(order)
        a, b = int(round(n * train)), int(round(n * (train + val)))
        split[order[:a]], split[order[a:b]], split[order[b:]] = "train", "val", "test"
    return split


# Minimum spread used by the scaler. Very regular benign traffic (sensor heartbeats, camera streams,
# 120 s active-timeout records) has near-zero IQR on some features (e.g. 0.001), which blew tiny,
# harmless deviations up to the +-10 clip and made the LSTM flag "anything not a heartbeat".
# All continuous features are log or share values, so 0.1 ~ a 10 % change.
MIN_SCALE = 0.1
# Soft tails instead of a hard +-10 clip: |z| <= TAIL_START unchanged, beyond it grows as
# TAIL_START + log1p(|z| - TAIL_START). Extreme traffic still ranks above mild anomalies (keeps
# severity information) but cannot explode; a hard clip made every flood/scan score identically.
TAIL_START = 3.0


class RobustScaler:
    """median / IQR scaling fitted on TRAIN + BENIGN flows only, then clipped to [-clip, clip].
    The IQR is floored at MIN_SCALE so near-constant benign features cannot explode."""

    def __init__(self, clip=10.0, min_scale=MIN_SCALE, tail_start=TAIL_START):
        self.clip, self.min_scale, self.tail_start, self.center, self.scale = clip, min_scale, tail_start, {}, {}

    def fit(self, frame):
        for c in CONT_FEATURES:
            v = frame[c].astype("float64")
            q1, med, q3 = np.nanpercentile(v, [25, 50, 75])
            self.center[c], self.scale[c] = float(med), float(max(q3 - q1, self.min_scale))
        return self

    def transform(self, frame):
        for c in CONT_FEATURES:
            z = ((frame[c] - self.center[c]) / self.scale[c]).to_numpy("float64")
            if self.tail_start:
                a = np.abs(z)
                soft = np.sign(z) * (self.tail_start + np.log1p(np.maximum(a - self.tail_start, 0.0)))
                z = np.where(a > self.tail_start, soft, z)
            frame[c] = np.clip(z, -self.clip, self.clip).astype("float32")
        return frame

    def to_dict(self):
        return {"method": "robust (x-median)/max(IQR, min_scale), log soft tails beyond tail_start, clipped",
                "clip": self.clip, "min_scale": self.min_scale, "tail_start": self.tail_start,
                "fit_on": "train split, benign flows only", "center": self.center, "scale": self.scale}

    @classmethod
    def from_dict(cls, d):
        s = cls(clip=d.get("clip", 10.0), min_scale=d.get("min_scale", 0.0), tail_start=d.get("tail_start", 0.0))
        s.center, s.scale = dict(d["center"]), dict(d["scale"])
        return s
