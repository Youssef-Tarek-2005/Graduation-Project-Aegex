"""Live attack detector: flags port scans (nmap) and floods / DDoS and records them.

Runs next to the capture (started by run.py). Alerts are printed and appended to
<session folder>/attacks.csv. Thresholds live in config.json under "detector".
"""
import csv, datetime, pathlib, subprocess, threading
from collections import defaultdict, deque

DEFAULTS = {"enabled": True,
            "scan_ports": 20,       # distinct ports probed by one source ...
            "scan_window": 30,      # ... within this many seconds = port scan
            "flood_packets": 150,   # packets to one target ...
            "flood_window": 5,      # ... within this many seconds = flood
            "ddos_sources": 3,      # flood from at least this many sources = DDoS
            "cooldown": 30}         # seconds before the same alert repeats


class Detector:
    def __init__(self, cfg, out_csv, hotspot_ip=None):
        self.c = {**DEFAULTS, **cfg}
        self.out = pathlib.Path(out_csv)
        self.hotspot_ip = hotspot_ip
        self.probes = defaultdict(deque)    # (src,dst) -> (t, proto, port) of SYN/UDP probes
        self.pkts = defaultdict(deque)      # dst -> (t, src)
        self.last_alert = {}
        if not self.out.exists():
            with open(self.out, "w", newline="", encoding="utf-8") as f:
                csv.writer(f).writerow(["time_iso", "type", "src", "dst", "detail"])

    def _alert(self, t, kind, src, dst, detail):
        key = (kind, src, dst)
        if t - self.last_alert.get(key, -1e9) < self.c["cooldown"]:
            return
        self.last_alert[key] = t
        iso = datetime.datetime.fromtimestamp(t).isoformat(timespec="seconds")
        with open(self.out, "a", newline="", encoding="utf-8") as f:
            csv.writer(f).writerow([iso, kind, src, dst, detail])
        print(f"ALERT {iso} {kind}: {src} -> {dst} ({detail})")

    def feed(self, t, src, dst, proto, dport, syn_only):
        """proto: 'tcp' | 'udp' | other; syn_only: TCP SYN without ACK."""
        if not src or not dst:
            return
        c = self.c

        # --- port scan: many distinct ports probed by one source ---
        if (proto == "tcp" and syn_only and dport) or (proto == "udp" and dport):
            q = self.probes[(src, dst)]
            q.append((t, proto, dport))
            while q and t - q[0][0] > c["scan_window"]:
                q.popleft()
            ports = {(p, d) for _, p, d in q}
            if len(ports) >= c["scan_ports"]:
                self._alert(t, "port_scan", src, dst,
                            f"{len(ports)} ports in {c['scan_window']}s")

        # --- flood / DDoS: many packets to one target ---
        q = self.pkts[dst]
        q.append((t, src))
        while q and t - q[0][0] > c["flood_window"]:
            q.popleft()
        if len(q) >= c["flood_packets"]:
            by_src = defaultdict(int)
            for _, s in q:
                by_src[s] += 1
            if len(by_src) >= c["ddos_sources"]:
                self._alert(t, "ddos", "multiple", dst,
                            f"{len(q)} packets from {len(by_src)} sources in {c['flood_window']}s")
            else:
                top = max(by_src, key=by_src.get)
                self._alert(t, "dos_flood", top, dst,
                            f"{by_src[top]} packets in {c['flood_window']}s")


def _flag(v):
    return str(v).strip().lower() in ("1", "true")


def start_live(tshark, iface, bpf, out_csv, cfg):
    """Stream packets from tshark into the detector. Returns (process, thread)."""
    fields = ["frame.time_epoch", "ip.src", "ip.dst", "tcp.dstport", "udp.dstport",
              "tcp.flags.syn", "tcp.flags.ack"]
    cmd = [tshark, "-n", "-l", "-i", iface, "-T", "fields", "-E", "separator=,"]
    if bpf:
        cmd += ["-f", bpf]
    for f in fields:
        cmd += ["-e", f]
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                            text=True, encoding="utf-8", errors="replace")
    det = Detector(cfg, out_csv)

    def loop():
        for line in proc.stdout:
            p = line.rstrip("\n").split(",")
            if len(p) != len(fields):
                continue
            try:
                t = float(p[0])
            except ValueError:
                continue
            if p[3]:
                proto, dport = "tcp", p[3]
            elif p[4]:
                proto, dport = "udp", p[4]
            else:
                proto, dport = "other", ""
            det.feed(t, p[1], p[2], proto, dport, _flag(p[5]) and not _flag(p[6]))

    th = threading.Thread(target=loop, daemon=True)
    th.start()
    return proc, th
