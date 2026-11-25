"""
Aegex - behaviour-based relabeling of the Kitsune "Mirai Botnet" capture.

The original Kitsune labels are a single time cut: every packet after the attack
start is labeled 1 (malicious), including the cameras' normal background traffic.
This script relabels each packet by what it actually does.

Rules (applied only from the original attack start onwards):
  R1 arp_sweep      ARP request sent by an infected host (Mirai local host discovery)
  R2 telnet_scan    TCP traffic to/from port 23 or 2323 that involves an infected host
                    (scan probes and the victims' replies)
  R3 new_behaviour  Other IP traffic from/to an infected host whose
                    (peer, protocol, service port) was never seen before the attack
                    (e.g. C&C / loader / report connections)
Everything else -> 0 (benign). Packets before the attack start stay 0.

Infected hosts are detected automatically from the attack window:
  - a host that sends ARP requests for >= ARP_SWEEP_MIN distinct IPs, or
  - a host that sends TCP packets to port 23/2323 (Telnet brute-force scanning).

Usage:
  python -I relabel_kitsune_mirai.py <Mirai_pcap.pcap | Mirai_pcap.pcap.zip> \
                                     <mirai_labels.csv | mirai_labels.csv.zip> <out_dir>

Outputs (in out_dir):
  mirai_labels_relabeled.csv   one label per line, same format/order as the original
  mirai_packets_detailed.csv   index, time, src, dst, proto, sport, dport, orig_label, new_label, rule
  relabel_report.txt           counts, detected hosts, and sanity checks
"""
import collections
import csv
import io
import os
import struct
import sys
import zipfile
from datetime import datetime, timezone

ARP_SWEEP_MIN = 20          # distinct ARP targets for a host to count as sweeping
TELNET_PORTS = {23, 2323}
PROTO = {1: "ICMP", 2: "IGMP", 6: "TCP", 17: "UDP", 47: "GRE"}


def open_maybe_zip(path):
    if path.lower().endswith(".zip"):
        z = zipfile.ZipFile(path)
        name = [n for n in z.namelist() if not n.endswith("/")][0]
        return z.open(name)
    return open(path, "rb")


def read_capture(path):
    """Yield (timestamp, frame_bytes) from a pcapng or classic pcap file."""
    f = io.BufferedReader(open_maybe_zip(path))
    magic = f.peek(4)[:4]
    if magic in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d"):
        gh = f.read(24)
        e = "<" if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1") else ">"
        div = 1e9 if magic in (b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d") else 1e6
        while True:
            h = f.read(16)
            if len(h) < 16:
                return
            s, frac, incl, _ = struct.unpack(e + "IIII", h)
            yield s + frac / div, f.read(incl)
    e = "<"
    ifaces = []
    while True:
        bh = f.read(8)
        if len(bh) < 8:
            return
        if struct.unpack("<I", bh[:4])[0] == 0x0A0D0D0A:          # section header
            bom = f.read(4)
            e = "<" if bom == b"\x4d\x3c\x2b\x1a" else ">"
            f.read(struct.unpack(e + "I", bh[4:8])[0] - 12)
            ifaces = []
            continue
        btype, blen = struct.unpack(e + "II", bh)
        body = f.read(blen - 8)
        if btype == 1:                                              # interface description
            div, opts, i = 1e6, body[8:-4], 0
            while i + 4 <= len(opts):
                code, ln = struct.unpack(e + "HH", opts[i:i + 4])
                if code == 0:
                    break
                if code == 9:
                    v = opts[i + 4]
                    div = float(2 ** (v & 0x7F)) if v & 0x80 else float(10 ** v)
                i += 4 + ((ln + 3) & ~3)
            ifaces.append(div)
        elif btype == 6:                                            # enhanced packet
            iid, th, tl, cap, _ = struct.unpack(e + "IIIII", body[:20])
            yield ((th << 32) | tl) / ifaces[iid], body[20:20 + cap]
        elif btype == 3:                                            # simple packet
            yield None, body[4:4 + struct.unpack(e + "I", body[:4])[0]]


def parse(frame):
    """Return dict with kind/src/dst/proto/sport/dport/arp_op (Ethernet frames)."""
    if len(frame) < 14:
        return {"kind": "other"}
    et, off = struct.unpack(">H", frame[12:14])[0], 14
    if et == 0x8100 and len(frame) >= 18:
        et, off = struct.unpack(">H", frame[16:18])[0], 18
    if et == 0x0806 and len(frame) >= off + 28:
        return {"kind": "arp", "op": struct.unpack(">H", frame[off + 6:off + 8])[0],
                "src": ".".join(map(str, frame[off + 14:off + 18])),
                "dst": ".".join(map(str, frame[off + 24:off + 28]))}
    if et == 0x0800 and len(frame) >= off + 20:
        ihl = (frame[off] & 0x0F) * 4
        p = frame[off + 9]
        r = {"kind": "ip", "proto": p,
             "src": ".".join(map(str, frame[off + 12:off + 16])),
             "dst": ".".join(map(str, frame[off + 16:off + 20])), "sport": 0, "dport": 0}
        if p in (6, 17) and len(frame) >= off + ihl + 4:
            r["sport"], r["dport"] = struct.unpack(">HH", frame[off + ihl:off + ihl + 4])
        return r
    return {"kind": "other", "ethertype": et}


def main():
    pcap_path, labels_path, out_dir = sys.argv[1:4]
    os.makedirs(out_dir, exist_ok=True)

    with open_maybe_zip(labels_path) as lf:
        orig = [int(float(x.split(b",")[-1])) for x in lf.read().split()]
    attack_start = orig.index(1)

    # ---- pass 1: parse every packet once, keep the light fields we need
    pkts = []
    for t, frame in read_capture(pcap_path):
        pkts.append((t, parse(frame)))
    n = len(pkts)
    if n != len(orig):
        sys.exit(f"ERROR: {n} packets but {len(orig)} labels - files do not belong together")

    # ---- detect infected hosts in the attack window
    arp_targets = collections.defaultdict(set)
    telnet_senders = collections.Counter()
    for t, p in pkts[attack_start:]:
        if p["kind"] == "arp" and p["op"] == 1:
            arp_targets[p["src"]].add(p["dst"])
        elif p["kind"] == "ip" and p["proto"] == 6 and p["dport"] in TELNET_PORTS:
            telnet_senders[p["src"]] += 1
    sweepers = {h for h, s in arp_targets.items() if len(s) >= ARP_SWEEP_MIN}
    infected = sweepers | set(telnet_senders)

    # ---- benign-phase behaviour profile for infected hosts (for R3)
    def service(p, host):
        peer = p["dst"] if p["src"] == host else p["src"]
        port = min(p["sport"], p["dport"]) if p["proto"] in (6, 17) else 0
        return (host, peer, p["proto"], port)

    seen_before = set()
    for t, p in pkts[:attack_start]:
        if p["kind"] == "ip":
            for h in (p["src"], p["dst"]):
                if h in infected:
                    seen_before.add(service(p, h))

    # ---- relabel
    new, rule = [0] * n, ["pre_attack"] * attack_start + ["benign_background"] * (n - attack_start)
    for i in range(attack_start, n):
        p = pkts[i][1]
        if p["kind"] == "arp":
            if p["op"] == 1 and p["src"] in sweepers:
                new[i], rule[i] = 1, "R1_arp_sweep"
        elif p["kind"] == "ip":
            hosts = {p["src"], p["dst"]} & infected
            if not hosts:
                continue
            if p["proto"] == 6 and (p["sport"] in TELNET_PORTS or p["dport"] in TELNET_PORTS):
                new[i], rule[i] = 1, "R2_telnet_scan"
            elif any(service(p, h) not in seen_before for h in hosts):
                new[i], rule[i] = 1, "R3_new_behaviour"

    # ---- write outputs
    with open(os.path.join(out_dir, "mirai_labels_relabeled.csv"), "w", newline="") as f:
        f.write("\n".join(map(str, new)) + "\n")
    with open(os.path.join(out_dir, "mirai_packets_detailed.csv"), "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["index", "timestamp", "kind", "src", "dst", "proto", "sport", "dport",
                     "orig_label", "new_label", "rule"])
        for i, (t, p) in enumerate(pkts):
            w.writerow([i, f"{t:.6f}" if t else "", p["kind"], p.get("src", ""), p.get("dst", ""),
                        PROTO.get(p.get("proto"), p.get("proto", "")), p.get("sport", ""),
                        p.get("dport", ""), orig[i], new[i], rule[i]])

    # ---- report
    ts = lambda x: datetime.fromtimestamp(x, timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    rc = collections.Counter(rule)
    trans = collections.Counter(zip(orig, new))
    lines = [
        "Kitsune Mirai relabeling report",
        f"packets: {n}   labels: {len(orig)}   match: {n == len(orig)}",
        f"attack start (first original label 1): packet {attack_start} at {ts(pkts[attack_start][0])}",
        f"infected hosts: {sorted(infected)}",
        f"  ARP sweepers (>= {ARP_SWEEP_MIN} distinct targets): "
        + ", ".join(f"{h} ({len(arp_targets[h])} targets)" for h in sorted(sweepers)),
        f"  Telnet scanners: {dict(telnet_senders)}",
        "",
        f"original labels : benign {orig.count(0)}  malicious {orig.count(1)}",
        f"new labels      : benign {new.count(0)}  malicious {new.count(1)}",
        f"orig->new  0->0 {trans[(0,0)]}  0->1 {trans[(0,1)]}  1->1 {trans[(1,1)]}  1->0 {trans[(1,0)]}",
        "",
        "packets per rule:",
    ] + [f"  {k:20s} {v}" for k, v in rc.most_common()]
    report = "\n".join(lines)
    with open(os.path.join(out_dir, "relabel_report.txt"), "w") as f:
        f.write(report + "\n")
    print(report)


if __name__ == "__main__":
    main()
