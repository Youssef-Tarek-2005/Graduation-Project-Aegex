"""Independent checks on the relabeled Kitsune Mirai output (reads only the output files)."""
import collections, csv, os, sys
from datetime import datetime, timezone

out = sys.argv[1]
ts = lambda x: datetime.fromtimestamp(float(x), timezone.utc).strftime("%H:%M:%S")
INF = {"192.168.2.110", "192.168.2.107"}

labels = open(os.path.join(out, "mirai_labels_relabeled.csv")).read().split()
print("1) label file lines:", len(labels), "values:", collections.Counter(labels))

rows = list(csv.DictReader(open(os.path.join(out, "mirai_packets_detailed.csv"))))
print("   detailed rows:", len(rows), "| labels agree with detailed file:",
      all(r["new_label"] == l for r, l in zip(rows, labels)))
start = next(i for i, r in enumerate(rows) if r["orig_label"] == "1")

# 2) did attack behaviour already happen BEFORE the original attack start?
pre = rows[:start]
pre_arp = collections.defaultdict(set)
for r in pre:
    if r["kind"] == "arp" and r["src"] in INF:
        pre_arp[r["src"]].add(r["dst"])
pre_tel = sum(1 for r in pre if r["proto"] == "TCP" and (r["dport"] in ("23", "2323") or r["sport"] in ("23", "2323")))
print("\n2) before attack start: ARP targets asked by infected hosts:",
      {h: len(s) for h, s in pre_arp.items()}, "| Telnet packets:", pre_tel)

# 3) is the traffic we called benign in the attack window similar to the pre-attack normal traffic?
def mix(rs):
    c = collections.Counter()
    for r in rs:
        port = min(int(r["sport"] or 0), int(r["dport"] or 0)) if r["proto"] in ("TCP", "UDP") else ""
        c[f'{r["kind"]}/{r["proto"]}/{port}'] += 1
    tot = sum(c.values())
    return {k: round(v / tot * 100, 1) for k, v in c.most_common(8)}
bg = [r for r in rows[start:] if r["new_label"] == "0"]
print("\n3) traffic mix % - pre-attack normal :", mix(pre))
print("   traffic mix % - relabeled benign  :", mix(bg))
bg_tel = sum(1 for r in bg if r["dport"] in ("23", "2323") or r["sport"] in ("23", "2323"))
bg_arp_inf = sum(1 for r in bg if r["kind"] == "arp" and r["src"] in INF and r["dst"])
print("   relabeled-benign packets that are Telnet:", bg_tel, "| ARP from infected hosts:", bg_arp_inf)
inf_bg = collections.Counter((r["src"], r["dst"], r["proto"], r["dport"]) for r in bg if r["src"] in INF)
print("   infected hosts' traffic kept benign (top):", inf_bg.most_common(5))

# 4) Telnet scanning detail and propagation timeline
tel = [r for r in rows[start:] if r["proto"] == "TCP" and ("23" in (r["dport"], r["sport"]) or "2323" in (r["dport"], r["sport"]))]
probes = [r for r in tel if r["src"] in INF and r["dport"] in ("23", "2323")]
replies = [r for r in tel if r["dst"] in INF and r["sport"] in ("23", "2323")]
print("\n4) Telnet packets:", len(tel), "| probes from infected:", len(probes), "| replies to infected:", len(replies))
for h in sorted(INF):
    hp = [r for r in probes if r["src"] == h]
    if hp:
        print(f"   {h}: first probe {ts(hp[0]['timestamp'])}, last {ts(hp[-1]['timestamp'])}, targets {sorted(set(r['dst'] for r in hp))}")
first_110_to_107 = next((r for r in tel if r["src"] == "192.168.2.110" and r["dst"] == "192.168.2.107"), None)
print("   first .110 -> .107 Telnet packet:", ts(first_110_to_107["timestamp"]) if first_110_to_107 else None)

# 5) the R3 packets
print("\n5) R3_new_behaviour packets:")
for r in rows:
    if r["rule"] == "R3_new_behaviour":
        print("  ", ts(r["timestamp"]), r["src"], "->", r["dst"], r["proto"], r["sport"], "->", r["dport"])

# 6) malicious timeline per 5 minutes
tl = collections.Counter()
t0 = float(rows[start]["timestamp"])
for r in rows[start:]:
    if r["new_label"] == "1":
        tl[int((float(r["timestamp"]) - t0) // 300) * 5] += 1
print("\n6) malicious packets per 5 min after attack start:", dict(sorted(tl.items())))
