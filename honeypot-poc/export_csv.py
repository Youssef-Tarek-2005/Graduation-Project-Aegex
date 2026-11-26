"""Export a session to CSV files (uses tshark, installed with Wireshark).

Usage:  python export_csv.py [session_folder]     (default: newest folder in data/)
Creates in the session folder:
  packets.csv  one row per packet, with a 'label' column (attack set or session label)
  events.csv   the ESP32's own event reports (from events.jsonl)
"""
import csv, json, subprocess, sys, datetime, pathlib
from common import load_config

ROOT = pathlib.Path(__file__).parent
TSHARK_FIELDS = ["frame.number", "frame.time_epoch", "ip.src", "ip.dst", "ip.proto",
                 "tcp.srcport", "tcp.dstport", "udp.srcport", "udp.dstport",
                 "frame.len", "tcp.flags.str", "_ws.col.Protocol",
                 "http.request.method", "http.request.uri"]
HEADER = ["file", "frame", "time_epoch", "time_iso", "src_ip", "dst_ip", "ip_proto",
          "src_port", "dst_port", "length", "tcp_flags", "protocol",
          "http_method", "http_uri", "label"]


def label_windows():
    """(start_epoch, end_epoch, name) for every logged test command."""
    log = ROOT / "data" / "test_log.jsonl"
    out = []
    if log.exists():
        for line in log.read_text(encoding="utf-8").splitlines():
            r = json.loads(line)
            out.append((datetime.datetime.fromisoformat(r["start"]).timestamp(),
                        datetime.datetime.fromisoformat(r["end"]).timestamp(), r["set"]))
    return out


def label_for(t, windows, default):
    for a, b, name in windows:
        if a - 1 <= t <= b + 1:
            return name
    return default


def flatten_events(src, dst):
    rows, keys = [], ["received"]
    for line in src.read_text(encoding="utf-8").splitlines():
        rec = json.loads(line)
        row = {"received": rec["received"]}
        try:
            data = json.loads(rec["raw"])
            row.update(data if isinstance(data, dict) else {"raw": rec["raw"]})
        except ValueError:
            row["raw"] = rec["raw"]
        for k in row:
            if k not in keys:
                keys.append(k)
        rows.append(row)
    with open(dst, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=keys)
        w.writeheader()
        w.writerows(rows)
    return len(rows)


def main():
    cfg = load_config()
    tshark = str(pathlib.Path(cfg["dumpcap"]).with_name("tshark.exe"))
    data = ROOT / "data"
    if len(sys.argv) > 1:
        folder = pathlib.Path(sys.argv[1])
    else:
        sessions = sorted(p for p in data.iterdir() if p.is_dir())
        if not sessions:
            sys.exit("No session folders in data/")
        folder = sessions[-1]

    meta = folder / "meta.json"
    default = (json.loads(meta.read_text())["label"] if meta.exists()
               else folder.name.split("_", 2)[-1])
    windows = label_windows()

    files = [f for f in [folder / "history.pcap", folder / "merged.pcap"] if f.exists()]
    files += sorted(folder.glob("capture_*.pcap"))
    if not files:
        sys.exit(f"No pcap files in {folder}")

    count = 0
    with open(folder / "packets.csv", "w", newline="", encoding="utf-8") as out:
        w = csv.writer(out)
        w.writerow(HEADER)
        for pcap in files:
            cmd = [tshark, "-n", "-r", str(pcap), "-T", "fields",
                   "-E", "separator=,", "-E", "quote=d", "-E", "header=n"]
            for f in TSHARK_FIELDS:
                cmd += ["-e", f]
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                    text=True, encoding="utf-8", errors="replace")
            for row in csv.reader(proc.stdout):
                if len(row) != len(TSHARK_FIELDS):
                    continue
                (num, t, sip, dip, proto, tsp, tdp, usp, udp,
                 length, flags, pname, meth, uri) = row
                try:
                    te = float(t)
                except ValueError:
                    continue
                w.writerow([pcap.name, num, t,
                            datetime.datetime.fromtimestamp(te).isoformat(timespec="milliseconds"),
                            sip, dip, proto, tsp or usp, tdp or udp, length, flags, pname,
                            meth, uri, label_for(te, windows, default)])
                count += 1
            proc.wait()
    print(f"packets.csv: {count} packets")

    ev = folder / "events.jsonl"
    if ev.exists():
        print(f"events.csv: {flatten_events(ev, folder / 'events.csv')} events")
    print("Saved in", folder)


if __name__ == "__main__":
    main()
