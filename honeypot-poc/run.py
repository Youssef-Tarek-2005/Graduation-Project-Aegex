"""Start one labeled session: packet capture + ESP32 event collector.

Usage:  python run.py <label>        e.g.  python run.py baseline
Stop with Ctrl+C. Everything lands in data/<timestamp>_<label>/
With two_files: true the session folder holds history.pcap (older traffic) + the live capture file.
"""
import json, os, signal, subprocess, sys, threading, time, datetime, pathlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT = pathlib.Path(__file__).parent
CFG = json.loads((ROOT / "config.json").read_text())


def find_interface():
    """Match the hotspot IP to a dumpcap interface number via the adapter GUID."""
    ps = (f"(Get-NetAdapter -InterfaceIndex "
          f"(Get-NetIPAddress -IPAddress '{CFG['hotspot_ip']}').InterfaceIndex).InterfaceGuid")
    guid = subprocess.run(["powershell", "-NoProfile", "-Command", ps],
                          capture_output=True, text=True).stdout.strip().lower()
    if not guid:
        sys.exit(f"No adapter has {CFG['hotspot_ip']}. Is the Windows hotspot on?")
    out = subprocess.run([CFG["dumpcap"], "-D"], capture_output=True, text=True).stdout
    for line in out.splitlines():
        if guid in line.lower():
            return line.split(".")[0].strip()
    sys.exit("Hotspot adapter not found in dumpcap -D. Is Npcap installed?")


def start_collector(events_file):
    lock = threading.Lock()

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"collector running\n")

        def do_POST(self):
            n = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(n).decode(errors="replace")
            rec = {"received": datetime.datetime.now().isoformat(), "raw": body}
            with lock, open(events_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(rec) + "\n")
            print("event:", body[:120])
            self.send_response(204)
            self.end_headers()

        def log_message(self, *a):
            pass

    srv = ThreadingHTTPServer(("0.0.0.0", CFG["collector_port"]), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv

def merge(mergecap, out, inputs):
    r = subprocess.run([mergecap, "-F", "pcap", "-w", str(out), *map(str, inputs)],
                       capture_output=True, text=True)
    return r.returncode == 0


def mergecap_path():
    return str(pathlib.Path(CFG["dumpcap"]).with_name("mergecap.exe"))


_merged_but_locked = set()


def start_updater(folder, two_files):
    """two_files: keep history.pcap + live file only.  Otherwise: keep every file and
    rewrite data/latest.pcap (whole session so far) each cycle."""
    mergecap = mergecap_path()
    merged, latest = folder / "merged.pcap", ROOT / "data" / "latest.pcap"
    done = set()

    def loop():
        while True:
            time.sleep(CFG["update_seconds"])
            if two_files:
                for f in list(_merged_but_locked):  # retry deleting files already merged
                    try:
                        f.unlink()
                        _merged_but_locked.discard(f)
                    except (PermissionError, FileNotFoundError):
                        pass
                consolidate_safe(folder)
                continue
            files = sorted(folder.glob("capture_*.pcap"))
            if not files:
                continue
            closed, current = files[:-1], files[-1]
            new = [f for f in closed if f not in done]
            base = [merged] if merged.exists() else []
            if new:
                tmp = folder / "tmp_merged.pcap"
                if merge(mergecap, tmp, base + new):
                    os.replace(tmp, merged)
                    done.update(new)
                    base = [merged]
            tmp = folder / "tmp_latest.pcap"
            if merge(mergecap, tmp, base + [current]):
                try:
                    os.replace(tmp, latest)
                    print(f"latest.pcap updated {datetime.datetime.now():%H:%M:%S}")
                except PermissionError:
                    print("latest.pcap is locked (close it in Wireshark); retrying next cycle")

    threading.Thread(target=loop, daemon=True).start()


def consolidate_safe(folder):
    # skip files whose merge succeeded but could not be deleted yet
    locked = {f for f in _merged_but_locked}
    files = [f for f in sorted(folder.glob("capture_*.pcap"))[:-1] if f not in locked]
    if files:
        consolidate_files(folder, files)


def consolidate_files(folder, files):
    mergecap = mergecap_path()
    history = folder / "history.pcap"
    tmp = folder / "tmp_history.pcap"
    base = [history] if history.exists() else []
    if merge(mergecap, tmp, base + files):
        os.replace(tmp, history)
        for f in files:
            try:
                f.unlink()
            except PermissionError:
                _merged_but_locked.add(f)
                print(f"{f.name} is open in Wireshark; close it so it can be removed")


def main():
    label = sys.argv[1] if len(sys.argv) > 1 else "session"
    start = datetime.datetime.now()
    folder = ROOT / "data" / f"{start:%Y%m%d_%H%M%S}_{label}"
    folder.mkdir(parents=True)

    iface = find_interface()
    start_collector(folder / "events.jsonl")
    two_files = CFG.get("two_files", True)
    start_updater(folder, two_files)

    net = CFG["hotspot_ip"].rsplit(".", 1)[0] + ".0/24"
    parts = []
    if CFG.get("local_only", True):  # keep only traffic between hotspot devices
        parts.append(f"src net {net} and dst net {net}")
    if CFG.get("capture_filter"):
        parts.append(f"({CFG['capture_filter']})")
    bpf = " and ".join(parts)

    cmd = [CFG["dumpcap"], "-i", iface, "-P",
           "-w", str(folder / "capture.pcap"),
           "-b", f"duration:{CFG['rotate_seconds']}"]
    if bpf:
        cmd += ["-f", bpf]
    proc = subprocess.Popen(cmd, creationflags=subprocess.CREATE_NEW_PROCESS_GROUP)

    det_proc = None
    if CFG.get("detector", {}).get("enabled", True):
        import detector
        tshark = str(pathlib.Path(CFG["dumpcap"]).with_name("tshark.exe"))
        det_proc, _ = detector.start_live(tshark, iface, bpf, folder / "attacks.csv",
                                          CFG.get("detector", {}))

    meta = {"label": label, "start": start.isoformat(), "interface": iface,
            "esp32_ip": CFG["esp32_ip"], "capture_filter": bpf, "two_files": two_files}
    print(f"Session '{label}' running -> {folder}\nCtrl+C to stop.")
    try:
        proc.wait()
    except KeyboardInterrupt:
        proc.send_signal(signal.CTRL_BREAK_EVENT)  # lets dumpcap flush and close the file
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.terminate()
    if det_proc:
        det_proc.terminate()
    if two_files:  # dumpcap has closed its last file: fold everything into one file
        rest = [f for f in sorted(folder.glob("capture_*.pcap")) if f not in _merged_but_locked]
        if rest:
            consolidate_files(folder, rest)
    meta["end"] = datetime.datetime.now().isoformat()
    (folder / "meta.json").write_text(json.dumps(meta, indent=2))
    print("Stopped. Saved meta.json.")


if __name__ == "__main__":
    main()
