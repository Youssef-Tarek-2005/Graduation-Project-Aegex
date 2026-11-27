"""Run labeled test traffic while a session is capturing.

Usage:  python tests.py gentle | scan
The ESP32 IP is found automatically when config.json has "esp32_ip": "auto".
Each command's start/end time goes to data/test_log.jsonl for labeling.
"""
import json, shutil, subprocess, sys, datetime, pathlib
from common import load_config, get_esp32_ip

ROOT = pathlib.Path(__file__).parent


def build_sets(ip):
    return {
        "gentle": [
            ["ping", "-c", "4", ip],
            ["curl", "-m", "10", f"http://{ip}/"],
            ["curl", "-m", "10", f"http://{ip}/status"],
            ["curl", "-m", "10", "-X", "POST", "-d", "user=admin&pass=test", f"http://{ip}/login"],
            ["curl", "-m", "10", f"http://{ip}/admin"],
        ],
        # slow connect scan, as the guide recommends (aggressive scans can crash the ESP32)
        "scan": [["nmap", "-Pn", "-sT", "-T2", "-p", "1-1024", ip]],
    }


names = ["gentle", "scan"]
if len(sys.argv) < 2 or sys.argv[1] not in names:
    sys.exit("Usage: python tests.py " + " | ".join(names))
name = sys.argv[1]

ip = get_esp32_ip(load_config())
cmds = build_sets(ip)[name]

missing = sorted({c[0] for c in cmds if not shutil.which(c[0])})
if missing:
    sys.exit(f"Not found in PATH: {', '.join(missing)}. "
             "Install it (nmap: https://nmap.org/download), reopen the terminal, "
             "and check with:  " + missing[0] + " --version")

(ROOT / "data").mkdir(exist_ok=True)
log = ROOT / "data" / "test_log.jsonl"
for cmd in cmds:
    t0 = datetime.datetime.now()
    print("run:", " ".join(cmd))
    subprocess.run(cmd)
    rec = {"set": name, "target": ip, "cmd": " ".join(cmd),
           "start": t0.isoformat(), "end": datetime.datetime.now().isoformat()}
    with open(log, "a", encoding="utf-8") as f:
        f.write(json.dumps(rec) + "\n")
