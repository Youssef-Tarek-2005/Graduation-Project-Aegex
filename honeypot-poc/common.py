"""Shared helpers: config loading and automatic ESP32 IP discovery (Windows)."""
import json, re, socket, subprocess, sys, pathlib
from concurrent.futures import ThreadPoolExecutor

ROOT = pathlib.Path(__file__).parent


def load_config():
    return json.loads((ROOT / "config.json").read_text())


def _arp_candidates(hotspot_ip):
    """Dynamic ARP entries on the hotspot subnet, excluding the laptop itself."""
    out = subprocess.run(["arp", "-a"], capture_output=True, text=True).stdout
    prefix = hotspot_ip.rsplit(".", 1)[0] + "."
    found, in_iface = [], False
    for line in out.splitlines():
        m = re.match(r"\s*Interface:\s*([\d.]+)", line)
        if m:
            in_iface = (m.group(1) == hotspot_ip)
            continue
        m = re.match(r"\s*([\d.]+)\s+([0-9a-f-]{17})\s+dynamic", line, re.I)
        if in_iface and m and m.group(1).startswith(prefix) and m.group(1) != hotspot_ip:
            found.append(m.group(1))
    return found


def _ping_sweep(hotspot_ip):
    """Wake up the ARP table by pinging every address on the hotspot subnet."""
    prefix = hotspot_ip.rsplit(".", 1)[0] + "."
    def ping(i):
        subprocess.run(["ping", "-n", "1", "-w", "300", prefix + str(i)],
                       capture_output=True)
    with ThreadPoolExecutor(max_workers=50) as ex:
        list(ex.map(ping, range(2, 255)))


def _port_open(ip, port=80, timeout=1.5):
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except OSError:
        return False


def find_esp32(hotspot_ip):
    cands = _arp_candidates(hotspot_ip)
    if not cands:
        print("Scanning hotspot subnet for the ESP32...")
        _ping_sweep(hotspot_ip)
        cands = _arp_candidates(hotspot_ip)
    if not cands:
        sys.exit("No device found on the hotspot. Is the ESP32 powered and connected "
                 "(2.4 GHz hotspot)? Or set esp32_ip manually in config.json.")
    if len(cands) > 1:  # several devices: keep the one serving the honeypot on port 80
        web = [c for c in cands if _port_open(c)]
        if len(web) == 1:
            cands = web
    if len(cands) > 1:
        sys.exit("Several devices found: " + ", ".join(cands) +
                 ". Set esp32_ip manually in config.json.")
    print("ESP32 found at", cands[0])
    return cands[0]


def get_esp32_ip(cfg):
    ip = str(cfg.get("esp32_ip", "auto")).strip().lower()
    return find_esp32(cfg["hotspot_ip"]) if ip in ("", "auto") else cfg["esp32_ip"]
