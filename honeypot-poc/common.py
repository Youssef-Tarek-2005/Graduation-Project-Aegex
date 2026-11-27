"""Shared helpers (Linux/Kali): config, tool lookup, interface network, ESP32 discovery."""
import ipaddress, json, re, shutil, subprocess, socket, sys, pathlib
from concurrent.futures import ThreadPoolExecutor

ROOT = pathlib.Path(__file__).parent


def load_config():
    return json.loads((ROOT / "config.json").read_text())


def tool(cfg, name):
    """Full path of dumpcap / tshark / mergecap (config entry or PATH)."""
    found = shutil.which(cfg.get(name) or name)
    if not found:
        sys.exit(f"'{name}' not found. Install it:  sudo apt install wireshark-common tshark\n"
                 f"or set \"{name}\" in config.json.")
    return found


def iface_network(cfg):
    """(own_ip, ip_network) of the capture interface, read with `ip -4 addr`."""
    iface = cfg["interface"]
    out = subprocess.run(["ip", "-4", "-o", "addr", "show", "dev", iface],
                         capture_output=True, text=True).stdout
    m = re.search(r"inet\s+(\d+\.\d+\.\d+\.\d+/\d+)", out)
    if not m:
        sys.exit(f"Interface '{iface}' not found or has no IPv4 address. "
                 f"Check the name with `ip -br addr` and set \"interface\" in config.json.")
    ifc = ipaddress.ip_interface(m.group(1))
    return str(ifc.ip), ifc.network


def _neighbors(iface, network, own_ip):
    """Hosts in the kernel neighbour (ARP) table on this interface, excluding ourselves."""
    out = subprocess.run(["ip", "-4", "neigh", "show", "dev", iface],
                         capture_output=True, text=True).stdout
    found = []
    for line in out.splitlines():
        m = re.match(r"(\d+\.\d+\.\d+\.\d+)\s.*lladdr\s+\S+\s+(\w+)", line)
        if not m or m.group(2) in ("FAILED", "INCOMPLETE"):
            continue
        ip = m.group(1)
        if ipaddress.ip_address(ip) in network and ip != own_ip and ip not in found:
            found.append(ip)
    return found


def _ping_sweep(network, own_ip):
    """Wake up the ARP table by pinging every address on the subnet."""
    hosts = [str(h) for h in network.hosts() if str(h) != own_ip]
    if len(hosts) > 510:
        sys.exit(f"Subnet {network} is too large to sweep. Set esp32_ip manually in config.json.")

    def ping(ip):
        subprocess.run(["ping", "-c", "1", "-W", "1", ip], capture_output=True)
    with ThreadPoolExecutor(max_workers=50) as ex:
        list(ex.map(ping, hosts))


def _port_open(ip, port=80, timeout=1.5):
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except OSError:
        return False


def find_esp32(cfg):
    iface = cfg["interface"]
    own_ip, network = iface_network(cfg)
    cands = _neighbors(iface, network, own_ip)
    if not cands:
        print("Scanning subnet for the ESP32...")
        _ping_sweep(network, own_ip)
        cands = _neighbors(iface, network, own_ip)
    if not cands:
        sys.exit(f"No device found on {iface} ({network}). Is the ESP32 powered and "
                 "connected (2.4 GHz)? Or set esp32_ip manually in config.json.")
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
    return find_esp32(cfg) if ip in ("", "auto") else cfg["esp32_ip"]
