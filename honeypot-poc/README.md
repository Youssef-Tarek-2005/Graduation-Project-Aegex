# ESP32 honeypot PoC: Kali Linux version

One-folder workflow: packet capture + ESP32 event collector + live scan/flood detector.

## Setup (once)

    sudo apt install wireshark tshark nmap curl     # dumpcap, tshark, mergecap, nmap
    ip -br addr                                     # find the interface the ESP32 connects through

Edit `config.json`: set `"interface"` (e.g. `wlan0`, `ap0`, `br0`). The subnet and Kali's own IP
are read from that interface, so there is no `hotspot_ip` any more. `esp32_ip: "auto"` finds the
ESP32 in the ARP table (with a ping sweep as fallback); set a fixed IP if several devices are
connected. Point the ESP32 sketch at `http://<kali_ip_on_that_interface>:5000`.

## Network requirement (important)

Capture only sees traffic that passes through Kali. That works when Kali *is* the access point /
gateway for the ESP32 (e.g. hostapd + dnsmasq on a second Wi-Fi adapter, or a bridge).
If Kali is just another Wi-Fi client, it will only see its own traffic plus broadcasts.

## Per session (needs root, or membership of the `wireshark` group)

    sudo python3 run.py baseline      # normal traffic, stop with Ctrl+C
    sudo python3 run.py scan_test     # then in a second terminal:
    python3 tests.py scan

Output: `data/<timestamp>_<label>/` with `capture_*.pcap` / `history.pcap`, `events.jsonl`,
`attacks.csv` and `meta.json`. Test timings go to `data/test_log.jsonl`. Nothing is deleted.
Files created under sudo belong to root: `sudo chown -R $USER data` before exporting.

`two_files: true` (default) keeps only `history.pcap` (older traffic) plus the live
`capture_*.pcap`; at stop everything is merged into `history.pcap`. With `two_files: false`
every file is kept and `data/latest.pcap` is rewritten each cycle (reload it with Ctrl+R in Wireshark).

Export to CSV:  `python3 export_csv.py`   (newest session) -> `packets.csv` + `events.csv`

Needs Python 3 only (standard library).
