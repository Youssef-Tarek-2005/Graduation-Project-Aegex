# ESP32 honeypot PoC: one-folder workflow

Setup (once): install Python, Wireshark (with Npcap) and Nmap; turn on the Windows
hotspot; check `config.json`. `esp32_ip: "auto"` finds the ESP32 on the hotspot for you; set a
fixed IP only if several devices are connected. Point the ESP32 sketch
at `http://<hotspot_ip>:5000`.

Per session (run the terminal as Administrator):

    python run.py baseline      # normal traffic, stop with Ctrl+C
    python run.py scan_test     # then in a second terminal:
    python tests.py scan

Output: `data/<timestamp>_<label>/` with `capture.pcap` (rotated hourly), `events.jsonl`
and `meta.json`. Test timings are in `data/test_log.jsonl`. Nothing is deleted.

`data/latest.pcap` is rewritten every minute (same file name, all packets of the running
session). Wireshark: press Ctrl+R to reload it; close it if Windows reports it as locked.

Capture is limited to the hotspot subnet (`local_only`) and keeps only the newest
files per session: with `two_files: true` (default) the session folder holds only `history.pcap`
(all older traffic) plus the live `capture_*.pcap`; at stop everything is merged into history.pcap.

Export to CSV:  python export_csv.py   (newest session) -> packets.csv + events.csv
