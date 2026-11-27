"""Copy the packets of a recording that come BEFORE a time into a new pcap (e.g. its clean, attack-free start).

    cd backend
    .venv\\Scripts\\python -m demo.cut_pcap C:\\aegex_data\\Mirai_pcap.pcap.zip --before 2018-10-25T06:58:00Z `
        --out C:\\aegex_data\\derived\\kitsune_mirai_normal.pcap

Why: the AI models calibrate on a normal recording of the SAME network (detect.py --normal). The honeypot records
one before the attacks start; for a public dataset, the minutes before its first attack play that part. Evaluate
only what comes after the cut (python -m evaluate --from ...), so the models are never scored on what they
calibrated on. The original file is only read (a .zip is read in place, never unpacked or changed).
"""
from __future__ import annotations

import argparse
import sys
import zipfile
from datetime import datetime
from pathlib import Path

import scapy.layers.inet  # noqa: F401  (registers IP / Ethernet, so packets are read as such, not as raw bytes)
import scapy.layers.l2  # noqa: F401
from scapy.utils import PcapReader, PcapWriter


def cut(src: Path, before: datetime, out: Path) -> tuple[int, int]:
    """Write every packet with time < before to out. Returns (packets written, packets read)."""
    limit = before.timestamp()
    out.parent.mkdir(parents=True, exist_ok=True)
    fh = zipfile.ZipFile(src).open(zipfile.ZipFile(src).namelist()[0]) if src.suffix.lower() == ".zip" else open(src, "rb")
    written = read = 0
    with fh, PcapReader(fh) as reader, PcapWriter(str(out), sync=False) as w:   # reads pcap and pcapng alike
        for pkt in reader:
            read += 1
            if float(pkt.time) >= limit:
                break                                       # captures are in time order
            w.write(pkt)
            written += 1
    return written, read


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Copy the packets before a time into a new pcap.")
    ap.add_argument("pcap", type=Path, help=".pcap / .pcapng, or a .zip holding one")
    ap.add_argument("--before", required=True, help="UTC time with Z, e.g. 2018-10-25T06:58:00Z")
    ap.add_argument("--out", type=Path, required=True)
    a = ap.parse_args(argv)
    before = datetime.fromisoformat(a.before.replace("Z", "+00:00"))
    if before.tzinfo is None:
        ap.error("--before needs a time zone (Z)")
    n, _ = cut(a.pcap, before, a.out)
    print(f"{a.out}: {n:,} packets before {a.before}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
