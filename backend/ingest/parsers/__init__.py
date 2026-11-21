"""Parsers: raw honeypot log lines -> Event objects (rows for the `events` table).

    from ingest.parsers import CowrieParser
    events = CowrieParser(device_id="gw-01").parse_file("samples/cowrie.json")

Zeek is not here on purpose: Zeek connections go to the `flows` table in step 5.
"""
from .base import FileFormatError, ParseStats, Parser
from .cowrie import CowrieParser
from .esp32 import Esp32CsvParser
from .mosquitto import MosquittoLogParser

PARSERS: dict[str, type[Parser]] = {
    "cowrie": CowrieParser,
    "mosquitto": MosquittoLogParser,
    "esp32": Esp32CsvParser,
}



def build_parser(source: str, device_id: str | None = None, *, broker_ip: str | None = None,
                 device_ip: str | None = None, tz: str = "UTC") -> Parser:
    """One place that knows which options each parser takes (used by both command-line tools)."""
    if source == "cowrie":
        return CowrieParser(device_id)
    if source == "mosquitto":
        return MosquittoLogParser(device_id, broker_ip=broker_ip)
    if source == "esp32":
        return Esp32CsvParser(device_id, device_ip=device_ip, tz=tz)
    raise ValueError(f"unknown source {source!r}; choose one of {sorted(PARSERS)}")


__all__ = ["PARSERS", "build_parser", "FileFormatError", "ParseStats", "Parser", "CowrieParser", "MosquittoLogParser", "Esp32CsvParser"]
