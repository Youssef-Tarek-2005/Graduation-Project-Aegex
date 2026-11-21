"""What every parser has in common.

A parser reads one line at a time and returns a list of Events (usually 0 or 1). It never touches the
database and never crashes on a bad line: bad lines are counted and skipped, so one broken line in a
1-million-line log cannot stop the whole load.
"""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from ..event import Event, make_dedup_key


class FileFormatError(Exception):
    """The whole file is wrong (e.g. a CSV with no time column). Stops the load instead of skipping every line."""


@dataclass
class ParseStats:
    lines: int = 0       # lines read
    events: int = 0      # events produced
    ignored: int = 0     # valid lines we don't need (e.g. Cowrie "client.size", Mosquitto "version 2.0.18")
    skipped: int = 0     # broken lines (not valid JSON, missing time, ...)

    def __str__(self) -> str:
        return f"{self.lines} lines -> {self.events} events ({self.ignored} ignored, {self.skipped} broken)"


class Parser:
    source: str = ""          # set by each subclass: "cowrie", "mosquitto", "esp32"

    def __init__(self, device_id: str | None = None) -> None:
        self.device_id = device_id
        self.stats = ParseStats()
        self._seen: Counter[str] = Counter()

    # ---- what each parser implements -------------------------------------------------------------
    def _parse(self, line: str) -> list[Event] | None:
        """Return events, [] for a valid line we don't need, or None for a broken line."""
        raise NotImplementedError

    # ---- shared ----------------------------------------------------------------------------------
    def dedup_key(self, line: str) -> str:
        """Same line seen again in this file -> next occurrence number -> different key."""
        occurrence = self._seen[line]
        self._seen[line] += 1
        return make_dedup_key(self.source, line, occurrence)

    def parse_line(self, line: str) -> list[Event]:
        line = line.rstrip("\r\n")
        if not line.strip():
            return []
        self.stats.lines += 1
        try:
            events = self._parse(line)
        except (ValueError, TypeError, KeyError):
            # A bad line. ContractError and FileFormatError are not caught here on purpose: they mean a bug
            # in our code or a wrong file, and must stop the load.
            events = None
        if events is None:
            self.stats.skipped += 1
            return []
        if not events:
            self.stats.ignored += 1
        self.stats.events += len(events)
        return events

    def parse_lines(self, lines: Iterable[str]) -> list[Event]:
        out: list[Event] = []
        for line in lines:
            out.extend(self.parse_line(line))
        return out

    def parse_file(self, path: str | Path) -> list[Event]:
        with open(path, "r", encoding="utf-8-sig", errors="replace") as fh:
            return self.parse_lines(fh)
