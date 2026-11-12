"""Collection - CSVSensorReader: replays / tails the sensor CSV row by row (simulated real time via esp_ms deltas).

Nothing is cleaned here: values stay as the raw strings so the Cleaning stage sees what really arrived."""
from __future__ import annotations

import asyncio
import csv
import logging
from typing import Any, AsyncIterator

from ..config import Settings

log = logging.getLogger(__name__)

# Header aliases -> canonical names (your CSV spells it `tempeture`; other exports use temperature_C).
COLUMN_ALIASES = {
    "time": "time", "esp_ms": "esp_ms", "smoke": "smoke",
    "tempeture": "tempeture", "temperature": "tempeture", "temperature_c": "tempeture", "temp": "tempeture",
    "humidity_pct": "humidity_pct", "humidity": "humidity_pct",
}


class CSVSensorReader:
    """Streams CSV rows as raw dicts. Tolerates BOMs, tab/comma/semicolon delimiters and ragged rows."""

    def __init__(self, s: Settings):
        self.s = s

    @staticmethod
    def _sniff(header: str) -> str:
        for d in ("\t", ";", ","):
            if d in header:
                return d
        return ","

    @staticmethod
    def _esp_ms(row: dict) -> int | None:
        try:
            return int(float(str(row.get("esp_ms")).strip()))
        except (TypeError, ValueError):
            return None

    async def stream(self) -> AsyncIterator[dict[str, Any]]:
        path = self.s.csv_path
        with open(path, "r", encoding="utf-8-sig", errors="replace", newline="") as fh:
            header_line = fh.readline()
            delim = self._sniff(header_line)
            header = [COLUMN_ALIASES.get(h.strip().lower(), h.strip().lower())
                      for h in next(csv.reader([header_line], delimiter=delim))]
            log.info("CSV opened: %s columns=%s delimiter=%r", path, header, delim)
            prev_ms: int | None = None
            while True:
                pos = fh.tell()
                line = fh.readline()
                if not line:
                    if self.s.follow_csv:
                        await asyncio.sleep(self.s.poll_interval)
                        continue
                    return
                if self.s.follow_csv and not line.endswith("\n"):   # half-written line: wait for the rest
                    fh.seek(pos)
                    await asyncio.sleep(self.s.poll_interval)
                    continue
                if not line.strip():
                    continue
                try:
                    values = next(csv.reader([line], delimiter=delim))
                except csv.Error:
                    values = [line.strip()]
                row: dict[str, Any] = {h: (values[i].strip() if i < len(values) else None) for i, h in enumerate(header)}
                row["_malformed"] = len(values) != len(header)

                # simulated real time: sleep for the gap between consecutive esp_ms stamps
                ms = self._esp_ms(row)
                if self.s.replay_speed > 0:
                    gap = (ms - prev_ms) / 1000.0 if (ms is not None and prev_ms is not None and ms >= prev_ms) else self.s.default_interval
                    await asyncio.sleep(min(gap / self.s.replay_speed, self.s.max_sleep))
                if ms is not None:
                    prev_ms = ms
                yield row
