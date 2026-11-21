"""ESP32 sensor CSV -> Events.

The ESP32 logs one reading per row, like data/my_data.csv:

  time,esp_ms,smoke,temperature_C,humidity_pct
  2026-10-23 10:14:52,3664,403,26.9,62

The first line is the header. Column names vary between exports (`temperature_C`, `tempeture`, `temp`...),
so they are mapped to one name. (Alias idea reused from the old CSVSensorReader.)

The `time` column has no time zone. You must say which clock wrote it (`tz=`). Ask Task A whether the
ESP32 time is UTC or local time. If this is wrong, every reading is shifted by hours and the labels from
the attack log land on the wrong rows.
"""
from __future__ import annotations

import csv
from datetime import datetime, timezone
from zoneinfo import ZoneInfo

from ..event import Event
from .base import FileFormatError, Parser

COLUMN_ALIASES = {
    "time": "time", "timestamp": "time", "esp_ms": "esp_ms",
    "smoke": "smoke",
    "temperature_c": "temperature_c", "temperature": "temperature_c", "tempeture": "temperature_c", "temp": "temperature_c",
    "humidity_pct": "humidity_pct", "humidity": "humidity_pct",
}
NUMERIC = ("esp_ms", "smoke", "temperature_c", "humidity_pct")
TIME_FORMATS = ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S.%f")


class Esp32CsvParser(Parser):
    source = "esp32"

    def __init__(self, device_id: str | None = None, device_ip: str | None = None, tz: str = "UTC") -> None:
        super().__init__(device_id)
        self.device_ip = device_ip
        self.tz = ZoneInfo(tz)
        self.header: list[str] | None = None
        self.delimiter = ","

    def _parse(self, line: str) -> list[Event] | None:
        if self.header is None:                     # first non-empty line is the header
            self.delimiter = next((d for d in ("\t", ";", ",") if d in line), ",")
            names = next(csv.reader([line], delimiter=self.delimiter))
            self.header = [COLUMN_ALIASES.get(n.strip().lower(), n.strip().lower()) for n in names]
            if "time" not in self.header:
                raise FileFormatError(f"ESP32 CSV has no time column (header: {line!r})")
            return []

        values = next(csv.reader([line], delimiter=self.delimiter))
        row = {h: (values[i].strip() if i < len(values) else "") for i, h in enumerate(self.header)}

        ts = self._time(row.get("time", ""))
        if ts is None:
            return None                             # a reading we can't place in time is useless

        payload: dict = {}
        invalid: list[str] = []
        for name in NUMERIC:
            if name not in row:
                continue
            try:
                payload[name] = float(row[name]) if name != "esp_ms" else int(float(row[name]))
            except ValueError:
                payload[name] = None                # keep the row, mark what was wrong; cleaning decides later
                invalid.append(name)
        if invalid:
            payload["invalid_fields"] = invalid
        if len(values) != len(self.header):
            payload["ragged_row"] = True

        return [Event(
            ts=ts, source=self.source, event_type="sensor_reading", severity="info",
            dedup_key=self.dedup_key(line), device_id=self.device_id, src_ip=self.device_ip,
            payload=payload,
        )]

    def _time(self, text: str) -> datetime | None:
        for fmt in TIME_FORMATS:
            try:
                return datetime.strptime(text, fmt).replace(tzinfo=self.tz).astimezone(timezone.utc)
            except ValueError:
                continue
        return None
