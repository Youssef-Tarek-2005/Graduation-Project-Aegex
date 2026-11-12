"""Collection - TelemetryCollector: merges the sensor CSV, the honeypot testbed and any externally pushed events
into TelemetryBatch objects (one per sensor reading)."""
from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from typing import Any, AsyncIterator

from ..config import Settings
from ..models import EventType, RawEvent, TelemetryBatch, utcnow
from ..testbed.simulator import HoneypotEventSimulator
from .csv_reader import CSVSensorReader

log = logging.getLogger(__name__)


class TelemetryCollector:
    """Combines CSV sensor rows, simulated honeypot events and externally pushed events into batches."""

    def __init__(self, s: Settings):
        self.s = s
        self.reader = CSVSensorReader(s)
        self.sim = HoneypotEventSimulator(s.sim_seed, s.attack_probability) if s.simulate_network else None
        self._external: asyncio.Queue[RawEvent] = asyncio.Queue()

    def submit_event(self, event_type: EventType, payload: dict[str, Any], source: str = "external",
                     timestamp: str | None = None) -> None:
        """Hook for real honeypot sensors (Cowrie, MQTT broker, BLE sniffer...): events join the next batch.
        Must be called from the event-loop thread (use loop.call_soon_threadsafe from other threads).
        `timestamp` (ISO-8601 UTC) keeps the sensor's own event time; default is now."""
        self._external.put_nowait(RawEvent(event_type, timestamp or utcnow().isoformat(), source, payload))

    @staticmethod
    def _parse_csv_time(raw: Any) -> datetime | None:
        if not raw:
            return None
        txt = str(raw).strip()
        try:
            dt = datetime.fromisoformat(txt.replace("Z", "+00:00"))
        except ValueError:
            for fmt in ("%Y-%m-%d %H:%M:%S", "%d/%m/%Y %H:%M:%S", "%m/%d/%Y %H:%M:%S", "%H:%M:%S"):
                try:
                    dt = datetime.strptime(txt, fmt)
                    break
                except ValueError:
                    dt = None
            if dt is None:
                return None
            if fmt == "%H:%M:%S":                       # time-of-day only: attach today's date
                today = utcnow()
                dt = dt.replace(year=today.year, month=today.month, day=today.day)
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)

    async def stream_batches(self) -> AsyncIterator[TelemetryBatch]:
        csv_queue: asyncio.Queue[dict[str, Any] | None] = asyncio.Queue(maxsize=100)
        csv_done = asyncio.Event()

        async def _read_csv() -> None:
            try:
                async for r in self.reader.stream():
                    await csv_queue.put(r)
            except Exception:
                log.exception("CSV reader encountered error")
            finally:
                csv_done.set()
                await csv_queue.put(None)

        csv_task = asyncio.create_task(_read_csv())
        last_sensor_row: dict[str, Any] = {"smoke": 0.0, "tempeture": 25.0, "humidity_pct": 50.0}

        try:
            while True:
                # 1. Drain external events if any arrived
                if not self._external.empty():
                    ext_events = []
                    while not self._external.empty():
                        ext_events.append(self._external.get_nowait())
                    now = utcnow()
                    sensor = RawEvent(EventType.SENSOR_READING, now.isoformat(), "csv", dict(last_sensor_row))
                    yield TelemetryBatch(timestamp=now, sensor_event=sensor, network_events=ext_events)
                    continue

                # 2. Consume ready CSV row if available
                if not csv_queue.empty():
                    row = csv_queue.get_nowait()
                    if row is not None:
                        last_sensor_row = row
                        now = utcnow()
                        ts = (self._parse_csv_time(row.get("time")) or now) if self.s.time_mode == "csv" else now
                        iso = ts.isoformat()
                        sensor = RawEvent(EventType.SENSOR_READING, iso, "csv", row)
                        net = self.sim.generate_window(iso) if self.sim else []
                        while not self._external.empty():
                            net.append(self._external.get_nowait())
                        yield TelemetryBatch(timestamp=ts, sensor_event=sensor, network_events=net)
                        continue

                # 3. If CSV finished, continue waiting solely for external honeypot events
                if csv_done.is_set():
                    ext = await self._external.get()
                    ext_events = [ext]
                    while not self._external.empty():
                        ext_events.append(self._external.get_nowait())
                    now = utcnow()
                    sensor = RawEvent(EventType.SENSOR_READING, now.isoformat(), "csv", dict(last_sensor_row))
                    yield TelemetryBatch(timestamp=now, sensor_event=sensor, network_events=ext_events)
                    continue

                # 4. Wait for either the next CSV row or next external event
                get_csv = asyncio.create_task(csv_queue.get())
                get_ext = asyncio.create_task(self._external.get())
                done, pending = await asyncio.wait([get_csv, get_ext], return_when=asyncio.FIRST_COMPLETED)
                for p in pending:
                    p.cancel()
                for d in done:
                    if d is get_csv:
                        row = d.result()
                        if row is not None:
                            last_sensor_row = row
                            now = utcnow()
                            ts = (self._parse_csv_time(row.get("time")) or now) if self.s.time_mode == "csv" else now
                            iso = ts.isoformat()
                            sensor = RawEvent(EventType.SENSOR_READING, iso, "csv", row)
                            net = self.sim.generate_window(iso) if self.sim else []
                            while not self._external.empty():
                                net.append(self._external.get_nowait())
                            yield TelemetryBatch(timestamp=ts, sensor_event=sensor, network_events=net)
                    else:
                        ext = d.result()
                        ext_events = [ext]
                        while not self._external.empty():
                            ext_events.append(self._external.get_nowait())
                        now = utcnow()
                        sensor = RawEvent(EventType.SENSOR_READING, now.isoformat(), "csv", dict(last_sensor_row))
                        yield TelemetryBatch(timestamp=now, sensor_event=sensor, network_events=ext_events)
        finally:
            csv_task.cancel()
