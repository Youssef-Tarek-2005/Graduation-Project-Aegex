"""Task 6 - orchestration. One asyncio loop wires everything together:

   CSV row (+ honeypot events) -> preprocessing (clean/normalise/extract) -> PostgreSQL + MinIO + Elasticsearch
                                                                           -> Kafka / webhooks (detection layer)

Each sink runs in a worker thread, concurrently, and is isolated: if one fails the others still succeed and the
failed payload goes to a dead-letter file for replay. Run:  python main.py"""
from __future__ import annotations

import asyncio
import json
import logging
import signal
import time

from aegex.config import get_settings
from aegex.detection.handoff import DetectionLayerHandoff
from aegex.collection import HoneypotFeeds, TelemetryCollector
from aegex.processing.preprocessing import PreprocessingPipeline
from aegex.storage.es_store import ElasticStore
from aegex.storage.minio_store import MinioStore
from aegex.storage.postgres_store import PostgresStore

log = logging.getLogger("aegex.main")


def retry(fn, name: str, attempts: int = 30, delay: float = 2.0):
    """Wait for Docker services to come up instead of crashing on the first refused connection."""
    for i in range(1, attempts + 1):
        try:
            return fn()
        except Exception as exc:  # noqa: BLE001
            log.warning("%s not ready (%d/%d): %s", name, i, attempts, type(exc).__name__)
            time.sleep(delay)
    raise RuntimeError(f"{name} unavailable after {attempts} attempts")


class Pipeline:
    def __init__(self):
        self.s = get_settings()
        self.collector = TelemetryCollector(self.s)
        self.pre = PreprocessingPipeline(self.s)
        self.pg, self.minio, self.es = PostgresStore(self.s.postgres_url), MinioStore(self.s), ElasticStore(self.s)
        self.handoff = DetectionLayerHandoff(self.s)
        self.feeds = HoneypotFeeds(self.s, self.collector) if self.s.feeds_enabled else None
        self.count = self.dropped = self.attacks = 0
        log.info("Network simulation: %s (attack probability %.0f%% per sensor row)",
                 "enabled" if self.s.simulate_network else "disabled", self.s.attack_probability * 100)

    def setup(self) -> None:
        retry(self.pg.init_schema, "PostgreSQL")
        retry(self.minio.init_bucket, "MinIO")
        retry(self.es.init_indices, "Elasticsearch")
        self.minio.archive_csv(self.s.csv_path)             # raw CSV -> immutable cold storage (once per content hash)

    def _dead_letter(self, sink: str, record: dict) -> None:
        with open(self.s.dead_letter_path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps({"sink": sink, "record": record}, default=str) + "\n")

    async def _safe(self, sink: str, fn, *args, record: dict) -> None:
        try:
            await asyncio.to_thread(fn, *args)
        except Exception:
            log.exception("Sink %s failed; payload sent to dead letter", sink)
            self._dead_letter(sink, record)

    async def handle(self, batch) -> None:
        fv = self.pre.process(batch)
        if fv is None:
            self.dropped += 1
            return
        payload = fv.to_payload()
        raw_events = [e.to_dict() for e in batch.all_events()]
        await asyncio.gather(
            self._safe("postgres", self.pg.save, fv, record=payload),
            self._safe("minio", self.minio.add_events, raw_events, record={"events": raw_events}),
            self._safe("elasticsearch", self.es.index_events, raw_events, batch.batch_id, record={"events": raw_events}),
            self._safe("detection", self.handoff.forward, payload, record=payload),
        )
        self.count += 1
        self.attacks += fv.analysis is not None
        if self.count % 50 == 0:
            log.info("processed=%d dropped=%d attacks_detected=%d  last: T=%.1fC smoke=%.0f H=%.1f%% failed_logins=%d rep=%.2f",
                     self.count, self.dropped, self.attacks, fv.sensor["tempeture"], fv.sensor["smoke"], fv.sensor["humidity_pct"],
                     fv.features["failed_logins"], fv.features["ip_reputation_score"])

    async def _periodic_flush(self) -> None:
        while True:                                         # time-based flush so quiet periods don't strand buffered data
            await asyncio.sleep(min(self.s.es_flush_seconds, self.s.archive_flush_seconds))
            await asyncio.gather(asyncio.to_thread(self.minio.flush), asyncio.to_thread(self.es.flush), return_exceptions=True)

    async def run(self) -> None:
        if self.feeds:
            self.feeds.start()                              # Cowrie / Zeek / Mosquitto -> collector.submit_event()
        flusher = asyncio.create_task(self._periodic_flush())
        try:
            async for batch in self.collector.stream_batches():
                await self.handle(batch)
            log.info("CSV exhausted (set AEGEX_FOLLOW_CSV=true to keep tailing)")
        finally:
            flusher.cancel()
            if self.feeds:
                self.feeds.stop()
            await self.shutdown()

    async def shutdown(self) -> None:
        log.info("Flushing buffers (processed=%d dropped=%d)...", self.count, self.dropped)
        await asyncio.gather(asyncio.to_thread(self.minio.flush), asyncio.to_thread(self.es.flush),
                             asyncio.to_thread(self.handoff.close), return_exceptions=True)


async def amain() -> None:
    logging.basicConfig(level=get_settings().log_level, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    pipe = Pipeline()
    await asyncio.to_thread(pipe.setup)
    task = asyncio.create_task(pipe.run())
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, task.cancel)       # graceful Ctrl-C: cancel -> finally -> flush
        except NotImplementedError:                         # Windows
            pass
    try:
        await task
    except asyncio.CancelledError:
        pass


if __name__ == "__main__":
    asyncio.run(amain())
