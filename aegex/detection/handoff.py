"""Task 5 - hand-off of processed payloads to the Multi-Stage Detection Layer.

Kafka (primary) carries two topics:
  aegex.detection.features : feature vector + sliding window of the last N vectors  -> LSTM / VAE / Autoencoder
  aegex.detection.graph    : (src_ip -> device) edges for the batch                  -> Temporal GAT
Optional HTTP webhooks receive the full payload too (e.g. a model-serving API). Failures never block the pipeline."""
from __future__ import annotations

import json
import logging
from abc import ABC, abstractmethod
from typing import Any

import httpx

from ..config import Settings

log = logging.getLogger(__name__)


class Forwarder(ABC):
    @abstractmethod
    def send(self, message: dict[str, Any]) -> None: ...

    def close(self) -> None:
        pass


class KafkaForwarder(Forwarder):
    def __init__(self, s: Settings):
        from confluent_kafka import Producer
        self.s = s
        self.producer = Producer({"bootstrap.servers": s.kafka_bootstrap, "enable.idempotence": True,
                                  "compression.type": "lz4", "linger.ms": 20, "message.timeout.ms": 15000})

    @staticmethod
    def _cb(err, msg) -> None:
        if err is not None:
            log.error("Kafka delivery failed (%s): %s", msg.topic(), err)

    def send(self, message: dict[str, Any]) -> None:
        key = message["batch_id"].encode()
        self.producer.produce(self.s.kafka_topic_features, key=key, callback=self._cb,
                              value=json.dumps({k: v for k, v in message.items() if k != "graph_edges"}).encode())
        if message.get("graph_edges"):
            graph = {"batch_id": message["batch_id"], "timestamp": message["timestamp"], "edges": message["graph_edges"]}
            self.producer.produce(self.s.kafka_topic_graph, key=key, value=json.dumps(graph).encode(), callback=self._cb)
        self.producer.poll(0)                       # serve delivery callbacks

    def close(self) -> None:
        self.producer.flush(10)


class WebhookForwarder(Forwarder):
    def __init__(self, urls: list[str]):
        self.urls, self.client = urls, httpx.Client(timeout=5.0)

    def send(self, message: dict[str, Any]) -> None:
        for url in self.urls:
            for attempt in range(3):
                try:
                    self.client.post(url, json=message).raise_for_status()
                    break
                except httpx.HTTPError as exc:
                    log.warning("Webhook %s attempt %d failed: %s", url, attempt + 1, exc)

    def close(self) -> None:
        self.client.close()


class DetectionLayerHandoff:
    """Fans a processed payload (vector, sliding window, graph edges, attack analysis) out to every configured forwarder."""

    def __init__(self, s: Settings):
        self.forwarders: list[Forwarder] = []
        if s.kafka_enabled:
            self.forwarders.append(KafkaForwarder(s))
        urls = [u.strip() for u in s.webhook_urls.split(",") if u.strip()]
        if urls:
            self.forwarders.append(WebhookForwarder(urls))

    def forward(self, payload: dict[str, Any]) -> None:
        message = {**payload, "window_size": len(payload.get("window", []))}   # window built in preprocessing step 5
        for f in self.forwarders:
            try:
                f.send(message)
            except Exception:
                log.exception("Forwarder %s failed", type(f).__name__)

    def close(self) -> None:
        for f in self.forwarders:
            f.close()
