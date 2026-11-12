"""Task 2, last box - "Sequence & Graph Construction".

Turns each feature vector into the two structures the detection layer consumes:
  * a sliding window of the last N feature vectors (sequence models)
  * (src_ip -> honeypot device) edges with counts (graph models)
Stateful: one instance per pipeline run, called once per batch in time order."""
from __future__ import annotations

from collections import deque
from typing import Any

from ..config import Settings
from ..models import EventType


class SequenceGraphBuilder:
    def __init__(self, s: Settings):
        self.window: deque[list[float]] = deque(maxlen=s.window_size)
        self.default_device = s.honeypot_device_id

    def build(self, vector: list[float], events: list[dict[str, Any]]) -> tuple[list[list[float]], list[dict[str, Any]]]:
        self.window.append(list(vector))
        return [list(v) for v in self.window], self._edges(events)

    def _edges(self, events: list[dict[str, Any]]) -> list[dict[str, Any]]:
        edges: dict[tuple[str, str], dict[str, Any]] = {}
        for e in events:
            if "src_ip" not in e:
                continue
            dst = e.get("device") or self.default_device
            edge = edges.setdefault((e["src_ip"], dst), {"src": e["src_ip"], "dst": dst, "count": 0, "failed": 0})
            edge["count"] += 1
            edge["failed"] += e["event_type"] == EventType.FAILED_LOGIN.value
        return list(edges.values())
