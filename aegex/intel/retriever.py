"""Threat Intelligence - "Vector Store & Semantic Retriever", implemented as a dependency-free keyword index.

TF-IDF style scoring over entry id, title, tags and description. The `search()` interface is the seam where an
embedding model + vector database could be dropped in later without touching the API or the report."""
from __future__ import annotations

import math
import re
from collections import Counter

from .knowledge_base import KNOWLEDGE_BASE, LAYER_TITLES, KBEntry

_TOKEN = re.compile(r"[a-z0-9][a-z0-9.\-_]*")


def _tokens(text: str) -> list[str]:
    return _TOKEN.findall(text.lower())


class KnowledgeRetriever:
    def __init__(self, entries: list[KBEntry] | None = None):
        self.entries = entries or KNOWLEDGE_BASE
        self._docs = [Counter(_tokens(f"{e.id} {e.id} {e.title} {e.title} {' '.join(e.tags)} {' '.join(e.tags)} {e.description}")) for e in self.entries]
        df = Counter(t for d in self._docs for t in d)
        n = len(self.entries)
        self._idf = {t: math.log(1 + n / c) for t, c in df.items()}

    def layers(self) -> list[dict]:
        counts = Counter(e.layer for e in self.entries)
        return [{"layer": k, "title": v, "entries": counts.get(k, 0)} for k, v in LAYER_TITLES.items()]

    def search(self, query: str, layer: str | None = None, limit: int = 8) -> list[dict]:
        q = _tokens(query)
        if not q:
            return []
        scored = []
        for e, d in zip(self.entries, self._docs):
            if layer and e.layer != layer:
                continue
            score = sum(self._idf.get(t, 0.0) * (1 + math.log(d[t])) for t in q if t in d)
            if score > 0:
                scored.append((score, e))
        scored.sort(key=lambda x: -x[0])
        return [{**e.to_dict(), "score": round(s, 3)} for s, e in scored[:limit]]
