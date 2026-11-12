"""Task 3 (MinIO) - immutable cold storage: the raw CSV and batched NDJSON logs of every raw event.

The bucket is created with Object Lock + versioning; each object gets a GOVERNANCE retention date, so it can't be
overwritten or deleted before the retention period ends (switch to COMPLIANCE for strict WORM)."""
from __future__ import annotations

import hashlib
import io
import json
import logging
import threading
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

from minio import Minio
from minio.commonconfig import GOVERNANCE
from minio.error import S3Error
from minio.retention import Retention

from ..config import Settings

log = logging.getLogger(__name__)


class MinioStore:
    def __init__(self, s: Settings):
        self.s = s
        self.client = Minio(s.minio_endpoint, access_key=s.minio_access_key, secret_key=s.minio_secret_key, secure=s.minio_secure)
        self._lock = threading.Lock()
        self._buf: list[dict] = []
        self._last_flush = time.monotonic()
        self._locked_bucket = s.minio_object_lock

    def init_bucket(self) -> None:
        if not self.client.bucket_exists(self.s.minio_bucket):
            self.client.make_bucket(self.s.minio_bucket, object_lock=self.s.minio_object_lock)   # lock only possible at creation
            log.info("Created bucket %s (object_lock=%s)", self.s.minio_bucket, self.s.minio_object_lock)
        elif self.s.minio_object_lock:
            try:
                self.client.get_object_lock_config(self.s.minio_bucket)
            except S3Error:
                log.warning("Bucket %s exists WITHOUT object lock; uploads will not be immutable.", self.s.minio_bucket)
                self._locked_bucket = False

    def _retention(self) -> Retention | None:
        if not (self._locked_bucket and self.s.minio_retention_days > 0):
            return None
        return Retention(GOVERNANCE, datetime.now(timezone.utc) + timedelta(days=self.s.minio_retention_days))

    def archive_csv(self, path: Path) -> str | None:
        """Back up the raw CSV once per unique content (sha256 in the object name makes this idempotent)."""
        if not path.exists():
            log.warning("CSV %s not found; skipping raw CSV backup", path)
            return None
        digest = hashlib.sha256(path.read_bytes()).hexdigest()[:16]
        key = f"raw/csv/{digest}_{path.name}"
        try:
            self.client.stat_object(self.s.minio_bucket, key)
            log.info("CSV already archived: %s", key)
            return key
        except S3Error:
            pass
        self.client.fput_object(self.s.minio_bucket, key, str(path), content_type="text/csv", retention=self._retention())
        log.info("Archived CSV -> s3://%s/%s", self.s.minio_bucket, key)
        return key

    def add_events(self, events: list[dict]) -> None:
        """Buffer raw events; flushed as one NDJSON object per batch/interval (avoids millions of tiny objects)."""
        with self._lock:
            self._buf.extend(events)
            due = len(self._buf) >= self.s.archive_batch_size or time.monotonic() - self._last_flush >= self.s.archive_flush_seconds
        if due:
            self.flush()

    def flush(self) -> None:
        with self._lock:
            batch, self._buf, self._last_flush = self._buf, [], time.monotonic()
        if not batch:
            return
        data = ("\n".join(json.dumps(e, default=str) for e in batch) + "\n").encode()
        now = datetime.now(timezone.utc)
        key = f"raw/telemetry/{now:%Y/%m/%d/%H}/{now:%Y%m%dT%H%M%S}_{uuid.uuid4().hex[:8]}.ndjson"
        try:
            self.client.put_object(self.s.minio_bucket, key, io.BytesIO(data), len(data),
                                   content_type="application/x-ndjson", retention=self._retention())
        except Exception:
            with self._lock:                      # keep the events so the next flush retries them
                self._buf = batch + self._buf
            raise
