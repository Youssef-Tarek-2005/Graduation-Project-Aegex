"""Task 3 (PostgreSQL) - structured, processed data: cleaned sensor readings + extracted features.
Writes are idempotent on batch_id, so a restart/replay never creates duplicates."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import (BigInteger, Boolean, DateTime, Float, ForeignKey, Index, Integer, String, create_engine, text)
from sqlalchemy.dialects.postgresql import JSONB, insert as pg_insert
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker

from ..processing.preprocessing import FeatureVector


class Base(DeclarativeBase):
    pass


class SensorReading(Base):
    __tablename__ = "sensor_readings"
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    batch_id: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    source_time: Mapped[str | None] = mapped_column(String(64))
    esp_ms: Mapped[int | None] = mapped_column(BigInteger)
    smoke: Mapped[float] = mapped_column(Float, nullable=False)
    temperature_c: Mapped[float] = mapped_column(Float, nullable=False)     # CSV column `tempeture`
    humidity_pct: Mapped[float] = mapped_column(Float, nullable=False)
    was_imputed: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    __table_args__ = (Index("ix_sensor_readings_ts", "ts"),)


class FeatureRecord(Base):
    __tablename__ = "feature_vectors"
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    batch_id: Mapped[str] = mapped_column(String(64), ForeignKey("sensor_readings.batch_id", ondelete="CASCADE"),
                                          unique=True, nullable=False)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    network_packet_size: Mapped[float] = mapped_column(Float, nullable=False)
    login_attempts: Mapped[int] = mapped_column(Integer, nullable=False)
    session_duration: Mapped[float] = mapped_column(Float, nullable=False)
    ip_reputation_score: Mapped[float] = mapped_column(Float, nullable=False)
    failed_logins: Mapped[int] = mapped_column(Integer, nullable=False)
    features_normalized: Mapped[dict] = mapped_column(JSONB, nullable=False)
    feature_source: Mapped[str] = mapped_column(String(16), nullable=False)
    quality: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    __table_args__ = (Index("ix_feature_vectors_ts", "ts"),)


class AttackAnalysisRecord(Base):
    """Rule-based attack analysis per batch (category, severity, confidence) - feeds the dashboard and blue-team report."""
    __tablename__ = "attack_analyses"
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    batch_id: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    category: Mapped[str] = mapped_column(String(48), nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    confidence: Mapped[float] = mapped_column(Float, nullable=False)
    src_ips: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    entry_vector: Mapped[str] = mapped_column(String(16), nullable=False, default="unknown")
    honeypot: Mapped[str] = mapped_column(String(32), nullable=False, default="unknown")
    signals: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    mitre: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    ground_truth: Mapped[str | None] = mapped_column(String(48))          # simulator label, for evaluation only
    __table_args__ = (Index("ix_attack_analyses_ts", "ts"), Index("ix_attack_analyses_category", "category"))


_SEV_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}


class PostgresStore:
    def __init__(self, url: str):
        self.engine = create_engine(url, pool_size=5, max_overflow=5, pool_pre_ping=True, future=True)
        self.Session = sessionmaker(self.engine, expire_on_commit=False)

    def init_schema(self) -> None:
        Base.metadata.create_all(self.engine)

    def save(self, fv: FeatureVector) -> None:
        """Insert the sensor row, then its features, in one transaction."""
        s, f = fv.sensor, fv.features
        with self.Session.begin() as db:
            db.execute(pg_insert(SensorReading).values(
                batch_id=fv.batch_id, ts=fv.timestamp, source_time=s.get("source_time"), esp_ms=s.get("esp_ms"),
                smoke=s["smoke"], temperature_c=s["tempeture"], humidity_pct=s["humidity_pct"],
                was_imputed=bool(s.get("was_imputed"))).on_conflict_do_nothing(index_elements=["batch_id"]))
            db.execute(pg_insert(FeatureRecord).values(
                batch_id=fv.batch_id, ts=fv.timestamp,
                network_packet_size=f["network_packet_size"], login_attempts=int(f["login_attempts"]),
                session_duration=f["session_duration"], ip_reputation_score=f["ip_reputation_score"],
                failed_logins=int(f["failed_logins"]), features_normalized=fv.features_normalized,
                feature_source=fv.feature_source, quality=fv.quality).on_conflict_do_nothing(index_elements=["batch_id"]))

        a = fv.analysis
        if a:
            with self.Session.begin() as db:
                db.execute(pg_insert(AttackAnalysisRecord).values(
                    batch_id=fv.batch_id, ts=fv.timestamp, category=a["category"], severity=a["severity"],
                    confidence=a["confidence"], src_ips=a["src_ips"], entry_vector=a["entry_vector"], honeypot=a["honeypot"],
                    signals=a["signals"], mitre=a["mitre"], ground_truth=a.get("ground_truth"),
                ).on_conflict_do_nothing(index_elements=["batch_id"]))

    # ---- dashboard queries --------------------------------------------------
    def recent_attacks(self, minutes: int, limit: int, category: str | None = None) -> list[dict[str, Any]]:
        since = datetime.now(timezone.utc) - timedelta(minutes=minutes)
        sql = text("""SELECT batch_id, ts, category, severity, confidence, src_ips, entry_vector, honeypot, signals, mitre, ground_truth
                      FROM attack_analyses WHERE ts >= :since AND (CAST(:cat AS text) IS NULL OR category = :cat)
                      ORDER BY ts DESC LIMIT :limit""")
        with self.engine.connect() as c:
            return [dict(r) for r in c.execute(sql, {"since": since, "cat": category, "limit": limit}).mappings().all()]

    def attack_summary(self, minutes: int) -> dict[str, Any]:
        since = datetime.now(timezone.utc) - timedelta(minutes=minutes)
        sql = text("""SELECT category, severity, entry_vector, honeypot, count(*) AS n, avg(confidence) AS conf,
                             min(ts) AS first_seen, max(ts) AS last_seen
                      FROM attack_analyses WHERE ts >= :since GROUP BY 1, 2, 3, 4""")
        with self.engine.connect() as c:
            rows = c.execute(sql, {"since": since}).mappings().all()
        cats: dict[str, dict] = {}
        by_vec: dict[str, int] = {}
        by_hp: dict[str, int] = {}
        by_sev: dict[str, int] = {}
        for r in rows:
            n = int(r["n"])
            c_ = cats.setdefault(r["category"], {"category": r["category"], "count": 0, "max_severity": "low", "_conf": 0.0,
                                                 "first_seen": r["first_seen"], "last_seen": r["last_seen"]})
            c_["count"] += n
            c_["_conf"] += float(r["conf"]) * n
            if _SEV_ORDER[r["severity"]] > _SEV_ORDER[c_["max_severity"]]:
                c_["max_severity"] = r["severity"]
            c_["first_seen"], c_["last_seen"] = min(c_["first_seen"], r["first_seen"]), max(c_["last_seen"], r["last_seen"])
            by_vec[r["entry_vector"]] = by_vec.get(r["entry_vector"], 0) + n
            by_hp[r["honeypot"]] = by_hp.get(r["honeypot"], 0) + n
            by_sev[r["severity"]] = by_sev.get(r["severity"], 0) + n
        out = []
        for c_ in sorted(cats.values(), key=lambda x: -x["count"]):
            c_["avg_confidence"] = round(c_.pop("_conf") / c_["count"], 2)
            out.append(c_)
        return {"total": sum(c_["count"] for c_ in out), "by_category": out, "by_entry_vector": by_vec,
                "by_honeypot": by_hp, "by_severity": by_sev}

    def sensor_timeseries(self, minutes: int, limit: int, bucket_seconds: int | None = None) -> list[dict[str, Any]]:
        since = datetime.now(timezone.utc) - timedelta(minutes=minutes)
        if bucket_seconds:                      # server-side downsampling (needs PostgreSQL 14+ for date_bin)
            sql = text("""
                SELECT date_bin(:b * interval '1 second', ts, TIMESTAMPTZ '2000-01-01') AS t,
                       avg(temperature_c) AS tempeture, avg(smoke) AS smoke, avg(humidity_pct) AS humidity_pct
                FROM sensor_readings WHERE ts >= :since GROUP BY t ORDER BY t DESC LIMIT :limit""")
            params = {"b": bucket_seconds, "since": since, "limit": limit}
        else:
            sql = text("""
                SELECT ts AS t, temperature_c AS tempeture, smoke, humidity_pct
                FROM sensor_readings WHERE ts >= :since ORDER BY ts DESC LIMIT :limit""")
            params = {"since": since, "limit": limit}
        with self.engine.connect() as c:
            rows = c.execute(sql, params).mappings().all()
        return [dict(r) for r in reversed(rows)]        # oldest -> newest for charting
