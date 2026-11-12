"""Response shapes. FastAPI shows these (with the examples) on the /docs page."""
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class HealthResponse(BaseModel):
    postgres: str = Field(description="'up' if PostgreSQL answers, otherwise 'down: <reason>'", examples=["up"])
    elasticsearch: str = Field(description="'up' or 'down'", examples=["up"])


class Series(BaseModel):
    name: str = Field(description="Sensor name: tempeture, smoke or humidity_pct", examples=["tempeture"])
    unit: str = Field(description="Unit of the values", examples=["°C"])
    data: list[float] = Field(description="One value per entry in `labels`, same order")


class TimeseriesResponse(BaseModel):
    meta: dict[str, Any] = Field(description="How many points were returned and what was asked for")
    labels: list[str] = Field(description="Timestamps (ISO 8601, UTC), oldest first. Use as the chart X axis.")
    series: list[Series] = Field(description="One line per sensor. Use as the chart datasets.")
    points: list[dict[str, Any]] = Field(description="The same data as one object per timestamp (handy for Recharts).")

    model_config = ConfigDict(json_schema_extra={"example": {
        "meta": {"count": 3, "window_minutes": 60, "bucket_seconds": None, "generated_at": "2026-10-23T12:00:00+00:00"},
        "labels": ["2026-10-23T11:58:00+00:00", "2026-10-23T11:59:00+00:00", "2026-10-23T12:00:00+00:00"],
        "series": [{"name": "tempeture", "unit": "°C", "data": [27.5, 27.6, 27.6]},
                   {"name": "smoke", "unit": "ADC", "data": [310, 312, 309]},
                   {"name": "humidity_pct", "unit": "%", "data": [55.2, 55.1, 55.0]}],
        "points": [{"t": "2026-10-23T11:58:00+00:00", "tempeture": 27.5, "smoke": 310, "humidity_pct": 55.2}]}})


class SecurityEvent(BaseModel):
    id: str = Field(description="Unique event id")
    timestamp: str = Field(description="When it happened (ISO 8601, UTC)")
    event_type: str = Field(description="failed_login, command_request, mqtt_event, ble_event, device_interaction, ...")
    severity: str = Field(description="low, medium, high or critical (rule-based, not from the AI models)")
    reasons: list[str] = Field(description="Why it was flagged")
    src_ip: str | None = Field(description="Where it came from, if known")
    source: str | None = Field(default=None, description="Event source: cowrie, zeek, mosquitto, honeypot-sim")
    honeypot: str | None = Field(default=None, description="Target honeypot")
    details: dict[str, Any] = Field(description="Raw event fields (username, command, topic, ...)")


class EventsResponse(BaseModel):
    meta: dict[str, Any] = Field(description="total = all matches, returned = how many are in this response")
    events: list[SecurityEvent] = Field(description="Newest first")


class HistogramSeries(BaseModel):
    name: str = Field(description="Event type", examples=["failed_login"])
    data: list[int] = Field(description="Event count per time bucket, same order as `labels`")


class HistogramResponse(BaseModel):
    meta: dict[str, Any]
    labels: list[str] = Field(description="Start time of each bucket")
    series: list[HistogramSeries] = Field(description="One series per event type (stacked bar chart)")
