"""Task 4 - Security Dashboard backend.   Run:  uvicorn aegex.api:app --reload --port 8000

  /          the dashboard page (frontend/dashboard.html)
  /docs      interactive API page (this is where you can test every endpoint)
"""
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse

from .routes import attacks, intel, reports, security, sensors, system

DESCRIPTION = """
Backend for the **AEGEX IoT honeypot** system. It serves the sensor readings and security events that the data pipeline stores.

### How to use this page
1. Click an endpoint below (a coloured bar) to open it.
2. Click the blue **Execute** button.
3. Read the result under **Server response**.

Each endpoint returns JSON shaped for charts: `labels` is the X axis and `series` holds the lines or bars.

The dashboard itself is at [/](/).
"""

TAGS = [
    {"name": "Sensors", "description": "Temperature, smoke and humidity readings from the ESP32 CSV (PostgreSQL)."},
    {"name": "Security events", "description": "Suspicious activity seen by the honeypot (Elasticsearch)."},
    {"name": "Attack analysis", "description": "Detected attack scenarios, severity, confidence, entry vector and target honeypot (PostgreSQL)."},
    {"name": "Threat intelligence", "description": "Layered knowledge base: MITRE ATT&CK, OWASP IoT Top 10, CVE/NVD, CWE/CAPEC, threat feeds."},
    {"name": "Reports", "description": "Blue team report with findings, recommendations and mitigation steps."},
    {"name": "System", "description": "Service status."},
]

app = FastAPI(
    title="AEGEX Dashboard API", version="1.0", description=DESCRIPTION, openapi_tags=TAGS,
    swagger_ui_parameters={"tryItOutEnabled": True, "defaultModelsExpandDepth": -1,
                           "docExpansion": "list", "displayRequestDuration": True},
)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["GET"], allow_headers=["*"])  # tighten in production
app.include_router(sensors.router)
app.include_router(security.router)
app.include_router(attacks.router)
app.include_router(intel.router)
app.include_router(reports.router)
app.include_router(system.router)

DASHBOARD = Path(__file__).resolve().parents[2] / "frontend" / "dashboard.html"


@app.get("/", include_in_schema=False)
def dashboard() -> FileResponse:
    return FileResponse(DASHBOARD)
