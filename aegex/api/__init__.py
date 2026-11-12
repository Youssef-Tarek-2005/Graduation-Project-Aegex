"""Dashboard API (Task 4). `uvicorn aegex.api:app` loads the app from here."""
from .app import app

__all__ = ["app"]
