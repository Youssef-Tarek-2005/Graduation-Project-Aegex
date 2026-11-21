"""Connecting to the database.

The address comes from the AEGEX_DB_URL environment variable. If it isn't set, we use the local
development database from backend/docker-compose.yml (port 5433).
"""
from __future__ import annotations

import os

import psycopg

DEFAULT_DB_URL = "postgresql://aegex:aegex@localhost:5433/aegex"


def db_url() -> str:
    return os.environ.get("AEGEX_DB_URL", DEFAULT_DB_URL)


def connect(url: str | None = None, **kwargs) -> psycopg.Connection:
    # autocommit=True: every statement saves on its own, and `with conn.transaction():` blocks are real
    # all-or-nothing transactions (without it, those blocks would silently become savepoints inside an
    # outer transaction that nobody commits).
    kwargs.setdefault("autocommit", True)
    return psycopg.connect(url or db_url(), **kwargs)
