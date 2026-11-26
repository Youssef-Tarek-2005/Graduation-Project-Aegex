"""Shared test setup.

Database tests never touch your real `aegex` database. They build a separate, throw-away database called
`aegex_test` on the same server, apply schema_v2.sql and seed_lab.sql to it, and empty the events and
flows tables before every test. If the database isn't running, those tests are skipped and the other tests still run.
"""
from __future__ import annotations

from pathlib import Path

import psycopg
import pytest
from psycopg.conninfo import make_conninfo

from ingest.db import connect, db_url

REPO = Path(__file__).resolve().parents[2]
SCHEMA = REPO / "database" / "schema_v2.sql"
SEED = REPO / "backend" / "sql" / "seed_lab.sql"
TEST_DB = "aegex_test"


@pytest.fixture(scope="session")
def test_db_url() -> str:
    try:
        admin = connect(connect_timeout=3)
    except psycopg.OperationalError:
        pytest.skip(f"database not reachable at {db_url()} (start it with docker compose)")
    with admin:
        admin.execute(f"DROP DATABASE IF EXISTS {TEST_DB} WITH (FORCE)")
        admin.execute(f"CREATE DATABASE {TEST_DB}")
    url = make_conninfo(db_url(), dbname=TEST_DB)
    with connect(url) as conn:
        conn.execute(SCHEMA.read_text(encoding="utf-8"))
        conn.execute(SEED.read_text(encoding="utf-8"))
    return url


@pytest.fixture
def db(test_db_url: str):
    with connect(test_db_url) as conn:
        conn.execute("DELETE FROM events")
        conn.execute("DELETE FROM flows")
        yield conn
