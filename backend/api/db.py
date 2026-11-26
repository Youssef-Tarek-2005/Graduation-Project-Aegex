"""Database connections for the API.

Opening a new PostgreSQL connection costs time on every request. A pool keeps a few connections open and lends
one to each request, then takes it back. The address comes from AEGEX_DB_URL, like the command-line tools.
"""
from __future__ import annotations

from contextlib import contextmanager
from typing import Iterator

import psycopg
from psycopg_pool import ConnectionPool

from ingest.db import db_url

_pool: ConnectionPool | None = None


def open_pool(url: str | None = None, timeout: float = 5) -> None:
    global _pool
    # open=True starts connecting in the background: the API starts even if the database is down,
    # and /health says so, instead of the server crashing at start.
    _pool = ConnectionPool(url or db_url(), min_size=1, max_size=10, timeout=timeout,
                           kwargs={"autocommit": True}, open=True)


def close_pool() -> None:
    global _pool
    if _pool is not None:
        _pool.close()
        _pool = None


@contextmanager
def connection() -> Iterator[psycopg.Connection]:
    """Borrow a connection from the pool; it goes back when the `with` block ends."""
    if _pool is None:
        raise RuntimeError("the connection pool is not open")
    with _pool.connection() as conn:
        yield conn


def get_conn() -> Iterator[psycopg.Connection]:
    """FastAPI dependency: one connection for the length of one request."""
    with connection() as conn:
        yield conn
