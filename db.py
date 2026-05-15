"""
db.py — database connection helpers for SkillChain.

Production continues to use PostgreSQL via DATABASE_URL.
Local development can fall back to SQLite when Postgres is unavailable.
"""

import logging
import os
from pathlib import Path
import sqlite3

import psycopg2
import psycopg2.extras


log = logging.getLogger(__name__)

_SQLITE_PATH = Path(__file__).resolve().parent / "skillchain_dev.db"
_SQLITE_URI = f"sqlite:///{_SQLITE_PATH.as_posix()}"
_ACTIVE_BACKEND = None
_ACTIVE_DATABASE_URL = None


def is_production_deployment() -> bool:
    return (
        os.getenv("RENDER") == "true"
        or bool(os.getenv("RENDER_SERVICE_ID"))
        or os.getenv("FLASK_ENV") == "production"
        or os.getenv("APP_ENV") == "production"
    )


def _connect_postgres(url: str):
    return psycopg2.connect(url, connect_timeout=3)


def _sqlite_query(query: str) -> str:
    return query.replace("%s", "?")


class _SQLiteCursorAdapter:
    def __init__(self, cursor: sqlite3.Cursor, *, dict_rows: bool):
        self._cursor = cursor
        self._dict_rows = dict_rows

    def execute(self, query, params=None):
        query = _sqlite_query(query)
        if params is None:
            return self._cursor.execute(query)
        return self._cursor.execute(query, params)

    def executemany(self, query, seq_of_params):
        return self._cursor.executemany(_sqlite_query(query), seq_of_params)

    def fetchone(self):
        row = self._cursor.fetchone()
        if row is None or not self._dict_rows:
            return row
        return dict(row)

    def fetchall(self):
        rows = self._cursor.fetchall()
        if not self._dict_rows:
            return rows
        return [dict(row) for row in rows]

    def close(self):
        return self._cursor.close()

    def __getattr__(self, name):
        return getattr(self._cursor, name)


class _SQLiteConnectionAdapter:
    def __init__(self, conn: sqlite3.Connection):
        self._conn = conn

    def cursor(self, cursor_factory=None):
        dict_rows = cursor_factory is psycopg2.extras.RealDictCursor
        return _SQLiteCursorAdapter(self._conn.cursor(), dict_rows=dict_rows)

    def close(self):
        return self._conn.close()

    def commit(self):
        return self._conn.commit()

    def rollback(self):
        return self._conn.rollback()

    def __getattr__(self, name):
        return getattr(self._conn, name)


def resolve_database_backend():
    global _ACTIVE_BACKEND, _ACTIVE_DATABASE_URL

    if _ACTIVE_BACKEND is not None:
        return _ACTIVE_BACKEND, _ACTIVE_DATABASE_URL

    database_url = os.environ.get("DATABASE_URL")
    if database_url:
        try:
            conn = _connect_postgres(database_url)
            conn.close()
            _ACTIVE_BACKEND = "postgres"
            _ACTIVE_DATABASE_URL = database_url
            log.info("Using Postgres database from DATABASE_URL.")
            return _ACTIVE_BACKEND, _ACTIVE_DATABASE_URL
        except Exception as exc:
            if is_production_deployment():
                log.exception("Postgres connection failed during startup.")
                raise
            log.warning(
                "Postgres unavailable locally (%s). Falling back to SQLite at %s.",
                exc,
                _SQLITE_PATH,
            )
    else:
        if is_production_deployment():
            raise RuntimeError(
                "DATABASE_URL environment variable is not set for production startup."
            )
        log.warning(
            "DATABASE_URL is not set locally. Falling back to SQLite at %s.",
            _SQLITE_PATH,
        )

    _ACTIVE_BACKEND = "sqlite"
    _ACTIVE_DATABASE_URL = _SQLITE_URI
    return _ACTIVE_BACKEND, _ACTIVE_DATABASE_URL


def get_sqlalchemy_database_uri() -> str:
    _, database_url = resolve_database_backend()
    return database_url


def using_sqlite_fallback() -> bool:
    backend, _ = resolve_database_backend()
    return backend == "sqlite"


def get_db_connection():
    """
    Return a database connection for the active backend.

    Production uses PostgreSQL. Local development falls back to SQLite when
    DATABASE_URL is missing or Postgres is temporarily unavailable.
    """
    backend, database_url = resolve_database_backend()
    if backend == "postgres":
        return _connect_postgres(database_url)

    conn = sqlite3.connect(_SQLITE_PATH)
    conn.row_factory = sqlite3.Row
    return _SQLiteConnectionAdapter(conn)


def dict_cursor(conn):
    """
    Return a cursor that yields rows as dicts.
    """
    return conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
