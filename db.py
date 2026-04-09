"""
db.py — PostgreSQL connection helper for SkillChain.

All services import get_db_connection() from here.
DATABASE_URL is injected by Railway as:
    postgresql://user:password@host:port/dbname
"""

import os
import psycopg2
import psycopg2.extras


def get_db_connection():
    """
    Return a new psycopg2 connection using DATABASE_URL from the environment.

    Raises:
        KeyError  — if DATABASE_URL is not set.
        psycopg2.OperationalError — if the DB is unreachable.
    """
    url = os.environ.get("DATABASE_URL")
    if not url:
        raise RuntimeError(
            "DATABASE_URL environment variable is not set. "
            "Add a PostgreSQL service in Railway and link it to this app."
        )
    return psycopg2.connect(url)


def dict_cursor(conn):
    """
    Return a cursor that yields rows as dicts (RealDictCursor).
    Use this wherever code accesses columns by name.
    """
    return conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)