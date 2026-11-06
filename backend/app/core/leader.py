"""Process coordination for several application workers sharing one PostgreSQL database.

The scan queue, scheduler, webhook dispatcher and the vuln / web-capture / domain workers are
threads started in the app lifespan. With N uvicorn workers every process would run its own
copy: one scheduled scan would be queued N times and notifications would be sent N times.

On PostgreSQL, only the process holding a session-level advisory lock starts those threads;
the others serve HTTP only (their background endpoints fall back to running inline). If the
holder dies, its connection closes, the lock is released, and the next process to start
takes over. SQLite is a single-file dev database and always has one owner.
"""
from __future__ import annotations

import logging
from collections.abc import Iterator
from contextlib import contextmanager

from sqlalchemy import create_engine, text
from sqlalchemy.engine import Connection, Engine

log = logging.getLogger("app.leader")

BACKGROUND_LOCK_KEY = 0x504F5254  # "PORT"
MIGRATION_LOCK_KEY = 0x50524D47  # "PRMG"

_held: Connection | None = None


def _try_lock(conn: Connection, key: int) -> bool:
    got = bool(conn.execute(text("SELECT pg_try_advisory_lock(:k)"), {"k": key}).scalar())
    conn.commit()
    return got


def acquire_background_leadership(engine: Engine) -> bool:
    """True when this process should start the background workers."""
    global _held
    if engine.dialect.name != "postgresql":
        return True
    if _held is not None:
        return True
    conn = engine.connect()
    try:
        got = _try_lock(conn, BACKGROUND_LOCK_KEY)
    except BaseException:
        conn.close()
        raise
    if not got:
        conn.close()
        return False
    _held = conn  # kept open: closing the connection would release the lock
    return True


def release_background_leadership() -> None:
    global _held
    conn, _held = _held, None
    if conn is None:
        return
    try:
        conn.execute(text("SELECT pg_advisory_unlock(:k)"), {"k": BACKGROUND_LOCK_KEY})
        conn.commit()
    except Exception:
        log.warning("could not release background-worker lock; it ends with the connection", exc_info=True)
    finally:
        conn.close()


@contextmanager
def migration_lock(url: str) -> Iterator[None]:
    """Serialise schema upgrades: concurrent workers wait, then find the schema already current."""
    if not url.startswith("postgresql"):
        yield
        return
    engine = create_engine(url)
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT pg_advisory_lock(:k)"), {"k": MIGRATION_LOCK_KEY})
            conn.commit()
            try:
                yield
            finally:
                conn.execute(text("SELECT pg_advisory_unlock(:k)"), {"k": MIGRATION_LOCK_KEY})
                conn.commit()
    finally:
        engine.dispose()
