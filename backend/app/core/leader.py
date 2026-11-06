"""Process coordination for several application workers sharing one PostgreSQL database.

The scan queue, scheduler, webhook dispatcher and the vuln / web-capture / domain workers are
threads started in the app lifespan. With N uvicorn workers every process would run its own
copy: one scheduled scan would be queued N times and notifications would be sent N times.

On PostgreSQL, only the process holding a session-level advisory lock starts those threads;
the others serve HTTP only (their background endpoints fall back to running inline). If the
holder dies, its connection closes and the lock is released. Non-owners poll with
``pg_try_advisory_lock`` and start workers when they acquire the lock (failover without waiting
for a full process restart). SQLite is a single-file dev database and always has one owner.
"""
from __future__ import annotations

import logging
import threading
from collections.abc import Callable, Iterator
from contextlib import contextmanager

from sqlalchemy import create_engine, text
from sqlalchemy.engine import Connection, Engine

log = logging.getLogger("app.leader")

BACKGROUND_LOCK_KEY = 0x504F5254  # "PORT"
MIGRATION_LOCK_KEY = 0x50524D47  # "PRMG"
# How often a non-owner retries the lock. Short enough for failover; long enough to avoid spin.
FAILOVER_POLL_S = 5.0

_held: Connection | None = None
_lock_engine: Engine | None = None  # dedicated engine so the lock does not occupy the app pool
_sqlite_owner = False  # SQLite has no advisory lock; the single process is always the owner.
_failover_stop: threading.Event | None = None
_failover_thread: threading.Thread | None = None


def _try_lock(conn: Connection, key: int) -> bool:
    got = bool(conn.execute(text("SELECT pg_try_advisory_lock(:k)"), {"k": key}).scalar())
    conn.commit()
    return got


def is_background_leader() -> bool:
    """True when this process currently holds the background-worker lock (or SQLite always-owner)."""
    return _held is not None or _sqlite_owner


def acquire_background_leadership(engine: Engine) -> bool:
    """True when this process should start the background workers."""
    global _held, _lock_engine, _sqlite_owner
    if engine.dialect.name != "postgresql":
        _sqlite_owner = True
        return True
    if _held is not None:
        return True
    # Separate engine/connection: holding a checkout from the app pool would stall work when
    # pool_size is small (and still wastes a slot on the shared pool).
    lock_engine = create_engine(engine.url, pool_size=1, max_overflow=0, pool_pre_ping=True)
    conn = lock_engine.connect()
    try:
        got = _try_lock(conn, BACKGROUND_LOCK_KEY)
    except BaseException:
        conn.close()
        lock_engine.dispose()
        raise
    if not got:
        conn.close()
        lock_engine.dispose()
        return False
    _held = conn  # kept open: closing the connection would release the lock
    _lock_engine = lock_engine
    return True


def release_background_leadership() -> None:
    global _held, _lock_engine, _sqlite_owner
    _sqlite_owner = False
    conn, _held = _held, None
    lock_engine, _lock_engine = _lock_engine, None
    if conn is None:
        if lock_engine is not None:
            lock_engine.dispose()
        return
    try:
        conn.execute(text("SELECT pg_advisory_unlock(:k)"), {"k": BACKGROUND_LOCK_KEY})
        conn.commit()
    except Exception:
        log.warning("could not release background-worker lock; it ends with the connection", exc_info=True)
    finally:
        conn.close()
        if lock_engine is not None:
            lock_engine.dispose()


def start_failover_watch(
    engine: Engine,
    on_become_leader: Callable[[], None],
    *,
    interval_s: float = FAILOVER_POLL_S,
    on_become_leader_failed: Callable[[], None] | None = None,
) -> None:
    """Poll for the background lock on non-owner PostgreSQL processes; call ``on_become_leader`` once acquired.

    If ``on_become_leader`` raises, the lock is released and (optional) ``on_become_leader_failed``
    runs so partial worker startup can be cleaned up; the loop keeps polling after ``interval_s``
    instead of exiting forever (a sole standby must recover from a transient startup failure).
    Success ends the watch thread (this process is now the leader). No-op on SQLite or when this
    process already holds the lock. ``stop_failover_watch`` must run on shutdown.
    """
    global _failover_stop, _failover_thread
    stop_failover_watch()
    if engine.dialect.name != "postgresql" or _held is not None:
        return
    stop = threading.Event()
    _failover_stop = stop

    def _loop() -> None:
        while not stop.wait(interval_s):
            if _held is not None:
                # Another path took leadership (should not happen on a standby); stop watching.
                return
            if not acquire_background_leadership(engine):
                continue
            log.info("background-worker lock acquired after failover poll; starting workers")
            try:
                on_become_leader()
            except Exception:
                log.exception("failover on_become_leader failed; releasing lock and retrying later")
                if on_become_leader_failed is not None:
                    try:
                        on_become_leader_failed()
                    except Exception:
                        log.exception("failover on_become_leader_failed cleanup raised")
                release_background_leadership()
                continue
            return  # workers started; this process is the leader

    _failover_thread = threading.Thread(target=_loop, name="background-leader-failover", daemon=True)
    _failover_thread.start()


def stop_failover_watch() -> None:
    global _failover_stop, _failover_thread
    stop, _failover_stop = _failover_stop, None
    thread, _failover_thread = _failover_thread, None
    if stop is not None:
        stop.set()
    if thread is not None and thread.is_alive():
        thread.join(timeout=FAILOVER_POLL_S + 1.0)


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
