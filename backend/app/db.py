"""Database engine/session handling. The same code serves SQLite and PostgreSQL."""
from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import DateTime, create_engine, event
from sqlalchemy.engine import Engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker
from sqlalchemy.types import TypeDecorator

from .config import get_settings


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class UTCDateTime(TypeDecorator):
    """Stores naive UTC in the database, always returns timezone-aware UTC."""

    impl = DateTime
    cache_ok = True

    def process_bind_param(self, value, dialect):
        if value is None:
            return None
        if value.tzinfo is not None:
            value = value.astimezone(timezone.utc).replace(tzinfo=None)
        return value

    def process_result_value(self, value, dialect):
        if value is None:
            return None
        return value.replace(tzinfo=timezone.utc)


class Base(DeclarativeBase):
    pass


_engine: Engine | None = None
SessionLocal = sessionmaker(autoflush=False, expire_on_commit=False)

# Per-process PostgreSQL pool. Keep the total database connection budget in mind when
# increasing either value or running more application workers.
POSTGRES_POOL_SIZE = 10
POSTGRES_MAX_OVERFLOW = 10
POSTGRES_POOL_TIMEOUT_SECONDS = 30
POSTGRES_POOL_RECYCLE_SECONDS = 1800


def _sqlite_pragmas(dbapi_conn, _record):
    cur = dbapi_conn.cursor()
    cur.execute("PRAGMA foreign_keys=ON")
    cur.execute("PRAGMA journal_mode=WAL")
    cur.execute("PRAGMA busy_timeout=15000")
    cur.execute("PRAGMA synchronous=NORMAL")
    cur.close()


def init_engine(url: str | None = None) -> Engine:
    global _engine
    url = url or get_settings().sqlalchemy_url
    if _engine is not None and str(_engine.url) == url:
        return _engine
    if _engine is not None:
        _engine.dispose()
    if url.startswith("sqlite"):
        db_file = url.replace("sqlite:///", "", 1)
        if db_file and ":memory:" not in db_file:
            Path(db_file).parent.mkdir(parents=True, exist_ok=True)
        engine = create_engine(url, connect_args={"check_same_thread": False, "timeout": 15})
        event.listen(engine, "connect", _sqlite_pragmas)
    else:
        engine = create_engine(
            url,
            pool_pre_ping=True,
            pool_size=POSTGRES_POOL_SIZE,
            max_overflow=POSTGRES_MAX_OVERFLOW,
            pool_timeout=POSTGRES_POOL_TIMEOUT_SECONDS,
            pool_recycle=POSTGRES_POOL_RECYCLE_SECONDS,
        )
    _engine = engine
    SessionLocal.configure(bind=engine)
    return engine


def get_engine() -> Engine:
    return _engine or init_engine()


def get_db() -> Iterator[Session]:
    """FastAPI dependency."""
    get_engine()
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@contextmanager
def session_scope() -> Iterator[Session]:
    get_engine()
    db = SessionLocal()
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def check_db() -> tuple[bool, str]:
    try:
        with get_engine().connect() as conn:
            conn.exec_driver_sql("SELECT 1")
        return True, "ok"
    except Exception as exc:  # pragma: no cover - depends on environment
        return False, str(exc)
