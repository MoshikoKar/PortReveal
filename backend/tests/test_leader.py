"""Background-worker ownership across several app processes (PostgreSQL advisory lock).

The Postgres path is exercised with an in-memory fake; ``test_leader_pg.py`` covers a real
server when one is available.
"""
from __future__ import annotations

import threading
from types import SimpleNamespace

import pytest
from sqlalchemy import create_engine

from app.core import leader


class FakeConn:
    def __init__(self, granted: bool, log: list[str]) -> None:
        self.granted = granted
        self.log = log
        self.closed = False

    def execute(self, stmt, params=None):
        sql = str(stmt)
        self.log.append(sql)
        return SimpleNamespace(scalar=lambda: self.granted)

    def commit(self) -> None:
        self.log.append("commit")

    def close(self) -> None:
        self.closed = True


class FakePgEngine:
    dialect = SimpleNamespace(name="postgresql")

    def __init__(self, granted: bool | list[bool]) -> None:
        self._grants = list(granted) if isinstance(granted, list) else None
        self.granted = bool(granted) if not isinstance(granted, list) else False
        self.log: list[str] = []
        self.conns: list[FakeConn] = []
        self.url = "postgresql+psycopg://fake/fake"

    def connect(self) -> FakeConn:
        if self._grants is not None:
            self.granted = self._grants.pop(0) if self._grants else False
        conn = FakeConn(self.granted, self.log)
        self.conns.append(conn)
        return conn

    def dispose(self) -> None:
        pass


@pytest.fixture(autouse=True)
def _reset_leader():
    leader.stop_failover_watch()
    leader._held = None
    leader._lock_engine = None
    leader._sqlite_owner = False
    yield
    leader.stop_failover_watch()
    leader.release_background_leadership()
    leader._held = None
    leader._lock_engine = None
    leader._sqlite_owner = False


def _use_fake(monkeypatch, engine: FakePgEngine):
    """``acquire`` builds a dedicated lock engine via ``create_engine(url)``; return the same fake."""
    monkeypatch.setattr(leader, "create_engine", lambda url, **kwargs: engine)


def test_sqlite_always_owns_background_workers():
    engine = create_engine("sqlite://")
    assert leader.acquire_background_leadership(engine) is True
    assert leader.is_background_leader() is True
    leader.release_background_leadership()
    assert leader.is_background_leader() is False


def test_postgres_first_process_takes_the_lock_and_keeps_connection_open(monkeypatch):
    engine = FakePgEngine(granted=True)
    _use_fake(monkeypatch, engine)
    assert leader.acquire_background_leadership(engine) is True
    assert engine.conns[0].closed is False  # closing would release the lock
    assert leader.acquire_background_leadership(engine) is True
    assert len(engine.conns) == 1


def test_postgres_second_process_does_not_own_background_workers(monkeypatch):
    engine = FakePgEngine(granted=False)
    _use_fake(monkeypatch, engine)
    assert leader.acquire_background_leadership(engine) is False
    assert engine.conns[0].closed is True
    assert leader._held is None


def test_release_unlocks_and_closes_the_held_connection(monkeypatch):
    engine = FakePgEngine(granted=True)
    _use_fake(monkeypatch, engine)
    leader.acquire_background_leadership(engine)
    leader.release_background_leadership()
    assert any("pg_advisory_unlock" in s for s in engine.log)
    assert engine.conns[0].closed is True
    assert leader._held is None
    leader.release_background_leadership()


def test_failover_watch_acquires_lock_and_starts_workers(monkeypatch):
    engine = FakePgEngine(granted=[False, True])
    _use_fake(monkeypatch, engine)
    started = threading.Event()

    def on_become():
        started.set()

    leader.start_failover_watch(engine, on_become, interval_s=0.05)
    assert started.wait(timeout=2.0)
    assert leader.is_background_leader() is True
    leader.stop_failover_watch()
    leader.release_background_leadership()


def test_migration_lock_is_a_no_op_on_sqlite():
    with leader.migration_lock("sqlite:///:memory:"):
        pass
