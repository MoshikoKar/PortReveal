"""Background-worker ownership across several app processes (PostgreSQL advisory lock).

The Postgres path is exercised with an in-memory fake: the real lock needs a live server.
"""
from __future__ import annotations

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

    def __init__(self, granted: bool) -> None:
        self.granted = granted
        self.log: list[str] = []
        self.conns: list[FakeConn] = []

    def connect(self) -> FakeConn:
        conn = FakeConn(self.granted, self.log)
        self.conns.append(conn)
        return conn


@pytest.fixture(autouse=True)
def _reset_leader():
    leader._held = None
    yield
    leader._held = None


def test_sqlite_always_owns_background_workers():
    engine = create_engine("sqlite://")
    assert leader.acquire_background_leadership(engine) is True
    leader.release_background_leadership()


def test_postgres_first_process_takes_the_lock_and_keeps_connection_open():
    engine = FakePgEngine(granted=True)
    assert leader.acquire_background_leadership(engine) is True
    assert engine.conns[0].closed is False  # closing would release the lock
    # Calling again in the same process does not take a second connection.
    assert leader.acquire_background_leadership(engine) is True
    assert len(engine.conns) == 1


def test_postgres_second_process_does_not_own_background_workers():
    engine = FakePgEngine(granted=False)
    assert leader.acquire_background_leadership(engine) is False
    assert engine.conns[0].closed is True
    assert leader._held is None


def test_release_unlocks_and_closes_the_held_connection():
    engine = FakePgEngine(granted=True)
    leader.acquire_background_leadership(engine)
    leader.release_background_leadership()
    assert any("pg_advisory_unlock" in s for s in engine.log)
    assert engine.conns[0].closed is True
    assert leader._held is None
    # Releasing again is a no-op.
    leader.release_background_leadership()


def test_migration_lock_is_a_no_op_on_sqlite():
    with leader.migration_lock("sqlite:///:memory:"):
        pass
