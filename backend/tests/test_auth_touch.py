"""Session / token last-seen bumps are best-effort when the SQLite writer lock is held."""
from __future__ import annotations

from sqlalchemy.exc import OperationalError

from app.auth.deps import _touch_commit


class _LockedSession:
    def __init__(self) -> None:
        self.rolled_back = False

    def commit(self) -> None:
        raise OperationalError("UPDATE sessions", {}, Exception("database is locked"))

    def rollback(self) -> None:
        self.rolled_back = True


def test_touch_commit_swallows_lock_and_rolls_back():
    s = _LockedSession()
    _touch_commit(s)
    assert s.rolled_back
