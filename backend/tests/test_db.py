"""Database engine configuration regressions."""
from __future__ import annotations

from unittest.mock import Mock

import pytest
from sqlalchemy import inspect
from sqlalchemy.engine import make_url
from sqlalchemy.exc import IntegrityError

from app import db as db_module
from app.models import CLOSED_VALUES, Device, Event, Network


def test_postgresql_pool_has_bounded_wait_and_connection_recycling(monkeypatch):
    url = "postgresql+psycopg://user:password@database/network_finder"
    captured: dict = {}
    fake_engine = Mock()
    fake_engine.url = make_url(url)

    def fake_create_engine(given_url, **kwargs):
        captured["url"] = given_url
        captured.update(kwargs)
        return fake_engine

    previous_engine = db_module._engine
    monkeypatch.setattr(db_module, "create_engine", fake_create_engine)
    db_module._engine = None
    try:
        assert db_module.init_engine(url) is fake_engine
    finally:
        db_module._engine = previous_engine
        db_module.SessionLocal.configure(bind=previous_engine)

    assert captured == {
        "url": url,
        "pool_pre_ping": True,
        "pool_size": db_module.POSTGRES_POOL_SIZE,
        "max_overflow": db_module.POSTGRES_MAX_OVERFLOW,
        "pool_timeout": db_module.POSTGRES_POOL_TIMEOUT_SECONDS,
        "pool_recycle": db_module.POSTGRES_POOL_RECYCLE_SECONDS,
    }


def test_migrated_schema_has_a_check_constraint_per_closed_value_set(db):
    insp = inspect(db.get_bind())
    for table, column in CLOSED_VALUES:
        names = {c["name"] for c in insp.get_check_constraints(table)}
        assert f"ck_{table}_{column}" in names, (table, column)


@pytest.mark.parametrize("row", [
    lambda: Device(current_ip="10.0.0.9", status="gone"),
    lambda: Network(name="bad zone", cidr="10.9.0.0/24", zone="intranet"),
    lambda: Event(event_type="port_wiggled", severity="info", message="m"),
])
def test_out_of_set_values_are_rejected_by_the_database(db, row):
    db.add(row())
    with pytest.raises(IntegrityError, match="CHECK constraint failed"):
        db.flush()
    db.rollback()


def test_nullable_closed_columns_still_accept_null(db):
    db.add(Network(name="no zone", cidr="10.8.0.0/24", zone=None))
    db.flush()
    db.rollback()


def test_pending_digest_index_exists(db):
    indexes = {ix["name"]: ix["column_names"] for ix in inspect(db.get_bind()).get_indexes("events")}
    assert indexes["ix_events_pending"] == ["notify", "notified_at"]
