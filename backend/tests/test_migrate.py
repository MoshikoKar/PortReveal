"""Alembic upgrade messaging: report applied revisions vs already-current."""
from __future__ import annotations

import logging
from pathlib import Path

from alembic import command

from app.migrate import alembic_config, upgrade


def test_upgrade_logs_applied_revision_then_up_to_date(tmp_path: Path, caplog):
    url = f"sqlite:///{(tmp_path / 'migrate.db').as_posix()}"
    cfg = alembic_config(url)

    # Fresh DB → first upgrade must report a real revision change, not "up to date".
    with caplog.at_level(logging.INFO, logger="app.migrate"):
        upgrade(url)
    applied = [r.message for r in caplog.records if "database schema upgraded" in r.message]
    assert applied, caplog.text
    assert "empty →" in applied[0]
    assert "up to date" not in applied[0]

    # Already at head → only then say the schema is up to date.
    caplog.clear()
    with caplog.at_level(logging.INFO, logger="app.migrate"):
        upgrade(url)
    current = [r.message for r in caplog.records if "database schema is up to date" in r.message]
    assert current, caplog.text
    assert "upgraded" not in " ".join(r.message for r in caplog.records)

    # Sanity: stepping from an older revision also logs "upgraded", not "up to date".
    command.downgrade(cfg, "-1")
    caplog.clear()
    with caplog.at_level(logging.INFO, logger="app.migrate"):
        upgrade(url)
    assert any("database schema upgraded" in r.message for r in caplog.records), caplog.text
