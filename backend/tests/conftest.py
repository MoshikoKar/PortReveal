"""Test setup: every test gets its own migrated SQLite database and the mock scanner.

No network access and no nmap are required.
"""
from __future__ import annotations

import os
import shutil
import sys
from pathlib import Path

import pytest

os.environ.update({
    "APP_ENV": "test",
    "SCANNER_MODE": "mock",
    "MOCK_SCAN_DELAY": "0",
    "BACKGROUND_JOBS": "false",
    "DEV_SEED": "false",
    "LOG_LEVEL": "WARNING",
    "APP_SECRET_KEY": "test-secret",
})
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.config import reset_settings_cache  # noqa: E402
from app.db import SessionLocal, init_engine  # noqa: E402
from app.migrate import upgrade  # noqa: E402


@pytest.fixture(scope="session")
def template_db(tmp_path_factory) -> Path:
    path = tmp_path_factory.mktemp("template") / "template.db"
    upgrade(f"sqlite:///{path.as_posix()}")  # exercises the real migrations
    return path


@pytest.fixture
def db_env(tmp_path, template_db, monkeypatch):
    path = tmp_path / "test.db"
    shutil.copy(template_db, path)
    url = f"sqlite:///{path.as_posix()}"
    monkeypatch.setenv("DATABASE_URL", url)
    monkeypatch.setenv("DATA_DIR", str(tmp_path / "data"))
    reset_settings_cache()
    from app.scanner import scanner_status

    scanner_status(refresh=True)
    init_engine(url)
    yield url
    reset_settings_cache()


@pytest.fixture
def db(db_env):
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()
