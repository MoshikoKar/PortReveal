"""Run Alembic migrations programmatically (startup, `npm run db:migrate`)."""
from __future__ import annotations

import logging
from pathlib import Path

from alembic import command
from alembic.config import Config

from .config import get_settings

log = logging.getLogger(__name__)
BACKEND_DIR = Path(__file__).resolve().parents[1]


def alembic_config(url: str | None = None) -> Config:
    cfg = Config(str(BACKEND_DIR / "alembic.ini"))
    cfg.set_main_option("script_location", str(BACKEND_DIR / "alembic"))
    cfg.set_main_option("sqlalchemy.url", (url or get_settings().sqlalchemy_url).replace("%", "%%"))
    cfg.attributes["configure_logger"] = False
    return cfg


def upgrade(url: str | None = None) -> None:
    url = url or get_settings().sqlalchemy_url
    kind = "sqlite" if url.startswith("sqlite") else "postgresql"
    if url.startswith("sqlite:///"):
        Path(url.replace("sqlite:///", "", 1)).parent.mkdir(parents=True, exist_ok=True)
    log.info("running alembic upgrade head (%s)", kind)
    try:
        command.upgrade(alembic_config(url), "head")
    except Exception:
        log.exception("alembic upgrade failed (%s)", kind)
        raise
    log.info("database schema is up to date (%s)", kind)
