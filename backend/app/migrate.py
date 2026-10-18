"""Run Alembic migrations programmatically (startup, `npm run db:migrate`)."""
from __future__ import annotations

import logging
from pathlib import Path

from alembic import command
from alembic.config import Config
from alembic.runtime.migration import MigrationContext
from alembic.script import ScriptDirectory
from sqlalchemy import create_engine

from .config import get_settings

log = logging.getLogger(__name__)
BACKEND_DIR = Path(__file__).resolve().parents[1]


def alembic_config(url: str | None = None) -> Config:
    cfg = Config(str(BACKEND_DIR / "alembic.ini"))
    cfg.set_main_option("script_location", str(BACKEND_DIR / "alembic"))
    cfg.set_main_option("sqlalchemy.url", (url or get_settings().sqlalchemy_url).replace("%", "%%"))
    cfg.attributes["configure_logger"] = False
    return cfg


def _current_revision(url: str) -> str | None:
    """Alembic revision currently applied to the database, or None on a fresh DB."""
    engine = create_engine(url)
    try:
        with engine.connect() as conn:
            return MigrationContext.configure(conn).get_current_revision()
    finally:
        engine.dispose()


def _head_revision(cfg: Config) -> str | None:
    heads = ScriptDirectory.from_config(cfg).get_heads()
    return heads[0] if len(heads) == 1 else None


def upgrade(url: str | None = None) -> None:
    url = url or get_settings().sqlalchemy_url
    kind = "sqlite" if url.startswith("sqlite") else "postgresql"
    if url.startswith("sqlite:///"):
        Path(url.replace("sqlite:///", "", 1)).parent.mkdir(parents=True, exist_ok=True)
    cfg = alembic_config(url)
    before = _current_revision(url)
    log.info("running alembic upgrade head (%s)", kind)
    try:
        command.upgrade(cfg, "head")
    except Exception:
        log.exception("alembic upgrade failed (%s)", kind)
        raise
    after = _current_revision(url)
    head = _head_revision(cfg)
    if before == after:
        log.info("database schema is up to date (%s, revision %s)", kind, after or "empty")
    else:
        log.info(
            "database schema upgraded (%s): %s → %s%s",
            kind,
            before or "empty",
            after or "empty",
            f" (head {head})" if head and head != after else "",
        )
