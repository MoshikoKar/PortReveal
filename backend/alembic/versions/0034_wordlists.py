"""Add wordlists (managed wordlist library) and migrate the free-text discovery wordlist setting.

Upgrade: if web_capture.discovery_wordlist names a readable file, it is imported (validated and
sanitized like an upload) and selected via discovery_wordlist_id; otherwise the built-in list is used.
Downgrade: the selected list's stored file path is written back to discovery_wordlist.

Revision ID: 0034
Revises: 0033
Create Date: 2026-10-29 12:00:00.000000
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

import sqlalchemy as sa
from alembic import op

revision = "0034"
down_revision = "0033"
branch_labels = None
depends_on = None

log = logging.getLogger("alembic.runtime.migration")

_settings = sa.table("app_settings", sa.column("key", sa.String), sa.column("value", sa.JSON))
_wordlists = sa.table(
    "wordlists",
    sa.column("id", sa.Integer),
    sa.column("name", sa.String),
    sa.column("kind", sa.String),
    sa.column("source", sa.String),
    sa.column("original_filename", sa.String),
    sa.column("storage_name", sa.String),
    sa.column("entries", sa.Integer),
    sa.column("skipped", sa.Integer),
    sa.column("size_bytes", sa.Integer),
    sa.column("sha256", sa.String),
    sa.column("created_at", sa.DateTime),
    sa.column("updated_at", sa.DateTime),
    sa.column("created_by", sa.String),
)


def _web_capture_value(bind) -> dict | None:
    row = bind.execute(sa.select(_settings.c.value).where(_settings.c.key == "web_capture")).first()
    return dict(row[0]) if row and isinstance(row[0], dict) else None


def _save(bind, value: dict) -> None:
    bind.execute(_settings.update().where(_settings.c.key == "web_capture").values(value=value))


def upgrade() -> None:
    op.create_table(
        "wordlists",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(length=64), nullable=False),
        sa.Column("kind", sa.String(length=20), nullable=False),
        sa.Column("source", sa.String(length=20), nullable=False),
        sa.Column("source_url", sa.String(length=2048), nullable=True),
        sa.Column("original_filename", sa.String(length=255), nullable=True),
        sa.Column("storage_name", sa.String(length=64), nullable=False),
        sa.Column("entries", sa.Integer(), nullable=False),
        sa.Column("skipped", sa.Integer(), nullable=False),
        sa.Column("size_bytes", sa.Integer(), nullable=False),
        sa.Column("sha256", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.Column("created_by", sa.String(length=150), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("name"),
        sa.UniqueConstraint("storage_name"),
    )

    bind = op.get_bind()
    value = _web_capture_value(bind)
    if value is None:
        return
    raw = str(value.pop("discovery_wordlist", "") or "").strip()
    value["discovery_wordlist_id"] = None
    if raw:
        from app.core.wordlists import import_legacy_file

        imported = import_legacy_file(raw)
        if imported is None:
            log.warning("discovery wordlist file is missing or invalid; Web capture now uses the built-in list")
        else:
            storage_name, result, name = imported
            now = datetime.now(timezone.utc).replace(tzinfo=None)
            bind.execute(_wordlists.insert().values(
                name=name, kind="paths", source="upload", original_filename=name[:255],
                storage_name=storage_name, entries=result.accepted, skipped=result.skipped,
                size_bytes=result.size_bytes, sha256=result.sha256, created_at=now, updated_at=now,
                created_by="migration",
            ))
            value["discovery_wordlist_id"] = bind.execute(
                sa.select(_wordlists.c.id).where(_wordlists.c.storage_name == storage_name)
            ).scalar_one()
            log.info("imported discovery wordlist file as %r (%d entries)", name, result.accepted)
    _save(bind, value)


def downgrade() -> None:
    bind = op.get_bind()
    value = _web_capture_value(bind)
    if value is not None:
        selected = value.pop("discovery_wordlist_id", None)
        path = ""
        if selected:
            row = bind.execute(
                sa.select(_wordlists.c.storage_name).where(_wordlists.c.id == selected)
            ).first()
            if row:
                from app.config import get_settings

                path = str(get_settings().data_path / "wordlists" / row[0])
        value["discovery_wordlist"] = path
        _save(bind, value)
    op.drop_table("wordlists")
