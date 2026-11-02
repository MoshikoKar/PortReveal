"""Web capture: select several discovery wordlists (built-in flag + stored list ids).

Upgrade: discovery_wordlist_id X becomes discovery_wordlist_ids [X] without the built-in list;
no selection keeps the built-in list only.
Downgrade: the first selected stored list (or the built-in list) becomes discovery_wordlist_id.

Revision ID: 0040
Revises: 0039
Create Date: 2026-11-02 12:00:00.000000
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0040"
down_revision = "0039"
branch_labels = None
depends_on = None

_settings = sa.table("app_settings", sa.column("key", sa.String), sa.column("value", sa.JSON))


def _web_capture_value(bind) -> dict | None:
    row = bind.execute(sa.select(_settings.c.value).where(_settings.c.key == "web_capture")).first()
    return dict(row[0]) if row and isinstance(row[0], dict) else None


def _save(bind, value: dict) -> None:
    bind.execute(_settings.update().where(_settings.c.key == "web_capture").values(value=value))


def upgrade() -> None:
    bind = op.get_bind()
    value = _web_capture_value(bind)
    if value is None:
        return
    selected = value.pop("discovery_wordlist_id", None)
    value["discovery_wordlist_ids"] = [selected] if selected else []
    value["discovery_builtin"] = not selected
    _save(bind, value)


def downgrade() -> None:
    bind = op.get_bind()
    value = _web_capture_value(bind)
    if value is None:
        return
    ids = value.pop("discovery_wordlist_ids", None) or []
    value.pop("discovery_builtin", None)
    value["discovery_wordlist_id"] = ids[0] if ids else None
    _save(bind, value)
