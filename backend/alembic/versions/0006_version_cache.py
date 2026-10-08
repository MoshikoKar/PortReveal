"""service version cache, per-scan cache bypass and live open-port count; top ports 3000 -> 1000

Revision ID: 0006
Revises: 0005
Create Date: 2026-10-08 22:00:00.000000
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "0006"
down_revision = "0005"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("device_ports", schema=None) as batch_op:
        batch_op.add_column(sa.Column("version_checked_at", sa.DateTime(), nullable=True))
    with op.batch_alter_table("scans", schema=None) as batch_op:
        batch_op.add_column(sa.Column("ignore_version_cache", sa.Boolean(), nullable=False, server_default=sa.false()))
        batch_op.add_column(sa.Column("open_ports_found", sa.Integer(), nullable=False, server_default="0"))

    # The standard scan now covers nmap's top 1000 plus an explicit list of uncommon web/AI ports.
    # Move only the old default; a value the admin chose on purpose is kept.
    settings = sa.table("app_settings", sa.column("key", sa.String), sa.column("value", sa.JSON))
    bind = op.get_bind()
    value = bind.execute(sa.select(settings.c.value).where(settings.c.key == "scan")).scalar()
    if isinstance(value, dict) and value.get("top_ports") == 3000:
        bind.execute(settings.update().where(settings.c.key == "scan").values(value={**value, "top_ports": 1000}))


def downgrade() -> None:
    with op.batch_alter_table("scans", schema=None) as batch_op:
        batch_op.drop_column("open_ports_found")
        batch_op.drop_column("ignore_version_cache")
    with op.batch_alter_table("device_ports", schema=None) as batch_op:
        batch_op.drop_column("version_checked_at")
