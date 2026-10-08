"""verified per-port script details and per-device self-reported identity

Revision ID: 0008
Revises: 0007
Create Date: 2026-10-09 01:00:00.000000
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "0008"
down_revision = "0007"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("device_ports", schema=None) as batch_op:
        batch_op.add_column(sa.Column("details", sa.JSON(), nullable=True))
    with op.batch_alter_table("devices", schema=None) as batch_op:
        batch_op.add_column(sa.Column("details", sa.JSON(), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("devices", schema=None) as batch_op:
        batch_op.drop_column("details")
    with op.batch_alter_table("device_ports", schema=None) as batch_op:
        batch_op.drop_column("details")
