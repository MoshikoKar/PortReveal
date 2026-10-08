"""device correlated absence tracking

Revision ID: 0004
Revises: 0003
Create Date: 2026-10-08 15:30:00.000000
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("devices", schema=None) as batch_op:
        batch_op.add_column(sa.Column("absence_days", sa.Integer(), nullable=False, server_default="0"))
        batch_op.add_column(sa.Column("absence_counted_on", sa.Date(), nullable=True))
        batch_op.add_column(sa.Column("absence_alerted", sa.Boolean(), nullable=False, server_default=sa.false()))


def downgrade() -> None:
    with op.batch_alter_table("devices", schema=None) as batch_op:
        batch_op.drop_column("absence_alerted")
        batch_op.drop_column("absence_counted_on")
        batch_op.drop_column("absence_days")
