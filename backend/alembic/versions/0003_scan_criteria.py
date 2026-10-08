"""scan selection criteria

Revision ID: 0003
Revises: 0002
Create Date: 2026-10-07 09:00:00.000000
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("scans", schema=None) as batch_op:
        batch_op.add_column(sa.Column("criteria", sa.Text(), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("scans", schema=None) as batch_op:
        batch_op.drop_column("criteria")
