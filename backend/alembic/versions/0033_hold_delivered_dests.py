"""Add recipient_holds.delivered_dest_ids for per-destination dedupe.

Revision ID: 0033
Revises: 0032
Create Date: 2026-10-22 16:00:00.000000
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0033"
down_revision = "0032"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("recipient_holds", schema=None) as batch_op:
        batch_op.add_column(sa.Column("delivered_dest_ids", sa.JSON(), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("recipient_holds", schema=None) as batch_op:
        batch_op.drop_column("delivered_dest_ids")
