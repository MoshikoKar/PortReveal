"""Add recipient_holds.pending_dest_ids for per-destination retries.

Revision ID: 0032
Revises: 0031
Create Date: 2026-10-22 15:40:00.000000

Idempotent for installs that already created the column via an edited 0031.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0032"
down_revision = "0031"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    insp = sa.inspect(bind)
    cols = {c["name"] for c in insp.get_columns("recipient_holds")}
    if "pending_dest_ids" not in cols:
        with op.batch_alter_table("recipient_holds", schema=None) as batch_op:
            batch_op.add_column(sa.Column("pending_dest_ids", sa.JSON(), nullable=True))


def downgrade() -> None:
    bind = op.get_bind()
    insp = sa.inspect(bind)
    cols = {c["name"] for c in insp.get_columns("recipient_holds")}
    if "pending_dest_ids" in cols:
        with op.batch_alter_table("recipient_holds", schema=None) as batch_op:
            batch_op.drop_column("pending_dest_ids")
