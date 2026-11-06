"""Record which evidence kept a device's identity across an address change (issue #37).

Revision ID: 0041
Revises: 0040
Create Date: 2026-11-06 12:00:00.000000
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0041"
down_revision = "0040"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("devices", schema=None) as batch_op:
        batch_op.add_column(sa.Column("identity_match", sa.String(16), nullable=True))
        batch_op.add_column(sa.Column("identity_matched_at", sa.DateTime(), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("devices", schema=None) as batch_op:
        batch_op.drop_column("identity_matched_at")
        batch_op.drop_column("identity_match")
