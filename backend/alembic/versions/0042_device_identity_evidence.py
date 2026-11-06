"""Store structured evidence for the last identity match (issue #37 / #39).

Revision ID: 0042
Revises: 0041
Create Date: 2026-11-06 12:20:00.000000
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0042"
down_revision = "0041"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("devices", schema=None) as batch_op:
        batch_op.add_column(sa.Column("identity_evidence", sa.JSON(), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("devices", schema=None) as batch_op:
        batch_op.drop_column("identity_evidence")
