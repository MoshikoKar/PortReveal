"""Weighted multi-signal device type (spec section 9): confidence, evidence, local discovery name

Revision ID: 0017
Revises: 0016
Create Date: 2026-10-18 10:00:00.000000
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0017"
down_revision = "0016"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("devices", schema=None) as batch_op:
        batch_op.add_column(sa.Column("type_confidence", sa.Integer(), nullable=True))
        batch_op.add_column(sa.Column("discovery_name", sa.String(length=255), nullable=True))
        batch_op.add_column(sa.Column("discovery_source", sa.String(length=10), nullable=True))

    with op.batch_alter_table("device_profiles", schema=None) as batch_op:
        batch_op.add_column(sa.Column("type_evidence", sa.JSON(), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("device_profiles", schema=None) as batch_op:
        batch_op.drop_column("type_evidence")

    with op.batch_alter_table("devices", schema=None) as batch_op:
        batch_op.drop_column("discovery_source")
        batch_op.drop_column("discovery_name")
        batch_op.drop_column("type_confidence")
