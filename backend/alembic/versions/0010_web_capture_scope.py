"""Add web_captures.scope for remote-only / web-only capture jobs

Revision ID: 0010
Revises: 0009
Create Date: 2026-10-13 10:10:00.000000
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0010"
down_revision = "0009"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("web_captures", schema=None) as batch_op:
        batch_op.add_column(
            sa.Column("scope", sa.String(length=16), nullable=False, server_default="all"),
        )


def downgrade() -> None:
    with op.batch_alter_table("web_captures", schema=None) as batch_op:
        batch_op.drop_column("scope")
