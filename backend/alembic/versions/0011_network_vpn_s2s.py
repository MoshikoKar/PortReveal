"""Add networks.vpn_s2s for the rate-capped site-to-site VPN scan profile

Revision ID: 0011
Revises: 0010
Create Date: 2026-10-13 13:30:00.000000
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0011"
down_revision = "0010"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("networks", schema=None) as batch_op:
        batch_op.add_column(
            sa.Column("vpn_s2s", sa.Boolean(), nullable=False, server_default=sa.false()),
        )


def downgrade() -> None:
    with op.batch_alter_table("networks", schema=None) as batch_op:
        batch_op.drop_column("vpn_s2s")
