"""Optional reason on dismissed vulnerability matches (shown in the findings list and reports).

Revision ID: 0039
Revises: 0038
Create Date: 2026-11-02 09:00:00.000000
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0039"
down_revision = "0038"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("device_port_vulns", schema=None) as batch_op:
        batch_op.add_column(sa.Column("dismiss_reason", sa.String(200), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("device_port_vulns", schema=None) as batch_op:
        batch_op.drop_column("dismiss_reason")
