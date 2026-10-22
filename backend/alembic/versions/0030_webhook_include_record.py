"""Webhook include_record_events flag (opt into non-alert/record events).

Revision ID: 0030
Revises: 0029
Create Date: 2026-10-22 12:00:00.000000
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0030"
down_revision = "0029"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("webhook_endpoints", schema=None) as batch_op:
        batch_op.add_column(
            sa.Column("include_record_events", sa.Boolean(), nullable=False, server_default=sa.false()),
        )


def downgrade() -> None:
    with op.batch_alter_table("webhook_endpoints", schema=None) as batch_op:
        batch_op.drop_column("include_record_events")
