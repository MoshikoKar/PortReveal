"""Store pre-dismiss state so Undo restores confirmed vs potential.

Revision ID: 0025
Revises: 0024
Create Date: 2026-10-18 18:00:00.000000

Dismiss used to flip state to dismissed and Undo always set potential, so a
confirmed finding became potential after dismiss→undo. Persist the prior
state on dismiss and restore it on undo.
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0025"
down_revision = "0024"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("device_port_vulns", schema=None) as batch_op:
        batch_op.add_column(sa.Column("state_before_dismiss", sa.String(length=10), nullable=True))
        batch_op.create_check_constraint(
            "ck_device_port_vulns_state_before_dismiss",
            "state_before_dismiss IS NULL OR state_before_dismiss IN ('confirmed', 'potential')",
        )


def downgrade() -> None:
    with op.batch_alter_table("device_port_vulns", schema=None) as batch_op:
        batch_op.drop_constraint("ck_device_port_vulns_state_before_dismiss", type_="check")
        batch_op.drop_column("state_before_dismiss")
