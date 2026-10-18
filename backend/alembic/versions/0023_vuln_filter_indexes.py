"""Index devices.os_name for the vulnerabilities dashboard's OS facet/filter.

Revision ID: 0023
Revises: 0022
Create Date: 2026-10-18 16:00:00.000000

Unlike `device_type`, `os_name` was never indexed; GET /api/vulns' os_name filter and facet would
otherwise scan every device row.
"""
from __future__ import annotations

from alembic import op

revision = "0023"
down_revision = "0022"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("devices", schema=None) as batch_op:
        batch_op.create_index(batch_op.f("ix_devices_os_name"), ["os_name"], unique=False)


def downgrade() -> None:
    with op.batch_alter_table("devices", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_devices_os_name"))
