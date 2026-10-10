"""FK networks.baseline_scan_id and devices.last_port_scan_id → scans.id SET NULL

Revision ID: 0008
Revises: 0007
Create Date: 2026-10-09 22:30:00.000000
"""
from __future__ import annotations

from alembic import op

revision = "0008"
down_revision = "0007"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Clear dangling soft refs before the engine can enforce them.
    op.execute(
        """
        UPDATE networks SET baseline_scan_id = NULL
        WHERE baseline_scan_id IS NOT NULL
          AND baseline_scan_id NOT IN (SELECT id FROM scans)
        """
    )
    op.execute(
        """
        UPDATE devices SET last_port_scan_id = NULL
        WHERE last_port_scan_id IS NOT NULL
          AND last_port_scan_id NOT IN (SELECT id FROM scans)
        """
    )
    with op.batch_alter_table("networks", schema=None) as batch_op:
        batch_op.create_foreign_key(
            "fk_networks_baseline_scan_id_scans",
            "scans",
            ["baseline_scan_id"],
            ["id"],
            ondelete="SET NULL",
        )
    with op.batch_alter_table("devices", schema=None) as batch_op:
        batch_op.create_foreign_key(
            "fk_devices_last_port_scan_id_scans",
            "scans",
            ["last_port_scan_id"],
            ["id"],
            ondelete="SET NULL",
        )


def downgrade() -> None:
    with op.batch_alter_table("devices", schema=None) as batch_op:
        batch_op.drop_constraint("fk_devices_last_port_scan_id_scans", type_="foreignkey")
    with op.batch_alter_table("networks", schema=None) as batch_op:
        batch_op.drop_constraint("fk_networks_baseline_scan_id_scans", type_="foreignkey")
