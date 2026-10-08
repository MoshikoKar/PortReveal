"""per-device port scan failure reason and extra port profile

Revision ID: 0007
Revises: 0006
Create Date: 2026-10-09 00:00:00.000000
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "0007"
down_revision = "0006"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("devices", schema=None) as batch_op:
        batch_op.add_column(sa.Column("scan_failure", sa.Text(), nullable=True))
        batch_op.add_column(sa.Column("scan_failure_scan_id", sa.Integer(), nullable=True))
        batch_op.add_column(sa.Column("port_profile", sa.String(length=20), nullable=True))
        batch_op.add_column(sa.Column("port_profile_source", sa.String(length=40), nullable=True))
        batch_op.add_column(sa.Column("port_profile_scan_id", sa.Integer(), nullable=True))

    # Devices already flagged as failed: take the reason from the latest scan that recorded the failure.
    devices = sa.table("devices", sa.column("id", sa.Integer), sa.column("port_scan_failed", sa.Boolean),
                       sa.column("scan_failure", sa.Text), sa.column("scan_failure_scan_id", sa.Integer))
    hosts = sa.table("scan_hosts", sa.column("scan_id", sa.Integer), sa.column("device_id", sa.Integer),
                     sa.column("status", sa.String))
    scans = sa.table("scans", sa.column("id", sa.Integer), sa.column("error", sa.Text))
    last_failed = (sa.select(sa.func.max(hosts.c.scan_id))
                   .where(hosts.c.device_id == devices.c.id, hosts.c.status == "port_scan_failed")
                   .scalar_subquery())
    op.get_bind().execute(
        devices.update().where(devices.c.port_scan_failed.is_(True)).values(
            scan_failure_scan_id=last_failed,
            scan_failure=sa.func.coalesce(
                sa.select(scans.c.error).where(scans.c.id == last_failed).scalar_subquery(),
                "port scan failed (reason not recorded)",
            ),
        )
    )


def downgrade() -> None:
    with op.batch_alter_table("devices", schema=None) as batch_op:
        batch_op.drop_column("port_profile_scan_id")
        batch_op.drop_column("port_profile_source")
        batch_op.drop_column("port_profile")
        batch_op.drop_column("scan_failure_scan_id")
        batch_op.drop_column("scan_failure")
