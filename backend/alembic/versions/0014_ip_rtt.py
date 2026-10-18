"""IP assignment (static/dynamic/unknown), RTT and continuous-uptime (spec sections 6-7)

Revision ID: 0014
Revises: 0013
Create Date: 2026-10-17 11:00:00.000000
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0014"
down_revision = "0013"
branch_labels = None
depends_on = None

_IP_ASSIGNMENTS = ("static", "dynamic", "unknown")


def upgrade() -> None:
    with op.batch_alter_table("devices", schema=None) as batch_op:
        batch_op.add_column(sa.Column("ip_assignment", sa.String(length=10), nullable=True))
        batch_op.add_column(sa.Column("last_rtt_ms", sa.Float(), nullable=True))
        batch_op.add_column(sa.Column("continuous_since", sa.DateTime(), nullable=True))
        batch_op.create_check_constraint(
            "ck_devices_ip_assignment",
            '"ip_assignment" IN (' + ", ".join(f"'{v}'" for v in _IP_ASSIGNMENTS) + ")",
        )

    op.create_table(
        "device_rtt_samples",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("device_id", sa.Integer(), nullable=False),
        sa.Column("rtt_ms", sa.Float(), nullable=False),
        sa.Column("sampled_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["device_id"], ["devices.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    with op.batch_alter_table("device_rtt_samples", schema=None) as batch_op:
        batch_op.create_index(
            "ix_device_rtt_samples_device_sampled", ["device_id", "sampled_at"], unique=False
        )
        batch_op.create_index(
            batch_op.f("ix_device_rtt_samples_device_id"), ["device_id"], unique=False
        )


def downgrade() -> None:
    with op.batch_alter_table("device_rtt_samples", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_device_rtt_samples_device_id"))
        batch_op.drop_index("ix_device_rtt_samples_device_sampled")
    op.drop_table("device_rtt_samples")

    with op.batch_alter_table("devices", schema=None) as batch_op:
        batch_op.drop_constraint("ck_devices_ip_assignment", type_="check")
        batch_op.drop_column("continuous_since")
        batch_op.drop_column("last_rtt_ms")
        batch_op.drop_column("ip_assignment")
