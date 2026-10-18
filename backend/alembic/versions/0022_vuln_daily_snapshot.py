"""Vulnerability dashboard: daily snapshot aggregates + finding lifecycle tracking.

Revision ID: 0022
Revises: 0021
Create Date: 2026-10-18 15:00:00.000000

No history backfill here: `vuln_daily_snapshots` gets its first row from the refresh hook the
next time a scan/sync completes, and `vuln_finding_lifecycle` is populated going forward by the
sync logic added alongside it.
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0022"
down_revision = "0021"
branch_labels = None
depends_on = None

_RESOLUTIONS = ("no_longer_matched", "device_removed")


def upgrade() -> None:
    op.create_table(
        "vuln_daily_snapshots",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("snapshot_date", sa.Date(), nullable=False),
        sa.Column("network_id", sa.Integer(), nullable=True),
        sa.Column("critical", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("high", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("medium", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("low", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("kev_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("confirmed_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("potential_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("avg_risk_score", sa.Float(), nullable=True),
        sa.Column("avg_combined_score", sa.Float(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["network_id"], ["networks.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("network_id", "snapshot_date", name="uq_vuln_snapshot_day"),
    )
    with op.batch_alter_table("vuln_daily_snapshots", schema=None) as batch_op:
        batch_op.create_index(
            batch_op.f("ix_vuln_daily_snapshots_snapshot_date"), ["snapshot_date"], unique=False,
        )
        batch_op.create_index(
            batch_op.f("ix_vuln_daily_snapshots_network_id"), ["network_id"], unique=False,
        )

    op.create_table(
        "vuln_finding_lifecycle",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("device_uuid", sa.String(length=36), nullable=False),
        sa.Column("port", sa.Integer(), nullable=False),
        sa.Column("protocol", sa.String(length=8), nullable=False),
        sa.Column("cve_id", sa.String(length=20), nullable=False),
        sa.Column("network_id", sa.Integer(), nullable=True),
        sa.Column("first_seen_at", sa.DateTime(), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(), nullable=False),
        sa.Column("resolved_at", sa.DateTime(), nullable=True),
        sa.Column("resolution", sa.String(length=20), nullable=True),
        sa.Column("dismissed_at", sa.DateTime(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["network_id"], ["networks.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("device_uuid", "port", "protocol", "cve_id", name="uq_vuln_finding_lifecycle"),
        sa.CheckConstraint(
            '"resolution" IN (' + ", ".join(f"'{v}'" for v in _RESOLUTIONS) + ")",
            name="ck_vuln_finding_lifecycle_resolution",
        ),
    )
    with op.batch_alter_table("vuln_finding_lifecycle", schema=None) as batch_op:
        batch_op.create_index(
            batch_op.f("ix_vuln_finding_lifecycle_network_id"), ["network_id"], unique=False,
        )
        batch_op.create_index(
            batch_op.f("ix_vuln_finding_lifecycle_first_seen_at"), ["first_seen_at"], unique=False,
        )
        batch_op.create_index(
            batch_op.f("ix_vuln_finding_lifecycle_resolved_at"), ["resolved_at"], unique=False,
        )


def downgrade() -> None:
    with op.batch_alter_table("vuln_finding_lifecycle", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_vuln_finding_lifecycle_resolved_at"))
        batch_op.drop_index(batch_op.f("ix_vuln_finding_lifecycle_first_seen_at"))
        batch_op.drop_index(batch_op.f("ix_vuln_finding_lifecycle_network_id"))
    op.drop_table("vuln_finding_lifecycle")

    with op.batch_alter_table("vuln_daily_snapshots", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_vuln_daily_snapshots_network_id"))
        batch_op.drop_index(batch_op.f("ix_vuln_daily_snapshots_snapshot_date"))
    op.drop_table("vuln_daily_snapshots")
