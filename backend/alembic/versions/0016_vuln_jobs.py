"""Background vulnerability-check jobs (spec section 8)

Revision ID: 0016
Revises: 0015
Create Date: 2026-10-18 09:00:00.000000
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0016"
down_revision = "0015"
branch_labels = None
depends_on = None

_STATUSES = ("queued", "running", "completed", "partial", "failed", "cancelled")
_TRIGGERS = ("after_scan", "manual")


def upgrade() -> None:
    op.create_table(
        "vuln_jobs",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("uuid", sa.String(length=36), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.Column("trigger", sa.String(length=20), nullable=False),
        sa.Column("scan_id", sa.Integer(), nullable=True),
        sa.Column("network_id", sa.Integer(), nullable=True),
        sa.Column("device_ids", sa.JSON(), nullable=True),
        sa.Column("requested_by", sa.String(length=150), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("started_at", sa.DateTime(), nullable=True),
        sa.Column("finished_at", sa.DateTime(), nullable=True),
        sa.Column("stage", sa.String(length=40), nullable=True),
        sa.Column("progress", sa.Float(), nullable=False),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("stats", sa.JSON(), nullable=True),
        sa.Column("notes", sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["network_id"], ["networks.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("uuid"),
        sa.CheckConstraint(
            '"status" IN (' + ", ".join(f"'{v}'" for v in _STATUSES) + ")", name="ck_vuln_jobs_status"
        ),
        sa.CheckConstraint(
            '"trigger" IN (' + ", ".join(f"'{v}'" for v in _TRIGGERS) + ")", name="ck_vuln_jobs_trigger"
        ),
    )
    with op.batch_alter_table("vuln_jobs", schema=None) as batch_op:
        batch_op.create_index(batch_op.f("ix_vuln_jobs_uuid"), ["uuid"], unique=True)
        batch_op.create_index(batch_op.f("ix_vuln_jobs_status"), ["status"], unique=False)
        batch_op.create_index(batch_op.f("ix_vuln_jobs_scan_id"), ["scan_id"], unique=False)
        batch_op.create_index(batch_op.f("ix_vuln_jobs_created_at"), ["created_at"], unique=False)


def downgrade() -> None:
    with op.batch_alter_table("vuln_jobs", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_vuln_jobs_created_at"))
        batch_op.drop_index(batch_op.f("ix_vuln_jobs_scan_id"))
        batch_op.drop_index(batch_op.f("ix_vuln_jobs_status"))
        batch_op.drop_index(batch_op.f("ix_vuln_jobs_uuid"))
    op.drop_table("vuln_jobs")
