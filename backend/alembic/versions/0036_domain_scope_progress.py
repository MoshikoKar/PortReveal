"""Domain scope for recipient groups; domain-scan phase progress; subdomain miss / verification state.

* recipient_groups.domain_ids: NULL = all domains (existing groups keep receiving domain events).
* domain_scans.phases: per-phase progress of a scan.
* subdomains.missed_scans / unverified / in_progress: "gone" only after two complete scans miss a name,
  names a partial scan could not check, rows a running scan has not classified yet.

Revision ID: 0036
Revises: 0035
Create Date: 2026-10-29 20:00:00.000000
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0036"
down_revision = "0035"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("recipient_groups", schema=None) as batch_op:
        batch_op.add_column(sa.Column("domain_ids", sa.JSON(), nullable=True))
    with op.batch_alter_table("domain_scans", schema=None) as batch_op:
        batch_op.add_column(sa.Column("phases", sa.JSON(), nullable=True))
    with op.batch_alter_table("subdomains", schema=None) as batch_op:
        batch_op.add_column(sa.Column("missed_scans", sa.Integer(), nullable=False, server_default="0"))
        batch_op.add_column(sa.Column("unverified", sa.Boolean(), nullable=False, server_default=sa.false()))
        batch_op.add_column(sa.Column("in_progress", sa.Boolean(), nullable=False, server_default=sa.false()))


def downgrade() -> None:
    with op.batch_alter_table("subdomains", schema=None) as batch_op:
        batch_op.drop_column("in_progress")
        batch_op.drop_column("unverified")
        batch_op.drop_column("missed_scans")
    with op.batch_alter_table("domain_scans", schema=None) as batch_op:
        batch_op.drop_column("phases")
    with op.batch_alter_table("recipient_groups", schema=None) as batch_op:
        batch_op.drop_column("domain_ids")
