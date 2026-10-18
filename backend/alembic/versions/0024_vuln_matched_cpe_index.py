"""Index device_port_vulns.matched_cpe for vendor/product facet filters.

Revision ID: 0024
Revises: 0023
Create Date: 2026-10-18 17:00:00.000000

GET /api/vulns?vendor=&product= joins findings to vuln_cpe_match on
(cve_id, matched_cpe = cpe23). matched_cpe was unindexed; this keeps that
filter from scanning every finding row. vendor_product is already indexed.
"""
from __future__ import annotations

from alembic import op

revision = "0024"
down_revision = "0023"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("device_port_vulns", schema=None) as batch_op:
        batch_op.create_index(batch_op.f("ix_device_port_vulns_matched_cpe"), ["matched_cpe"], unique=False)


def downgrade() -> None:
    with op.batch_alter_table("device_port_vulns", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_device_port_vulns_matched_cpe"))
