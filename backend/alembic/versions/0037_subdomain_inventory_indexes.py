"""Indexes for the paged subdomain inventory (sort / filter columns) and device -> domain names.

Revision ID: 0037
Revises: 0036
Create Date: 2026-10-29 22:00:00.000000
"""
from __future__ import annotations

from alembic import op

revision = "0037"
down_revision = "0036"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_index("ix_subdomains_domain_exposure", "subdomains", ["domain_id", "exposure"])
    op.create_index("ix_subdomains_domain_wildcard", "subdomains", ["domain_id", "wildcard"])
    op.create_index("ix_subdomains_domain_last_seen", "subdomains", ["domain_id", "last_seen"])
    op.create_index("ix_subdomains_device_id", "subdomains", ["device_id"])


def downgrade() -> None:
    op.drop_index("ix_subdomains_device_id", table_name="subdomains")
    op.drop_index("ix_subdomains_domain_last_seen", table_name="subdomains")
    op.drop_index("ix_subdomains_domain_wildcard", table_name="subdomains")
    op.drop_index("ix_subdomains_domain_exposure", table_name="subdomains")
