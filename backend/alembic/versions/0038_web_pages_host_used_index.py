"""Index web_pages.host_used: the subdomain inventory flags names that have captured web pages.

Revision ID: 0038
Revises: 0037
Create Date: 2026-10-29 23:00:00.000000
"""
from __future__ import annotations

from alembic import op

revision = "0038"
down_revision = "0037"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_index("ix_web_pages_host_used", "web_pages", ["host_used"])


def downgrade() -> None:
    op.drop_index("ix_web_pages_host_used", table_name="web_pages")
