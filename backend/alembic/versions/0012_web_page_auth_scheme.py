"""Add web_pages.auth_scheme: HTTP authentication challenge (Basic, Digest, NTLM, …)

Revision ID: 0012
Revises: 0011
Create Date: 2026-10-15 10:00:00.000000
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0012"
down_revision = "0011"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("web_pages", schema=None) as batch_op:
        batch_op.add_column(sa.Column("auth_scheme", sa.String(length=20), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("web_pages", schema=None) as batch_op:
        batch_op.drop_column("auth_scheme")
