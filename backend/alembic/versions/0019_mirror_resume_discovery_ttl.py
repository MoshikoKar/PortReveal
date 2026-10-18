"""Resumable NVD mirror progress and discovery name last-heard timestamp.

Revision ID: 0019
Revises: 0018
Create Date: 2026-10-18 18:00:00.000000

- ``vuln_feed_state.mirror_complete`` / ``mirror_next_year``: a partial yearly NVD JSON
  mirror must resume remaining years instead of falling through to the 120-day API window.
- ``devices.discovery_name_seen_at``: local discovery names age out on a TTL instead of
  being wiped when a single pass does not hear the host.
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0019"
down_revision = "0018"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("vuln_feed_state", schema=None) as batch_op:
        batch_op.add_column(
            sa.Column("mirror_complete", sa.Boolean(), server_default=sa.false(), nullable=False)
        )
        batch_op.add_column(sa.Column("mirror_next_year", sa.Integer(), nullable=True))

    # Healthy prior syncs: assume the yearly mirror finished. Rows with a recorded error (or never
    # synced) stay incomplete so the next sync resumes / re-runs the mirror.
    # Use SQL true (not 1): PostgreSQL rejects integer literals for boolean columns; SQLite accepts true.
    op.execute(
        sa.text(
            "UPDATE vuln_feed_state SET mirror_complete = true "
            "WHERE source = 'nvd' AND last_synced_at IS NOT NULL AND last_error IS NULL"
        )
    )

    with op.batch_alter_table("devices", schema=None) as batch_op:
        batch_op.add_column(sa.Column("discovery_name_seen_at", sa.DateTime(), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("devices", schema=None) as batch_op:
        batch_op.drop_column("discovery_name_seen_at")
    with op.batch_alter_table("vuln_feed_state", schema=None) as batch_op:
        batch_op.drop_column("mirror_next_year")
        batch_op.drop_column("mirror_complete")
