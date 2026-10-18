"""OS detection depth: accuracy, detected-at, source, and the os_changed event

Revision ID: 0013
Revises: 0012
Create Date: 2026-10-17 10:00:00.000000

This migration only adds columns; it does not touch stored settings data. Existing
installs that already persisted a ``scan`` row in ``app_settings`` with an explicit
``"os_detection": false`` keep that value (the pydantic default only fills in a
*missing* key) — an admin opts back in from Settings. Only fresh installs, which have
no stored row yet, pick up the new ``ScanSettings.os_detection = True`` default.
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0013"
down_revision = "0012"
branch_labels = None
depends_on = None


_EVENT_TYPES = (
    "device_discovered", "device_disappeared", "device_reappeared", "ip_changed", "port_opened",
    "port_closed", "service_detected", "service_changed", "version_changed", "tag_added",
    "tag_removed", "watch_match", "policy_violation", "banner_changed", "os_changed",
)


def upgrade() -> None:
    with op.batch_alter_table("devices", schema=None) as batch_op:
        batch_op.add_column(sa.Column("os_accuracy", sa.Integer(), nullable=True))
        batch_op.add_column(sa.Column("os_detected_at", sa.DateTime(), nullable=True))
        batch_op.add_column(sa.Column("os_source", sa.String(length=20), nullable=True))
        batch_op.add_column(sa.Column("os_pending", sa.JSON(), nullable=True))

    with op.batch_alter_table("events", schema=None) as batch_op:
        batch_op.drop_constraint("ck_events_event_type", type_="check")
        batch_op.create_check_constraint(
            "ck_events_event_type",
            '"event_type" IN (' + ", ".join(f"'{v}'" for v in _EVENT_TYPES) + ")",
        )


def downgrade() -> None:
    # Remove os_changed rows first — otherwise recreating the CHECK without that value fails.
    op.execute(sa.text("DELETE FROM events WHERE event_type = 'os_changed'"))
    old = (
        "device_discovered", "device_disappeared", "device_reappeared", "ip_changed", "port_opened",
        "port_closed", "service_detected", "service_changed", "version_changed", "tag_added",
        "tag_removed", "watch_match", "policy_violation", "banner_changed",
    )
    with op.batch_alter_table("events", schema=None) as batch_op:
        batch_op.drop_constraint("ck_events_event_type", type_="check")
        batch_op.create_check_constraint(
            "ck_events_event_type",
            '"event_type" IN (' + ", ".join(f"'{v}'" for v in old) + ")",
        )
    with op.batch_alter_table("devices", schema=None) as batch_op:
        batch_op.drop_column("os_pending")
        batch_op.drop_column("os_source")
        batch_op.drop_column("os_detected_at")
        batch_op.drop_column("os_accuracy")
