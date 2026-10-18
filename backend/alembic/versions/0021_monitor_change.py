"""Allow monitor_change events for saved-search host monitoring.

Revision ID: 0021
Revises: 0020
Create Date: 2026-10-18 13:20:00.000000
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0021"
down_revision = "0020"
branch_labels = None
depends_on = None


_EVENT_TYPES = (
    "device_discovered", "device_disappeared", "device_reappeared", "ip_changed", "port_opened",
    "port_closed", "service_detected", "service_changed", "version_changed", "tag_added",
    "tag_removed", "watch_match", "policy_violation", "banner_changed", "os_changed",
    "monitor_change",
)


def upgrade() -> None:
    with op.batch_alter_table("events", schema=None) as batch_op:
        batch_op.drop_constraint("ck_events_event_type", type_="check")
        batch_op.create_check_constraint(
            "ck_events_event_type",
            '"event_type" IN (' + ", ".join(f"'{v}'" for v in _EVENT_TYPES) + ")",
        )


def downgrade() -> None:
    op.execute(sa.text("DELETE FROM events WHERE event_type = 'monitor_change'"))
    old = (
        "device_discovered", "device_disappeared", "device_reappeared", "ip_changed", "port_opened",
        "port_closed", "service_detected", "service_changed", "version_changed", "tag_added",
        "tag_removed", "watch_match", "policy_violation", "banner_changed", "os_changed",
    )
    with op.batch_alter_table("events", schema=None) as batch_op:
        batch_op.drop_constraint("ck_events_event_type", type_="check")
        batch_op.create_check_constraint(
            "ck_events_event_type",
            '"event_type" IN (' + ", ".join(f"'{v}'" for v in old) + ")",
        )
