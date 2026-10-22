"""CVE watchlist tables and cve_watch_match events.

Revision ID: 0029
Revises: 0028
Create Date: 2026-10-22 10:00:00.000000
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0029"
down_revision = "0028"
branch_labels = None
depends_on = None

_EVENT_TYPES = (
    "device_discovered", "device_disappeared", "device_reappeared", "ip_changed", "port_opened",
    "port_closed", "service_detected", "service_changed", "version_changed", "tag_added",
    "tag_removed", "watch_match", "policy_violation", "banner_changed", "os_changed",
    "monitor_change", "geo_mismatch", "cve_watch_match",
)

_OLD_EVENT_TYPES = (
    "device_discovered", "device_disappeared", "device_reappeared", "ip_changed", "port_opened",
    "port_closed", "service_detected", "service_changed", "version_changed", "tag_added",
    "tag_removed", "watch_match", "policy_violation", "banner_changed", "os_changed",
    "monitor_change", "geo_mismatch",
)


def _check_sql(column: str, values: tuple[str, ...]) -> str:
    return f'"{column}" IN (' + ", ".join(f"'{v}'" for v in values) + ")"


def _replace_event_type_check(values: tuple[str, ...]) -> None:
    """Swap ck_events_event_type. Postgres needs IF EXISTS; SQLite uses batch rebuild."""
    conn = op.get_bind()
    expr = _check_sql("event_type", values)
    if conn.dialect.name == "postgresql":
        conn.execute(sa.text("ALTER TABLE events DROP CONSTRAINT IF EXISTS ck_events_event_type"))
        conn.execute(sa.text("ALTER TABLE events DROP CONSTRAINT IF EXISTS events_event_type_check"))
        conn.execute(sa.text(f"ALTER TABLE events ADD CONSTRAINT ck_events_event_type CHECK ({expr})"))
        return
    with op.batch_alter_table("events", schema=None) as batch_op:
        batch_op.drop_constraint("ck_events_event_type", type_="check")
        batch_op.create_check_constraint("ck_events_event_type", expr)


def upgrade() -> None:
    op.create_table(
        "cve_watchlist",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("cve_id", sa.String(length=20), nullable=False),
        sa.Column("note", sa.Text(), nullable=True),
        sa.Column("created_by", sa.String(length=150), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.UniqueConstraint("cve_id", name="uq_cve_watchlist_cve_id"),
    )
    op.create_index("ix_cve_watchlist_cve_id", "cve_watchlist", ["cve_id"])
    op.create_table(
        "cve_watchlist_alerts",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("watch_id", sa.Integer(), sa.ForeignKey("cve_watchlist.id", ondelete="CASCADE"),
                  nullable=False),
        sa.Column("cve_id", sa.String(length=20), nullable=False),
        sa.Column("device_uuid", sa.String(length=36), nullable=False),
        sa.Column("port", sa.Integer(), nullable=False),
        sa.Column("protocol", sa.String(length=8), nullable=False),
        sa.Column("alerted_at", sa.DateTime(), nullable=False),
        sa.Column("event_id", sa.Integer(), sa.ForeignKey("events.id", ondelete="SET NULL"),
                  nullable=True),
        sa.UniqueConstraint(
            "watch_id", "cve_id", "device_uuid", "port", "protocol",
            name="uq_cve_watchlist_alert_hit",
        ),
    )
    op.create_index("ix_cve_watchlist_alerts_watch_id", "cve_watchlist_alerts", ["watch_id"])
    op.create_index("ix_cve_watchlist_alerts_cve_id", "cve_watchlist_alerts", ["cve_id"])
    _replace_event_type_check(_EVENT_TYPES)


def downgrade() -> None:
    op.execute(sa.text("DELETE FROM events WHERE event_type = 'cve_watch_match'"))
    _replace_event_type_check(_OLD_EVENT_TYPES)
    op.drop_index("ix_cve_watchlist_alerts_cve_id", table_name="cve_watchlist_alerts")
    op.drop_index("ix_cve_watchlist_alerts_watch_id", table_name="cve_watchlist_alerts")
    op.drop_table("cve_watchlist_alerts")
    op.drop_index("ix_cve_watchlist_cve_id", table_name="cve_watchlist")
    op.drop_table("cve_watchlist")
