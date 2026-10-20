"""Network expected countries, device geo fields, geo cache/feeds, geo_mismatch events.

Revision ID: 0027
Revises: 0026
Create Date: 2026-10-20 09:30:00.000000
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0027"
down_revision = "0026"
branch_labels = None
depends_on = None

_EVENT_TYPES = (
    "device_discovered", "device_disappeared", "device_reappeared", "ip_changed", "port_opened",
    "port_closed", "service_detected", "service_changed", "version_changed", "tag_added",
    "tag_removed", "watch_match", "policy_violation", "banner_changed", "os_changed",
    "monitor_change", "geo_mismatch",
)

_OLD_EVENT_TYPES = (
    "device_discovered", "device_disappeared", "device_reappeared", "ip_changed", "port_opened",
    "port_closed", "service_detected", "service_changed", "version_changed", "tag_added",
    "tag_removed", "watch_match", "policy_violation", "banner_changed", "os_changed",
    "monitor_change",
)

_GEO_STATUSES = ("ok", "mismatch", "mismatch_cdn", "not_checked", "unavailable")
_GEO_SOURCES = ("published_name", "device_ip")


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
    with op.batch_alter_table("networks", schema=None) as batch_op:
        batch_op.add_column(sa.Column("expected_countries", sa.JSON(), nullable=True))
    with op.batch_alter_table("devices", schema=None) as batch_op:
        batch_op.add_column(sa.Column("geo_status", sa.String(length=20), nullable=True))
        batch_op.add_column(sa.Column("geo_country", sa.String(length=2), nullable=True))
        batch_op.add_column(sa.Column("geo_ip", sa.String(length=45), nullable=True))
        batch_op.add_column(sa.Column("geo_asn", sa.Integer(), nullable=True))
        batch_op.add_column(sa.Column("geo_as_org", sa.String(length=200), nullable=True))
        batch_op.add_column(sa.Column("geo_cdn", sa.Boolean(), nullable=False, server_default=sa.false()))
        batch_op.add_column(sa.Column("geo_source", sa.String(length=20), nullable=True))
        batch_op.add_column(sa.Column("geo_name", sa.String(length=255), nullable=True))
        batch_op.add_column(sa.Column("geo_checked_at", sa.DateTime(), nullable=True))
        batch_op.add_column(sa.Column("geo_mismatch", sa.Boolean(), nullable=False, server_default=sa.false()))
        batch_op.create_index("ix_devices_geo_mismatch", ["geo_mismatch"])
        batch_op.create_check_constraint("ck_devices_geo_status", _check_sql("geo_status", _GEO_STATUSES))
        batch_op.create_check_constraint("ck_devices_geo_source", _check_sql("geo_source", _GEO_SOURCES))
    op.create_table(
        "geo_feed_state",
        sa.Column("source", sa.String(length=20), primary_key=True),
        sa.Column("last_synced_at", sa.DateTime(), nullable=True),
        sa.Column("file_month", sa.String(length=7), nullable=True),
        sa.Column("last_error", sa.Text(), nullable=True),
    )
    op.create_table(
        "geo_lookup_cache",
        sa.Column("cache_key", sa.String(length=300), primary_key=True),
        sa.Column("kind", sa.String(length=10), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("expires_at", sa.DateTime(), nullable=False),
    )
    op.create_index("ix_geo_lookup_cache_expires_at", "geo_lookup_cache", ["expires_at"])
    _replace_event_type_check(_EVENT_TYPES)


def downgrade() -> None:
    op.execute(sa.text("DELETE FROM events WHERE event_type = 'geo_mismatch'"))
    _replace_event_type_check(_OLD_EVENT_TYPES)
    op.drop_index("ix_geo_lookup_cache_expires_at", table_name="geo_lookup_cache")
    op.drop_table("geo_lookup_cache")
    op.drop_table("geo_feed_state")
    with op.batch_alter_table("devices", schema=None) as batch_op:
        batch_op.drop_constraint("ck_devices_geo_status", type_="check")
        batch_op.drop_constraint("ck_devices_geo_source", type_="check")
        batch_op.drop_index("ix_devices_geo_mismatch")
        batch_op.drop_column("geo_mismatch")
        batch_op.drop_column("geo_checked_at")
        batch_op.drop_column("geo_name")
        batch_op.drop_column("geo_source")
        batch_op.drop_column("geo_cdn")
        batch_op.drop_column("geo_as_org")
        batch_op.drop_column("geo_asn")
        batch_op.drop_column("geo_ip")
        batch_op.drop_column("geo_country")
        batch_op.drop_column("geo_status")
    with op.batch_alter_table("networks", schema=None) as batch_op:
        batch_op.drop_column("expected_countries")
