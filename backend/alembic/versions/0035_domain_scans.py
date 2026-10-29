"""Domain scans: domains, domain_scans, subdomains, subdomain_observations; domain change events.

Events gain domain_id / domain_scan_id / hostname (domain events have no device) and the
event_type CHECK constraint is rewritten to include the domain event types.

Revision ID: 0035
Revises: 0034
Create Date: 2026-10-29 18:00:00.000000
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0035"
down_revision = "0034"
branch_labels = None
depends_on = None

_OLD_EVENT_TYPES = (
    "device_discovered", "device_disappeared", "device_reappeared", "ip_changed", "port_opened",
    "port_closed", "service_detected", "service_changed", "version_changed", "tag_added",
    "tag_removed", "watch_match", "policy_violation", "banner_changed", "os_changed",
    "monitor_change", "geo_mismatch", "cve_watch_match",
)
_DOMAIN_EVENT_TYPES = (
    "subdomain_new", "subdomain_gone", "subdomain_ip_changed", "subdomain_exposure_changed",
    "internal_name_exposed", "wildcard_detected", "wildcard_removed", "zone_transfer_open",
)
_SCAN_STATUSES = ("queued", "running", "completed", "partial", "failed", "cancelled")


def _check_sql(column: str, values: tuple[str, ...]) -> str:
    return f'"{column}" IN (' + ", ".join(f"'{v}'" for v in values) + ")"


def _replace_event_type_check(values: tuple[str, ...]) -> None:
    """Swap ck_events_event_type. Postgres needs IF EXISTS; SQLite uses batch rebuild."""
    conn = op.get_bind()
    expr = _check_sql("event_type", values)
    if conn.dialect.name == "postgresql":
        conn.execute(sa.text("ALTER TABLE events DROP CONSTRAINT IF EXISTS ck_events_event_type"))
        conn.execute(sa.text(f"ALTER TABLE events ADD CONSTRAINT ck_events_event_type CHECK ({expr})"))
        return
    with op.batch_alter_table("events", schema=None) as batch_op:
        batch_op.drop_constraint("ck_events_event_type", type_="check")
        batch_op.create_check_constraint("ck_events_event_type", expr)


def upgrade() -> None:
    op.create_table(
        "domains",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(length=253), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("notes", sa.Text(), nullable=True),
        sa.Column("wordlist_mode", sa.String(length=10), nullable=False),
        sa.Column("wordlist_id", sa.Integer(), sa.ForeignKey("wordlists.id", ondelete="SET NULL"), nullable=True),
        sa.Column("custom_words", sa.JSON(), nullable=True),
        sa.Column("passive_enabled", sa.Boolean(), nullable=False),
        sa.Column("axfr_enabled", sa.Boolean(), nullable=False),
        sa.Column("axfr_servers", sa.JSON(), nullable=True),
        sa.Column("internal_resolvers", sa.JSON(), nullable=True),
        sa.Column("public_resolvers", sa.JSON(), nullable=True),
        sa.Column("schedule", sa.JSON(), nullable=True),
        sa.Column("last_scheduled_on", sa.String(length=10), nullable=True),
        sa.Column("created_by", sa.String(length=150), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("name"),
        sa.CheckConstraint(_check_sql("wordlist_mode", ("none", "library", "custom")), name="ck_domains_wordlist_mode"),
    )
    op.create_table(
        "domain_scans",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("domain_id", sa.Integer(), sa.ForeignKey("domains.id", ondelete="CASCADE"), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.Column("trigger", sa.String(length=20), nullable=False),
        sa.Column("requested_by", sa.String(length=150), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("started_at", sa.DateTime(), nullable=True),
        sa.Column("finished_at", sa.DateTime(), nullable=True),
        sa.Column("stage", sa.String(length=40), nullable=True),
        sa.Column("progress", sa.Float(), nullable=False),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("notes", sa.Text(), nullable=True),
        sa.Column("stats", sa.JSON(), nullable=True),
        sa.Column("wildcard", sa.JSON(), nullable=True),
        sa.Column("axfr", sa.JSON(), nullable=True),
        sa.Column("port_scan_id", sa.Integer(), sa.ForeignKey("scans.id", ondelete="SET NULL"), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.CheckConstraint(_check_sql("status", _SCAN_STATUSES), name="ck_domain_scans_status"),
        sa.CheckConstraint(_check_sql("trigger", ("manual", "scheduled")), name="ck_domain_scans_trigger"),
    )
    op.create_index("ix_domain_scans_domain_id", "domain_scans", ["domain_id"])
    op.create_index("ix_domain_scans_status", "domain_scans", ["status"])
    op.create_index("ix_domain_scans_created_at", "domain_scans", ["created_at"])
    op.create_table(
        "subdomains",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("domain_id", sa.Integer(), sa.ForeignKey("domains.id", ondelete="CASCADE"), nullable=False),
        sa.Column("name", sa.String(length=253), nullable=False),
        sa.Column("exposure", sa.String(length=12), nullable=False),
        sa.Column("records", sa.JSON(), nullable=True),
        sa.Column("ips", sa.JSON(), nullable=True),
        sa.Column("sources", sa.JSON(), nullable=True),
        sa.Column("wildcard", sa.Boolean(), nullable=False),
        sa.Column("flags", sa.JSON(), nullable=True),
        sa.Column("hosting", sa.JSON(), nullable=True),
        sa.Column("device_id", sa.Integer(), sa.ForeignKey("devices.id", ondelete="SET NULL"), nullable=True),
        sa.Column("status", sa.String(length=10), nullable=False),
        sa.Column("first_seen", sa.DateTime(), nullable=False),
        sa.Column("last_seen", sa.DateTime(), nullable=False),
        sa.Column("last_scan_id", sa.Integer(), sa.ForeignKey("domain_scans.id", ondelete="SET NULL"), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("domain_id", "name", name="uq_subdomain_name"),
        sa.CheckConstraint(_check_sql("exposure", ("external", "internal", "both", "unresolved")),
                           name="ck_subdomains_exposure"),
        sa.CheckConstraint(_check_sql("status", ("active", "gone")), name="ck_subdomains_status"),
    )
    op.create_index("ix_subdomains_domain_id", "subdomains", ["domain_id"])
    op.create_index("ix_subdomains_name", "subdomains", ["name"])
    op.create_index("ix_subdomains_last_seen", "subdomains", ["last_seen"])
    op.create_index("ix_subdomains_domain_status", "subdomains", ["domain_id", "status"])
    op.create_table(
        "subdomain_observations",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("domain_scan_id", sa.Integer(), sa.ForeignKey("domain_scans.id", ondelete="CASCADE"),
                  nullable=False),
        sa.Column("subdomain_id", sa.Integer(), sa.ForeignKey("subdomains.id", ondelete="SET NULL"), nullable=True),
        sa.Column("name", sa.String(length=253), nullable=False),
        sa.Column("exposure", sa.String(length=12), nullable=False),
        sa.Column("records", sa.JSON(), nullable=True),
        sa.Column("ips", sa.JSON(), nullable=True),
        sa.Column("sources", sa.JSON(), nullable=True),
        sa.Column("wildcard", sa.Boolean(), nullable=False),
        sa.Column("flags", sa.JSON(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_subdomain_observations_domain_scan_id", "subdomain_observations", ["domain_scan_id"])
    op.create_index("ix_subdomain_observations_subdomain_id", "subdomain_observations", ["subdomain_id"])

    with op.batch_alter_table("events", schema=None) as batch_op:
        batch_op.add_column(sa.Column("domain_id", sa.Integer(), nullable=True))
        batch_op.add_column(sa.Column("domain_scan_id", sa.Integer(), nullable=True))
        batch_op.add_column(sa.Column("hostname", sa.String(length=255), nullable=True))
        batch_op.create_foreign_key("fk_events_domain_id", "domains", ["domain_id"], ["id"], ondelete="SET NULL")
        batch_op.create_foreign_key("fk_events_domain_scan_id", "domain_scans", ["domain_scan_id"], ["id"],
                                    ondelete="SET NULL")
        batch_op.create_index("ix_events_domain_id", ["domain_id"])
    _replace_event_type_check(_OLD_EVENT_TYPES + _DOMAIN_EVENT_TYPES)


def downgrade() -> None:
    types = ", ".join(f"'{t}'" for t in _DOMAIN_EVENT_TYPES)
    op.execute(sa.text(f"DELETE FROM events WHERE event_type IN ({types})"))
    _replace_event_type_check(_OLD_EVENT_TYPES)
    with op.batch_alter_table("events", schema=None) as batch_op:
        batch_op.drop_index("ix_events_domain_id")
        batch_op.drop_constraint("fk_events_domain_scan_id", type_="foreignkey")
        batch_op.drop_constraint("fk_events_domain_id", type_="foreignkey")
        batch_op.drop_column("hostname")
        batch_op.drop_column("domain_scan_id")
        batch_op.drop_column("domain_id")
    op.drop_index("ix_subdomain_observations_subdomain_id", table_name="subdomain_observations")
    op.drop_index("ix_subdomain_observations_domain_scan_id", table_name="subdomain_observations")
    op.drop_table("subdomain_observations")
    op.drop_index("ix_subdomains_domain_status", table_name="subdomains")
    op.drop_index("ix_subdomains_last_seen", table_name="subdomains")
    op.drop_index("ix_subdomains_name", table_name="subdomains")
    op.drop_index("ix_subdomains_domain_id", table_name="subdomains")
    op.drop_table("subdomains")
    op.drop_index("ix_domain_scans_created_at", table_name="domain_scans")
    op.drop_index("ix_domain_scans_status", table_name="domain_scans")
    op.drop_index("ix_domain_scans_domain_id", table_name="domain_scans")
    op.drop_table("domain_scans")
    op.drop_table("domains")
