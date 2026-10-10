"""Shodan-style enrichment: banners, TLS, HTTP hashes, CPE sources, SNMP, webhooks

Revision ID: 0009
Revises: 0008
Create Date: 2026-10-10 11:00:00.000000
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0009"
down_revision = "0008"
branch_labels = None
depends_on = None


_EVENT_TYPES = (
    "device_discovered", "device_disappeared", "device_reappeared", "ip_changed", "port_opened",
    "port_closed", "service_detected", "service_changed", "version_changed", "tag_added",
    "tag_removed", "watch_match", "policy_violation", "banner_changed",
)


def upgrade() -> None:
    # Expand events.event_type CHECK to allow banner_changed.
    with op.batch_alter_table("events", schema=None) as batch_op:
        batch_op.drop_constraint("ck_events_event_type", type_="check")
        batch_op.create_check_constraint(
            "ck_events_event_type",
            '"event_type" IN (' + ", ".join(f"'{v}'" for v in _EVENT_TYPES) + ")",
        )

    op.create_table(
        "service_banners",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("device_port_id", sa.Integer(), nullable=False),
        sa.Column("hash", sa.String(length=64), nullable=False),
        sa.Column("raw_truncated", sa.Text(), nullable=False),
        sa.Column("seen_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["device_port_id"], ["device_ports.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    with op.batch_alter_table("service_banners", schema=None) as batch_op:
        batch_op.create_index("ix_service_banners_device_port_id", ["device_port_id"], unique=False)
        batch_op.create_index("ix_service_banners_hash", ["hash"], unique=False)

    op.create_table(
        "port_tls",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("device_port_id", sa.Integer(), nullable=False),
        sa.Column("device_id", sa.Integer(), nullable=False),
        sa.Column("cn", sa.String(length=255), nullable=True),
        sa.Column("san", sa.Text(), nullable=True),
        sa.Column("issuer", sa.String(length=500), nullable=True),
        sa.Column("not_before", sa.DateTime(), nullable=True),
        sa.Column("not_after", sa.DateTime(), nullable=True),
        sa.Column("fingerprint_sha256", sa.String(length=64), nullable=True),
        sa.Column("self_signed", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("expired", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("expires_soon", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("wildcard", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("weak", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("first_seen", sa.DateTime(), nullable=False),
        sa.Column("last_seen", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["device_id"], ["devices.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["device_port_id"], ["device_ports.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("device_port_id"),
    )
    with op.batch_alter_table("port_tls", schema=None) as batch_op:
        batch_op.create_index("ix_port_tls_device_id", ["device_id"], unique=False)
        batch_op.create_index("ix_port_tls_fingerprint", ["fingerprint_sha256"], unique=False)
        batch_op.create_index("ix_port_tls_cn", ["cn"], unique=False)

    op.create_table(
        "port_cpes",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("device_port_id", sa.Integer(), nullable=False),
        sa.Column("cpe", sa.String(length=255), nullable=False),
        sa.Column("source", sa.String(length=20), nullable=False),
        sa.Column("first_seen", sa.DateTime(), nullable=False),
        sa.Column("last_seen", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["device_port_id"], ["device_ports.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("device_port_id", "cpe", "source", name="uq_port_cpe_source"),
    )
    with op.batch_alter_table("port_cpes", schema=None) as batch_op:
        batch_op.create_index("ix_port_cpes_device_port_id", ["device_port_id"], unique=False)
        batch_op.create_index("ix_port_cpes_cpe", ["cpe"], unique=False)

    op.create_table(
        "port_snmp",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("device_port_id", sa.Integer(), nullable=False),
        sa.Column("device_id", sa.Integer(), nullable=False),
        sa.Column("sys_descr", sa.Text(), nullable=True),
        sa.Column("sys_name", sa.String(length=255), nullable=True),
        sa.Column("sys_object_id", sa.String(length=255), nullable=True),
        sa.Column("sys_location", sa.String(length=255), nullable=True),
        sa.Column("sys_contact", sa.String(length=255), nullable=True),
        sa.Column("vendor", sa.String(length=120), nullable=True),
        sa.Column("model", sa.String(length=120), nullable=True),
        sa.Column("first_seen", sa.DateTime(), nullable=False),
        sa.Column("last_seen", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["device_id"], ["devices.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["device_port_id"], ["device_ports.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("device_port_id"),
    )
    with op.batch_alter_table("port_snmp", schema=None) as batch_op:
        batch_op.create_index("ix_port_snmp_device_id", ["device_id"], unique=False)

    op.create_table(
        "webhook_endpoints",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(length=120), nullable=False),
        sa.Column("url", sa.Text(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("secret_enc", sa.String(length=500), nullable=True),
        sa.Column("event_types", sa.JSON(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("last_success_at", sa.DateTime(), nullable=True),
        sa.Column("last_error", sa.Text(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )

    with op.batch_alter_table("port_http", schema=None) as batch_op:
        batch_op.add_column(sa.Column("favicon_hash", sa.Integer(), nullable=True))
        batch_op.add_column(sa.Column("html_hash", sa.String(length=64), nullable=True))
        batch_op.add_column(sa.Column("header_set_hash", sa.String(length=64), nullable=True))
        batch_op.add_column(sa.Column("web_vnc", sa.Boolean(), nullable=False, server_default=sa.false()))
        batch_op.create_index("ix_port_http_favicon_hash", ["favicon_hash"], unique=False)

    with op.batch_alter_table("web_pages", schema=None) as batch_op:
        batch_op.add_column(sa.Column("phash", sa.String(length=32), nullable=True))
        batch_op.add_column(sa.Column("ocr_text", sa.Text(), nullable=True))

    with op.batch_alter_table("devices", schema=None) as batch_op:
        batch_op.add_column(sa.Column("ssh_hostkey_sha256", sa.String(length=64), nullable=True))


def downgrade() -> None:
    old = (
        "device_discovered", "device_disappeared", "device_reappeared", "ip_changed", "port_opened",
        "port_closed", "service_detected", "service_changed", "version_changed", "tag_added",
        "tag_removed", "watch_match", "policy_violation",
    )
    with op.batch_alter_table("events", schema=None) as batch_op:
        batch_op.drop_constraint("ck_events_event_type", type_="check")
        batch_op.create_check_constraint(
            "ck_events_event_type",
            '"event_type" IN (' + ", ".join(f"'{v}'" for v in old) + ")",
        )
    with op.batch_alter_table("devices", schema=None) as batch_op:
        batch_op.drop_column("ssh_hostkey_sha256")
    with op.batch_alter_table("web_pages", schema=None) as batch_op:
        batch_op.drop_column("ocr_text")
        batch_op.drop_column("phash")
    with op.batch_alter_table("port_http", schema=None) as batch_op:
        batch_op.drop_index("ix_port_http_favicon_hash")
        batch_op.drop_column("web_vnc")
        batch_op.drop_column("header_set_hash")
        batch_op.drop_column("html_hash")
        batch_op.drop_column("favicon_hash")
    op.drop_table("webhook_endpoints")
    op.drop_table("port_snmp")
    op.drop_table("port_cpes")
    op.drop_table("port_tls")
    op.drop_table("service_banners")
