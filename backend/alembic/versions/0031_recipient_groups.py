"""Recipient groups (notification channels) and webhook last_error_at.

Revision ID: 0031
Revises: 0030
Create Date: 2026-10-22 14:30:00.000000
"""

from __future__ import annotations

import json

import sqlalchemy as sa
from alembic import op

revision = "0031"
down_revision = "0030"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "recipient_groups",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("name", sa.String(120), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("is_default", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("event_types", sa.JSON(), nullable=True),
        sa.Column("min_severity", sa.String(10), nullable=False, server_default="info"),
        sa.Column("network_ids", sa.JSON(), nullable=True),
        sa.Column("delivery_mode", sa.String(20), nullable=False, server_default="daily"),
        sa.Column("digest_time", sa.String(5), nullable=True),
        sa.Column("max_per_hour", sa.Integer(), nullable=False, server_default="20"),
        sa.Column("dedupe_seconds", sa.Integer(), nullable=False, server_default="300"),
        sa.Column("quiet_start", sa.String(5), nullable=True),
        sa.Column("quiet_end", sa.String(5), nullable=True),
        sa.Column("quiet_bypass_critical", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("rate_hour_bucket", sa.String(10), nullable=True),
        sa.Column("rate_sent", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.Column("last_success_at", sa.DateTime(), nullable=True),
        sa.Column("last_error", sa.Text(), nullable=True),
        sa.Column("last_error_at", sa.DateTime(), nullable=True),
        sa.CheckConstraint(
            "delivery_mode IN ('immediate', 'hourly', 'daily')",
            name="ck_recipient_groups_delivery_mode",
        ),
        sa.CheckConstraint(
            "min_severity IN ('high', 'medium', 'low', 'info')",
            name="ck_recipient_groups_min_severity",
        ),
    )
    op.create_table(
        "recipient_destinations",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("group_id", sa.Integer(), sa.ForeignKey("recipient_groups.id", ondelete="CASCADE"), nullable=False),
        sa.Column("kind", sa.String(20), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("target", sa.String(255), nullable=True),
        sa.Column("webhook_id", sa.Integer(), sa.ForeignKey("webhook_endpoints.id", ondelete="SET NULL"), nullable=True),
        sa.Column("url_enc", sa.String(500), nullable=True),
        sa.CheckConstraint(
            "kind IN ('email', 'webhook', 'slack', 'teams')",
            name="ck_recipient_destinations_kind",
        ),
    )
    op.create_index("ix_recipient_destinations_group_id", "recipient_destinations", ["group_id"])
    op.create_table(
        "recipient_holds",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("group_id", sa.Integer(), sa.ForeignKey("recipient_groups.id", ondelete="CASCADE"), nullable=False),
        sa.Column("event_id", sa.Integer(), sa.ForeignKey("events.id", ondelete="CASCADE"), nullable=False),
        sa.Column("reason", sa.String(40), nullable=False),
        sa.Column("dedupe_key", sa.String(200), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.UniqueConstraint("group_id", "event_id", name="uq_recipient_hold_event"),
    )
    op.create_index("ix_recipient_holds_group_id", "recipient_holds", ["group_id"])
    op.create_index("ix_recipient_holds_event_id", "recipient_holds", ["event_id"])
    op.create_index("ix_recipient_holds_group_created", "recipient_holds", ["group_id", "created_at"])
    op.create_index("ix_recipient_holds_dedupe_key", "recipient_holds", ["dedupe_key"])

    with op.batch_alter_table("webhook_endpoints", schema=None) as batch_op:
        batch_op.add_column(sa.Column("last_error_at", sa.DateTime(), nullable=True))

    # Migrate existing global email digest into a default recipient group (behavior unchanged).
    # Notification settings live as one JSON document under app_settings.key = 'notifications'.
    bind = op.get_bind()
    row = bind.execute(sa.text("SELECT value FROM app_settings WHERE key = 'notifications'")).fetchone()
    cfg: dict = {}
    if row and row[0] is not None:
        raw = row[0]
        if isinstance(raw, str):
            try:
                cfg = json.loads(raw)
            except (TypeError, ValueError, json.JSONDecodeError):
                cfg = {}
        elif isinstance(raw, dict):
            cfg = dict(raw)

    recipients = cfg.get("recipients") if isinstance(cfg.get("recipients"), list) else []
    event_types = cfg.get("event_types") if isinstance(cfg.get("event_types"), list) else []
    digest_time = str(cfg.get("digest_time") or "08:00").strip() or "08:00"
    # Always create the default group so upgrades have a channel even with empty recipients.
    bind.execute(
        sa.text(
            "INSERT INTO recipient_groups "
            "(name, enabled, is_default, event_types, min_severity, network_ids, delivery_mode, "
            "digest_time, max_per_hour, dedupe_seconds, quiet_bypass_critical, rate_sent, "
            "created_at, updated_at) "
            "VALUES (:name, 1, 1, :event_types, 'info', NULL, 'daily', :digest_time, 20, 300, 1, 0, "
            "CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)"
        ),
        {
            "name": "Email digest",
            "event_types": json.dumps(event_types) if event_types else None,
            "digest_time": digest_time,
        },
    )
    gid = bind.execute(sa.text("SELECT id FROM recipient_groups WHERE is_default = 1 LIMIT 1")).scalar()
    if gid and recipients:
        for addr in recipients:
            if not isinstance(addr, str) or not addr.strip():
                continue
            bind.execute(
                sa.text(
                    "INSERT INTO recipient_destinations (group_id, kind, enabled, target) "
                    "VALUES (:gid, 'email', 1, :target)"
                ),
                {"gid": gid, "target": addr.strip()},
            )


def downgrade() -> None:
    with op.batch_alter_table("webhook_endpoints", schema=None) as batch_op:
        batch_op.drop_column("last_error_at")
    op.drop_table("recipient_holds")
    op.drop_table("recipient_destinations")
    op.drop_table("recipient_groups")
