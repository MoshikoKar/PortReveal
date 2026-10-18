"""Strip legacy OS accuracy suffixes, backfill, and enable OS detection for existing installs.

Revision ID: 0018
Revises: 0017
Create Date: 2026-10-18 12:00:00.000000

Pre-phase-1 installs stored ``os_name`` as ``"Linux 5.x (94%)"``. After the parser split
name/accuracy, the next scan would treat that as a rename and emit a burst of ``os_changed``
events. This migration strips the suffix and backfills ``os_accuracy`` / ``os_source``.

Spec 3.2 also requires OS detection ON for existing installs (one-time): stored
``scan.os_detection=false`` is flipped to true, an audit row is written, and
``os_detection_enabled_notice`` is set so Settings can show an admin banner.
"""
from __future__ import annotations

import json
import re

import sqlalchemy as sa
from alembic import op

revision = "0018"
down_revision = "0017"
branch_labels = None
depends_on = None

_OS_SUFFIX = re.compile(r"\s*\((\d{1,3})%\)\s*$")


def upgrade() -> None:
    conn = op.get_bind()
    rows = conn.execute(sa.text("SELECT id, os_name FROM devices WHERE os_name IS NOT NULL")).fetchall()
    for device_id, os_name in rows:
        if not os_name:
            continue
        m = _OS_SUFFIX.search(os_name)
        if not m:
            continue
        accuracy = int(m.group(1))
        clean = _OS_SUFFIX.sub("", os_name).strip() or os_name
        conn.execute(
            sa.text(
                "UPDATE devices SET os_name = :name, os_accuracy = COALESCE(os_accuracy, :acc), "
                "os_source = COALESCE(os_source, 'nmap_os') WHERE id = :id"
            ),
            {"name": clean, "acc": accuracy, "id": device_id},
        )

    scan_row = conn.execute(sa.text("SELECT value FROM app_settings WHERE key = 'scan'")).fetchone()
    enabled = False
    now = sa.text("(CURRENT_TIMESTAMP)")
    if scan_row is None:
        payload = {
            "os_detection": True,
            "os_detection_enabled_notice": True,
            "os_refresh_days": 7,
            "os_min_accuracy_display": 85,
        }
        conn.execute(
            sa.text(
                "INSERT INTO app_settings (key, value, updated_at) VALUES ('scan', :value, CURRENT_TIMESTAMP)"
            ),
            {"value": json.dumps(payload)},
        )
        enabled = True
    else:
        value = scan_row[0]
        if isinstance(value, str):
            data = json.loads(value)
        elif isinstance(value, dict):
            data = dict(value)
        else:
            data = {}
        if data.get("os_detection") is not True:
            data["os_detection"] = True
            enabled = True
        data.setdefault("os_refresh_days", 7)
        data.setdefault("os_min_accuracy_display", 85)
        if enabled:
            data["os_detection_enabled_notice"] = True
        conn.execute(
            sa.text(
                "UPDATE app_settings SET value = :value, updated_at = CURRENT_TIMESTAMP WHERE key = 'scan'"
            ),
            {"value": json.dumps(data)},
        )

    if enabled:
        conn.execute(
            sa.text(
                "INSERT INTO audit_log (created_at, username, action, target, details, ip) "
                "VALUES (CURRENT_TIMESTAMP, 'system', 'settings.os_detection_enabled', 'scan', :details, NULL)"
            ),
            {
                "details": json.dumps({
                    "reason": "one-time migration: OS detection enabled for existing install (spec 3.2)",
                    "os_detection": True,
                }),
            },
        )


def downgrade() -> None:
    # Data migration is not reversible without losing the stripped accuracy suffix.
    pass
