"""Soft-archive networks.

Revision ID: 0020
Revises: 0019
Create Date: 2026-10-18 10:00:00.000000

- ``networks.archived_at``: removing a network from Settings archives it instead of deleting the
  row, so its devices, events and scans stay linked but are hidden from default views.
- Recovery of networks hard-deleted by older versions: every ``network.delete`` audit entry
  (name + CIDR) becomes an archived network, and devices left without a network whose IP falls in
  that CIDR are re-linked to it, so they are hidden like any other archived finding.
"""
from __future__ import annotations

import ipaddress
import json

import sqlalchemy as sa
from alembic import op

revision = "0020"
down_revision = "0019"
branch_labels = None
depends_on = None

NAME_MAX = 120


def _details_dict(details) -> dict:
    if details is None or details == "":
        return {}
    if isinstance(details, dict):
        return details
    try:
        parsed = json.loads(details)
    except (TypeError, ValueError, json.JSONDecodeError):
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _recover_deleted_networks() -> None:
    conn = op.get_bind()
    deletes = conn.execute(sa.text(
        "SELECT id, created_at, target, details FROM audit_log WHERE action = 'network.delete' ORDER BY id"
    )).all()
    if not deletes:
        return
    names = {r[0].lower() for r in conn.execute(sa.text("SELECT name FROM networks")).all()}
    orphans = list(conn.execute(sa.text("SELECT id, current_ip FROM devices WHERE network_id IS NULL")).all())
    # Use SQL false (not bound Python bools): portable across SQLite and PostgreSQL.
    insert_sql = sa.text(
        "INSERT INTO networks (name, cidr, enabled, vpn_s2s, archived_at, created_at, updated_at) "
        "VALUES (:name, :cidr, false, false, :archived_at, :created_at, :updated_at)"
    )
    for audit_id, created_at, target, details in deletes:
        try:
            cidr = _details_dict(details).get("cidr")
            net = ipaddress.ip_network(cidr, strict=False)
        except (ValueError, TypeError, AttributeError):
            continue
        name = (target or f"Network {audit_id}")[:NAME_MAX]
        if name.lower() in names:
            name = f"{name} (archived {audit_id})"[:NAME_MAX]
        names.add(name.lower())
        conn.execute(insert_sql, {
            "name": name,
            "cidr": str(net),
            "archived_at": created_at,
            "created_at": created_at,
            "updated_at": created_at,
        })
        net_id = conn.execute(sa.text("SELECT id FROM networks WHERE name = :name"), {"name": name}).scalar()
        matched: list[int] = []
        for dev_id, ip in orphans:
            try:
                if ipaddress.ip_address(ip) in net:
                    matched.append(dev_id)
            except ValueError:
                continue
        for dev_id in matched:
            conn.execute(
                sa.text("UPDATE devices SET network_id = :nid WHERE id = :id"),
                {"nid": net_id, "id": dev_id},
            )
        matched_set = set(matched)
        orphans = [o for o in orphans if o[0] not in matched_set]


def upgrade() -> None:
    conn = op.get_bind()
    cols = {c["name"] for c in sa.inspect(conn).get_columns("networks")}
    if "archived_at" not in cols:
        # Plain ALTER on Postgres; batch rebuild only matters for SQLite.
        if conn.dialect.name == "postgresql":
            op.add_column("networks", sa.Column("archived_at", sa.DateTime(), nullable=True))
            op.create_index("ix_networks_archived_at", "networks", ["archived_at"])
        else:
            with op.batch_alter_table("networks", schema=None) as batch_op:
                batch_op.add_column(sa.Column("archived_at", sa.DateTime(), nullable=True))
                batch_op.create_index("ix_networks_archived_at", ["archived_at"])
    _recover_deleted_networks()


def downgrade() -> None:
    conn = op.get_bind()
    cols = {c["name"] for c in sa.inspect(conn).get_columns("networks")}
    if "archived_at" not in cols:
        return
    if conn.dialect.name == "postgresql":
        op.drop_index("ix_networks_archived_at", table_name="networks")
        op.drop_column("networks", "archived_at")
    else:
        with op.batch_alter_table("networks", schema=None) as batch_op:
            batch_op.drop_index("ix_networks_archived_at")
            batch_op.drop_column("archived_at")
