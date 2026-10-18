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


def _recover_deleted_networks() -> None:
    conn = op.get_bind()
    deletes = conn.execute(sa.text(
        "SELECT id, created_at, target, details FROM audit_log WHERE action = 'network.delete' ORDER BY id"
    )).all()
    if not deletes:
        return
    names = {r[0].lower() for r in conn.execute(sa.text("SELECT name FROM networks")).all()}
    orphans = conn.execute(sa.text("SELECT id, current_ip FROM devices WHERE network_id IS NULL")).all()
    for audit_id, created_at, target, details in deletes:
        try:
            cidr = json.loads(details or "{}").get("cidr")
            net = ipaddress.ip_network(cidr, strict=False)
        except (ValueError, TypeError, AttributeError):
            continue
        name = (target or f"Network {audit_id}")[:NAME_MAX]
        if name.lower() in names:
            name = f"{name} (archived {audit_id})"[:NAME_MAX]
        names.add(name.lower())
        conn.execute(sa.text(
            "INSERT INTO networks (name, cidr, enabled, vpn_s2s, archived_at, created_at, updated_at) "
            "VALUES (:name, :cidr, :enabled, :vpn, :at, :at, :at)"
        ), {"name": name, "cidr": str(net), "enabled": False, "vpn": False, "at": created_at})
        net_id = conn.execute(sa.text("SELECT id FROM networks WHERE name = :name"), {"name": name}).scalar()
        matched = []
        for dev_id, ip in orphans:
            try:
                if ipaddress.ip_address(ip) in net:
                    matched.append(dev_id)
            except ValueError:
                continue
        for dev_id in matched:
            conn.execute(sa.text("UPDATE devices SET network_id = :nid WHERE id = :id"),
                         {"nid": net_id, "id": dev_id})
        orphans = [o for o in orphans if o[0] not in set(matched)]


def upgrade() -> None:
    with op.batch_alter_table("networks", schema=None) as batch_op:
        batch_op.add_column(sa.Column("archived_at", sa.DateTime(), nullable=True))
        batch_op.create_index("ix_networks_archived_at", ["archived_at"])
    _recover_deleted_networks()


def downgrade() -> None:
    with op.batch_alter_table("networks", schema=None) as batch_op:
        batch_op.drop_index("ix_networks_archived_at")
        batch_op.drop_column("archived_at")
