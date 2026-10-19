"""Add networks.arp_snmp (router ARP table over SNMP) and devices.mac_source

Revision ID: 0026
Revises: 0025
Create Date: 2026-10-19 12:00:00.000000
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0026"
down_revision = "0025"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("networks", schema=None) as batch_op:
        batch_op.add_column(sa.Column("arp_snmp", sa.JSON(), nullable=True))
    with op.batch_alter_table("devices", schema=None) as batch_op:
        batch_op.add_column(sa.Column("mac_source", sa.String(length=20), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("devices", schema=None) as batch_op:
        batch_op.drop_column("mac_source")
    with op.batch_alter_table("networks", schema=None) as batch_op:
        batch_op.drop_column("arp_snmp")
