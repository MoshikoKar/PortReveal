"""Vulnerability core: local NVD/KEV/EPSS cache, CPE matches, device risk/combined scores

Revision ID: 0015
Revises: 0014
Create Date: 2026-10-17 12:00:00.000000
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0015"
down_revision = "0014"
branch_labels = None
depends_on = None

_VULN_STATES = ("confirmed", "potential", "dismissed")
_VULN_SOURCES = ("cache", "nmap_script")


def upgrade() -> None:
    op.create_table(
        "vulnerabilities",
        sa.Column("cve_id", sa.String(length=20), nullable=False),
        sa.Column("cvss_base", sa.Float(), nullable=True),
        sa.Column("cvss_vector", sa.String(length=100), nullable=True),
        sa.Column("severity", sa.String(length=10), nullable=True),
        sa.Column("published_at", sa.DateTime(), nullable=True),
        sa.Column("last_modified", sa.DateTime(), nullable=True),
        sa.Column("kev", sa.Boolean(), server_default=sa.false(), nullable=False),
        sa.Column("kev_added_at", sa.DateTime(), nullable=True),
        sa.Column("epss", sa.Float(), nullable=True),
        sa.Column("epss_percentile", sa.Float(), nullable=True),
        sa.Column("summary", sa.Text(), nullable=True),
        sa.PrimaryKeyConstraint("cve_id"),
    )
    with op.batch_alter_table("vulnerabilities", schema=None) as batch_op:
        batch_op.create_index(batch_op.f("ix_vulnerabilities_kev"), ["kev"], unique=False)
        batch_op.create_index(batch_op.f("ix_vulnerabilities_last_modified"), ["last_modified"], unique=False)

    op.create_table(
        "vuln_cpe_match",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("cve_id", sa.String(length=20), nullable=False),
        sa.Column("cpe23", sa.String(length=255), nullable=False),
        sa.Column("vendor_product", sa.String(length=200), nullable=False),
        sa.Column("version_start", sa.String(length=100), nullable=True),
        sa.Column("version_start_incl", sa.Boolean(), nullable=True),
        sa.Column("version_end", sa.String(length=100), nullable=True),
        sa.Column("version_end_excl", sa.Boolean(), nullable=True),
        sa.ForeignKeyConstraint(["cve_id"], ["vulnerabilities.cve_id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    with op.batch_alter_table("vuln_cpe_match", schema=None) as batch_op:
        batch_op.create_index("ix_vuln_cpe_match_vendor_product", ["vendor_product"], unique=False)
        batch_op.create_index(batch_op.f("ix_vuln_cpe_match_cve_id"), ["cve_id"], unique=False)

    op.create_table(
        "device_port_vulns",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("device_port_id", sa.Integer(), nullable=False),
        sa.Column("cve_id", sa.String(length=20), nullable=False),
        sa.Column("matched_cpe", sa.String(length=255), nullable=True),
        sa.Column("state", sa.String(length=10), nullable=False),
        sa.Column("source", sa.String(length=15), nullable=False),
        sa.Column("matched_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["device_port_id"], ["device_ports.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["cve_id"], ["vulnerabilities.cve_id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("device_port_id", "cve_id", name="uq_device_port_vuln"),
        sa.CheckConstraint(
            '"state" IN (' + ", ".join(f"'{v}'" for v in _VULN_STATES) + ")", name="ck_device_port_vulns_state"
        ),
        sa.CheckConstraint(
            '"source" IN (' + ", ".join(f"'{v}'" for v in _VULN_SOURCES) + ")", name="ck_device_port_vulns_source"
        ),
    )
    with op.batch_alter_table("device_port_vulns", schema=None) as batch_op:
        batch_op.create_index(batch_op.f("ix_device_port_vulns_device_port_id"), ["device_port_id"], unique=False)
        batch_op.create_index(batch_op.f("ix_device_port_vulns_cve_id"), ["cve_id"], unique=False)

    op.create_table(
        "vuln_feed_state",
        sa.Column("source", sa.String(length=10), nullable=False),
        sa.Column("last_synced_at", sa.DateTime(), nullable=True),
        sa.Column("last_modified_cursor", sa.String(length=40), nullable=True),
        sa.Column("record_count", sa.Integer(), nullable=False),
        sa.Column("last_error", sa.Text(), nullable=True),
        sa.PrimaryKeyConstraint("source"),
    )

    with op.batch_alter_table("devices", schema=None) as batch_op:
        batch_op.add_column(sa.Column("risk_score", sa.Integer(), server_default="0", nullable=False))
        batch_op.add_column(sa.Column("combined_score", sa.Integer(), server_default="0", nullable=False))
        batch_op.add_column(sa.Column("risk_scored_at", sa.DateTime(), nullable=True))
        batch_op.create_index(batch_op.f("ix_devices_risk_score"), ["risk_score"], unique=False)
        batch_op.create_index(batch_op.f("ix_devices_combined_score"), ["combined_score"], unique=False)

    with op.batch_alter_table("device_profiles", schema=None) as batch_op:
        batch_op.add_column(sa.Column("risk_factors", sa.JSON(), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("device_profiles", schema=None) as batch_op:
        batch_op.drop_column("risk_factors")

    with op.batch_alter_table("devices", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_devices_combined_score"))
        batch_op.drop_index(batch_op.f("ix_devices_risk_score"))
        batch_op.drop_column("risk_scored_at")
        batch_op.drop_column("combined_score")
        batch_op.drop_column("risk_score")

    op.drop_table("vuln_feed_state")

    with op.batch_alter_table("device_port_vulns", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_device_port_vulns_cve_id"))
        batch_op.drop_index(batch_op.f("ix_device_port_vulns_device_port_id"))
    op.drop_table("device_port_vulns")

    with op.batch_alter_table("vuln_cpe_match", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_vuln_cpe_match_cve_id"))
        batch_op.drop_index("ix_vuln_cpe_match_vendor_product")
    op.drop_table("vuln_cpe_match")

    with op.batch_alter_table("vulnerabilities", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_vulnerabilities_last_modified"))
        batch_op.drop_index(batch_op.f("ix_vulnerabilities_kev"))
    op.drop_table("vulnerabilities")
