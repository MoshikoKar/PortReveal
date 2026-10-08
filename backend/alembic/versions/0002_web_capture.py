"""web capture tables

Revision ID: 0002
Revises: 0001
Create Date: 2026-10-05 18:00:00.000000
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "web_captures",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("uuid", sa.String(length=36), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.Column("targets", sa.Text(), nullable=False),
        sa.Column("target_count", sa.Integer(), nullable=False),
        sa.Column("requested_by", sa.String(length=150), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("started_at", sa.DateTime(), nullable=True),
        sa.Column("finished_at", sa.DateTime(), nullable=True),
        sa.Column("stage", sa.String(length=40), nullable=True),
        sa.Column("progress", sa.Float(), nullable=False),
        sa.Column("endpoints_found", sa.Integer(), nullable=False),
        sa.Column("pages_captured", sa.Integer(), nullable=False),
        sa.Column("screenshots_captured", sa.Integer(), nullable=False),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("notes", sa.Text(), nullable=True),
        sa.Column("mock_mode", sa.Boolean(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    with op.batch_alter_table("web_captures", schema=None) as batch_op:
        batch_op.create_index(batch_op.f("ix_web_captures_uuid"), ["uuid"], unique=True)
        batch_op.create_index(batch_op.f("ix_web_captures_status"), ["status"], unique=False)
        batch_op.create_index(batch_op.f("ix_web_captures_created_at"), ["created_at"], unique=False)

    op.create_table(
        "web_pages",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("uuid", sa.String(length=36), nullable=False),
        sa.Column("capture_id", sa.Integer(), nullable=False),
        sa.Column("device_id", sa.Integer(), nullable=True),
        sa.Column("device_port_id", sa.Integer(), nullable=True),
        sa.Column("ip", sa.String(length=45), nullable=False),
        sa.Column("port", sa.Integer(), nullable=False),
        sa.Column("scheme", sa.String(length=8), nullable=False),
        sa.Column("host_used", sa.String(length=255), nullable=False),
        sa.Column("kind", sa.String(length=20), nullable=False),
        sa.Column("url", sa.Text(), nullable=False),
        sa.Column("final_url", sa.Text(), nullable=True),
        sa.Column("redirect_target", sa.Text(), nullable=True),
        sa.Column("external_redirect", sa.Boolean(), nullable=False),
        sa.Column("http_status", sa.Integer(), nullable=True),
        sa.Column("title", sa.String(length=500), nullable=True),
        sa.Column("content_type", sa.String(length=255), nullable=True),
        sa.Column("server_header", sa.String(length=255), nullable=True),
        sa.Column("tls_verified", sa.Boolean(), nullable=True),
        sa.Column("screenshot_status", sa.String(length=20), nullable=False),
        sa.Column("screenshot_relpath", sa.String(length=500), nullable=True),
        sa.Column("capture_error", sa.String(length=500), nullable=True),
        sa.Column("captured_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["capture_id"], ["web_captures.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["device_id"], ["devices.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["device_port_id"], ["device_ports.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    with op.batch_alter_table("web_pages", schema=None) as batch_op:
        batch_op.create_index(batch_op.f("ix_web_pages_uuid"), ["uuid"], unique=True)
        batch_op.create_index(batch_op.f("ix_web_pages_capture_id"), ["capture_id"], unique=False)
        batch_op.create_index(batch_op.f("ix_web_pages_device_id"), ["device_id"], unique=False)
        batch_op.create_index("ix_web_pages_device_captured", ["device_id", "captured_at"], unique=False)
        batch_op.create_index("ix_web_pages_capture", ["capture_id"], unique=False)


def downgrade() -> None:
    with op.batch_alter_table("web_pages", schema=None) as batch_op:
        batch_op.drop_index("ix_web_pages_capture")
        batch_op.drop_index("ix_web_pages_device_captured")
        batch_op.drop_index(batch_op.f("ix_web_pages_device_id"))
        batch_op.drop_index(batch_op.f("ix_web_pages_capture_id"))
        batch_op.drop_index(batch_op.f("ix_web_pages_uuid"))
    op.drop_table("web_pages")
    with op.batch_alter_table("web_captures", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_web_captures_created_at"))
        batch_op.drop_index(batch_op.f("ix_web_captures_status"))
        batch_op.drop_index(batch_op.f("ix_web_captures_uuid"))
    op.drop_table("web_captures")
