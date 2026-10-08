"""Database schema (one logical schema for SQLite and PostgreSQL)."""
from __future__ import annotations

import uuid as uuidlib
from datetime import date, datetime

from sqlalchemy import (
    JSON,
    Boolean,
    Date,
    Float,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .db import Base, UTCDateTime, utcnow

# --- enumerations (stored as plain strings) ---------------------------------
ROLE_ADMIN = "admin"
ROLE_VIEWER = "viewer"

DEVICE_ACTIVE = "active"            # seen in the latest scan that covered it
DEVICE_UNKNOWN = "unknown"          # missed by a scan, not yet confirmed gone
DEVICE_NOT_DETECTED = "not_detected"  # missed by N consecutive complete scans

SCAN_QUEUED = "queued"
SCAN_RUNNING = "running"
SCAN_COMPLETED = "completed"
SCAN_PARTIAL = "partial"
SCAN_FAILED = "failed"
SCAN_CANCELLED = "cancelled"
SCAN_ACTIVE_STATES = (SCAN_QUEUED, SCAN_RUNNING)

SCAN_DISCOVERY = "discovery"
SCAN_STANDARD = "standard"
SCAN_FULL = "full"
SCAN_TYPES = (SCAN_DISCOVERY, SCAN_STANDARD, SCAN_FULL)

TRIGGER_MANUAL = "manual"
TRIGGER_SCHEDULED = "scheduled"  # night inventory schedule
TRIGGER_PRESENCE = "presence"    # daytime discovery-only presence schedule

EV_DEVICE_DISCOVERED = "device_discovered"
EV_DEVICE_DISAPPEARED = "device_disappeared"
EV_DEVICE_REAPPEARED = "device_reappeared"
EV_IP_CHANGED = "ip_changed"
EV_PORT_OPENED = "port_opened"
EV_PORT_CLOSED = "port_closed"
EV_SERVICE_DETECTED = "service_detected"
EV_SERVICE_CHANGED = "service_changed"
EV_VERSION_CHANGED = "version_changed"
EVENT_TYPES = (
    EV_DEVICE_DISCOVERED,
    EV_DEVICE_DISAPPEARED,
    EV_DEVICE_REAPPEARED,
    EV_IP_CHANGED,
    EV_PORT_OPENED,
    EV_PORT_CLOSED,
    EV_SERVICE_DETECTED,
    EV_SERVICE_CHANGED,
    EV_VERSION_CHANGED,
)
EVENT_SEVERITY = {
    EV_DEVICE_DISCOVERED: "high",
    EV_PORT_OPENED: "high",
    EV_SERVICE_CHANGED: "medium",
    EV_DEVICE_DISAPPEARED: "medium",
    EV_PORT_CLOSED: "medium",
    EV_IP_CHANGED: "low",
    EV_VERSION_CHANGED: "low",
    EV_DEVICE_REAPPEARED: "low",
    EV_SERVICE_DETECTED: "info",
}


def new_uuid() -> str:
    return str(uuidlib.uuid4())


class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(150), unique=True, index=True)
    display_name: Mapped[str | None] = mapped_column(String(200))
    password_hash: Mapped[str | None] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(20), default=ROLE_VIEWER)
    source: Mapped[str] = mapped_column(String(20), default="local")  # local | ldap
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    last_login_at: Mapped[datetime | None] = mapped_column(UTCDateTime)


class UserSession(Base):
    __tablename__ = "sessions"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    csrf_token: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    last_seen_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(UTCDateTime, index=True)  # retention purge
    ip: Mapped[str | None] = mapped_column(String(64))
    user: Mapped[User] = relationship(lazy="joined")


class Network(Base):
    __tablename__ = "networks"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(120), unique=True)
    cidr: Mapped[str] = mapped_column(String(64))
    description: Mapped[str | None] = mapped_column(Text)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    baseline_scan_id: Mapped[int | None] = mapped_column(Integer)
    baseline_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, onupdate=utcnow)


class Exclusion(Base):
    __tablename__ = "exclusions"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    value: Mapped[str] = mapped_column(Text)  # IPs / ranges / CIDRs, comma or newline separated
    description: Mapped[str | None] = mapped_column(Text)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, onupdate=utcnow)


class AppSetting(Base):
    __tablename__ = "app_settings"
    key: Mapped[str] = mapped_column(String(100), primary_key=True)
    value: Mapped[dict] = mapped_column(JSON)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, onupdate=utcnow)


class Device(Base):
    __tablename__ = "devices"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    uuid: Mapped[str] = mapped_column(String(36), unique=True, index=True, default=new_uuid)
    network_id: Mapped[int | None] = mapped_column(ForeignKey("networks.id", ondelete="SET NULL"), index=True)
    current_ip: Mapped[str] = mapped_column(String(45), index=True)
    mac: Mapped[str | None] = mapped_column(String(17), index=True)
    vendor: Mapped[str | None] = mapped_column(String(200))
    hostname: Mapped[str | None] = mapped_column(String(255), index=True)
    dns_name: Mapped[str | None] = mapped_column(String(255))
    os_name: Mapped[str | None] = mapped_column(String(255))
    status: Mapped[str] = mapped_column(String(20), default=DEVICE_ACTIVE, index=True)
    first_seen: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, index=True)  # retention purge
    missed_scans: Mapped[int] = mapped_column(Integer, default=0)
    last_port_scan_id: Mapped[int | None] = mapped_column(Integer)
    last_port_scan_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    full_scanned_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    port_scan_failed: Mapped[bool] = mapped_column(Boolean, default=False)
    # Correlated absence: local days on which the night scan and every presence scan missed it.
    absence_days: Mapped[int] = mapped_column(Integer, default=0)
    absence_counted_on: Mapped[date | None] = mapped_column(Date)
    absence_alerted: Mapped[bool] = mapped_column(Boolean, default=False)

    ports: Mapped[list[DevicePort]] = relationship(
        back_populates="device", cascade="all, delete-orphan", order_by="DevicePort.port"
    )
    ips: Mapped[list[DeviceIP]] = relationship(
        back_populates="device", cascade="all, delete-orphan", order_by="DeviceIP.last_seen.desc()"
    )


class DeviceIP(Base):
    __tablename__ = "device_ips"
    __table_args__ = (UniqueConstraint("device_id", "ip", name="uq_device_ip"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    device_id: Mapped[int] = mapped_column(ForeignKey("devices.id", ondelete="CASCADE"), index=True)
    ip: Mapped[str] = mapped_column(String(45), index=True)
    first_seen: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    device: Mapped[Device] = relationship(back_populates="ips")


class DevicePort(Base):
    """Current known state of one port on one device (one row per device/protocol/port)."""

    __tablename__ = "device_ports"
    __table_args__ = (
        UniqueConstraint("device_id", "protocol", "port", name="uq_device_port"),
        Index("ix_device_ports_open", "is_open", "port"),
    )
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    device_id: Mapped[int] = mapped_column(ForeignKey("devices.id", ondelete="CASCADE"), index=True)
    protocol: Mapped[str] = mapped_column(String(8), default="tcp")
    port: Mapped[int] = mapped_column(Integer)
    is_open: Mapped[bool] = mapped_column(Boolean, default=True)
    service: Mapped[str | None] = mapped_column(String(100))
    product: Mapped[str | None] = mapped_column(String(255))
    version: Mapped[str | None] = mapped_column(String(255))
    extra_info: Mapped[str | None] = mapped_column(String(255))
    method: Mapped[str | None] = mapped_column(String(20))  # nmap: probed | table
    confidence: Mapped[int | None] = mapped_column(Integer)
    first_seen: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    opened_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    closed_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    device: Mapped[Device] = relationship(back_populates="ports")


class Scan(Base):
    __tablename__ = "scans"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_type: Mapped[str] = mapped_column(String(20))
    trigger: Mapped[str] = mapped_column(String(20), default=TRIGGER_MANUAL)  # manual | scheduled | presence
    status: Mapped[str] = mapped_column(String(20), default=SCAN_QUEUED, index=True)
    scanner_mode: Mapped[str | None] = mapped_column(String(10))  # nmap | mock
    network_id: Mapped[int | None] = mapped_column(ForeignKey("networks.id", ondelete="SET NULL"), index=True)
    targets: Mapped[str | None] = mapped_column(Text)  # explicit targets for ad-hoc scans
    target_count: Mapped[int] = mapped_column(Integer, default=0)
    criteria: Mapped[str | None] = mapped_column(Text)  # human-readable selection filter, if any
    port_scope: Mapped[str | None] = mapped_column(Text)  # nmap port list actually scanned
    requested_by: Mapped[str | None] = mapped_column(String(150))
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, index=True)
    started_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    finished_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    stage: Mapped[str | None] = mapped_column(String(40))
    progress: Mapped[float] = mapped_column(Float, default=0.0)
    hosts_discovered: Mapped[int] = mapped_column(Integer, default=0)
    hosts_scanned: Mapped[int] = mapped_column(Integer, default=0)
    hosts_failed: Mapped[int] = mapped_column(Integer, default=0)
    events_count: Mapped[int] = mapped_column(Integer, default=0)
    is_baseline: Mapped[bool] = mapped_column(Boolean, default=False)
    error: Mapped[str | None] = mapped_column(Text)
    notes: Mapped[str | None] = mapped_column(Text)


class ScanHost(Base):
    """Per-scan observation of a device (device scan history)."""

    __tablename__ = "scan_hosts"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    device_id: Mapped[int] = mapped_column(ForeignKey("devices.id", ondelete="CASCADE"), index=True)
    ip: Mapped[str] = mapped_column(String(45))
    status: Mapped[str] = mapped_column(String(20))  # up | port_scan_failed
    open_ports: Mapped[int | None] = mapped_column(Integer)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)


class Event(Base):
    __tablename__ = "events"
    __table_args__ = (Index("ix_events_type_created", "event_type", "created_at"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, index=True)
    scan_id: Mapped[int | None] = mapped_column(ForeignKey("scans.id", ondelete="SET NULL"), index=True)
    device_id: Mapped[int | None] = mapped_column(ForeignKey("devices.id", ondelete="CASCADE"), index=True)
    event_type: Mapped[str] = mapped_column(String(40))
    severity: Mapped[str] = mapped_column(String(10), default="info")
    ip: Mapped[str | None] = mapped_column(String(45))
    protocol: Mapped[str | None] = mapped_column(String(8))
    port: Mapped[int | None] = mapped_column(Integer)
    old_value: Mapped[str | None] = mapped_column(Text)
    new_value: Mapped[str | None] = mapped_column(Text)
    message: Mapped[str] = mapped_column(Text)
    notify: Mapped[bool] = mapped_column(Boolean, default=True)
    notified_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    device: Mapped[Device | None] = relationship(lazy="joined")


class Snapshot(Base):
    """Compact daily copy of the normalized network state (zlib-compressed JSON)."""

    __tablename__ = "snapshots"
    __table_args__ = (UniqueConstraint("network_id", "snapshot_date", name="uq_snapshot_day"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    network_id: Mapped[int] = mapped_column(ForeignKey("networks.id", ondelete="CASCADE"), index=True)
    scan_id: Mapped[int | None] = mapped_column(ForeignKey("scans.id", ondelete="SET NULL"))
    snapshot_date: Mapped[date] = mapped_column(Date, index=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    hosts_total: Mapped[int] = mapped_column(Integer, default=0)
    hosts_active: Mapped[int] = mapped_column(Integer, default=0)
    open_ports: Mapped[int] = mapped_column(Integer, default=0)
    data: Mapped[bytes] = mapped_column(LargeBinary)


class AuditLog(Base):
    __tablename__ = "audit_log"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, index=True)
    username: Mapped[str | None] = mapped_column(String(150))
    action: Mapped[str] = mapped_column(String(80))
    target: Mapped[str | None] = mapped_column(String(255))
    details: Mapped[str | None] = mapped_column(Text)
    ip: Mapped[str | None] = mapped_column(String(64))


# --- Web Capture (inventory enrichment; independent of nmap scans) -------------
WEB_CAPTURE_QUEUED = "queued"
WEB_CAPTURE_RUNNING = "running"
WEB_CAPTURE_COMPLETED = "completed"
WEB_CAPTURE_PARTIAL = "partial"
WEB_CAPTURE_FAILED = "failed"
WEB_CAPTURE_CANCELLED = "cancelled"
WEB_CAPTURE_ACTIVE_STATES = (WEB_CAPTURE_QUEUED, WEB_CAPTURE_RUNNING)

WEB_PAGE_HOME = "home"
WEB_PAGE_LOGIN = "login"
WEB_PAGE_REGISTER = "register"
WEB_PAGE_OTHER = "other"
WEB_PAGE_STREAM = "stream"
WEB_PAGE_KINDS = (WEB_PAGE_HOME, WEB_PAGE_LOGIN, WEB_PAGE_REGISTER, WEB_PAGE_OTHER, WEB_PAGE_STREAM)

SCREENSHOT_CAPTURED = "captured"
SCREENSHOT_SKIPPED = "skipped"
SCREENSHOT_FAILED = "failed"
SCREENSHOT_NOT_REQUESTED = "not_requested"
SCREENSHOT_STATUSES = (
    SCREENSHOT_CAPTURED,
    SCREENSHOT_SKIPPED,
    SCREENSHOT_FAILED,
    SCREENSHOT_NOT_REQUESTED,
)


class WebCapture(Base):
    """Web interface capture job (manual targets, or auto-queued after a scan)."""

    __tablename__ = "web_captures"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    uuid: Mapped[str] = mapped_column(String(36), unique=True, index=True, default=new_uuid)
    status: Mapped[str] = mapped_column(String(20), default=WEB_CAPTURE_QUEUED, index=True)
    targets: Mapped[str] = mapped_column(Text)
    target_count: Mapped[int] = mapped_column(Integer, default=0)
    requested_by: Mapped[str | None] = mapped_column(String(150))
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, index=True)
    started_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    finished_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    stage: Mapped[str | None] = mapped_column(String(40))
    progress: Mapped[float] = mapped_column(Float, default=0.0)
    endpoints_found: Mapped[int] = mapped_column(Integer, default=0)
    pages_captured: Mapped[int] = mapped_column(Integer, default=0)
    screenshots_captured: Mapped[int] = mapped_column(Integer, default=0)
    error: Mapped[str | None] = mapped_column(Text)
    notes: Mapped[str | None] = mapped_column(Text)
    mock_mode: Mapped[bool] = mapped_column(Boolean, default=False)

    pages: Mapped[list[WebPage]] = relationship(
        back_populates="capture", cascade="all, delete-orphan", order_by="WebPage.id"
    )


class WebPage(Base):
    """One classified web page observed during a Web Capture job."""

    __tablename__ = "web_pages"
    __table_args__ = (
        Index("ix_web_pages_device_captured", "device_id", "captured_at"),
        Index("ix_web_pages_capture", "capture_id"),
    )
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    uuid: Mapped[str] = mapped_column(String(36), unique=True, index=True, default=new_uuid)
    capture_id: Mapped[int] = mapped_column(ForeignKey("web_captures.id", ondelete="CASCADE"), index=True)
    device_id: Mapped[int | None] = mapped_column(ForeignKey("devices.id", ondelete="SET NULL"), index=True)
    device_port_id: Mapped[int | None] = mapped_column(ForeignKey("device_ports.id", ondelete="SET NULL"))
    ip: Mapped[str] = mapped_column(String(45))
    port: Mapped[int] = mapped_column(Integer)
    scheme: Mapped[str] = mapped_column(String(8))  # http | https | rtsp | rtsps
    host_used: Mapped[str] = mapped_column(String(255))
    kind: Mapped[str] = mapped_column(String(20), default=WEB_PAGE_OTHER)
    url: Mapped[str] = mapped_column(Text)
    final_url: Mapped[str | None] = mapped_column(Text)
    redirect_target: Mapped[str | None] = mapped_column(Text)
    external_redirect: Mapped[bool] = mapped_column(Boolean, default=False)
    http_status: Mapped[int | None] = mapped_column(Integer)
    title: Mapped[str | None] = mapped_column(String(500))
    content_type: Mapped[str | None] = mapped_column(String(255))
    server_header: Mapped[str | None] = mapped_column(String(255))
    tls_verified: Mapped[bool | None] = mapped_column(Boolean)
    screenshot_status: Mapped[str] = mapped_column(String(20), default=SCREENSHOT_NOT_REQUESTED)
    screenshot_relpath: Mapped[str | None] = mapped_column(String(500))
    capture_error: Mapped[str | None] = mapped_column(String(500))
    captured_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)

    capture: Mapped[WebCapture] = relationship(back_populates="pages")
    device: Mapped[Device | None] = relationship()
