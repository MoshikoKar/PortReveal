"""Database schema (one logical schema for SQLite and PostgreSQL)."""
from __future__ import annotations

import uuid as uuidlib
from datetime import date, datetime

from sqlalchemy import (
    JSON,
    Boolean,
    CheckConstraint,
    Date,
    Float,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    String,
    Text,
    UniqueConstraint,
    false,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .db import Base, UTCDateTime, utcnow

# --- enumerations (stored as plain strings) ---------------------------------
ROLE_ADMIN = "admin"
ROLE_VIEWER = "viewer"
ROLES = (ROLE_ADMIN, ROLE_VIEWER)
USER_SOURCES = ("local", "ldap")

DEVICE_ACTIVE = "active"            # seen in the latest scan that covered it
DEVICE_UNKNOWN = "unknown"          # missed by a scan, not yet confirmed gone
DEVICE_NOT_DETECTED = "not_detected"  # missed by N consecutive complete scans
DEVICE_STATUSES = (DEVICE_ACTIVE, DEVICE_UNKNOWN, DEVICE_NOT_DETECTED)

SCAN_QUEUED = "queued"
SCAN_RUNNING = "running"
SCAN_COMPLETED = "completed"
SCAN_PARTIAL = "partial"
SCAN_FAILED = "failed"
SCAN_CANCELLED = "cancelled"
SCAN_ACTIVE_STATES = (SCAN_QUEUED, SCAN_RUNNING)
SCAN_STATUSES = (SCAN_QUEUED, SCAN_RUNNING, SCAN_COMPLETED, SCAN_PARTIAL, SCAN_FAILED, SCAN_CANCELLED)
# Stored as scan / web-capture `error` after an unexpected crash; the exception itself goes to the log only.
INTERNAL_ERROR = "internal error (see the application log)"

SCAN_DISCOVERY = "discovery"
SCAN_STANDARD = "standard"
SCAN_FULL = "full"
SCAN_TYPES = (SCAN_DISCOVERY, SCAN_STANDARD, SCAN_FULL)

TRIGGER_MANUAL = "manual"
TRIGGER_SCHEDULED = "scheduled"  # night inventory schedule
TRIGGER_PRESENCE = "presence"    # daytime discovery-only presence schedule
SCAN_TRIGGERS = (TRIGGER_MANUAL, TRIGGER_SCHEDULED, TRIGGER_PRESENCE)

EV_DEVICE_DISCOVERED = "device_discovered"
EV_DEVICE_DISAPPEARED = "device_disappeared"
EV_DEVICE_REAPPEARED = "device_reappeared"
EV_IP_CHANGED = "ip_changed"
EV_PORT_OPENED = "port_opened"
EV_PORT_CLOSED = "port_closed"
EV_SERVICE_DETECTED = "service_detected"
EV_SERVICE_CHANGED = "service_changed"
EV_VERSION_CHANGED = "version_changed"
# Inventory intelligence
EV_TAG_ADDED = "tag_added"
EV_TAG_REMOVED = "tag_removed"
EV_WATCH_MATCH = "watch_match"
EV_POLICY_VIOLATION = "policy_violation"
EV_BANNER_CHANGED = "banner_changed"
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
    EV_TAG_ADDED,
    EV_TAG_REMOVED,
    EV_WATCH_MATCH,
    EV_POLICY_VIOLATION,
    EV_BANNER_CHANGED,
)
# Saved-search alerts are explicit subscriptions: the digest includes them regardless of event_types.
ALWAYS_NOTIFY_TYPES = (EV_WATCH_MATCH, EV_POLICY_VIOLATION)
EVENT_SEVERITY = {
    EV_DEVICE_DISCOVERED: "high",
    EV_PORT_OPENED: "high",
    EV_WATCH_MATCH: "high",
    EV_POLICY_VIOLATION: "high",
    EV_SERVICE_CHANGED: "medium",
    EV_DEVICE_DISAPPEARED: "medium",
    EV_PORT_CLOSED: "medium",
    EV_IP_CHANGED: "low",
    EV_VERSION_CHANGED: "low",
    EV_DEVICE_REAPPEARED: "low",
    EV_SERVICE_DETECTED: "info",
    EV_TAG_ADDED: "info",
    EV_TAG_REMOVED: "info",
    EV_BANNER_CHANGED: "info",
}

SEVERITIES = ("high", "medium", "low", "info")

NETWORK_ZONES = ("servers", "users", "iot", "dmz", "management", "guest", "lab")
CRITICALITY_LEVELS = ("low", "medium", "high", "critical")
TAG_SOURCE_RULE = "rule"
TAG_SOURCE_MANUAL = "manual"
TAG_SOURCE_SUPPRESSED = "suppressed"
TAG_SOURCES = (TAG_SOURCE_RULE, TAG_SOURCE_MANUAL, TAG_SOURCE_SUPPRESSED)
SEARCH_KIND_WATCH = "watch"
SEARCH_KIND_POLICY = "policy"

CPE_SOURCE_NMAP = "nmap"
CPE_SOURCE_FAVICON = "favicon"
CPE_SOURCE_SNMP = "snmp"
CPE_SOURCE_SSDP = "ssdp"
CPE_SOURCE_HTTP = "http"
CPE_SOURCES = (CPE_SOURCE_NMAP, CPE_SOURCE_FAVICON, CPE_SOURCE_SNMP, CPE_SOURCE_SSDP, CPE_SOURCE_HTTP)

# Closed value sets the database enforces with CHECK constraints (NULL stays allowed where the
# column is nullable); data import validates against the same sets. Adding a value here needs a
# migration that rewrites the matching constraint.
CLOSED_VALUES: dict[tuple[str, str], tuple[str, ...]] = {
    ("users", "role"): ROLES,
    ("users", "source"): USER_SOURCES,
    ("networks", "zone"): NETWORK_ZONES,
    ("devices", "status"): DEVICE_STATUSES,
    ("device_tags", "source"): TAG_SOURCES,
    ("device_profiles", "criticality"): CRITICALITY_LEVELS,
    ("scans", "scan_type"): SCAN_TYPES,
    ("scans", "trigger"): SCAN_TRIGGERS,
    ("scans", "status"): SCAN_STATUSES,
    ("events", "event_type"): EVENT_TYPES,
    ("events", "severity"): SEVERITIES,
}


def one_of(table: str, column: str) -> CheckConstraint:
    """CHECK constraint `ck_<table>_<column>` limiting the column to its CLOSED_VALUES set."""
    values = ", ".join(f"'{v}'" for v in CLOSED_VALUES[(table, column)])
    return CheckConstraint(f'"{column}" IN ({values})', name=f"ck_{table}_{column}")


def new_uuid() -> str:
    return str(uuidlib.uuid4())


class User(Base):
    __tablename__ = "users"
    __table_args__ = (one_of("users", "role"), one_of("users", "source"))
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
    __table_args__ = (one_of("networks", "zone"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(120), unique=True)
    cidr: Mapped[str] = mapped_column(String(64))
    description: Mapped[str | None] = mapped_column(Text)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    zone: Mapped[str | None] = mapped_column(String(20))  # NETWORK_ZONES; weights the exposure score
    # Reached over a site-to-site VPN: scans use a serial, rate-capped profile so the tunnel stays up.
    vpn_s2s: Mapped[bool] = mapped_column(Boolean, default=False, server_default=false())
    baseline_scan_id: Mapped[int | None] = mapped_column(ForeignKey("scans.id", ondelete="SET NULL"))
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
    __table_args__ = (one_of("devices", "status"),)
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
    last_port_scan_id: Mapped[int | None] = mapped_column(ForeignKey("scans.id", ondelete="SET NULL"))
    last_port_scan_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    full_scanned_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    port_scan_failed: Mapped[bool] = mapped_column(Boolean, default=False)
    # Correlated absence: local days on which the night scan and every presence scan missed it.
    absence_days: Mapped[int] = mapped_column(Integer, default=0)
    absence_counted_on: Mapped[date | None] = mapped_column(Date)
    absence_alerted: Mapped[bool] = mapped_column(Boolean, default=False)
    # Inventory intelligence (recomputed after every scan / web capture that touches the device)
    device_type: Mapped[str | None] = mapped_column(String(40), index=True)
    exposure_score: Mapped[int] = mapped_column(Integer, default=0, server_default="0", index=True)
    classified_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    ssh_hostkey_sha256: Mapped[str | None] = mapped_column(String(64))

    ports: Mapped[list[DevicePort]] = relationship(
        back_populates="device", cascade="all, delete-orphan", order_by="DevicePort.port"
    )
    ips: Mapped[list[DeviceIP]] = relationship(
        back_populates="device", cascade="all, delete-orphan", order_by="DeviceIP.last_seen.desc()"
    )
    tags: Mapped[list[DeviceTag]] = relationship(
        back_populates="device", cascade="all, delete-orphan", order_by="DeviceTag.tag"
    )
    profile: Mapped[DeviceProfile | None] = relationship(
        back_populates="device", cascade="all, delete-orphan", uselist=False
    )
    network: Mapped[Network | None] = relationship()


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
    cpe: Mapped[str | None] = mapped_column(String(500))  # space-separated nmap CPE strings
    tunnel: Mapped[str | None] = mapped_column(String(10))  # nmap service tunnel ("ssl")
    first_seen: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    opened_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    closed_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    device: Mapped[Device] = relationship(back_populates="ports")
    http: Mapped[PortHttp | None] = relationship(cascade="all, delete-orphan", uselist=False,
                                                 back_populates="port_row")
    tls: Mapped[PortTls | None] = relationship(cascade="all, delete-orphan", uselist=False,
                                               back_populates="port_row")
    snmp: Mapped[PortSnmp | None] = relationship(cascade="all, delete-orphan", uselist=False,
                                                 back_populates="port_row")
    banners: Mapped[list[ServiceBanner]] = relationship(
        cascade="all, delete-orphan", order_by="ServiceBanner.seen_at.desc()",
    )
    cpes: Mapped[list[PortCpe]] = relationship(cascade="all, delete-orphan")


class PortHttp(Base):
    """HTTP metadata of one port's landing page, kept from the latest web capture (searchable)."""

    __tablename__ = "port_http"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    device_port_id: Mapped[int] = mapped_column(ForeignKey("device_ports.id", ondelete="CASCADE"), unique=True)
    device_id: Mapped[int] = mapped_column(ForeignKey("devices.id", ondelete="CASCADE"), index=True)
    scheme: Mapped[str | None] = mapped_column(String(8))
    status: Mapped[int | None] = mapped_column(Integer)
    title: Mapped[str | None] = mapped_column(String(500))
    server: Mapped[str | None] = mapped_column(String(255))
    content_type: Mapped[str | None] = mapped_column(String(255))
    location: Mapped[str | None] = mapped_column(Text)  # redirect target
    login: Mapped[bool] = mapped_column(Boolean, default=False)
    default_page: Mapped[bool] = mapped_column(Boolean, default=False)
    favicon_hash: Mapped[int | None] = mapped_column(Integer, index=True)  # mmh3, Shodan-compatible
    html_hash: Mapped[str | None] = mapped_column(String(64))
    header_set_hash: Mapped[str | None] = mapped_column(String(64))
    web_vnc: Mapped[bool] = mapped_column(Boolean, default=False)  # noVNC / Guacamole / websockify UI
    first_seen: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    port_row: Mapped[DevicePort] = relationship(back_populates="http")


class ServiceBanner(Base):
    """Truncated banner / probe text for one open port. New row only when the hash changes."""

    __tablename__ = "service_banners"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    device_port_id: Mapped[int] = mapped_column(ForeignKey("device_ports.id", ondelete="CASCADE"), index=True)
    hash: Mapped[str] = mapped_column(String(64), index=True)
    raw_truncated: Mapped[str] = mapped_column(Text)
    seen_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)


class PortTls(Base):
    """TLS certificate observed on an open port (HTTPS, LDAPS, RDP, etc.)."""

    __tablename__ = "port_tls"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    device_port_id: Mapped[int] = mapped_column(ForeignKey("device_ports.id", ondelete="CASCADE"), unique=True)
    device_id: Mapped[int] = mapped_column(ForeignKey("devices.id", ondelete="CASCADE"), index=True)
    cn: Mapped[str | None] = mapped_column(String(255), index=True)
    san: Mapped[str | None] = mapped_column(Text)
    issuer: Mapped[str | None] = mapped_column(String(500))
    not_before: Mapped[datetime | None] = mapped_column(UTCDateTime)
    not_after: Mapped[datetime | None] = mapped_column(UTCDateTime)
    fingerprint_sha256: Mapped[str | None] = mapped_column(String(64), index=True)
    self_signed: Mapped[bool] = mapped_column(Boolean, default=False)
    expired: Mapped[bool] = mapped_column(Boolean, default=False)
    expires_soon: Mapped[bool] = mapped_column(Boolean, default=False)  # < 30 days
    wildcard: Mapped[bool] = mapped_column(Boolean, default=False)
    weak: Mapped[bool] = mapped_column(Boolean, default=False)  # SHA-1 / weak key
    first_seen: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    port_row: Mapped[DevicePort] = relationship(back_populates="tls")


class PortCpe(Base):
    """One CPE string for a port, with provenance (nmap or rule-produced)."""

    __tablename__ = "port_cpes"
    __table_args__ = (UniqueConstraint("device_port_id", "cpe", "source", name="uq_port_cpe_source"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    device_port_id: Mapped[int] = mapped_column(ForeignKey("device_ports.id", ondelete="CASCADE"), index=True)
    cpe: Mapped[str] = mapped_column(String(255), index=True)
    source: Mapped[str] = mapped_column(String(20), default=CPE_SOURCE_NMAP)
    first_seen: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)


class PortSnmp(Base):
    """Read-only SNMPv2c sys* fields from an open UDP/161 (or TCP) SNMP service."""

    __tablename__ = "port_snmp"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    device_port_id: Mapped[int] = mapped_column(ForeignKey("device_ports.id", ondelete="CASCADE"), unique=True)
    device_id: Mapped[int] = mapped_column(ForeignKey("devices.id", ondelete="CASCADE"), index=True)
    sys_descr: Mapped[str | None] = mapped_column(Text)
    sys_name: Mapped[str | None] = mapped_column(String(255))
    sys_object_id: Mapped[str | None] = mapped_column(String(255))
    sys_location: Mapped[str | None] = mapped_column(String(255))
    sys_contact: Mapped[str | None] = mapped_column(String(255))
    vendor: Mapped[str | None] = mapped_column(String(120))
    model: Mapped[str | None] = mapped_column(String(120))
    first_seen: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    port_row: Mapped[DevicePort] = relationship(back_populates="snmp")


class WebhookEndpoint(Base):
    """Outbound event webhook (SIEM / automation)."""

    __tablename__ = "webhook_endpoints"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(120))
    url: Mapped[str] = mapped_column(Text)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    secret_enc: Mapped[str | None] = mapped_column(String(500))
    event_types: Mapped[list | None] = mapped_column(JSON)  # None / empty = all
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    last_success_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    last_error: Mapped[str | None] = mapped_column(Text)


class DeviceTag(Base):
    __tablename__ = "device_tags"
    __table_args__ = (UniqueConstraint("device_id", "tag", name="uq_device_tag"), one_of("device_tags", "source"))
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    device_id: Mapped[int] = mapped_column(ForeignKey("devices.id", ondelete="CASCADE"), index=True)
    tag: Mapped[str] = mapped_column(String(60), index=True)
    source: Mapped[str] = mapped_column(String(10), default=TAG_SOURCE_RULE)  # rule | manual | suppressed
    reason: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    device: Mapped[Device] = relationship(back_populates="tags")


class DeviceProfile(Base):
    """Operator context for a device (1:1) plus the explanation of its exposure score."""

    __tablename__ = "device_profiles"
    __table_args__ = (one_of("device_profiles", "criticality"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    device_id: Mapped[int] = mapped_column(ForeignKey("devices.id", ondelete="CASCADE"), unique=True)
    owner: Mapped[str | None] = mapped_column(String(150))
    location: Mapped[str | None] = mapped_column(String(200))
    criticality: Mapped[str | None] = mapped_column(String(10))  # CRITICALITY_LEVELS
    notes: Mapped[str | None] = mapped_column(Text)
    exposure_factors: Mapped[list | None] = mapped_column(JSON)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, onupdate=utcnow)
    device: Mapped[Device] = relationship(back_populates="profile")


class SavedSearch(Base):
    """A named query. Watches alert on new matches; policies treat every match as a violation."""

    __tablename__ = "saved_searches"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(120))
    query: Mapped[str] = mapped_column(Text)
    description: Mapped[str | None] = mapped_column(Text)
    kind: Mapped[str] = mapped_column(String(10), default=SEARCH_KIND_WATCH)
    alert: Mapped[bool] = mapped_column(Boolean, default=True)
    created_by: Mapped[str | None] = mapped_column(String(150))
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, onupdate=utcnow)
    last_run_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    last_count: Mapped[int] = mapped_column(Integer, default=0)
    last_error: Mapped[str | None] = mapped_column(Text)
    # False until the first evaluation, which records the current matches silently (its baseline)
    initialized: Mapped[bool] = mapped_column(Boolean, default=False)


class SavedSearchHit(Base):
    __tablename__ = "saved_search_hits"
    __table_args__ = (UniqueConstraint("search_id", "device_id", name="uq_search_hit"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    search_id: Mapped[int] = mapped_column(ForeignKey("saved_searches.id", ondelete="CASCADE"), index=True)
    device_id: Mapped[int] = mapped_column(ForeignKey("devices.id", ondelete="CASCADE"), index=True)
    first_matched_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)


class ApiToken(Base):
    """Read-only bearer token for scripts (only its SHA-256 hash is stored)."""

    __tablename__ = "api_tokens"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(100))
    prefix: Mapped[str] = mapped_column(String(12))
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    last_used_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    expires_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)
    user: Mapped[User] = relationship(lazy="joined")


class Scan(Base):
    __tablename__ = "scans"
    __table_args__ = (one_of("scans", "scan_type"), one_of("scans", "trigger"), one_of("scans", "status"))
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
    __table_args__ = (
        Index("ix_events_type_created", "event_type", "created_at"),
        # Digest hot path: notify IS TRUE AND notified_at IS NULL.
        Index("ix_events_pending", "notify", "notified_at"),
        one_of("events", "event_type"),
        one_of("events", "severity"),
    )
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
    # all = HTTP/RTSP/RDP/VNC; remote = RDP/VNC only; web = HTTP(S)/RTSP only
    scope: Mapped[str] = mapped_column(String(16), default="all")
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
    phash: Mapped[str | None] = mapped_column(String(32))  # perceptual hash of screenshot
    ocr_text: Mapped[str | None] = mapped_column(Text)  # optional OCR of screenshot
    captured_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)

    capture: Mapped[WebCapture] = relationship(back_populates="pages")
    device: Mapped[Device | None] = relationship()
