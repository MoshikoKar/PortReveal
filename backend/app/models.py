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

DEVICE_ACTIVE = "active"  # seen in the latest scan that covered it
DEVICE_UNKNOWN = "unknown"  # missed by a scan, not yet confirmed gone
DEVICE_NOT_DETECTED = "not_detected"  # missed by N consecutive complete scans
DEVICE_STATUSES = (DEVICE_ACTIVE, DEVICE_UNKNOWN, DEVICE_NOT_DETECTED)

IP_ASSIGNMENT_STATIC = "static"
IP_ASSIGNMENT_DYNAMIC = "dynamic"
IP_ASSIGNMENT_UNKNOWN = "unknown"
IP_ASSIGNMENTS = (IP_ASSIGNMENT_STATIC, IP_ASSIGNMENT_DYNAMIC, IP_ASSIGNMENT_UNKNOWN)

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
TRIGGER_PRESENCE = "presence"  # daytime discovery-only presence schedule
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
EV_OS_CHANGED = "os_changed"
EV_MONITOR_CHANGE = "monitor_change"
EV_GEO_MISMATCH = "geo_mismatch"
EV_CVE_WATCH_MATCH = "cve_watch_match"
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
    EV_OS_CHANGED,
    EV_MONITOR_CHANGE,
    EV_GEO_MISMATCH,
    EV_CVE_WATCH_MATCH,
)
# Saved-search alerts are explicit subscriptions: the digest includes them regardless of event_types.
ALWAYS_NOTIFY_TYPES = (EV_WATCH_MATCH, EV_POLICY_VIOLATION, EV_MONITOR_CHANGE, EV_CVE_WATCH_MATCH)
EVENT_SEVERITY = {
    EV_DEVICE_DISCOVERED: "high",
    EV_PORT_OPENED: "high",
    EV_WATCH_MATCH: "high",
    EV_POLICY_VIOLATION: "high",
    EV_MONITOR_CHANGE: "high",
    EV_GEO_MISMATCH: "high",
    EV_CVE_WATCH_MATCH: "high",
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
    EV_OS_CHANGED: "low",
}

SEVERITIES = ("high", "medium", "low", "info")
# Severity rank for recipient-group min_severity filters (higher = more severe).
SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3}

DELIVERY_IMMEDIATE = "immediate"
DELIVERY_HOURLY = "hourly"
DELIVERY_DAILY = "daily"
DELIVERY_MODES = (DELIVERY_IMMEDIATE, DELIVERY_HOURLY, DELIVERY_DAILY)

DEST_EMAIL = "email"
DEST_WEBHOOK = "webhook"
DEST_SLACK = "slack"
DEST_TEAMS = "teams"
DEST_KINDS = (DEST_EMAIL, DEST_WEBHOOK, DEST_SLACK, DEST_TEAMS)

NETWORK_ZONES = ("servers", "users", "iot", "dmz", "management", "guest", "lab")
CRITICALITY_LEVELS = ("low", "medium", "high", "critical")
TAG_SOURCE_RULE = "rule"
TAG_SOURCE_MANUAL = "manual"
TAG_SOURCE_SUPPRESSED = "suppressed"
TAG_SOURCES = (TAG_SOURCE_RULE, TAG_SOURCE_MANUAL, TAG_SOURCE_SUPPRESSED)
SEARCH_KIND_WATCH = "watch"
SEARCH_KIND_POLICY = "policy"
SEARCH_KIND_MONITOR = "monitor"

CPE_SOURCE_NMAP = "nmap"
CPE_SOURCE_FAVICON = "favicon"
CPE_SOURCE_SNMP = "snmp"
CPE_SOURCE_SSDP = "ssdp"
CPE_SOURCE_HTTP = "http"
CPE_SOURCES = (CPE_SOURCE_NMAP, CPE_SOURCE_FAVICON, CPE_SOURCE_SNMP, CPE_SOURCE_SSDP, CPE_SOURCE_HTTP)

# Vulnerability matching (spec section 5): confidence is driven only by version precision, never by
# backport heuristics. `dismissed` is a manual, learned no - it never reappears for that CVE/port.
VULN_STATE_CONFIRMED = "confirmed"
VULN_STATE_POTENTIAL = "potential"
VULN_STATE_DISMISSED = "dismissed"
VULN_STATES = (VULN_STATE_CONFIRMED, VULN_STATE_POTENTIAL, VULN_STATE_DISMISSED)

VULN_SOURCE_CACHE = "cache"  # local NVD/KEV/EPSS cache match (core/vuln/match.py)
VULN_SOURCE_NMAP_SCRIPT = "nmap_script"  # phase 4: SCRIPT_ALLOWLIST finding (e.g. smb-vuln-ms17-010)
VULN_SOURCES = (VULN_SOURCE_CACHE, VULN_SOURCE_NMAP_SCRIPT)

# Background vulnerability-check jobs (spec section 8): mirrors SCAN_* / WEB_CAPTURE_* below.
VULN_JOB_QUEUED = "queued"
VULN_JOB_RUNNING = "running"
VULN_JOB_COMPLETED = "completed"
VULN_JOB_PARTIAL = "partial"
VULN_JOB_FAILED = "failed"
VULN_JOB_CANCELLED = "cancelled"
VULN_JOB_ACTIVE_STATES = (VULN_JOB_QUEUED, VULN_JOB_RUNNING)
VULN_JOB_STATUSES = (
    VULN_JOB_QUEUED,
    VULN_JOB_RUNNING,
    VULN_JOB_COMPLETED,
    VULN_JOB_PARTIAL,
    VULN_JOB_FAILED,
    VULN_JOB_CANCELLED,
)
VULN_JOB_TRIGGER_AFTER_SCAN = "after_scan"
VULN_JOB_TRIGGER_MANUAL = "manual"
VULN_JOB_TRIGGERS = (VULN_JOB_TRIGGER_AFTER_SCAN, VULN_JOB_TRIGGER_MANUAL)

# Why a finding stopped matching (vuln dashboard "resolved" count, spec decision #3): the version
# changed or the port closed (re-match no longer produces this CVE) vs. the device itself leaving
# the inventory. Dismissed is tracked separately on the same row and is never "resolved".
VULN_RESOLUTION_NO_LONGER_MATCHED = "no_longer_matched"
VULN_RESOLUTION_DEVICE_REMOVED = "device_removed"
VULN_RESOLUTIONS = (VULN_RESOLUTION_NO_LONGER_MATCHED, VULN_RESOLUTION_DEVICE_REMOVED)

# Weighted device-type classification (spec section 9): a real, open-ended set driven by
# core/tagging.py's RULES, so not a CHECK-constrained CLOSED_VALUES column. "unknown" is a
# sentinel distinct from None/NULL: None means no rule matched at all; "unknown" means some
# evidence pointed at a type but the combined score stayed below TYPE_CONFIDENCE_THRESHOLD.
DEVICE_TYPE_UNKNOWN = "unknown"

# Geo check against a network's expected countries (core/geo.py). NULL on the device means the
# network has no expected countries (check skipped). not_checked = configured but no public IP.
GEO_OK = "ok"
GEO_MISMATCH = "mismatch"
GEO_MISMATCH_CDN = "mismatch_cdn"
GEO_NOT_CHECKED = "not_checked"
GEO_UNAVAILABLE = "unavailable"
GEO_STATUSES = (GEO_OK, GEO_MISMATCH, GEO_MISMATCH_CDN, GEO_NOT_CHECKED, GEO_UNAVAILABLE)
GEO_SOURCE_PUBLISHED_NAME = "published_name"
GEO_SOURCE_DEVICE_IP = "device_ip"
GEO_SOURCES = (GEO_SOURCE_PUBLISHED_NAME, GEO_SOURCE_DEVICE_IP)

# Closed value sets the database enforces with CHECK constraints (NULL stays allowed where the
# column is nullable); data import validates against the same sets. Adding a value here needs a
# migration that rewrites the matching constraint.
CLOSED_VALUES: dict[tuple[str, str], tuple[str, ...]] = {
    ("users", "role"): ROLES,
    ("users", "source"): USER_SOURCES,
    ("networks", "zone"): NETWORK_ZONES,
    ("devices", "status"): DEVICE_STATUSES,
    ("devices", "ip_assignment"): IP_ASSIGNMENTS,
    ("devices", "geo_status"): GEO_STATUSES,
    ("devices", "geo_source"): GEO_SOURCES,
    ("device_tags", "source"): TAG_SOURCES,
    ("device_profiles", "criticality"): CRITICALITY_LEVELS,
    ("scans", "scan_type"): SCAN_TYPES,
    ("scans", "trigger"): SCAN_TRIGGERS,
    ("scans", "status"): SCAN_STATUSES,
    ("events", "event_type"): EVENT_TYPES,
    ("events", "severity"): SEVERITIES,
    ("recipient_groups", "delivery_mode"): DELIVERY_MODES,
    ("recipient_groups", "min_severity"): SEVERITIES,
    ("recipient_destinations", "kind"): DEST_KINDS,
    ("device_port_vulns", "state"): VULN_STATES,
    ("device_port_vulns", "source"): VULN_SOURCES,
    ("vuln_jobs", "status"): VULN_JOB_STATUSES,
    ("vuln_jobs", "trigger"): VULN_JOB_TRIGGERS,
    ("vuln_finding_lifecycle", "resolution"): VULN_RESOLUTIONS,
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
    # Per-user UI prefs (e.g. dashboard layout). null = built-in defaults.
    preferences: Mapped[dict | None] = mapped_column(JSON)
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
    # Remote gateway whose ARP table (read over SNMP) supplies MACs the scanner cannot see across a
    # routed / VPN path. {"host", "port", "version", "user", "auth_protocol", "priv_protocol",
    # "community_enc", "auth_key_enc", "priv_key_enc"} (secrets Fernet-encrypted) or None.
    arp_snmp: Mapped[dict | None] = mapped_column(JSON)
    # ISO 3166-1 alpha-2 codes this network is expected to live in. Empty/null turns geo checks off.
    expected_countries: Mapped[list | None] = mapped_column(JSON)
    baseline_scan_id: Mapped[int | None] = mapped_column(ForeignKey("scans.id", ondelete="SET NULL"))
    baseline_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    # Set when removed from Settings: the row and its findings stay, hidden from default views.
    archived_at: Mapped[datetime | None] = mapped_column(UTCDateTime, index=True)
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
    __table_args__ = (
        one_of("devices", "status"),
        one_of("devices", "ip_assignment"),
        one_of("devices", "geo_status"),
        one_of("devices", "geo_source"),
    )
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    uuid: Mapped[str] = mapped_column(String(36), unique=True, index=True, default=new_uuid)
    network_id: Mapped[int | None] = mapped_column(ForeignKey("networks.id", ondelete="SET NULL"), index=True)
    current_ip: Mapped[str] = mapped_column(String(45), index=True)
    mac: Mapped[str | None] = mapped_column(String(17), index=True)
    mac_source: Mapped[str | None] = mapped_column(String(20))  # arp | snmp | netbios (None: pre-0026 rows)
    vendor: Mapped[str | None] = mapped_column(String(200))
    hostname: Mapped[str | None] = mapped_column(String(255), index=True)
    dns_name: Mapped[str | None] = mapped_column(String(255))
    os_name: Mapped[str | None] = mapped_column(String(255), index=True)
    os_accuracy: Mapped[int | None] = mapped_column(Integer)
    os_detected_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    os_source: Mapped[str | None] = mapped_column(String(20))  # nmap_os | service | ssh | http | snmp | ntlm
    # Flap guard (compare.py): an OS name that differs from os_name but hasn't yet been seen twice
    # or crossed the +10 accuracy bar. {"name": str, "accuracy": int | None} or None.
    os_pending: Mapped[dict | None] = mapped_column(JSON)
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
    # Weighted multi-signal confidence for device_type, 0-100 (spec section 9). device_type is
    # "unknown" (not a guess) when the winning type's score falls below TYPE_CONFIDENCE_THRESHOLD.
    type_confidence: Mapped[int | None] = mapped_column(Integer)
    exposure_score: Mapped[int] = mapped_column(Integer, default=0, server_default="0", index=True)
    classified_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    # Vulnerability-based risk (spec section 5): separate from exposure_score above.
    risk_score: Mapped[int] = mapped_column(Integer, default=0, server_default="0", index=True)
    combined_score: Mapped[int] = mapped_column(Integer, default=0, server_default="0", index=True)
    risk_scored_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    ssh_hostkey_sha256: Mapped[str | None] = mapped_column(String(64))
    # Static vs dynamic IP (spec 7): derived from device_ips history in core/ip_assignment.py.
    ip_assignment: Mapped[str | None] = mapped_column(String(10))
    # Local-only discovery name (spec section 9.2): mDNS/SSDP/NetBIOS, never nmap/-sU. A weighted
    # type-classification signal, and a fallback display name when no DNS/nmap hostname is known.
    discovery_name: Mapped[str | None] = mapped_column(String(255))
    discovery_source: Mapped[str | None] = mapped_column(String(10))  # mdns | ssdp | netbios
    # Last time a local discovery pass heard this name; used to age out quietly instead of wiping
    # per pass when mDNS/SSDP windows or the NetBIOS query budget miss a host.
    discovery_name_seen_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    # Latency / uptime (spec 6)
    last_rtt_ms: Mapped[float | None] = mapped_column(Float)
    # Since when the device has been continuously seen (reset on a not_detected -> seen transition).
    continuous_since: Mapped[datetime | None] = mapped_column(UTCDateTime)
    # Public-IP geography vs Network.expected_countries (core/geo.py). Private scan addresses are
    # never geolocated; status is not_checked when no public candidate IP exists.
    geo_status: Mapped[str | None] = mapped_column(String(20))
    geo_country: Mapped[str | None] = mapped_column(String(2))
    geo_ip: Mapped[str | None] = mapped_column(String(45))
    geo_asn: Mapped[int | None] = mapped_column(Integer)
    geo_as_org: Mapped[str | None] = mapped_column(String(200))
    geo_cdn: Mapped[bool] = mapped_column(Boolean, default=False, server_default=false())
    geo_source: Mapped[str | None] = mapped_column(String(20))
    geo_name: Mapped[str | None] = mapped_column(String(255))
    geo_checked_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    geo_mismatch: Mapped[bool] = mapped_column(Boolean, default=False, server_default=false(), index=True)

    ports: Mapped[list[DevicePort]] = relationship(
        back_populates="device", cascade="all, delete-orphan", order_by="DevicePort.port"
    )
    ips: Mapped[list[DeviceIP]] = relationship(
        back_populates="device", cascade="all, delete-orphan", order_by="DeviceIP.last_seen.desc()"
    )
    tags: Mapped[list[DeviceTag]] = relationship(back_populates="device", cascade="all, delete-orphan", order_by="DeviceTag.tag")
    profile: Mapped[DeviceProfile | None] = relationship(back_populates="device", cascade="all, delete-orphan", uselist=False)
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


class DeviceRttSample(Base):
    """One RTT measurement (nmap `<times srtt=...>`) for a device's RTT-over-time chart."""

    __tablename__ = "device_rtt_samples"
    __table_args__ = (Index("ix_device_rtt_samples_device_sampled", "device_id", "sampled_at"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    device_id: Mapped[int] = mapped_column(ForeignKey("devices.id", ondelete="CASCADE"), index=True)
    rtt_ms: Mapped[float] = mapped_column(Float)
    sampled_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)


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
    method: Mapped[str | None] = mapped_column(String(20))  # nmap: probed | table; verified
    confidence: Mapped[int | None] = mapped_column(Integer)
    cpe: Mapped[str | None] = mapped_column(String(500))  # space-separated nmap CPE strings
    tunnel: Mapped[str | None] = mapped_column(String(10))  # nmap service tunnel ("ssl")
    first_seen: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    opened_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    closed_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    device: Mapped[Device] = relationship(back_populates="ports")
    http: Mapped[PortHttp | None] = relationship(cascade="all, delete-orphan", uselist=False, back_populates="port_row")
    tls: Mapped[PortTls | None] = relationship(cascade="all, delete-orphan", uselist=False, back_populates="port_row")
    snmp: Mapped[PortSnmp | None] = relationship(cascade="all, delete-orphan", uselist=False, back_populates="port_row")
    banners: Mapped[list[ServiceBanner]] = relationship(
        cascade="all, delete-orphan",
        order_by="ServiceBanner.seen_at.desc()",
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
    # Name must match migration 0009 (`ix_port_tls_fingerprint`); auto `index=True` would drift to
    # `ix_port_tls_fingerprint_sha256` and fail `alembic check` on existing installs.
    __table_args__ = (Index("ix_port_tls_fingerprint", "fingerprint_sha256"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    device_port_id: Mapped[int] = mapped_column(ForeignKey("device_ports.id", ondelete="CASCADE"), unique=True)
    device_id: Mapped[int] = mapped_column(ForeignKey("devices.id", ondelete="CASCADE"), index=True)
    cn: Mapped[str | None] = mapped_column(String(255), index=True)
    san: Mapped[str | None] = mapped_column(Text)
    issuer: Mapped[str | None] = mapped_column(String(500))
    not_before: Mapped[datetime | None] = mapped_column(UTCDateTime)
    not_after: Mapped[datetime | None] = mapped_column(UTCDateTime)
    fingerprint_sha256: Mapped[str | None] = mapped_column(String(64))
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


class Vulnerability(Base):
    """One CVE record from the local vulnerability cache (NVD + CISA KEV + FIRST EPSS)."""

    __tablename__ = "vulnerabilities"
    cve_id: Mapped[str] = mapped_column(String(20), primary_key=True)
    cvss_base: Mapped[float | None] = mapped_column(Float)
    cvss_vector: Mapped[str | None] = mapped_column(String(100))
    severity: Mapped[str | None] = mapped_column(String(10))  # NVD baseSeverity, informational only
    published_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    last_modified: Mapped[datetime | None] = mapped_column(UTCDateTime, index=True)
    kev: Mapped[bool] = mapped_column(Boolean, default=False, server_default=false(), index=True)
    kev_added_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    epss: Mapped[float | None] = mapped_column(Float)
    epss_percentile: Mapped[float | None] = mapped_column(Float)
    summary: Mapped[str | None] = mapped_column(Text)


class VulnCpeMatch(Base):
    """One CPE 2.3 (optionally version-ranged) that a CVE applies to."""

    __tablename__ = "vuln_cpe_match"
    __table_args__ = (Index("ix_vuln_cpe_match_vendor_product", "vendor_product"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    cve_id: Mapped[str] = mapped_column(ForeignKey("vulnerabilities.cve_id", ondelete="CASCADE"), index=True)
    cpe23: Mapped[str] = mapped_column(String(255))
    vendor_product: Mapped[str] = mapped_column(String(200))  # "vendor:product", lowercased, for fast lookup
    version_start: Mapped[str | None] = mapped_column(String(100))
    version_start_incl: Mapped[bool | None] = mapped_column(Boolean)
    version_end: Mapped[str | None] = mapped_column(String(100))
    version_end_excl: Mapped[bool | None] = mapped_column(Boolean)


class DevicePortVuln(Base):
    """A CVE matched to one device port, by local CPE cache lookup or an allow-listed nmap script."""

    __tablename__ = "device_port_vulns"
    __table_args__ = (
        UniqueConstraint("device_port_id", "cve_id", name="uq_device_port_vuln"),
        one_of("device_port_vulns", "state"),
        one_of("device_port_vulns", "source"),
        CheckConstraint(
            "state_before_dismiss IS NULL OR state_before_dismiss IN ('confirmed', 'potential')",
            name="ck_device_port_vulns_state_before_dismiss",
        ),
    )
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    device_port_id: Mapped[int] = mapped_column(ForeignKey("device_ports.id", ondelete="CASCADE"), index=True)
    cve_id: Mapped[str] = mapped_column(ForeignKey("vulnerabilities.cve_id", ondelete="CASCADE"), index=True)
    matched_cpe: Mapped[str | None] = mapped_column(String(255), index=True)
    state: Mapped[str] = mapped_column(String(10), default=VULN_STATE_POTENTIAL)
    # Set on dismiss; Undo restores this instead of always falling back to potential.
    state_before_dismiss: Mapped[str | None] = mapped_column(String(10))
    source: Mapped[str] = mapped_column(String(15), default=VULN_SOURCE_CACHE)
    matched_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    vulnerability: Mapped[Vulnerability] = relationship(lazy="joined")


class VulnFeedState(Base):
    """Sync bookkeeping for one vulnerability feed source (nvd / kev / epss)."""

    __tablename__ = "vuln_feed_state"
    source: Mapped[str] = mapped_column(String(10), primary_key=True)
    last_synced_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    last_modified_cursor: Mapped[str | None] = mapped_column(String(40))
    record_count: Mapped[int] = mapped_column(Integer, default=0)
    last_error: Mapped[str | None] = mapped_column(Text)
    # NVD yearly JSON mirror progress (nvd source only). Incomplete mirrors must resume remaining
    # years; do not treat a partial cache as "bootstrap done".
    mirror_complete: Mapped[bool] = mapped_column(Boolean, default=False, server_default="0")
    mirror_next_year: Mapped[int | None] = mapped_column(Integer)


class GeoFeedState(Base):
    """Sync bookkeeping for one geo MMDB source (country / asn)."""

    __tablename__ = "geo_feed_state"
    source: Mapped[str] = mapped_column(String(20), primary_key=True)
    last_synced_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    file_month: Mapped[str | None] = mapped_column(String(7))  # YYYY-MM of the DB-IP build
    last_error: Mapped[str | None] = mapped_column(Text)


class GeoLookupCache(Base):
    """TTL cache for DNS answers and MMDB country/ASN lookups (keyed dns:<name> or ip:<addr>)."""

    __tablename__ = "geo_lookup_cache"
    cache_key: Mapped[str] = mapped_column(String(300), primary_key=True)
    kind: Mapped[str] = mapped_column(String(10))  # dns | ip
    payload: Mapped[dict] = mapped_column(JSON)
    expires_at: Mapped[datetime] = mapped_column(UTCDateTime, index=True)


class VulnJob(Base):
    """Background vulnerability-check job (spec section 8): local CPE match, optional allow-listed
    NSE scripts, then risk/combined rescoring. Mirrors `Scan` / `WebCapture`."""

    __tablename__ = "vuln_jobs"
    __table_args__ = (one_of("vuln_jobs", "status"), one_of("vuln_jobs", "trigger"))
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    uuid: Mapped[str] = mapped_column(String(36), unique=True, index=True, default=new_uuid)
    status: Mapped[str] = mapped_column(String(20), default=VULN_JOB_QUEUED, index=True)
    trigger: Mapped[str] = mapped_column(String(20), default=VULN_JOB_TRIGGER_MANUAL)
    scan_id: Mapped[int | None] = mapped_column(ForeignKey("scans.id", ondelete="SET NULL"), index=True)
    network_id: Mapped[int | None] = mapped_column(ForeignKey("networks.id", ondelete="SET NULL"))
    device_ids: Mapped[list | None] = mapped_column(JSON)
    requested_by: Mapped[str | None] = mapped_column(String(150))
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, index=True)
    started_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    finished_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    stage: Mapped[str | None] = mapped_column(String(40))
    progress: Mapped[float] = mapped_column(Float, default=0.0)
    error: Mapped[str | None] = mapped_column(Text)
    stats: Mapped[dict | None] = mapped_column(JSON)
    notes: Mapped[str | None] = mapped_column(Text)


class VulnDailySnapshot(Base):
    """Daily vuln-aggregate point for the dashboard's trend charts. Deliberately separate from
    `Snapshot` (zlib-blob network-state copies): this is small, structured counters only, kept for
    a year and downsampled to weekly beyond 90 days at read time (spec decision #6)."""

    __tablename__ = "vuln_daily_snapshots"
    __table_args__ = (UniqueConstraint("network_id", "snapshot_date", name="uq_vuln_snapshot_day"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    snapshot_date: Mapped[date] = mapped_column(Date, index=True)
    network_id: Mapped[int | None] = mapped_column(ForeignKey("networks.id", ondelete="CASCADE"), index=True)
    critical: Mapped[int] = mapped_column(Integer, default=0)
    high: Mapped[int] = mapped_column(Integer, default=0)
    medium: Mapped[int] = mapped_column(Integer, default=0)
    low: Mapped[int] = mapped_column(Integer, default=0)
    kev_count: Mapped[int] = mapped_column(Integer, default=0)
    confirmed_count: Mapped[int] = mapped_column(Integer, default=0)
    potential_count: Mapped[int] = mapped_column(Integer, default=0)
    avg_risk_score: Mapped[float | None] = mapped_column(Float)
    avg_combined_score: Mapped[float | None] = mapped_column(Float)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)


class VulnFindingLifecycle(Base):
    """First-seen/resolved tracking for one finding identity (device + port + CVE), spec decision
    #3. `DevicePortVuln.matched_at` is overwritten on every re-match and the row is hard-deleted
    once it stops matching, so neither can answer "when was this first seen" or "is this resolved"
    after the fact -- this table is the durable side-channel for both.

    Identity is stored as plain values (not cascading FKs) so history survives the device or CVE
    being removed from the live tables; `network_id` is the one soft link, nulled rather than
    deleted when its network goes away. The sync logic that maintains these rows is added in a
    later part; this part only defines the shape.
    """

    __tablename__ = "vuln_finding_lifecycle"
    __table_args__ = (
        UniqueConstraint("device_uuid", "port", "protocol", "cve_id", name="uq_vuln_finding_lifecycle"),
        one_of("vuln_finding_lifecycle", "resolution"),
    )
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    device_uuid: Mapped[str] = mapped_column(String(36))
    port: Mapped[int] = mapped_column(Integer)
    protocol: Mapped[str] = mapped_column(String(8))
    cve_id: Mapped[str] = mapped_column(String(20))
    network_id: Mapped[int | None] = mapped_column(ForeignKey("networks.id", ondelete="SET NULL"), index=True)
    first_seen_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, index=True)
    last_seen_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    resolved_at: Mapped[datetime | None] = mapped_column(UTCDateTime, index=True)
    resolution: Mapped[str | None] = mapped_column(String(20))
    dismissed_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)


class CveWatchlistEntry(Base):
    """Admin-subscribed CVE IDs. No FK to `vulnerabilities`: a watched CVE may not be in the local
    cache yet (weekly sync), so the id is stored as plain text after normalize/validate."""

    __tablename__ = "cve_watchlist"
    __table_args__ = (UniqueConstraint("cve_id", name="uq_cve_watchlist_cve_id"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    cve_id: Mapped[str] = mapped_column(String(20), index=True)
    note: Mapped[str | None] = mapped_column(Text)
    created_by: Mapped[str | None] = mapped_column(String(150))
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, server_default="1")


class CveWatchlistAlert(Base):
    """One alerted hit per (watch, device, port, protocol, cve). Cleared when the finding goes away
    so a reopen (resolved then matched again) alerts again."""

    __tablename__ = "cve_watchlist_alerts"
    __table_args__ = (
        UniqueConstraint(
            "watch_id",
            "cve_id",
            "device_uuid",
            "port",
            "protocol",
            name="uq_cve_watchlist_alert_hit",
        ),
    )
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    watch_id: Mapped[int] = mapped_column(ForeignKey("cve_watchlist.id", ondelete="CASCADE"), index=True)
    cve_id: Mapped[str] = mapped_column(String(20), index=True)
    device_uuid: Mapped[str] = mapped_column(String(36))
    port: Mapped[int] = mapped_column(Integer)
    protocol: Mapped[str] = mapped_column(String(8))
    alerted_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    event_id: Mapped[int | None] = mapped_column(ForeignKey("events.id", ondelete="SET NULL"))


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
    """Outbound event webhook (SIEM / automation).

    By default only events with ``notify=True`` (alert mode) are delivered. Set
    ``include_record_events`` to also receive ``notify=False`` (record) events that match
    the hook's event-type filter. Silent network modes never create Event rows.
    """

    __tablename__ = "webhook_endpoints"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(120))
    url: Mapped[str] = mapped_column(Text)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    secret_enc: Mapped[str | None] = mapped_column(String(500))
    event_types: Mapped[list | None] = mapped_column(JSON)  # None / empty = all
    # When False (default), skip events with notify=False — same safety as the email digest.
    include_record_events: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    last_success_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    last_error: Mapped[str | None] = mapped_column(Text)
    last_error_at: Mapped[datetime | None] = mapped_column(UTCDateTime)


# --- Recipient groups (notification channels) ---------------------------------
class RecipientGroup(Base):
    """Audience channel: what / how / when / how much for outbound notifications."""

    __tablename__ = "recipient_groups"
    __table_args__ = (
        one_of("recipient_groups", "delivery_mode"),
        one_of("recipient_groups", "min_severity"),
    )
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(120))
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    # Migrated global email digest; UI may treat it specially but it is editable.
    is_default: Mapped[bool] = mapped_column(Boolean, default=False)
    # WHAT
    event_types: Mapped[list | None] = mapped_column(JSON)  # empty/None = all types
    min_severity: Mapped[str] = mapped_column(String(10), default="info")
    network_ids: Mapped[list | None] = mapped_column(JSON)  # empty/None = all networks
    # WHEN
    delivery_mode: Mapped[str] = mapped_column(String(20), default=DELIVERY_DAILY)
    digest_time: Mapped[str | None] = mapped_column(String(5))  # HH:MM local, daily mode
    # HOW MUCH
    max_per_hour: Mapped[int] = mapped_column(Integer, default=20)
    dedupe_seconds: Mapped[int] = mapped_column(Integer, default=300)
    quiet_start: Mapped[str | None] = mapped_column(String(5))  # HH:MM
    quiet_end: Mapped[str | None] = mapped_column(String(5))
    quiet_bypass_critical: Mapped[bool] = mapped_column(Boolean, default=True)
    # Rate-cap bookkeeping (local hour bucket YYYYMMDDHH)
    rate_hour_bucket: Mapped[str | None] = mapped_column(String(10))
    rate_sent: Mapped[int] = mapped_column(Integer, default=0)
    # Local YYYY-MM-DD of last successful daily digest flush for this group.
    last_digest_on: Mapped[str | None] = mapped_column(String(10))
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, onupdate=utcnow)
    last_success_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    last_error: Mapped[str | None] = mapped_column(Text)
    last_error_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    destinations: Mapped[list[RecipientDestination]] = relationship(
        back_populates="group",
        cascade="all, delete-orphan",
        order_by="RecipientDestination.id",
    )


class RecipientDestination(Base):
    """One delivery target on a recipient group (email, PortReveal webhook, Slack, or Teams)."""

    __tablename__ = "recipient_destinations"
    __table_args__ = (one_of("recipient_destinations", "kind"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    group_id: Mapped[int] = mapped_column(ForeignKey("recipient_groups.id", ondelete="CASCADE"), index=True)
    kind: Mapped[str] = mapped_column(String(20))
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    # email: address; slack/teams: never store plaintext — use url_enc; webhook: leave null
    target: Mapped[str | None] = mapped_column(String(255))
    webhook_id: Mapped[int | None] = mapped_column(
        ForeignKey("webhook_endpoints.id", ondelete="SET NULL"),
        index=True,
    )
    url_enc: Mapped[str | None] = mapped_column(String(500))  # Slack / Teams incoming webhook URL
    group: Mapped[RecipientGroup] = relationship(back_populates="destinations")


class RecipientHold(Base):
    """Event held for a group (hourly/daily digest, rate-cap overflow, quiet hours)."""

    __tablename__ = "recipient_holds"
    __table_args__ = (
        Index("ix_recipient_holds_group_created", "group_id", "created_at"),
        # Named to match 0031 — do not also set index=True on the column (that creates a second name).
        Index("ix_recipient_holds_next_attempt", "next_attempt_at"),
        UniqueConstraint("group_id", "event_id", name="uq_recipient_hold_event"),
    )
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    group_id: Mapped[int] = mapped_column(ForeignKey("recipient_groups.id", ondelete="CASCADE"), index=True)
    event_id: Mapped[int] = mapped_column(ForeignKey("events.id", ondelete="CASCADE"), index=True)
    reason: Mapped[str] = mapped_column(String(40))  # digest | hourly | rate_cap | quiet | dedupe
    dedupe_key: Mapped[str | None] = mapped_column(String(200), index=True)
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    next_attempt_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    # After a partial failure: destination ids still owed a send (None = all enabled dests).
    pending_dest_ids: Mapped[list | None] = mapped_column(JSON)
    # Destinations that already received this event/key (per-dest dedupe across retries).
    delivered_dest_ids: Mapped[list | None] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)


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
    risk_factors: Mapped[list | None] = mapped_column(JSON)
    type_evidence: Mapped[list | None] = mapped_column(JSON)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, onupdate=utcnow)
    device: Mapped[Device] = relationship(back_populates="profile")


class SavedSearch(Base):
    """A named query. Watches/policies alert on new matches; monitors alert on changes to matching hosts."""

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


class Wordlist(Base):
    """Admin-managed wordlist (Web capture discovery). Entries live in a server-named file under
    <data dir>/wordlists; only sanitized, accepted entries are stored there."""

    __tablename__ = "wordlists"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(64), unique=True)
    kind: Mapped[str] = mapped_column(String(20))  # paths | subdomains
    source: Mapped[str] = mapped_column(String(20))  # upload | url
    source_url: Mapped[str | None] = mapped_column(String(2048))
    original_filename: Mapped[str | None] = mapped_column(String(255))
    storage_name: Mapped[str] = mapped_column(String(64), unique=True)
    entries: Mapped[int] = mapped_column(Integer, default=0)
    skipped: Mapped[int] = mapped_column(Integer, default=0)
    size_bytes: Mapped[int] = mapped_column(Integer, default=0)  # bytes received (compressed for .gz)
    sha256: Mapped[str] = mapped_column(String(64))  # of the bytes received
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, onupdate=utcnow)
    created_by: Mapped[str | None] = mapped_column(String(150))


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

    pages: Mapped[list[WebPage]] = relationship(back_populates="capture", cascade="all, delete-orphan", order_by="WebPage.id")


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
    # WWW-Authenticate scheme (Basic, Digest, NTLM, Negotiate, Bearer) when the page or the API
    # calls it makes answer 401: a login-protected application, not an error page.
    auth_scheme: Mapped[str | None] = mapped_column(String(20))
    phash: Mapped[str | None] = mapped_column(String(32))  # perceptual hash of screenshot
    ocr_text: Mapped[str | None] = mapped_column(Text)  # optional OCR of screenshot
    captured_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)

    capture: Mapped[WebCapture] = relationship(back_populates="pages")
    device: Mapped[Device | None] = relationship()
