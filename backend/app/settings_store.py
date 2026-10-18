"""Runtime settings editable from the web UI, stored as JSON rows in app_settings.

Every section is a pydantic model with defaults, so missing rows/fields are fine.
"""
from __future__ import annotations

import re
import time
from typing import Literal, TypeVar

from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import event
from sqlalchemy.orm import Session

from .models import (
    EV_DEVICE_DISAPPEARED,
    EV_DEVICE_DISCOVERED,
    EV_DEVICE_REAPPEARED,
    EV_IP_CHANGED,
    EV_PORT_CLOSED,
    EV_PORT_OPENED,
    EV_SERVICE_CHANGED,
    EVENT_TYPES,
    AppSetting,
)


class ScheduleSettings(BaseModel):
    enabled: bool = True
    time: str = "02:00"  # local time HH:MM
    days: list[int] = Field(default_factory=lambda: [0, 1, 2, 3, 4, 5, 6])  # 0=Monday
    # Queue a fast discovery-only scan per network immediately before the daily standard scan
    # so new hosts are registered before the longer service scan runs.
    discovery_before_standard: bool = True

    @field_validator("time")
    @classmethod
    def _time(cls, v: str) -> str:
        m = re.fullmatch(r"(\d{1,2}):(\d{2})", v.strip())
        if not m or int(m.group(1)) > 23 or int(m.group(2)) > 59:
            raise ValueError("time must be HH:MM (24h)")
        return f"{int(m.group(1)):02d}:{m.group(2)}"

    @field_validator("days")
    @classmethod
    def _days(cls, v: list[int]) -> list[int]:
        if any(d < 0 or d > 6 for d in v):
            raise ValueError("days must be 0 (Monday) .. 6 (Sunday)")
        return sorted(set(v))


def _hhmm(v: str, field: str) -> str:
    m = re.fullmatch(r"(\d{1,2}):(\d{2})", v.strip())
    if not m or int(m.group(1)) > 23 or int(m.group(2)) > 59:
        raise ValueError(f"{field} must be HH:MM (24h)")
    return f"{int(m.group(1)):02d}:{m.group(2)}"


class PresenceSettings(BaseModel):
    """Daytime discovery-only presence scans, correlated with the night scan.

    A device only accumulates an absence day when both that day's night standard scan and all of
    that day's presence scans missed it; any sighting resets the streak. Disappear/reappear emails
    are sent only once the streak reaches `absence_days`.
    """

    enabled: bool = True
    times: list[str] = Field(default_factory=lambda: ["10:00", "15:00"])  # local time HH:MM
    days: list[int] = Field(default_factory=lambda: [6, 0, 1, 2, 3, 4])  # 0=Monday; Sunday-Friday
    absence_days: int = Field(5, ge=1, le=30)

    @field_validator("times")
    @classmethod
    def _times(cls, v: list[str]) -> list[str]:
        out = sorted({_hhmm(t, "presence time") for t in v})
        if not 1 <= len(out) <= 4:
            raise ValueError("between 1 and 4 distinct presence times are required")
        return out

    @field_validator("days")
    @classmethod
    def _days(cls, v: list[int]) -> list[int]:
        if any(d < 0 or d > 6 for d in v):
            raise ValueError("days must be 0 (Monday) .. 6 (Sunday)")
        return sorted(set(v))


class ScanSettings(BaseModel):
    """Scan profile tuning. Deliberately small: no raw nmap arguments."""

    # Unknown keys (an "nmap_args" smuggled into PUT /api/settings/scan) are a 422, never stored.
    # Rows stored by older versions still load: _load_section drops fields the model no longer has.
    model_config = ConfigDict(extra="forbid")

    top_ports: int = Field(3000, ge=100, le=10000)
    timing: Literal["polite", "normal", "fast"] = "normal"
    parallelism: int = Field(4, ge=1, le=16)
    discovery_chunk_size: int = Field(1024, ge=16, le=16384)
    port_batch_size: int = Field(32, ge=1, le=256)
    host_timeout_minutes: int = Field(15, ge=1, le=240)
    full_host_timeout_minutes: int = Field(120, ge=5, le=720)
    os_detection: bool = True
    # Re-run -O only when the last OS guess is older than this many days (or ports changed).
    os_refresh_days: int = Field(7, ge=1, le=90)
    # Below this accuracy the UI labels the OS guess as uncertain (spec 3.5).
    os_min_accuracy_display: int = Field(85, ge=0, le=100)
    # Set by migration 0018 when OS detection is flipped on for an existing install; Settings
    # shows a one-time admin notice until dismissed (cleared by saving scan settings).
    os_detection_enabled_notice: bool = False
    disappear_after_missed: int = Field(2, ge=1, le=30)
    mass_change_guard_percent: int = Field(50, ge=10, le=100)
    keep_raw_xml: bool = False
    raw_retention_days: int = Field(7, ge=1, le=90)


class NotificationSettings(BaseModel):
    enabled: bool = False
    smtp_host: str = ""
    smtp_port: int = Field(25, ge=1, le=65535)
    security: Literal["none", "starttls", "ssl"] = "none"
    username: str = ""
    password_enc: str = ""
    sender: str = "network-monitor@localhost"
    recipients: list[str] = Field(default_factory=list)
    event_types: list[str] = Field(
        default_factory=lambda: [
            EV_DEVICE_DISCOVERED,
            EV_DEVICE_DISAPPEARED,
            EV_DEVICE_REAPPEARED,
            EV_IP_CHANGED,
            EV_PORT_OPENED,
            EV_PORT_CLOSED,
            EV_SERVICE_CHANGED,
        ]
    )
    digest_time: str = "08:00"  # local time HH:MM — one categorized HTML summary per day

    @field_validator("digest_time")
    @classmethod
    def _digest_time(cls, v: str) -> str:
        m = re.fullmatch(r"(\d{1,2}):(\d{2})", v.strip())
        if not m or int(m.group(1)) > 23 or int(m.group(2)) > 59:
            raise ValueError("digest_time must be HH:MM (24h)")
        return f"{int(m.group(1)):02d}:{m.group(2)}"

    @field_validator("event_types")
    @classmethod
    def _types(cls, v: list[str]) -> list[str]:
        bad = [t for t in v if t not in EVENT_TYPES]
        if bad:
            raise ValueError(f"unknown event types: {bad}")
        return v

    @field_validator("recipients")
    @classmethod
    def _recipients(cls, v: list[str]) -> list[str]:
        out = []
        for r in v:
            r = r.strip()
            if not r:
                continue
            if not re.fullmatch(r"[^@\s]+@[^@\s]+", r):
                raise ValueError(f"invalid email address: {r}")
            out.append(r)
        return out


class LdapSettings(BaseModel):
    enabled: bool = False
    server_uri: str = ""  # ldap://dc01.corp.local or ldaps://dc01.corp.local:636
    start_tls: bool = False
    verify_tls: bool = True
    bind_dn: str = ""
    bind_password_enc: str = ""
    user_base_dn: str = ""
    user_filter: str = "(sAMAccountName={username})"
    admin_group_dn: str = ""
    viewer_group_dn: str = ""  # empty = any authenticated directory user is a viewer
    timeout_seconds: int = Field(10, ge=1, le=60)

    @field_validator("server_uri")
    @classmethod
    def _uri(cls, v: str) -> str:
        v = v.strip()
        if v and not re.match(r"^ldaps?://[A-Za-z0-9.\-\[\]:]+/?$", v):
            raise ValueError("server URI must look like ldap://host[:port] or ldaps://host[:port]")
        return v

    @field_validator("user_filter")
    @classmethod
    def _filter(cls, v: str) -> str:
        if "{username}" not in v:
            raise ValueError("user filter must contain {username}")
        return v


class RetentionSettings(BaseModel):
    days: int = Field(365, ge=7, le=3650)
    # RTT samples (device_rtt_samples) churn far faster than everything else here (one row per
    # scan per device), so they get their own, shorter window instead of riding on `days`.
    rtt_sample_days: int = Field(90, ge=7, le=365)
    # Hard cap per device (newest kept); graph API also limits to this many points.
    rtt_samples_per_device: int = Field(200, ge=50, le=2000)


class WebCaptureSettings(BaseModel):
    """On-demand web interface capture (inventory enrichment)."""

    enabled: bool = True
    # After a completed/partial standard or full scan, queue a capture for web/RTSP services found.
    auto_after_scan: bool = True
    # When true: only new/changed web hosts (and never-captured endpoints). When false: every
    # scanned host that has a known web/RTSP endpoint.
    auto_only_new_or_changed: bool = True
    max_addresses: int = Field(256, ge=1, le=4096)
    max_endpoints: int = Field(128, ge=1, le=1024)
    max_pages_per_endpoint: int = Field(3, ge=1, le=10)
    max_screenshots_per_job: int = Field(64, ge=0, le=512)
    max_candidate_probes: int = Field(10, ge=1, le=30)
    # When "/" serves only an error or a web server's default page, try this many extra app paths.
    max_discovery_paths: int = Field(12, ge=0, le=200)
    # Optional path to a newline-delimited wordlist (absolute, or relative to the data dir).
    # Empty means use the built-in list.
    discovery_wordlist: str = Field("", max_length=1000)
    max_response_bytes: int = Field(512_000, ge=8_000, le=5_000_000)
    max_job_minutes: int = Field(30, ge=1, le=240)
    http_timeout_seconds: float = Field(8.0, ge=1.0, le=60.0)
    browser_timeout_seconds: float = Field(15.0, ge=3.0, le=120.0)
    # After a page loads, how long to wait for late JS / meta-refresh redirects and slow rendering
    # before the screenshot; a page still blank after this is skipped.
    page_settle_seconds: float = Field(8.0, ge=0.0, le=60.0)
    # HTTP(S) endpoints probed in parallel (look-ahead while the job thread saves pages/screenshots).
    http_concurrency: int = Field(3, ge=1, le=8)
    # Not used yet: screenshots stay sequential on the job thread. Each one drives its own
    # sync Playwright/Chromium instance, and the per-job screenshot budget and landing-URL reuse
    # cache depend on processing pages in order. Kept so saved settings/exports stay valid.
    screenshot_concurrency: int = Field(1, ge=1, le=2)
    force_mock: bool = False  # tests / DEV without network


class VulnSettings(BaseModel):
    """Vulnerability risk scoring (spec section 5). Off until an admin enables it: the first enable
    (or any start with an empty local cache) triggers an automatic background full sync."""

    model_config = ConfigDict(extra="forbid")

    enabled: bool = False
    sources: list[str] = Field(default_factory=lambda: ["nvd", "kev", "epss"])
    sync_interval_hours: int = Field(168, ge=24, le=720)  # default: weekly
    sync_time: str = "04:00"  # local time HH:MM, best-effort slot for the weekly sync
    offline_mode: bool = False  # only offline snapshot imports; no outbound feed requests at all
    nvd_api_key_enc: str = ""  # optional: raises the NVD API rate limit, never required
    include_potential: bool = True  # show `potential` (imprecise-version) matches, not just `confirmed`
    min_cvss_display: float = Field(0.0, ge=0.0, le=10.0)
    epss_high_threshold: float = Field(0.10, ge=0.0, le=1.0)  # EPSS above which a finding is "high exploitation probability"
    # Phase 4: safe/discovery NSE scripts from the fixed SCRIPT_ALLOWLIST, on when vulnerabilities are.
    scripts_enabled: bool = True

    @field_validator("sources")
    @classmethod
    def _sources(cls, v: list[str]) -> list[str]:
        allowed = {"nvd", "kev", "epss"}
        bad = [s for s in v if s not in allowed]
        if bad:
            raise ValueError(f"unknown vulnerability source(s): {bad}")
        out = sorted(set(v))
        if not out:
            raise ValueError("at least one vulnerability source is required")
        return out

    @field_validator("sync_time")
    @classmethod
    def _sync_time(cls, v: str) -> str:
        return _hhmm(v, "sync_time")


class DiscoverySettings(BaseModel):
    """Local-only mDNS/SSDP/NetBIOS device-naming channel (spec section 9.2).

    Spec: default on only when cheap — passive listening without an active network probe.
    mDNS (passive multicast listen) is on by default; SSDP M-SEARCH and NetBIOS unicast queries
    are opt-in. Never runs an nmap UDP scan (-sU stays banned everywhere else).
    """

    model_config = ConfigDict(extra="forbid")

    enabled: bool = True
    mdns: bool = True
    ssdp: bool = False
    netbios: bool = False
    timeout_seconds: float = Field(2.0, ge=0.5, le=15.0)


SECTIONS: dict[str, type[BaseModel]] = {
    "schedule": ScheduleSettings,
    "presence": PresenceSettings,
    "scan": ScanSettings,
    "notifications": NotificationSettings,
    "ldap": LdapSettings,
    "retention": RetentionSettings,
    "web_capture": WebCaptureSettings,
    "vuln": VulnSettings,
    "discovery": DiscoverySettings,
}

T = TypeVar("T", bound=BaseModel)

# Short process-local cache for get_section: sections are read on most requests and every scan but
# change rarely. Writes through set_value invalidate immediately and again on commit; the TTL bounds
# staleness for writes made by another process sharing the database.
_CACHE_TTL_SECONDS = 5.0
_cache: dict[tuple[str, str], tuple[float, BaseModel]] = {}
_WRITTEN = "nf_settings_written"  # Session.info key: section keys this session wrote (uncommitted)


def _drop_cached(key: str) -> None:
    for ck in list(_cache):  # snapshot: scan/scheduler threads may fill the cache concurrently
        if ck[1] == key:
            _cache.pop(ck, None)


@event.listens_for(Session, "after_commit")
def _invalidate_committed(session: Session) -> None:
    for key in session.info.pop(_WRITTEN, ()):
        _drop_cached(key)


def _load_section(db: Session, key: str, model: type[T]) -> T:
    row = db.get(AppSetting, key)
    data = row.value if row and isinstance(row.value, dict) else {}
    try:
        return model.model_validate(data)
    except Exception:
        # Stored data from an older version; keep valid fields, default the rest
        clean = {k: v for k, v in data.items() if k in model.model_fields}
        try:
            return model.model_validate(clean)
        except Exception:
            return model()


def get_section(db: Session, model: type[T]) -> T:
    key = next(k for k, m in SECTIONS.items() if m is model)
    if key in db.info.get(_WRITTEN, ()):
        return _load_section(db, key, model)  # this session's own uncommitted write; never cache it
    ck = (str(db.get_bind().url), key)
    now = time.monotonic()
    hit = _cache.get(ck)
    if hit is None or hit[0] <= now:
        hit = (now + _CACHE_TTL_SECONDS, _load_section(db, key, model))
        _cache[ck] = hit
    return hit[1].model_copy(deep=True)  # callers may edit the result before put_section


def put_section(db: Session, value: BaseModel) -> None:
    key = next(k for k, m in SECTIONS.items() if isinstance(value, m))
    set_value(db, key, value.model_dump())


def get_value(db: Session, key: str, default=None):
    row = db.get(AppSetting, key)
    return row.value.get("v", default) if row and isinstance(row.value, dict) else default


def set_value(db: Session, key: str, value) -> None:
    payload = value if isinstance(value, dict) and key in SECTIONS else {"v": value}
    row = db.get(AppSetting, key)
    if row is None:
        db.add(AppSetting(key=key, value=payload))
    else:
        row.value = payload
    if key in SECTIONS:
        db.info.setdefault(_WRITTEN, set()).add(key)
        _drop_cached(key)
