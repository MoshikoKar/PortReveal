"""Runtime settings editable from the web UI, stored as JSON rows in app_settings.

Every section is a pydantic model with defaults, so missing rows/fields are fine.
"""
from __future__ import annotations

import re
from typing import Literal, TypeVar

from pydantic import BaseModel, Field, field_validator
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


class ScanSettings(BaseModel):
    """Scan profile tuning. Deliberately small: no raw nmap arguments."""

    top_ports: int = Field(3000, ge=100, le=10000)
    timing: Literal["polite", "normal", "fast"] = "normal"
    parallelism: int = Field(4, ge=1, le=16)
    discovery_chunk_size: int = Field(1024, ge=16, le=16384)
    port_batch_size: int = Field(32, ge=1, le=256)
    host_timeout_minutes: int = Field(15, ge=1, le=240)
    full_host_timeout_minutes: int = Field(120, ge=5, le=720)
    os_detection: bool = False
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
    max_individual: int = Field(10, ge=1, le=100)  # above this, one digest email is sent

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


class WebCaptureSettings(BaseModel):
    """On-demand web interface capture (inventory enrichment)."""

    enabled: bool = True
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
    http_concurrency: int = Field(3, ge=1, le=8)
    screenshot_concurrency: int = Field(1, ge=1, le=2)
    force_mock: bool = False  # tests / DEV without network


SECTIONS: dict[str, type[BaseModel]] = {
    "schedule": ScheduleSettings,
    "scan": ScanSettings,
    "notifications": NotificationSettings,
    "ldap": LdapSettings,
    "retention": RetentionSettings,
    "web_capture": WebCaptureSettings,
}

T = TypeVar("T", bound=BaseModel)


def get_section(db: Session, model: type[T]) -> T:
    key = next(k for k, m in SECTIONS.items() if m is model)
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
