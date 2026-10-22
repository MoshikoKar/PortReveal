"""Centralized runtime settings (admin only). Secrets are write-only."""
from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..auth.deps import client_ip, require_admin
from ..auth.ldap_auth import ldap_authenticate, ldap_test
from ..core.audit import audit
from ..core.notify import format_sample_digest, send_email, smtp_failure_reason
from ..core.retention import run_retention
from ..core.scheduler import last_scheduled_date, next_presence_run, next_run, presence_slots_done_today
from ..db import get_db
from ..models import EVENT_TYPES, GeoFeedState, User, Vulnerability, VulnFeedState
from ..security import encrypt_secret
from ..settings_store import (
    CdnAsnEntry,
    DiscoverySettings,
    GeoSettings,
    LdapSettings,
    NotificationSettings,
    PresenceSettings,
    RetentionSettings,
    ScanSettings,
    ScheduleSettings,
    VulnSettings,
    WebCaptureSettings,
    get_section,
    put_section,
)
from .errors import ApiError

router = APIRouter(prefix="/api/settings", tags=["settings"])
log = logging.getLogger(__name__)


def _ip(request: Request) -> str | None:
    return client_ip(request)


# --- schedule -----------------------------------------------------------------
def schedule_out(cfg: ScheduleSettings) -> dict:
    nxt = next_run(cfg, last_run_date=last_scheduled_date())
    return {**cfg.model_dump(), "next_run": nxt.isoformat() if nxt else None}


@router.get("/schedule")
def get_schedule(db: Session = Depends(get_db), user: User = Depends(require_admin)):
    return schedule_out(get_section(db, ScheduleSettings))


@router.put("/schedule")
def put_schedule(body: ScheduleSettings, request: Request, db: Session = Depends(get_db),
                 user: User = Depends(require_admin)):
    put_section(db, body)
    audit(db, user.username, "settings.schedule", None, body.model_dump(), _ip(request))
    db.commit()
    return schedule_out(body)


# --- presence (daytime discovery + correlated absence) ----------------------------
def presence_out(cfg: PresenceSettings) -> dict:
    nxt = next_presence_run(cfg, done_today=presence_slots_done_today())
    return {**cfg.model_dump(), "next_run": nxt.isoformat() if nxt else None}


@router.get("/presence")
def get_presence(db: Session = Depends(get_db), user: User = Depends(require_admin)):
    return presence_out(get_section(db, PresenceSettings))


@router.put("/presence")
def put_presence(body: PresenceSettings, request: Request, db: Session = Depends(get_db),
                 user: User = Depends(require_admin)):
    put_section(db, body)
    audit(db, user.username, "settings.presence", None, body.model_dump(), _ip(request))
    db.commit()
    return presence_out(body)


# --- scan profile ---------------------------------------------------------------
@router.get("/scan")
def get_scan_settings(db: Session = Depends(get_db), user: User = Depends(require_admin)):
    return get_section(db, ScanSettings).model_dump()


@router.put("/scan")
def put_scan_settings(body: ScanSettings, request: Request, db: Session = Depends(get_db),
                      user: User = Depends(require_admin)):
    put_section(db, body)
    audit(db, user.username, "settings.scan_profile", None, body.model_dump(), _ip(request))
    db.commit()
    return body.model_dump()


# --- web capture ------------------------------------------------------------------
@router.get("/web-capture")
def get_web_capture_settings(db: Session = Depends(get_db), user: User = Depends(require_admin)):
    return get_section(db, WebCaptureSettings).model_dump()


@router.put("/web-capture")
def put_web_capture_settings(body: WebCaptureSettings, request: Request, db: Session = Depends(get_db),
                             user: User = Depends(require_admin)):
    put_section(db, body)
    audit(db, user.username, "settings.web_capture", None, body.model_dump(), _ip(request))
    db.commit()
    return body.model_dump()


# --- vulnerability feed (risk scoring) ---------------------------------------------
def vuln_out(cfg: VulnSettings) -> dict:
    data = cfg.model_dump(exclude={"nvd_api_key_enc"})
    data["nvd_api_key_set"] = bool(cfg.nvd_api_key_enc)
    return data


@router.get("/vuln")
def get_vuln_settings(db: Session = Depends(get_db), user: User = Depends(require_admin)):
    return vuln_out(get_section(db, VulnSettings))


class VulnIn(BaseModel):
    enabled: bool = False
    sources: list[str] = Field(default_factory=lambda: ["nvd", "kev", "epss"])
    sync_interval_hours: int = Field(168, ge=24, le=720)
    sync_time: str = Field("04:00", max_length=5)
    offline_mode: bool = False
    nvd_api_key: str | None = Field(None, max_length=200, description="omit to keep the stored key")
    include_potential: bool = True
    min_cvss_display: float = Field(0.0, ge=0.0, le=10.0)
    epss_high_threshold: float = Field(0.10, ge=0.0, le=1.0)
    scripts_enabled: bool = True


@router.put("/vuln")
def put_vuln_settings(body: VulnIn, request: Request, db: Session = Depends(get_db),
                      user: User = Depends(require_admin)):
    current = get_section(db, VulnSettings)
    data = body.model_dump(exclude={"nvd_api_key"})
    data["nvd_api_key_enc"] = encrypt_secret(body.nvd_api_key) if body.nvd_api_key is not None else current.nvd_api_key_enc
    try:
        cfg = VulnSettings.model_validate(data)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    put_section(db, cfg)
    audit(db, user.username, "settings.vuln", None,
          {k: v for k, v in data.items() if k != "nvd_api_key_enc"} | {"api_key_changed": body.nvd_api_key is not None},
          _ip(request))
    db.commit()
    if cfg.enabled and not cfg.offline_mode:
        from ..core.vuln.sync import sync_due, sync_running, trigger_background_sync
        if sync_due(db, cfg) and not sync_running():
            trigger_background_sync(cfg)
    return vuln_out(cfg)


@router.get("/vuln/status")
def vuln_feed_status(db: Session = Depends(get_db), user: User = Depends(require_admin)):
    """Local CVE cache state: per-feed bookkeeping, cache size and whether a sync is running.

    ``cve_count`` prefers ``vuln_feed_state.record_count`` for NVD so the endpoint stays cheap
    while a large import/sync holds a write lock on ``vulnerabilities`` (COUNT(*) would stall).
    """
    from ..core.vuln.sync import NVD_MIRROR_START_YEAR, sync_in_progress

    feed_rows = db.scalars(select(VulnFeedState).order_by(VulnFeedState.source)).all()
    feeds = [
        {"source": f.source, "last_synced_at": f.last_synced_at, "record_count": f.record_count or 0,
         "last_error": f.last_error,
         "mirror_complete": f.mirror_complete if f.source == "nvd" else None,
         "mirror_next_year": (f.mirror_next_year or NVD_MIRROR_START_YEAR)
         if f.source == "nvd" and not f.mirror_complete else None}
        for f in feed_rows
    ]
    # Heartbeat-aware: a browser refresh must not flip the badge to "idle" while ingest is active.
    running = sync_in_progress(db)
    nvd = next((f for f in feed_rows if f.source == "nvd"), None)
    if running:
        # During import/sync avoid COUNT(*) (SQLite write-lock stalls). Prefer the unique
        # tally persisted on the NVD feed row at sync/import time.
        cve_count = (nvd.record_count if nvd is not None else 0) or 0
    else:
        # Idle: unique CVE rows (corrects older installs that stored an ingest tally).
        cve_count = db.scalar(select(func.count(Vulnerability.cve_id))) or 0
        if nvd is not None and (nvd.record_count or 0) != cve_count:
            nvd.record_count = cve_count
            db.commit()
    return {
        "sync_running": running,
        "cve_count": cve_count,
        "mirror_start_year": NVD_MIRROR_START_YEAR,
        "feeds": feeds,
    }


@router.post("/vuln/sync")
def sync_vuln_now(request: Request, db: Session = Depends(get_db), user: User = Depends(require_admin)):
    from ..core.vuln.sync import sync_running, trigger_background_sync

    cfg = get_section(db, VulnSettings)
    if not cfg.enabled:
        raise HTTPException(409, "Vulnerability scoring is disabled in settings")
    if cfg.offline_mode:
        raise HTTPException(409, "Offline mode is on; use the CLI import for a local snapshot instead")
    if sync_running():
        return {"ok": True, "message": "A sync is already running"}
    started = trigger_background_sync(cfg)
    audit(db, user.username, "settings.vuln_sync", None, {"started": started}, _ip(request))
    db.commit()
    return {"ok": True, "message": "Sync started in the background" if started else "A sync is already running"}


# --- local discovery channel (mDNS/SSDP/NetBIOS device names, spec section 9.2) -----------------
@router.get("/discovery")
def get_discovery_settings(db: Session = Depends(get_db), user: User = Depends(require_admin)):
    return get_section(db, DiscoverySettings).model_dump()


@router.put("/discovery")
def put_discovery_settings(body: DiscoverySettings, request: Request, db: Session = Depends(get_db),
                           user: User = Depends(require_admin)):
    put_section(db, body)
    audit(db, user.username, "settings.discovery", None, body.model_dump(), _ip(request))
    db.commit()
    return body.model_dump()


# --- geo (expected-country mismatch vs public IPs) --------------------------------
def _geo_out(cfg: GeoSettings, db: Session) -> dict:
    from ..core.geo_sync import (
        DBIP_ATTRIBUTION,
        DBIP_LICENSE,
        asn_db_path,
        country_db_path,
        files_ready,
        maxmind_country_path,
        sync_running,
    )
    feeds = [
        {"source": f.source, "last_synced_at": f.last_synced_at, "file_month": f.file_month,
         "last_error": f.last_error}
        for f in db.scalars(select(GeoFeedState).order_by(GeoFeedState.source)).all()
    ]
    mm = maxmind_country_path(cfg)
    return {
        **cfg.model_dump(),
        "attribution": DBIP_ATTRIBUTION,
        "license": DBIP_LICENSE,
        "country_db_loaded": country_db_path().is_file() or bool(mm),
        "asn_db_loaded": asn_db_path().is_file(),
        "maxmind_loaded": bool(mm),
        "files_ready": files_ready(cfg),
        "sync_running": sync_running(),
        "feeds": feeds,
    }


@router.get("/geo")
def get_geo_settings(db: Session = Depends(get_db), user: User = Depends(require_admin)):
    return _geo_out(get_section(db, GeoSettings), db)


class GeoIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    cache_ttl_hours: int = Field(24, ge=1, le=168)
    offline_mode: bool = False
    maxmind_country_path: str = Field("", max_length=1000)
    cdn_asns: list[CdnAsnEntry] = Field(default_factory=list)


@router.put("/geo")
def put_geo_settings(body: GeoIn, request: Request, db: Session = Depends(get_db),
                     user: User = Depends(require_admin)):
    try:
        cfg = GeoSettings.model_validate(body.model_dump())
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    put_section(db, cfg)
    audit(db, user.username, "settings.geo", None, cfg.model_dump(), _ip(request))
    db.commit()
    return _geo_out(cfg, db)


@router.post("/geo/sync")
def sync_geo_now(request: Request, db: Session = Depends(get_db), user: User = Depends(require_admin)):
    from ..core.geo_sync import sync_running, trigger_background_sync

    cfg = get_section(db, GeoSettings)
    if cfg.offline_mode:
        raise HTTPException(409, "Offline mode is on; place MMDB files in the data geo directory instead")
    if sync_running():
        return {"ok": True, "message": "A sync is already running"}
    started = trigger_background_sync(cfg)
    audit(db, user.username, "settings.geo_sync", None, {"started": started}, _ip(request))
    db.commit()
    return {"ok": True, "message": "Sync started in the background" if started else "A sync is already running"}


# --- notifications --------------------------------------------------------------
class NotificationIn(BaseModel):
    enabled: bool = False
    smtp_host: str = Field("", max_length=255)
    smtp_port: int = Field(25, ge=1, le=65535)
    security: str = Field("none", pattern="^(none|starttls|ssl)$")
    username: str = Field("", max_length=255)
    password: str | None = Field(None, max_length=1024, description="omit to keep the stored password")
    sender: str = Field("network-monitor@localhost", max_length=255)
    recipients: list[str] = Field(default_factory=list, max_length=100)
    event_types: list[str] = Field(default_factory=list)
    digest_time: str = Field("08:00", max_length=5)
    watchlist_email_enabled: bool = True
    watchlist_webhooks_enabled: bool = True


def notifications_out(cfg: NotificationSettings) -> dict:
    data = cfg.model_dump(exclude={"password_enc"})
    data["password_set"] = bool(cfg.password_enc)
    data["available_event_types"] = list(EVENT_TYPES)
    return data


@router.get("/notifications")
def get_notifications(db: Session = Depends(get_db), user: User = Depends(require_admin)):
    return notifications_out(get_section(db, NotificationSettings))


@router.put("/notifications")
def put_notifications(body: NotificationIn, request: Request, db: Session = Depends(get_db),
                      user: User = Depends(require_admin)):
    current = get_section(db, NotificationSettings)
    data = body.model_dump(exclude={"password"})
    data["password_enc"] = encrypt_secret(body.password) if body.password is not None else current.password_enc
    try:
        cfg = NotificationSettings.model_validate(data)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    if cfg.enabled and (not cfg.smtp_host or not cfg.recipients):
        raise HTTPException(422, "SMTP host and at least one recipient are required to enable notifications")
    put_section(db, cfg)
    audit(db, user.username, "settings.smtp", cfg.smtp_host,
          {k: v for k, v in data.items() if k != "password_enc"} | {"password_changed": body.password is not None},
          _ip(request))
    db.commit()
    return notifications_out(cfg)


class TestEmailIn(BaseModel):
    recipient: str | None = Field(None, max_length=255)


@router.post("/notifications/test")
def test_notifications(body: TestEmailIn, request: Request, db: Session = Depends(get_db),
                       user: User = Depends(require_admin)):
    cfg = get_section(db, NotificationSettings)
    if body.recipient:
        cfg = cfg.model_copy(update={"recipients": [body.recipient.strip()]})
    db.commit()  # end the read transaction: no DB connection is held during SMTP I/O (up to the 20 s timeout)
    try:
        subject, plain, html_body = format_sample_digest()
        send_email(cfg, subject, plain + f"\nSent by: {user.username}\n", html_body)
    except Exception as exc:
        reason = smtp_failure_reason(exc)
        log.warning("SMTP test via %s:%s failed (%s): %s", cfg.smtp_host, cfg.smtp_port, type(exc).__name__, exc)
        audit(db, user.username, "settings.smtp_test", cfg.smtp_host,
              {"ok": False, "error": reason, "error_type": type(exc).__name__}, _ip(request))
        db.commit()
        raise ApiError(502, f"Sending failed: {reason}.", "smtp_send_failed") from exc
    audit(db, user.username, "settings.smtp_test", cfg.smtp_host, {"ok": True}, _ip(request))
    db.commit()
    return {"ok": True, "message": f"Test email sent to {', '.join(cfg.recipients)}"}


# --- LDAP -------------------------------------------------------------------------
class LdapIn(BaseModel):
    enabled: bool = False
    server_uri: str = Field("", max_length=255)
    start_tls: bool = False
    verify_tls: bool = True
    bind_dn: str = Field("", max_length=500)
    bind_password: str | None = Field(None, max_length=1024)
    user_base_dn: str = Field("", max_length=500)
    user_filter: str = Field("(sAMAccountName={username})", max_length=500)
    admin_group_dn: str = Field("", max_length=500)
    viewer_group_dn: str = Field("", max_length=500)
    timeout_seconds: int = Field(10, ge=1, le=60)


def ldap_out(cfg: LdapSettings) -> dict:
    data = cfg.model_dump(exclude={"bind_password_enc"})
    data["bind_password_set"] = bool(cfg.bind_password_enc)
    return data


@router.get("/ldap")
def get_ldap(db: Session = Depends(get_db), user: User = Depends(require_admin)):
    return ldap_out(get_section(db, LdapSettings))


def _ldap_from(body: LdapIn, current: LdapSettings) -> LdapSettings:
    data = body.model_dump(exclude={"bind_password"})
    data["bind_password_enc"] = (
        encrypt_secret(body.bind_password) if body.bind_password is not None else current.bind_password_enc
    )
    try:
        return LdapSettings.model_validate(data)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc


@router.put("/ldap")
def put_ldap(body: LdapIn, request: Request, db: Session = Depends(get_db), user: User = Depends(require_admin)):
    cfg = _ldap_from(body, get_section(db, LdapSettings))
    if cfg.enabled and (not cfg.server_uri or not cfg.user_base_dn):
        raise HTTPException(422, "Server URI and user base DN are required to enable LDAP")
    put_section(db, cfg)
    audit(db, user.username, "settings.ldap", cfg.server_uri,
          ldap_out(cfg) | {"password_changed": body.bind_password is not None}, _ip(request))
    db.commit()
    return ldap_out(cfg)


class LdapTestIn(LdapIn):
    test_username: str | None = Field(None, max_length=150)
    test_password: str | None = Field(None, max_length=1024)


@router.post("/ldap/test")
def test_ldap(body: LdapTestIn, request: Request, db: Session = Depends(get_db), user: User = Depends(require_admin)):
    cfg = _ldap_from(body, get_section(db, LdapSettings))
    ok, msg = ldap_test(cfg)
    result = {"ok": ok, "message": msg}
    if ok and body.test_username and body.test_password:
        res = ldap_authenticate(cfg.model_copy(update={"enabled": True}), body.test_username, body.test_password)
        result = {"ok": res.ok, "message": f"{msg} User test: " + (
            f"authenticated as {res.display_name}, role {res.role}." if res.ok else f"failed ({res.error}).")}
    audit(db, user.username, "settings.ldap_test", cfg.server_uri, {"ok": result["ok"]}, _ip(request))
    db.commit()
    return result


# --- retention -----------------------------------------------------------------------
@router.get("/retention")
def get_retention(db: Session = Depends(get_db), user: User = Depends(require_admin)):
    return get_section(db, RetentionSettings).model_dump()


@router.put("/retention")
def put_retention(body: RetentionSettings, request: Request, db: Session = Depends(get_db),
                  user: User = Depends(require_admin)):
    put_section(db, body)
    audit(db, user.username, "settings.retention", None, body.model_dump(), _ip(request))
    db.commit()
    return body.model_dump()


@router.post("/retention/run")
def run_retention_now(request: Request, db: Session = Depends(get_db), user: User = Depends(require_admin)):
    ret = get_section(db, RetentionSettings)
    counts = run_retention(db, ret.days, get_section(db, ScanSettings).raw_retention_days, rtt_days=ret.rtt_sample_days)
    audit(db, user.username, "retention.run", None, counts, _ip(request))
    db.commit()
    return {"ok": True, "deleted": counts}
