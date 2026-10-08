"""Centralized runtime settings (admin only). Secrets are write-only."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from ..auth.deps import client_ip, require_admin
from ..auth.ldap_auth import ldap_authenticate, ldap_test
from ..core.audit import audit
from ..core.notify import SUBJECT_PREFIX, send_email
from ..core.retention import run_retention
from ..core.scheduler import last_scheduled_date, next_run
from ..db import get_db
from ..models import EVENT_TYPES, User
from ..security import encrypt_secret
from ..settings_store import (
    LdapSettings,
    NotificationSettings,
    RetentionSettings,
    ScanSettings,
    ScheduleSettings,
    get_section,
    put_section,
)

router = APIRouter(prefix="/api/settings", tags=["settings"])


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
    max_individual: int = Field(10, ge=1, le=100)


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
    try:
        send_email(cfg, f"{SUBJECT_PREFIX} Test email",
                   f"This is a test email from Network Finder.\nSent by: {user.username}\n")
    except Exception as exc:
        audit(db, user.username, "settings.smtp_test", cfg.smtp_host, {"ok": False, "error": str(exc)}, _ip(request))
        db.commit()
        return {"ok": False, "message": f"Sending failed: {exc}"}
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
    counts = run_retention(db, get_section(db, RetentionSettings).days, get_section(db, ScanSettings).raw_retention_days)
    audit(db, user.username, "retention.run", None, counts, _ip(request))
    db.commit()
    return {"ok": True, "deleted": counts}
