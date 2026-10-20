from __future__ import annotations

import json
import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .. import metrics
from ..auth.deps import client_ip, current_user, end_session, get_session_record, start_session
from ..auth.ldap_auth import ldap_authenticate
from ..auth.ratelimit import LoginRateLimiter
from ..config import get_settings
from ..core.audit import audit
from ..dashboard_prefs import (
    PreferencesValidationError,
    merge_preferences,
    validate_preferences_payload,
)
from ..db import get_db
from ..models import User, UserSession
from ..security import hash_password, verify_password
from ..settings_store import LdapSettings, get_section
from .common import user_out

router = APIRouter(prefix="/api/auth", tags=["auth"])
log = logging.getLogger(__name__)
_s = get_settings()
limiter = LoginRateLimiter(_s.login_max_failures, _s.login_window_minutes * 60)
_DUMMY_HASH = hash_password("timing-equalizer")


class LoginIn(BaseModel):
    username: str = Field(min_length=1, max_length=150)
    password: str = Field(min_length=1, max_length=1024)


def require_json(request: Request) -> None:
    if not request.headers.get("content-type", "").lower().startswith("application/json"):
        raise HTTPException(415, "Content-Type must be application/json")


@router.post("/login", dependencies=[Depends(require_json)])
def login(body: LoginIn, request: Request, response: Response, db: Session = Depends(get_db)):
    ip = client_ip(request) or "unknown"
    username = body.username.strip()
    keys = (f"ip:{ip}", f"user:{username.lower()}")
    if limiter.blocked(*keys):
        metrics.observe_login_rate_limited()
        log.warning("login refused for %r from %s: too many failed attempts", username, ip)
        audit(db, username, "auth.login_rate_limited", None, None, ip)
        db.commit()
        raise HTTPException(429, "Too many failed login attempts. Try again later.")

    user = db.scalar(select(User).where(func.lower(User.username) == username.lower()))
    ok = False
    if user is not None and user.source == "local":
        ok = verify_password(body.password, user.password_hash) and user.is_active
    else:
        ldap_cfg = get_section(db, LdapSettings)
        if ldap_cfg.enabled:
            res = ldap_authenticate(ldap_cfg, username, body.password)
            if res.ok:
                if user is None:
                    user = User(username=username, source="ldap", role=res.role, display_name=res.display_name)
                    db.add(user)
                    db.flush()
                    audit(db, username, "user.ldap_provisioned", username, {"role": res.role}, ip)
                elif user.is_active:
                    user.role = res.role or user.role
                    user.display_name = res.display_name
                ok = user.is_active
        else:
            verify_password(body.password, _DUMMY_HASH)

    if not ok or user is None:
        limiter.failure(*keys)
        audit(db, username, "auth.login_failed", None, None, ip)
        db.commit()
        raise HTTPException(401, "Invalid username or password")

    limiter.success(*keys)
    sess = start_session(db, user, request, response)
    audit(db, user.username, "auth.login", None, {"source": user.source}, ip)
    db.commit()
    return {"user": user_out(user), "csrf_token": sess.csrf_token}


@router.post("/logout")
def logout(request: Request, response: Response, sess: UserSession = Depends(get_session_record),
           db: Session = Depends(get_db)):
    end_session(db, request, response)
    db.commit()
    return {"ok": True}


@router.get("/me")
def me(request: Request, user: User = Depends(current_user)):
    sess = getattr(request.state, "session", None)  # absent for API-token requests
    return {"user": user_out(user), "csrf_token": sess.csrf_token if sess else None}


@router.put("/me/preferences", dependencies=[Depends(require_json)])
def put_preferences(body: dict[str, Any], db: Session = Depends(get_db), user: User = Depends(current_user)):
    """Replace the caller's dashboard (and future) UI preferences."""
    try:
        encoded = json.dumps(body, separators=(",", ":")).encode("utf-8")
        validated = validate_preferences_payload(body, raw_bytes=len(encoded))
    except PreferencesValidationError as exc:
        raise HTTPException(422, str(exc)) from exc
    existing = user.preferences if isinstance(user.preferences, dict) else None
    user.preferences = merge_preferences(existing, validated)
    db.add(user)
    db.commit()
    db.refresh(user)
    return {"user": user_out(user)}
