"""Session authentication, CSRF protection and role checks (FastAPI dependencies).

* Session: random token in an HttpOnly, SameSite=Lax cookie; only its SHA-256
  hash is stored. Idle timeout + absolute lifetime.
* CSRF: per-session token, readable by the SPA from a non-HttpOnly cookie and
  required in the X-CSRF-Token header for every state-changing request.
* API tokens: `Authorization: Bearer nf_...`, read-only (GET/HEAD), stored as SHA-256 hashes.
"""
from __future__ import annotations

import hmac
from datetime import timedelta

from fastapi import Depends, HTTPException, Request, Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..config import get_settings
from ..db import get_db, utcnow
from ..models import ROLE_ADMIN, ApiToken, User, UserSession
from ..security import hash_token, new_token

SESSION_COOKIE = "nf_session"
CSRF_COOKIE = "nf_csrf"
CSRF_HEADER = "X-CSRF-Token"
UNSAFE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
API_TOKEN_PREFIX = "nf_"
TOKEN_METHODS = {"GET", "HEAD"}
TOKEN_TOUCH_SECONDS = 60


def client_ip(request: Request) -> str | None:
    return request.client.host if request.client else None


def start_session(db: Session, user: User, request: Request, response: Response) -> UserSession:
    s = get_settings()
    token = new_token()
    now = utcnow()
    sess = UserSession(
        token_hash=hash_token(token),
        user_id=user.id,
        csrf_token=new_token(24),
        created_at=now,
        last_seen_at=now,
        expires_at=now + timedelta(minutes=s.session_idle_minutes),
        ip=client_ip(request),
    )
    db.add(sess)
    user.last_login_at = now
    max_age = s.session_max_hours * 3600
    response.set_cookie(SESSION_COOKIE, token, max_age=max_age, httponly=True, secure=s.cookie_secure,
                        samesite="lax", path="/")
    response.set_cookie(CSRF_COOKIE, sess.csrf_token, max_age=max_age, httponly=False, secure=s.cookie_secure,
                        samesite="lax", path="/")
    return sess


def end_session(db: Session, request: Request, response: Response) -> None:
    token = request.cookies.get(SESSION_COOKIE)
    if token:
        sess = db.scalar(select(UserSession).where(UserSession.token_hash == hash_token(token)))
        if sess:
            db.delete(sess)
    response.delete_cookie(SESSION_COOKIE, path="/")
    response.delete_cookie(CSRF_COOKIE, path="/")


def get_session_record(request: Request, db: Session = Depends(get_db)) -> UserSession:
    token = request.cookies.get(SESSION_COOKIE)
    if not token:
        raise HTTPException(401, "Not authenticated")
    sess = db.scalar(select(UserSession).where(UserSession.token_hash == hash_token(token)))
    now = utcnow()
    s = get_settings()
    if (
        sess is None
        or sess.expires_at < now
        or sess.created_at + timedelta(hours=s.session_max_hours) < now
        or not sess.user.is_active
    ):
        if sess is not None:
            db.delete(sess)
            db.commit()
        raise HTTPException(401, "Session expired")
    if request.method in UNSAFE_METHODS:
        sent = request.headers.get(CSRF_HEADER, "")
        if not sent or not hmac.compare_digest(sent, sess.csrf_token):
            raise HTTPException(403, "CSRF token missing or invalid")
    if (now - sess.last_seen_at).total_seconds() > 60:
        sess.last_seen_at = now
        sess.expires_at = now + timedelta(minutes=s.session_idle_minutes)
        db.commit()
    request.state.session = sess
    return sess


def _api_token_user(request: Request, db: Session) -> User | None:
    """User of a valid `Authorization: Bearer nf_...` token, None when no bearer token is sent."""
    header = request.headers.get("Authorization", "")
    scheme, _, raw = header.partition(" ")
    if scheme.lower() != "bearer":
        return None
    raw = raw.strip()
    tok = db.scalar(select(ApiToken).where(ApiToken.token_hash == hash_token(raw))) \
        if raw.startswith(API_TOKEN_PREFIX) else None
    now = utcnow()
    if tok is None or tok.revoked or (tok.expires_at is not None and tok.expires_at < now) or not tok.user.is_active:
        raise HTTPException(401, "Invalid, revoked or expired API token")
    if request.method not in TOKEN_METHODS:
        raise HTTPException(403, "API tokens are read-only")
    if tok.last_used_at is None or (now - tok.last_used_at).total_seconds() > TOKEN_TOUCH_SECONDS:
        tok.last_used_at = now
        db.commit()
    request.state.api_token = tok
    return tok.user


def current_user(request: Request, db: Session = Depends(get_db)) -> User:
    """Cookie session, or a read-only API token for scripts."""
    user = _api_token_user(request, db)
    if user is not None:
        return user
    return get_session_record(request, db).user


def session_user(sess: UserSession = Depends(get_session_record)) -> User:
    """Cookie session only (API tokens cannot manage API tokens)."""
    return sess.user


def require_admin(user: User = Depends(current_user)) -> User:
    if user.role != ROLE_ADMIN:
        raise HTTPException(403, "Administrator role required")
    return user
