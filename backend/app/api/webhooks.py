"""CRUD for outbound event webhooks."""

from __future__ import annotations

from urllib.parse import urlparse

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..auth.deps import client_ip, require_admin
from ..core.audit import audit
from ..core.webhooks import _host, send_test_webhook
from ..db import get_db, utcnow
from ..models import EVENT_TYPES, User, WebhookEndpoint
from ..security import encrypt_secret, new_token
from .common import UNPAGED_LIST, Row

router = APIRouter(prefix="/api/webhooks", tags=["webhooks"])


class WebhookIn(BaseModel):
    name: str = Field(..., max_length=120)
    url: str = Field(..., max_length=2000)
    enabled: bool = True
    secret: str | None = Field(None, max_length=200)
    # When true (and no ``secret``), generate a fresh secret (returned once as ``secret``).
    rotate_secret: bool = False
    event_types: list[str] | None = None
    include_record_events: bool = False


class WebhookPatch(BaseModel):
    """Partial update: omitted fields keep their stored values."""

    name: str | None = Field(None, max_length=120)
    url: str | None = Field(None, max_length=2000)
    enabled: bool | None = None
    secret: str | None = Field(None, max_length=200)
    rotate_secret: bool | None = None
    event_types: list[str] | None = None
    include_record_events: bool | None = None


def _validate_name(name: str) -> str:
    n = name.strip()
    if not n:
        raise HTTPException(422, "name is required")
    if len(n) > 120:
        raise HTTPException(422, "name must be at most 120 characters")
    return n


def _validate_url(url: str) -> str:
    u = url.strip()
    if not (u.startswith("https://") or u.startswith("http://")):
        raise HTTPException(422, "url must start with http:// or https://")
    # Prefer hostname over netloc: urlparse("http://:80/x").netloc is ":80" but hostname is None.
    if not (urlparse(u).hostname or "").strip():
        raise HTTPException(422, "url must include a host")
    return u


def _validate_types(types: list[str] | None) -> list[str] | None:
    if types is None:
        return None
    bad = [t for t in types if t not in EVENT_TYPES]
    if bad:
        raise HTTPException(422, f"unknown event types: {bad}")
    return types


def _out(h: WebhookEndpoint, *, secret: str | None = None) -> dict:
    data = {
        "id": h.id,
        "name": h.name,
        "url": h.url,
        "enabled": h.enabled,
        "has_secret": bool(h.secret_enc),
        "event_types": h.event_types or [],
        "include_record_events": bool(h.include_record_events),
        "created_at": h.created_at,
        "last_success_at": h.last_success_at,
        "last_error": h.last_error,
        "last_error_at": h.last_error_at,
    }
    if secret is not None:
        data["secret"] = secret
    return data


def _audit_details(h: WebhookEndpoint, **extra) -> dict:
    """Audit payload: never includes the signing secret."""
    return {
        "id": h.id,
        "url_host": _host(h.url),
        "enabled": h.enabled,
        "event_types": h.event_types or [],
        "include_record_events": bool(h.include_record_events),
        "has_secret": bool(h.secret_enc),
        **extra,
    }


@router.get("", response_model=list[Row], description=UNPAGED_LIST)
def list_webhooks(db: Session = Depends(get_db), user: User = Depends(require_admin)):
    return [_out(h) for h in db.scalars(select(WebhookEndpoint).order_by(WebhookEndpoint.id))]


@router.post("", status_code=201)
def create_webhook(
    body: WebhookIn,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(require_admin),
):
    name = _validate_name(body.name)
    url = _validate_url(body.url)
    types = _validate_types(body.event_types)
    plain: str | None = None
    if body.secret:
        plain = body.secret
    elif body.rotate_secret:
        plain = new_token(24)
    h = WebhookEndpoint(
        name=name,
        url=url,
        enabled=body.enabled,
        secret_enc=encrypt_secret(plain) if plain else None,
        event_types=types,
        include_record_events=body.include_record_events,
        created_at=utcnow(),
    )
    db.add(h)
    db.flush()
    audit(db, user.username, "webhook.create", h.name, _audit_details(h, secret_set=bool(plain)), client_ip(request))
    db.commit()
    db.refresh(h)
    return _out(h, secret=plain)


@router.patch("/{webhook_id}")
def patch_webhook(
    webhook_id: int,
    body: WebhookPatch,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(require_admin),
):
    h = db.get(WebhookEndpoint, webhook_id)
    if h is None:
        raise HTTPException(404, "webhook not found")
    before = _audit_details(h)
    plain: str | None = None
    secret_changed = False
    if body.name is not None:
        h.name = _validate_name(body.name)
    if body.url is not None:
        h.url = _validate_url(body.url)
    if body.enabled is not None:
        h.enabled = body.enabled
    if body.event_types is not None:
        h.event_types = _validate_types(body.event_types)
    if body.include_record_events is not None:
        h.include_record_events = body.include_record_events
    if body.secret is not None:
        plain = body.secret
        h.secret_enc = encrypt_secret(plain) if plain else None
        secret_changed = True
    elif body.rotate_secret:
        plain = new_token(24)
        h.secret_enc = encrypt_secret(plain)
        secret_changed = True
    audit(
        db,
        user.username,
        "webhook.update",
        h.name,
        {"before": before, "after": _audit_details(h, secret_rotated=secret_changed)},
        client_ip(request),
    )
    db.commit()
    db.refresh(h)
    return _out(h, secret=plain)


@router.post("/{webhook_id}/test")
def test_webhook(
    webhook_id: int,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(require_admin),
):
    h = db.get(WebhookEndpoint, webhook_id)
    if h is None:
        raise HTTPException(404, "webhook not found")
    # Snapshot for HTTP, then end the read transaction so no DB lock is held during the POST.
    snap = WebhookEndpoint(
        id=h.id,
        name=h.name,
        url=h.url,
        enabled=h.enabled,
        secret_enc=h.secret_enc,
        event_types=h.event_types,
        include_record_events=h.include_record_events,
    )
    name, host = h.name, _host(h.url)
    db.commit()
    result = send_test_webhook(snap)
    row = db.get(WebhookEndpoint, webhook_id)
    if row is not None:
        if result["ok"]:
            row.last_success_at = utcnow()
            row.last_error = None
        else:
            row.last_error = result["error"]
        audit(
            db,
            user.username,
            "webhook.test",
            name,
            {"ok": result["ok"], "status_code": result.get("status_code"), "host": host, "error": result.get("error")},
            client_ip(request),
        )
        db.commit()
    return result


@router.delete("/{webhook_id}", status_code=204)
def delete_webhook(
    webhook_id: int,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(require_admin),
):
    h = db.get(WebhookEndpoint, webhook_id)
    if h is None:
        raise HTTPException(404, "webhook not found")
    details = _audit_details(h)
    name = h.name
    db.delete(h)
    audit(db, user.username, "webhook.delete", name, details, client_ip(request))
    db.commit()
