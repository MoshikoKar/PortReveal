"""CRUD for outbound event webhooks."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..auth.deps import require_admin
from ..db import get_db, utcnow
from ..models import EVENT_TYPES, User, WebhookEndpoint
from ..security import encrypt_secret
from .common import UNPAGED_LIST, Row

router = APIRouter(prefix="/api/webhooks", tags=["webhooks"])


class WebhookIn(BaseModel):
    name: str = Field(..., min_length=1, max_length=120)
    url: str = Field(..., min_length=8, max_length=2000)
    enabled: bool = True
    secret: str | None = Field(None, max_length=200)
    event_types: list[str] | None = None


def _out(h: WebhookEndpoint) -> dict:
    return {
        "id": h.id, "name": h.name, "url": h.url, "enabled": h.enabled,
        "has_secret": bool(h.secret_enc), "event_types": h.event_types or [],
        "created_at": h.created_at, "last_success_at": h.last_success_at, "last_error": h.last_error,
    }


@router.get("", response_model=list[Row], description=UNPAGED_LIST)
def list_webhooks(db: Session = Depends(get_db), user: User = Depends(require_admin)):
    return [_out(h) for h in db.scalars(select(WebhookEndpoint).order_by(WebhookEndpoint.id))]


@router.post("", status_code=201)
def create_webhook(body: WebhookIn, db: Session = Depends(get_db), user: User = Depends(require_admin)):
    if body.event_types:
        bad = [t for t in body.event_types if t not in EVENT_TYPES]
        if bad:
            raise HTTPException(422, f"unknown event types: {bad}")
    h = WebhookEndpoint(
        name=body.name.strip(), url=body.url.strip(), enabled=body.enabled,
        secret_enc=encrypt_secret(body.secret) if body.secret else None,
        event_types=body.event_types, created_at=utcnow(),
    )
    db.add(h)
    db.commit()
    return _out(h)


@router.delete("/{webhook_id}", status_code=204)
def delete_webhook(webhook_id: int, db: Session = Depends(get_db), user: User = Depends(require_admin)):
    h = db.get(WebhookEndpoint, webhook_id)
    if h is None:
        raise HTTPException(404, "webhook not found")
    db.delete(h)
    db.commit()
