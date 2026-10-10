"""Outbound event webhooks (SIEM / automation). Best-effort, never fails the scan."""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
from datetime import datetime

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db import session_scope, utcnow
from ..models import Event, WebhookEndpoint
from ..security import decrypt_secret

log = logging.getLogger(__name__)


def _sign(secret: str, body: bytes) -> str:
    return hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


def deliver_event(db: Session, event: Event) -> None:
    hooks = db.scalars(select(WebhookEndpoint).where(WebhookEndpoint.enabled.is_(True))).all()
    if not hooks:
        return
    payload = {
        "id": event.id,
        "type": event.event_type,
        "severity": event.severity,
        "ip": event.ip,
        "port": event.port,
        "protocol": event.protocol,
        "message": event.message,
        "created_at": event.created_at.isoformat() if event.created_at else None,
        "old_value": event.old_value,
        "new_value": event.new_value,
    }
    body = json.dumps(payload, default=str).encode()
    for hook in hooks:
        types = hook.event_types or []
        if types and event.event_type not in types:
            continue
        headers = {"Content-Type": "application/json", "User-Agent": "NetworkFinder-Webhook/1.0"}
        secret = decrypt_secret(hook.secret_enc) if hook.secret_enc else ""
        if secret:
            headers["X-NF-Signature"] = _sign(secret, body)
        try:
            r = httpx.post(hook.url, content=body, headers=headers, timeout=8.0)
            if r.status_code >= 400:
                hook.last_error = f"HTTP {r.status_code}"
            else:
                hook.last_success_at = utcnow()
                hook.last_error = None
        except Exception as exc:
            hook.last_error = str(exc)[:500]
            log.debug("webhook %s failed: %s", hook.id, exc)


def deliver_event_ids(event_ids: list[int]) -> None:
    if not event_ids:
        return
    try:
        with session_scope() as db:
            for ev in db.scalars(select(Event).where(Event.id.in_(event_ids))):
                deliver_event(db, ev)
    except Exception:
        log.exception("webhook delivery failed")
