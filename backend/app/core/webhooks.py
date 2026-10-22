"""Outbound event webhooks (SIEM / automation). Best-effort, never fails the scan."""
from __future__ import annotations

import hashlib
import hmac
import json
import logging

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import metrics
from ..db import session_scope, utcnow
from ..models import Event, WebhookEndpoint
from ..security import decrypt_secret

log = logging.getLogger(__name__)


def _host(url: str) -> str:
    try:
        return httpx.URL(url).host or "?"
    except Exception:
        return "?"


def _sign(secret: str, body: bytes) -> str:
    return hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


def deliver_event(db: Session, event: Event) -> None:
    from ..models import EV_CVE_WATCH_MATCH

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
    # cve_watch_match stores structured detail in old_value; promote fields for SIEM consumers.
    if event.event_type == EV_CVE_WATCH_MATCH and event.old_value:
        try:
            detail = json.loads(event.old_value)
        except (TypeError, ValueError, json.JSONDecodeError):
            detail = None
        if isinstance(detail, dict):
            for key in (
                "cve_id", "device_uuid", "hostname", "ip", "port", "protocol",
                "state", "cvss", "kev",
            ):
                if key in detail and detail[key] is not None:
                    payload[key] = detail[key]
    body = json.dumps(payload, default=str).encode()
    for hook in hooks:
        types = hook.event_types or []
        if types and event.event_type not in types:
            continue
        headers = {"Content-Type": "application/json", "User-Agent": "PortReveal-Webhook/1.0"}
        secret = decrypt_secret(hook.secret_enc) if hook.secret_enc else ""
        if secret:
            headers["X-NF-Signature"] = _sign(secret, body)
        # Logs name the hook and host only: the URL path or query may carry a token.
        try:
            r = httpx.post(hook.url, content=body, headers=headers, timeout=8.0)
            if r.status_code >= 400:
                hook.last_error = f"HTTP {r.status_code}"
                metrics.observe_webhook_delivery("http_error")
                log.warning("webhook %s (%s) answered HTTP %s for event %s",
                            hook.id, _host(hook.url), r.status_code, event.id)
            else:
                hook.last_success_at = utcnow()
                hook.last_error = None
                metrics.observe_webhook_delivery("ok")
        except Exception as exc:
            hook.last_error = str(exc)[:500]
            metrics.observe_webhook_delivery("network_error")
            log.warning("webhook %s (%s) delivery failed for event %s: %s",
                        hook.id, _host(hook.url), event.id, type(exc).__name__)


def deliver_event_ids(event_ids: list[int]) -> None:
    if not event_ids:
        return
    try:
        with session_scope() as db:
            for ev in db.scalars(select(Event).where(Event.id.in_(event_ids))):
                deliver_event(db, ev)
    except Exception:
        log.exception("webhook delivery failed")
