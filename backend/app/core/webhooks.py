"""Outbound event webhooks (SIEM / automation). Best-effort, never fails the scan.

Delivery follows the CVE watchlist pattern: load a plan, close the DB session, perform HTTP,
then short follow-up transactions to record success/error. Holding a write lock during HTTP
would block SQLite (and stall Postgres writers under load).

Notify-flag default (safe): only events with ``notify=True`` (network alert mode) are sent,
matching the email digest. Hooks with ``include_record_events=True`` also receive
``notify=False`` (record) events that match their type filter. Silent modes never create rows.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import time

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import metrics
from ..db import SessionLocal, get_engine, session_scope, utcnow
from ..models import EV_CVE_WATCH_MATCH, Event, WebhookEndpoint
from ..security import decrypt_secret
from ..settings_store import NotificationSettings, get_section

log = logging.getLogger(__name__)

USER_AGENT = "PortReveal-Webhook/1.0"
HTTP_TIMEOUT = 8.0


def _host(url: str) -> str:
    try:
        return httpx.URL(url).host or "?"
    except Exception:
        return "?"


def _sign(secret: str, body: bytes) -> str:
    return hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


def _event_payload(event: Event) -> dict:
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
        "notify": bool(event.notify),
    }
    # cve_watch_match stores structured detail in old_value; promote fields for SIEM consumers.
    if event.event_type == EV_CVE_WATCH_MATCH and event.old_value:
        try:
            detail = json.loads(event.old_value)
        except (TypeError, ValueError, json.JSONDecodeError):
            detail = None
        if isinstance(detail, dict):
            for key in (
                "cve_id",
                "device_uuid",
                "hostname",
                "ip",
                "port",
                "protocol",
                "state",
                "cvss",
                "kev",
            ):
                if key in detail and detail[key] is not None:
                    payload[key] = detail[key]
    return payload


def _hook_accepts(hook: WebhookEndpoint, event: Event) -> bool:
    """Whether this hook should receive the event (type filter + notify / record opt-in)."""
    types = hook.event_types or []
    if types and event.event_type not in types:
        return False
    if event.notify:
        return True
    # Record-mode events: only when the hook explicitly opts in.
    return bool(hook.include_record_events)


def deliver_event(db: Session, event: Event) -> None:
    """Deliver one event. Prefer ``deliver_event_ids`` so HTTP does not hold the caller's session."""
    # Flush so the event id is durable for the follow-up load; caller still owns the transaction.
    db.flush()
    if event.id is None:
        return
    deliver_event_ids([event.id])


def deliver_event_ids(event_ids: list[int]) -> None:
    """Deliver events after the creating transaction has committed (no DB lock during HTTP)."""
    ids = [i for i in event_ids if i]
    if not ids:
        return
    try:
        plan = _load_delivery_plan(ids)
    except Exception:
        log.exception("webhook delivery plan load failed")
        return
    if not plan:
        return
    for item in plan:
        _post_and_record(item)


def _load_delivery_plan(event_ids: list[int]) -> list[dict]:
    """Read events + hooks, build signed POST jobs, then close the session (no writes)."""
    get_engine()
    db = SessionLocal()
    try:
        cfg = get_section(db, NotificationSettings)
        if not cfg.webhooks_enabled:
            return []
        events = list(db.scalars(select(Event).where(Event.id.in_(event_ids)).order_by(Event.id)).unique().all())
        if not events:
            return []
        hooks = list(db.scalars(select(WebhookEndpoint).where(WebhookEndpoint.enabled.is_(True))).all())
        if not hooks:
            return []
        jobs: list[dict] = []
        for event in events:
            payload = _event_payload(event)
            body = json.dumps(payload, default=str).encode()
            for hook in hooks:
                if not _hook_accepts(hook, event):
                    continue
                secret = decrypt_secret(hook.secret_enc) if hook.secret_enc else ""
                headers = {"Content-Type": "application/json", "User-Agent": USER_AGENT}
                if secret:
                    headers["X-NF-Signature"] = _sign(secret, body)
                jobs.append(
                    {
                        "hook_id": hook.id,
                        "url": hook.url,
                        "host": _host(hook.url),
                        "headers": headers,
                        "body": body,
                        "event_id": event.id,
                    }
                )
        return jobs
    finally:
        db.close()


def _post_and_record(item: dict) -> None:
    ok = False
    err: str | None = None
    try:
        r = httpx.post(item["url"], content=item["body"], headers=item["headers"], timeout=HTTP_TIMEOUT)
        if r.status_code >= 400:
            err = f"HTTP {r.status_code}"
            metrics.observe_webhook_delivery("http_error")
            log.warning(
                "webhook %s (%s) answered HTTP %s for event %s",
                item["hook_id"],
                item["host"],
                r.status_code,
                item["event_id"],
            )
        else:
            ok = True
            metrics.observe_webhook_delivery("ok")
    except Exception as exc:
        err = str(exc)[:500]
        metrics.observe_webhook_delivery("network_error")
        log.warning(
            "webhook %s (%s) delivery failed for event %s: %s",
            item["hook_id"],
            item["host"],
            item["event_id"],
            type(exc).__name__,
        )

    try:
        with session_scope() as db:
            row = db.get(WebhookEndpoint, item["hook_id"])
            if row is None:
                return
            if ok:
                row.last_success_at = utcnow()
                row.last_error = None
            else:
                row.last_error = err
    except Exception:
        log.exception("Failed to record webhook %s delivery result", item["hook_id"])


def send_test_webhook(hook: WebhookEndpoint) -> dict:
    """POST a signed synthetic test event; update last_success/last_error. Returns a result dict."""
    payload = {
        "id": 0,
        "type": "webhook_test",
        "severity": "info",
        "message": "PortReveal webhook test",
        "created_at": utcnow().isoformat(),
        "test": True,
    }
    body = json.dumps(payload, default=str).encode()
    headers = {"Content-Type": "application/json", "User-Agent": USER_AGENT}
    secret = decrypt_secret(hook.secret_enc) if hook.secret_enc else ""
    if secret:
        headers["X-NF-Signature"] = _sign(secret, body)
    host = _host(hook.url)
    started = time.monotonic()
    ok = False
    status_code: int | None = None
    err: str | None = None
    try:
        r = httpx.post(hook.url, content=body, headers=headers, timeout=HTTP_TIMEOUT)
        status_code = r.status_code
        if r.status_code >= 400:
            err = f"HTTP {r.status_code}"
            metrics.observe_webhook_delivery("http_error")
            log.warning("webhook %s (%s) test answered HTTP %s", hook.id, host, r.status_code)
        else:
            ok = True
            metrics.observe_webhook_delivery("ok")
    except Exception as exc:
        err = str(exc)[:500]
        metrics.observe_webhook_delivery("network_error")
        log.warning("webhook %s (%s) test failed: %s", hook.id, host, type(exc).__name__)
    latency_ms = int((time.monotonic() - started) * 1000)
    return {
        "ok": ok,
        "status_code": status_code,
        "error": err,
        "latency_ms": latency_ms,
        "host": host,
    }
