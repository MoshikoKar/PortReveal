"""Outbound event webhooks (SIEM / automation). Best-effort, never fails the scan.

Delivery follows the CVE watchlist pattern: load a plan, close the DB session, perform HTTP,
then short follow-up transactions to record success/error. Holding a write lock during HTTP
would block SQLite (and stall Postgres writers under load).

Notify-flag default (safe): only events with ``notify=True`` (alert) are sent, matching the
email digest. Hooks with ``include_record_events=True`` also receive ``notify=False`` (record)
events that match their type filter. Silent modes never create rows.

Callers use ``schedule_event_delivery`` so scan/scheduler/intel threads return immediately.
A long-lived daemon worker drains a bounded queue. Each HTTP POST has a hard wall-clock
deadline (connect/read timeouts alone cannot stop a trickling server).
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import queue
import threading
import time
from concurrent.futures import ThreadPoolExecutor

import httpx
from sqlalchemy import select

from .. import metrics
from ..db import SessionLocal, get_engine, session_scope, utcnow
from ..models import EV_CVE_WATCH_MATCH, Event, WebhookEndpoint
from ..security import decrypt_secret
from ..settings_store import NotificationSettings, get_section

log = logging.getLogger(__name__)

USER_AGENT = "PortReveal-Webhook/1.0"
# Hard wall-clock deadline for one HTTP POST (trickling responses cannot exceed this).
HTTP_DEADLINE = 8.0
# Short per-operation timeouts so stalls between bytes fail fast; total still capped by HTTP_DEADLINE.
HTTP_CONNECT_TIMEOUT = 2.0
HTTP_IO_TIMEOUT = 2.0
MAX_HOOK_WORKERS = 8
# Split large deliveries into multiple POSTs (same envelope shape as CVE watchlist batches).
MAX_BATCH_EVENTS = 50
QUEUE_MAXSIZE = 256

_delivery_queue: queue.Queue[list[int] | None] | None = None
_worker_thread: threading.Thread | None = None
_worker_lock = threading.Lock()


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
    return bool(hook.include_record_events)


def start_delivery_worker() -> None:
    """Start the daemon webhook delivery worker once (idempotent)."""
    global _delivery_queue, _worker_thread
    with _worker_lock:
        if _worker_thread is not None and _worker_thread.is_alive():
            return
        _delivery_queue = queue.Queue(maxsize=QUEUE_MAXSIZE)
        _worker_thread = threading.Thread(
            target=_worker_loop,
            name="webhook-delivery",
            daemon=True,
        )
        _worker_thread.start()
        log.info("webhook delivery worker started")


def stop_delivery_worker() -> None:
    """Signal the worker to exit (used on app shutdown)."""
    global _worker_thread
    with _worker_lock:
        q = _delivery_queue
        thr = _worker_thread
    if q is None or thr is None:
        return
    try:
        q.put_nowait(None)
    except queue.Full:
        # Drop one job to make room for the sentinel so shutdown can proceed.
        try:
            q.get_nowait()
            q.task_done()
        except queue.Empty:
            pass
        try:
            q.put_nowait(None)
        except queue.Full:
            return
    thr.join(timeout=HTTP_DEADLINE + 2)
    with _worker_lock:
        if _worker_thread is thr:
            _worker_thread = None


def schedule_event_delivery(event_ids: list[int], *, wait: bool = False) -> None:
    """Enqueue delivery after the creating transaction has committed.

    ``wait=False`` (default): put ids on the bounded daemon queue and return immediately so
    scan / scheduler / intel callers are never stalled by slow hooks.
    ``wait=True``: deliver synchronously on this thread (tests / CLI).
    """
    ids = [i for i in event_ids if i]
    if not ids:
        return
    if wait:
        deliver_event_ids(ids)
        return
    start_delivery_worker()
    assert _delivery_queue is not None
    try:
        _delivery_queue.put_nowait(ids)
    except queue.Full:
        log.warning("webhook delivery queue full; dropping %d event(s)", len(ids))


def _worker_loop() -> None:
    assert _delivery_queue is not None
    while True:
        item = _delivery_queue.get()
        try:
            if item is None:
                return
            deliver_event_ids(item)
        except Exception:
            log.exception("webhook delivery worker failed")
        finally:
            _delivery_queue.task_done()


def wait_delivery_idle(timeout: float = 30.0) -> bool:
    """Block until the delivery queue is drained (tests). Returns False on timeout."""
    q = _delivery_queue
    if q is None:
        return True
    done = threading.Event()

    def _join() -> None:
        q.join()
        done.set()

    threading.Thread(target=_join, name="webhook-queue-join", daemon=True).start()
    return done.wait(timeout)


def deliver_event_ids(event_ids: list[int]) -> None:
    """Deliver events synchronously (no DB lock during HTTP). Used by the worker and wait=True.

    One signed POST per enabled hook per batch chunk (at most ``MAX_BATCH_EVENTS`` events).
    Hooks in a round run concurrently; each POST is capped by ``HTTP_DEADLINE``.
    """
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

    workers = min(MAX_HOOK_WORKERS, len(plan))
    with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="webhook") as pool:
        futures = [pool.submit(_post_hook_batches, item) for item in plan]
        for fut, item in zip(futures, plan, strict=True):
            try:
                ok, err = fut.result()
            except Exception as exc:
                ok, err = False, str(exc)[:500]
                log.warning(
                    "webhook %s (%s) delivery raised: %s",
                    item["hook_id"],
                    item["host"],
                    type(exc).__name__,
                )
            _record_hook_result(item["hook_id"], ok=ok, err=err)


def _load_delivery_plan(event_ids: list[int]) -> list[dict]:
    """Read events + hooks, group matching events per hook, then close the session (no writes)."""
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
        for hook in hooks:
            matched = [_event_payload(ev) for ev in events if _hook_accepts(hook, ev)]
            if not matched:
                continue
            secret = decrypt_secret(hook.secret_enc) if hook.secret_enc else ""
            jobs.append(
                {
                    "hook_id": hook.id,
                    "url": hook.url,
                    "host": _host(hook.url),
                    "secret": secret,
                    "events": matched,
                }
            )
        return jobs
    finally:
        db.close()


def _chunks(events: list[dict], size: int) -> list[list[dict]]:
    return [events[i : i + size] for i in range(0, len(events), size)]


def _build_body(events: list[dict]) -> bytes:
    """Single-event payloads keep the historical shape; multi-event use a batch envelope.

    Batch shape matches CVE watchlist webhooks (``batch`` / ``count`` / array), using
    ``events`` instead of ``matches`` because the payload may mix event types.
    """
    if len(events) == 1:
        return json.dumps(events[0], default=str).encode()
    payload = {
        "batch": True,
        "count": len(events),
        "events": events,
    }
    return json.dumps(payload, default=str).encode()


def _http_post(url: str, body: bytes, headers: dict[str, str], *, deadline: float = HTTP_DEADLINE) -> int:
    """POST with short connect/read timeouts and a hard wall-clock deadline. Returns status code."""
    started = time.monotonic()
    timeout = httpx.Timeout(
        connect=min(HTTP_CONNECT_TIMEOUT, deadline),
        read=min(HTTP_IO_TIMEOUT, deadline),
        write=min(HTTP_IO_TIMEOUT, deadline),
        pool=min(HTTP_CONNECT_TIMEOUT, deadline),
    )
    with httpx.Client(timeout=timeout) as client:
        with client.stream("POST", url, content=body, headers=headers) as response:
            status = response.status_code
            for _chunk in response.iter_bytes():
                if time.monotonic() - started >= deadline:
                    raise TimeoutError(f"timeout after {int(deadline)}s")
            if time.monotonic() - started >= deadline:
                raise TimeoutError(f"timeout after {int(deadline)}s")
            return status


def _post_hook_batches(item: dict) -> tuple[bool, str | None]:
    """HTTP only — no DB session. Posts each chunk; returns (ok, error_message)."""
    chunks = _chunks(item["events"], MAX_BATCH_EVENTS)
    last_err: str | None = None
    any_ok = False
    for chunk in chunks:
        body = _build_body(chunk)
        headers = {"Content-Type": "application/json", "User-Agent": USER_AGENT}
        if item["secret"]:
            headers["X-NF-Signature"] = _sign(item["secret"], body)
        n = len(chunk)
        try:
            status = _http_post(item["url"], body, headers, deadline=HTTP_DEADLINE)
            if status >= 400:
                metrics.observe_webhook_delivery("http_error")
                log.warning(
                    "webhook %s (%s) answered HTTP %s for %d event(s)",
                    item["hook_id"],
                    item["host"],
                    status,
                    n,
                )
                last_err = f"HTTP {status}"
            else:
                metrics.observe_webhook_delivery("ok")
                any_ok = True
        except TimeoutError as exc:
            metrics.observe_webhook_delivery("network_error")
            err = str(exc)[:500]
            log.warning(
                "webhook %s (%s) delivery timed out for %d event(s): %s",
                item["hook_id"],
                item["host"],
                n,
                err,
            )
            last_err = err
        except Exception as exc:
            metrics.observe_webhook_delivery("network_error")
            log.warning(
                "webhook %s (%s) delivery failed for %d event(s): %s",
                item["hook_id"],
                item["host"],
                n,
                type(exc).__name__,
            )
            last_err = str(exc)[:500]
    if last_err is None and any_ok:
        return True, None
    if last_err is None:
        return True, None
    # Partial success still surfaces the last error so the UI is truthful.
    return False, last_err


def _record_hook_result(hook_id: int, *, ok: bool, err: str | None) -> None:
    try:
        with session_scope() as db:
            row = db.get(WebhookEndpoint, hook_id)
            if row is None:
                return
            if ok:
                row.last_success_at = utcnow()
                row.last_error = None
            else:
                row.last_error = err
    except Exception:
        log.exception("Failed to record webhook %s delivery result", hook_id)


def send_test_webhook(hook: WebhookEndpoint) -> dict:
    """POST a signed synthetic test event. Returns a result dict (caller records last_success/error)."""
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
        status_code = _http_post(hook.url, body, headers, deadline=HTTP_DEADLINE)
        if status_code >= 400:
            err = f"HTTP {status_code}"
            metrics.observe_webhook_delivery("http_error")
            log.warning("webhook %s (%s) test answered HTTP %s", hook.id, host, status_code)
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
