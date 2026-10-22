"""Outbound event webhooks (SIEM / automation). Best-effort, never fails the scan.

Delivery follows the CVE watchlist pattern: load a plan, close the DB session, perform HTTP,
then short follow-up transactions to record success/error. Holding a write lock during HTTP
would block SQLite (and stall Postgres writers under load).

Notify-flag default (safe): only events with ``notify=True`` (alert) are sent, matching the
email digest. Hooks with ``include_record_events=True`` also receive ``notify=False`` (record)
events that match their type filter. Silent modes never create rows.

Callers use ``schedule_event_delivery`` so scan/scheduler/intel threads return immediately.
A dispatcher drains a bounded queue and hands each hook to a small pool (at most one in-flight
POST chain per hook), so a stuck endpoint cannot delay other hooks. Each HTTP POST is capped by
a hard whole-request wall-clock deadline (a watchdog closes the client).
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
# Hard wall-clock deadline for one whole HTTP POST (headers + body).
HTTP_DEADLINE = 8.0
# Connect may take a few seconds; response is allowed the remaining budget up to HTTP_DEADLINE.
HTTP_CONNECT_TIMEOUT = 3.0
MAX_HOOK_WORKERS = 8
# Split large deliveries into multiple POSTs (same envelope shape as CVE watchlist batches).
MAX_BATCH_EVENTS = 50
QUEUE_MAXSIZE = 256
# Cap coalesced events waiting behind a stuck hook (overflow is recorded as dropped).
MAX_PENDING_EVENTS_PER_HOOK = 200

_delivery_queue: queue.Queue[list[int] | None] | None = None
_worker_thread: threading.Thread | None = None
_hook_pool: ThreadPoolExecutor | None = None
_worker_lock = threading.Lock()
_stopping = False

# Per-hook serialization: at most one in-flight delivery chain per hook_id.
_hook_state_lock = threading.Lock()
_hook_busy: set[int] = set()
_hook_pending: dict[int, list[dict]] = {}
_hook_inflight = 0  # jobs running in the hook pool (for idle waits)
_hook_idle = threading.Condition(_hook_state_lock)


def _host(url: str) -> str:
    try:
        return httpx.URL(url).host or "?"
    except Exception:
        return "?"


def _sign(secret: str, body: bytes) -> str:
    return hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


def _timeout_message(elapsed: float) -> str:
    return f"timeout after {elapsed:.1f}s"


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
    """Start the dispatcher + hook pool once (idempotent).

    If a previous stop() is still waiting on a live thread, refuse to spawn a second
    dispatcher. After a clean exit, a new start is allowed (tests / rare restart).
    """
    global _delivery_queue, _worker_thread, _hook_pool, _stopping
    with _worker_lock:
        if _worker_thread is not None and _worker_thread.is_alive():
            return
        _stopping = False
        _delivery_queue = queue.Queue(maxsize=QUEUE_MAXSIZE)
        if _hook_pool is None:
            _hook_pool = ThreadPoolExecutor(max_workers=MAX_HOOK_WORKERS, thread_name_prefix="webhook-hook")
        _worker_thread = threading.Thread(
            target=_worker_loop,
            name="webhook-delivery",
            daemon=True,
        )
        _worker_thread.start()
        log.info("webhook delivery worker started")


def stop_delivery_worker() -> None:
    """Signal the dispatcher to exit. Does not clear the thread handle if it outlives the grace."""
    global _worker_thread, _stopping
    with _worker_lock:
        _stopping = True
        q = _delivery_queue
        thr = _worker_thread
    if q is None or thr is None:
        return
    try:
        q.put_nowait(None)
    except queue.Full:
        try:
            dropped = q.get_nowait()
            q.task_done()
            if isinstance(dropped, list) and dropped:
                _record_dropped_events(dropped, "shutdown")
        except queue.Empty:
            pass
        try:
            q.put_nowait(None)
        except queue.Full:
            return
    thr.join(timeout=HTTP_DEADLINE + 2)
    # In-flight POSTs abandoned at shutdown: mark hook status so the UI is truthful.
    with _hook_state_lock:
        busy_ids = list(_hook_busy)
        pending_counts = {hid: len(evs) for hid, evs in _hook_pending.items()}
        _hook_pending.clear()
    for hid in busy_ids:
        n = pending_counts.get(hid, 0)
        msg = "delivery interrupted: shutdown"
        if n:
            msg = f"{_drop_label(n)} dropped: shutdown; {msg}"
        _record_hook_result(hid, ok=False, err=msg)
    with _worker_lock:
        if thr.is_alive():
            # Keep the handle so start_delivery_worker will not spawn a second dispatcher.
            log.warning("webhook delivery worker did not stop within grace; not starting another")
        else:
            _worker_thread = None


def enqueue_channel_delivery(event_ids: list[int]) -> None:
    """Put channel-only work on the shared queue (CVE watchlist / direct callers)."""
    ids = [i for i in event_ids if i]
    if not ids:
        return
    _enqueue_delivery(ids, channels_only=True)


def schedule_event_delivery(event_ids: list[int], *, wait: bool = False) -> None:
    """Enqueue delivery after the creating transaction has committed.

    ``wait=False`` (default): put ids on the bounded daemon queue and return immediately so
    scan / scheduler / intel callers are never stalled by slow hooks. The worker runs global
    webhooks then recipient-group routing (no new thread per call).
    ``wait=True``: deliver synchronously on this thread (tests / CLI).
    """
    ids = [i for i in event_ids if i]
    if not ids:
        return
    if wait:
        deliver_event_ids(ids)
        try:
            from .channels import deliver_channel_event_ids

            deliver_channel_event_ids(ids)
        except Exception:
            log.exception("recipient-group delivery failed")
        return
    _enqueue_delivery(ids, channels_only=False)


def _enqueue_delivery(ids: list[int], *, channels_only: bool) -> None:
    if _stopping:
        log.warning("webhook delivery refused during shutdown; dropping %d event(s)", len(ids))
        if not channels_only:
            _record_dropped_events(ids, "shutdown")
        return
    start_delivery_worker()
    if _stopping or _delivery_queue is None:
        log.warning("webhook delivery worker unavailable; dropping %d event(s)", len(ids))
        if not channels_only:
            _record_dropped_events(ids, "shutdown")
        return
    item = {"ids": ids, "channels_only": channels_only}
    try:
        _delivery_queue.put_nowait(item)
    except queue.Full:
        log.warning("webhook delivery queue full; dropping %d event(s)", len(ids))
        if not channels_only:
            threading.Thread(
                target=_record_dropped_events,
                args=(ids, "queue full"),
                name="webhook-drop-status",
                daemon=True,
            ).start()
        # Still attempt channel routing off the scan thread when the webhook queue is saturated.
        threading.Thread(
            target=_safe_channel_deliver,
            args=(ids,),
            name="channel-fallback",
            daemon=True,
        ).start()


def _safe_channel_deliver(ids: list[int]) -> None:
    try:
        from .channels import deliver_channel_event_ids

        deliver_channel_event_ids(ids)
    except Exception:
        log.exception("recipient-group delivery failed")


def _worker_loop() -> None:
    assert _delivery_queue is not None
    while True:
        item = _delivery_queue.get()
        try:
            if item is None:
                return
            if isinstance(item, dict):
                ids = list(item.get("ids") or [])
                channels_only = bool(item.get("channels_only"))
            else:
                # Legacy bare list of event ids (tests / older callers).
                ids = list(item)
                channels_only = False
            if not channels_only:
                _dispatch_event_ids(ids)
            try:
                from .channels import deliver_channel_event_ids

                deliver_channel_event_ids(ids)
            except Exception:
                log.exception("recipient-group delivery failed")
        except Exception:
            log.exception("webhook delivery worker failed")
        finally:
            _delivery_queue.task_done()


def wait_delivery_idle(timeout: float = 30.0) -> bool:
    """Block until the event queue and per-hook pool are idle (tests)."""
    q = _delivery_queue
    if q is not None:
        done = threading.Event()

        def _join_q() -> None:
            q.join()
            done.set()

        threading.Thread(target=_join_q, name="webhook-queue-join", daemon=True).start()
        if not done.wait(timeout):
            return False
    deadline = time.monotonic() + timeout
    with _hook_idle:
        while _hook_inflight > 0 or _hook_pending or _hook_busy:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return False
            _hook_idle.wait(timeout=remaining)
    return True


def deliver_event_ids(event_ids: list[int]) -> None:
    """Deliver events synchronously (no DB lock during HTTP). Used by wait=True callers/tests.

    Posts each matching hook (chunked at ``MAX_BATCH_EVENTS``); hooks run concurrently in a
    local pool and this call waits for all of them.
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
    with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="webhook-sync") as pool:
        futures = [pool.submit(_post_and_record, item) for item in plan]
        for fut in futures:
            fut.result()


def _dispatch_event_ids(event_ids: list[int]) -> None:
    """Load plan and hand each hook to the pool without waiting (async path)."""
    try:
        plan = _load_delivery_plan(event_ids)
    except Exception:
        log.exception("webhook delivery plan load failed")
        return
    for item in plan:
        _submit_hook_job(item)


def _drop_label(n: int) -> str:
    return "1 event" if n == 1 else f"{n} events"


def _submit_hook_job(item: dict) -> None:
    """Ensure at most one in-flight delivery chain per hook; coalesce extras onto pending."""
    global _hook_inflight
    hid = item["hook_id"]
    overflow: list[dict] = []
    start_now = False
    pool = None
    with _hook_state_lock:
        if hid in _hook_busy:
            bucket = _hook_pending.setdefault(hid, [])
            room = max(0, MAX_PENDING_EVENTS_PER_HOOK - len(bucket))
            if room:
                bucket.extend(item["events"][:room])
            overflow = list(item["events"][room:])
        else:
            _hook_busy.add(hid)
            _hook_inflight += 1
            pool = _hook_pool
            start_now = True
    if overflow:
        _record_hook_result(
            hid,
            ok=False,
            err=f"{_drop_label(len(overflow))} dropped: pending cap ({MAX_PENDING_EVENTS_PER_HOOK})",
        )
    if not start_now:
        return
    if pool is None:
        with _hook_state_lock:
            _hook_busy.discard(hid)
            _hook_inflight = max(0, _hook_inflight - 1)
            _hook_idle.notify_all()
        _post_and_record(item)
        return
    pool.submit(_hook_pool_run, item)


def _hook_pool_run(item: dict) -> None:
    """Drain this hook's work (including coalesced pending events), then mark idle."""
    global _hook_inflight
    hid = item["hook_id"]
    try:
        while True:
            _post_and_record(item)
            with _hook_state_lock:
                pending = _hook_pending.pop(hid, None)
                if not pending:
                    _hook_busy.discard(hid)
                    break
                item = {
                    "hook_id": hid,
                    "url": item["url"],
                    "host": item["host"],
                    "secret": item["secret"],
                    "events": pending,
                }
    except Exception:
        log.exception("webhook hook-pool job failed for %s", hid)
        with _hook_state_lock:
            _hook_busy.discard(hid)
            _hook_pending.pop(hid, None)
    finally:
        with _hook_state_lock:
            _hook_inflight = max(0, _hook_inflight - 1)
            _hook_idle.notify_all()


def _post_and_record(item: dict) -> None:
    try:
        ok, err = _post_hook_batches(item)
    except Exception as exc:
        ok, err = False, str(exc)[:500]
        log.warning(
            "webhook %s (%s) delivery raised: %s",
            item["hook_id"],
            item["host"],
            type(exc).__name__,
        )
    _record_hook_result(item["hook_id"], ok=ok, err=err)


def _record_dropped_events(event_ids: list[int], reason: str) -> None:
    """Surface dropped deliveries on matching hooks' last_error (not only logs)."""
    try:
        plan = _load_delivery_plan(event_ids)
    except Exception:
        log.exception("failed to load plan for dropped webhook events")
        return
    for item in plan:
        n = len(item["events"])
        _record_hook_result(item["hook_id"], ok=False, err=f"{_drop_label(n)} dropped: {reason}")


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
        # Webhooks attached to a recipient group are group-managed — skip global fan-out.
        from .channels import group_managed_webhook_ids

        managed = group_managed_webhook_ids(db)
        jobs: list[dict] = []
        for hook in hooks:
            if hook.id in managed:
                continue
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
    """POST with a hard whole-request wall-clock deadline. Returns status code.

    Connect timeout is capped near ``HTTP_CONNECT_TIMEOUT``; read/write may use the full
    deadline. A watchdog closes the client when the wall clock expires so header trickling
    cannot outlive the budget. Error text includes the real elapsed time.
    """
    started = time.monotonic()
    timeout = httpx.Timeout(
        connect=min(HTTP_CONNECT_TIMEOUT, deadline),
        read=deadline,
        write=deadline,
        pool=min(HTTP_CONNECT_TIMEOUT, deadline),
    )
    client = httpx.Client(timeout=timeout)
    done = threading.Event()

    def _watchdog() -> None:
        if not done.wait(timeout=deadline):
            try:
                client.close()
            except Exception:
                pass

    threading.Thread(target=_watchdog, name="webhook-deadline", daemon=True).start()
    try:
        with client.stream("POST", url, content=body, headers=headers) as response:
            status = response.status_code
            for _chunk in response.iter_bytes():
                if time.monotonic() - started >= deadline:
                    raise TimeoutError(_timeout_message(time.monotonic() - started))
            elapsed = time.monotonic() - started
            if elapsed >= deadline:
                raise TimeoutError(_timeout_message(elapsed))
            return status
    except TimeoutError:
        raise
    except Exception as exc:
        elapsed = time.monotonic() - started
        # Watchdog close / deadline expiry surfaces as transport errors; report real elapsed.
        if elapsed >= deadline * 0.9:
            raise TimeoutError(_timeout_message(elapsed)) from exc
        raise
    finally:
        done.set()
        try:
            client.close()
        except Exception:
            pass


def _post_hook_batches(item: dict) -> tuple[bool, str | None]:
    """HTTP only — no DB session. Posts each chunk; returns (ok, error_message)."""
    chunks = _chunks(item["events"], MAX_BATCH_EVENTS)
    last_err: str | None = None
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
                row.last_error_at = None
            else:
                row.last_error = err
                row.last_error_at = utcnow()
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
