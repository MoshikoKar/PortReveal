"""Recipient-group (channel) delivery: route events by what / how / when / how much.

Load → close session → HTTP/SMTP (concurrent, 8s deadline) → short status write.
Reuses the shared webhook delivery queue (no new thread per call). Slack/Teams get
native cards; email digests reuse the HTML daily-summary formatter.
"""

from __future__ import annotations

import concurrent.futures
import hashlib
import json
import logging
from datetime import datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from ..db import SessionLocal, get_engine, session_scope, utcnow
from ..models import (
    DELIVERY_DAILY,
    DELIVERY_HOURLY,
    DELIVERY_IMMEDIATE,
    DEST_EMAIL,
    DEST_SLACK,
    DEST_TEAMS,
    DEST_WEBHOOK,
    EV_CVE_WATCH_MATCH,
    SEVERITY_RANK,
    Event,
    RecipientDestination,
    RecipientGroup,
    RecipientHold,
    WebhookEndpoint,
)
from ..security import decrypt_secret
from ..settings_store import NotificationSettings, get_section
from .notify import SUBJECT_PREFIX, format_daily_digest, send_email
from .webhooks import HTTP_DEADLINE, USER_AGENT, _host, _http_post, _sign

log = logging.getLogger(__name__)

HOLD_DIGEST = "digest"
HOLD_HOURLY = "hourly"
HOLD_RATE = "rate_cap"
HOLD_QUIET = "quiet"
HOLD_DEDUPE = "dedupe"

MAX_HOLD_ATTEMPTS = 8
# Backoff seconds by attempt index (1-based after failure): 1m, 5m, 15m, 30m, 1h, 2h, 4h, 8h
_BACKOFF_SECONDS = (60, 300, 900, 1800, 3600, 7200, 14400, 28800)


def schedule_channel_delivery(event_ids: list[int]) -> None:
    """Enqueue channel routing on the shared webhook delivery queue (preferred).

    Prefer calling via ``schedule_event_delivery`` so scan threads stay free. This entry
    point exists for CVE watchlist and tests that need channels without global webhooks.
    """
    ids = [i for i in event_ids if i]
    if not ids:
        return
    from . import webhooks as wh

    wh.enqueue_channel_delivery(ids)


def deliver_channel_event_ids(event_ids: list[int]) -> None:
    """Synchronous channel routing (tests / wait=True / worker)."""
    _route_event_ids([i for i in event_ids if i])


def group_matches_event(group: RecipientGroup, ev: Event) -> bool:
    """WHAT filters: event type, min severity, network scope. Alert-only (notify=True)."""
    if not ev.notify:
        return False
    types = group.event_types or []
    if types and ev.event_type not in types:
        return False
    min_rank = SEVERITY_RANK.get(group.min_severity or "info", 0)
    ev_rank = SEVERITY_RANK.get(ev.severity or "info", 0)
    if ev_rank < min_rank:
        return False
    net_ids = group.network_ids or []
    if net_ids:
        dev = ev.device
        nid = getattr(dev, "network_id", None) if dev is not None else None
        if nid is None or nid not in net_ids:
            return False
    return True


def group_managed_webhook_ids(db: Session) -> set[int]:
    """Webhook endpoint ids owned by an *enabled* group destination (skip global delivery)."""
    rows = db.scalars(
        select(RecipientDestination.webhook_id)
        .join(RecipientGroup, RecipientDestination.group_id == RecipientGroup.id)
        .where(
            RecipientGroup.enabled.is_(True),
            RecipientDestination.enabled.is_(True),
            RecipientDestination.kind == DEST_WEBHOOK,
            RecipientDestination.webhook_id.is_not(None),
        )
    ).all()
    return {int(wid) for wid in rows if wid is not None}


def emails_covered_by_groups_for_cve(db: Session) -> set[str]:
    """Email addresses on enabled groups that accept CVE watchlist matches (avoid double-send)."""
    groups = list(
        db.scalars(
            select(RecipientGroup).where(RecipientGroup.enabled.is_(True)).options(selectinload(RecipientGroup.destinations))
        )
        .unique()
        .all()
    )
    covered: set[str] = set()
    for g in groups:
        types = g.event_types or []
        if types and EV_CVE_WATCH_MATCH not in types:
            continue
        for d in g.destinations or []:
            if d.enabled and d.kind == DEST_EMAIL and d.target:
                covered.add(d.target.strip().lower())
    return covered


def _is_critical(ev: Event | dict) -> bool:
    if isinstance(ev, dict):
        return (ev.get("severity") or "") == "high" or ev.get("type") == EV_CVE_WATCH_MATCH
    return (ev.severity or "") == "high" or ev.event_type == EV_CVE_WATCH_MATCH


def _in_quiet_hours(quiet_start: str | None, quiet_end: str | None, now: datetime) -> bool:
    if not quiet_start or not quiet_end:
        return False
    try:
        sh, sm = (int(x) for x in quiet_start.split(":"))
        eh, em = (int(x) for x in quiet_end.split(":"))
    except ValueError:
        return False
    mins = now.hour * 60 + now.minute
    start = sh * 60 + sm
    end = eh * 60 + em
    if start == end:
        return False
    if start < end:
        return start <= mins < end
    return mins >= start or mins < end


def _dedupe_key(ev: Event) -> str:
    raw = f"{ev.event_type}|{ev.ip}|{ev.port}|{ev.protocol}|{ev.message}"
    return hashlib.sha256(raw.encode()).hexdigest()[:40]


def _hour_bucket(now: datetime) -> str:
    return now.strftime("%Y%m%d%H")


def _route_event_ids(event_ids: list[int]) -> None:
    """Route events: short DB write for holds / rate bookkeeping, then deliver outside the session.

    Immediate mode batches all matching events in this delivery round into one message per
    destination (not one message per event).
    """
    if not event_ids:
        return
    get_engine()
    immediate_jobs: list[dict] = []
    db = SessionLocal()
    try:
        groups = list(
            db.scalars(
                select(RecipientGroup)
                .where(RecipientGroup.enabled.is_(True))
                .options(selectinload(RecipientGroup.destinations))
                .order_by(RecipientGroup.id)
            )
            .unique()
            .all()
        )
        if not groups:
            return
        events = list(db.scalars(select(Event).where(Event.id.in_(event_ids)).order_by(Event.id)).unique().all())
        if not events:
            return
        cfg = get_section(db, NotificationSettings)
        cfg_snap = _cfg_snap(cfg)
        now = utcnow().astimezone()

        for group in groups:
            destinations = [d for d in (group.destinations or []) if d.enabled]
            if not destinations:
                continue
            matched: list[Event] = []
            for ev in events:
                if not group_matches_event(group, ev):
                    continue
                key = _dedupe_key(ev)
                if group.dedupe_seconds and group.dedupe_seconds > 0:
                    cutoff = utcnow() - timedelta(seconds=group.dedupe_seconds)
                    recent = db.scalar(
                        select(RecipientHold.id)
                        .where(
                            RecipientHold.group_id == group.id,
                            RecipientHold.dedupe_key == key,
                            RecipientHold.created_at >= cutoff,
                        )
                        .limit(1)
                    )
                    if recent:
                        continue
                quiet = _in_quiet_hours(group.quiet_start, group.quiet_end, now)
                if quiet and not (group.quiet_bypass_critical and _is_critical(ev)):
                    _hold(db, group.id, ev.id, HOLD_QUIET, key)
                    continue
                mode = group.delivery_mode or DELIVERY_DAILY
                if mode == DELIVERY_DAILY:
                    _hold(db, group.id, ev.id, HOLD_DIGEST, key)
                    continue
                if mode == DELIVERY_HOURLY:
                    _hold(db, group.id, ev.id, HOLD_HOURLY, key)
                    continue
                # Immediate — collect for one batched send; rate-cap overflow → digest hold.
                bucket = _hour_bucket(now)
                if group.rate_hour_bucket != bucket:
                    group.rate_hour_bucket = bucket
                    group.rate_sent = 0
                if group.rate_sent >= max(1, group.max_per_hour or 20):
                    _hold(db, group.id, ev.id, HOLD_RATE, key)
                    continue
                matched.append(ev)
                # Do not create HOLD_DEDUPE before send — a pre-send dedupe hold
                # blocked retry holds on failure (unique group+event). Record
                # dedupe only after a successful delivery.

            if matched:
                n = len(matched)
                # Count one message toward the hourly cap (batched).
                group.rate_sent = (group.rate_sent or 0) + 1
                # Snapshot dedupe keys for post-success HOLD_DEDUPE.
                keys = {_dedupe_key(e): e.id for e in matched}
                immediate_jobs.append(
                    {
                        "group_id": group.id,
                        "group_name": group.name,
                        "event_ids": [e.id for e in matched],
                        "destinations": _dest_snaps(db, destinations),
                        "cfg": cfg_snap,
                        "rate_count": n,
                        "dedupe_keys": keys,
                        "dedupe_seconds": group.dedupe_seconds or 0,
                    }
                )
        db.commit()
    finally:
        db.close()

    for job in immediate_jobs:
        try:
            _deliver_job(job)
        except Exception:
            log.exception("channel immediate delivery failed for group %s", job.get("group_id"))


def _cfg_snap(cfg: NotificationSettings) -> dict:
    return {
        "enabled": cfg.enabled,
        "smtp_host": cfg.smtp_host,
        "smtp_port": cfg.smtp_port,
        "security": cfg.security,
        "username": cfg.username,
        "password_enc": cfg.password_enc,
        "sender": cfg.sender,
        "recipients": list(cfg.recipients),
    }


def _dest_snaps(db: Session, destinations: list[RecipientDestination]) -> list[dict]:
    snaps = []
    for d in destinations:
        snap = {
            "id": d.id,
            "kind": d.kind,
            "target": d.target,
            "webhook_id": d.webhook_id,
            "url": decrypt_secret(d.url_enc) if d.url_enc else "",
            "secret": "",
        }
        if d.kind == DEST_WEBHOOK and d.webhook_id:
            hook = db.get(WebhookEndpoint, d.webhook_id)
            if hook and hook.enabled:
                snap["url"] = hook.url
                snap["secret"] = decrypt_secret(hook.secret_enc) if hook.secret_enc else ""
            else:
                snap["url"] = ""
        snaps.append(snap)
    return snaps


def _hold(
    db: Session,
    group_id: int,
    event_id: int,
    reason: str,
    key: str | None,
    *,
    pending_dest_ids: list[int] | None = None,
    attempts: int = 0,
    next_attempt_at: datetime | None = None,
) -> RecipientHold:
    """Insert or return existing hold for (group, event). Does not overwrite on conflict."""
    existing = db.scalar(
        select(RecipientHold).where(
            RecipientHold.group_id == group_id,
            RecipientHold.event_id == event_id,
        )
    )
    if existing:
        return existing
    h = RecipientHold(
        group_id=group_id,
        event_id=event_id,
        reason=reason,
        dedupe_key=key,
        attempts=attempts,
        next_attempt_at=next_attempt_at,
        pending_dest_ids=pending_dest_ids,
        created_at=utcnow(),
    )
    db.add(h)
    db.flush()
    return h


def _mark_hold_retry(
    h: RecipientHold,
    *,
    pending_dest_ids: list[int] | None,
) -> None:
    """Bump attempts / backoff; convert dedupe markers into retryable rate holds."""
    attempts = (h.attempts or 0) + 1
    h.attempts = attempts
    if h.reason == HOLD_DEDUPE:
        h.reason = HOLD_RATE
    h.pending_dest_ids = pending_dest_ids
    if attempts >= MAX_HOLD_ATTEMPTS:
        return  # caller deletes
    delay = _BACKOFF_SECONDS[min(attempts, len(_BACKOFF_SECONDS)) - 1]
    h.next_attempt_at = utcnow() + timedelta(seconds=delay)


def flush_due_holds(*, hourly: bool = False) -> None:
    """Flush holds that are due. Call on every scheduler tick.

    Daily groups flush at their own ``digest_time`` (tracked via ``last_digest_on``),
    independent of the legacy email master switch. Hourly / rate / quiet / retries as due.
    Failed deliveries keep holds and schedule backoff retries (capped).
    """
    get_engine()
    jobs: list[dict] = []
    db = SessionLocal()
    try:
        cfg = get_section(db, NotificationSettings)
        cfg_snap = _cfg_snap(cfg)
        now = utcnow().astimezone()
        today = now.date().isoformat()
        groups = list(
            db.scalars(
                select(RecipientGroup).where(RecipientGroup.enabled.is_(True)).options(selectinload(RecipientGroup.destinations))
            )
            .unique()
            .all()
        )
        for group in groups:
            destinations = [d for d in (group.destinations or []) if d.enabled]
            if not destinations:
                continue
            reasons: list[str] = []
            claim_daily = False
            if group.delivery_mode == DELIVERY_DAILY:
                if group.last_digest_on != today and _daily_due(group.digest_time, now):
                    reasons.append(HOLD_DIGEST)
                    claim_daily = True
            if hourly and group.delivery_mode == DELIVERY_HOURLY:
                reasons.append(HOLD_HOURLY)
            if hourly or (group.delivery_mode == DELIVERY_IMMEDIATE and claim_daily):
                reasons.append(HOLD_RATE)
            if not _in_quiet_hours(group.quiet_start, group.quiet_end, now):
                reasons.append(HOLD_QUIET)

            uniq: list[str] = []
            for r in reasons:
                if r not in uniq:
                    uniq.append(r)

            # Holds ready now: matching reason OR retry due.
            q = select(RecipientHold).where(
                RecipientHold.group_id == group.id,
                RecipientHold.reason != HOLD_DEDUPE,
            )
            holds = list(db.scalars(q.order_by(RecipientHold.id)).all())
            ready: list[RecipientHold] = []
            for h in holds:
                if h.next_attempt_at and h.next_attempt_at > utcnow():
                    continue
                if h.attempts and h.attempts > 0:
                    ready.append(h)  # retry
                elif h.reason in uniq:
                    ready.append(h)
            if not ready:
                continue

            event_ids = [h.event_id for h in ready]
            events = list(db.scalars(select(Event).where(Event.id.in_(event_ids)).order_by(Event.id)).unique().all())
            if not events:
                for h in ready:
                    db.delete(h)
                continue
            hold_ids = [h.id for h in ready]
            # Intersect pending dest ids across ready holds (None = all dests).
            pending: set[int] | None = None
            for h in ready:
                ids = h.pending_dest_ids
                if not ids:
                    pending = None
                    break
                pending = set(ids) if pending is None else (pending & set(ids))
            dest_snaps = _dest_snaps(db, destinations)
            if pending is not None:
                dest_snaps = [d for d in dest_snaps if d.get("id") in pending]
                if not dest_snaps:
                    # Stale pending ids — fall back to all enabled destinations.
                    dest_snaps = _dest_snaps(db, destinations)
            jobs.append(
                {
                    "group_id": group.id,
                    "group_name": group.name,
                    "event_ids": [e.id for e in events],
                    "hold_ids": hold_ids,
                    "destinations": dest_snaps,
                    "cfg": cfg_snap,
                    "claim_daily": claim_daily,
                    "digest_day": today if claim_daily else None,
                    "pending_dest_ids": sorted(pending) if pending is not None else None,
                }
            )
        db.commit()
    except Exception:
        log.exception("flush_due_holds plan failed")
        db.rollback()
        return
    finally:
        db.close()

    for job in jobs:
        try:
            _deliver_job(job)
        except Exception:
            log.exception("channel flush delivery failed for group %s", job.get("group_id"))


def _daily_due(digest_time: str | None, now: datetime) -> bool:
    raw = (digest_time or "08:00").strip() or "08:00"
    try:
        hh, mm = (int(x) for x in raw.split(":"))
    except ValueError:
        hh, mm = 8, 0
    due = now.replace(hour=hh, minute=mm, second=0, microsecond=0)
    return now >= due


def daily_seed_last_digest_on(digest_time: str | None, now: datetime | None = None) -> str | None:
    """If today's digest time already passed, return today's date iso so we wait until tomorrow."""
    now = now or utcnow().astimezone()
    if _daily_due(digest_time, now):
        return now.date().isoformat()
    return None


def _deliver_job(job: dict) -> None:
    """HTTP/SMTP with no open DB session; then short write for status / holds."""
    event_ids: list[int] = job["event_ids"]
    destinations = list(job.get("destinations") or [])
    # Load event cards + ORM rows for HTML digest in a short read session.
    get_engine()
    db = SessionLocal()
    try:
        events = (
            list(db.scalars(select(Event).where(Event.id.in_(event_ids)).order_by(Event.id)).unique().all()) if event_ids else []
        )
        cards = [_event_card(ev) for ev in events]
        # Detach plain dicts for SMTP HTML builder (needs Event-like attrs) — use cards + format from Events before close.
        html_pack = None
        if any(d["kind"] == DEST_EMAIL for d in destinations) and events:
            subject, plain, html_body = format_daily_digest(events)
            # Retitle for the group.
            n = len(events)
            subject = f"{SUBJECT_PREFIX} {job['group_name']} — {n} event{'s' if n != 1 else ''}"
            html_pack = (subject, plain, html_body)
    finally:
        db.close()

    if not cards and event_ids:
        return
    if not destinations:
        return

    results = _send_destinations_concurrent(
        destinations,
        cards,
        job["cfg"],
        job["group_name"],
        html_pack=html_pack,
    )
    failed = [r for r in results if not r.get("ok")]
    succeeded = [r for r in results if r.get("ok")]
    all_ok = bool(results) and not failed
    last_err = next((r["error"] for r in failed), None)
    failed_dest_ids = [r["dest_id"] for r in failed if r.get("dest_id") is not None]
    # Preserve previously-pending dests that were not attempted this round.
    prior_pending = job.get("pending_dest_ids")
    if prior_pending and failed_dest_ids:
        # Keep any prior pending that we did not try (should be none if filtered correctly).
        attempted = {d.get("id") for d in destinations}
        leftover = [i for i in prior_pending if i not in attempted]
        failed_dest_ids = sorted(set(failed_dest_ids) | set(leftover))

    db = SessionLocal()
    try:
        group = db.get(RecipientGroup, job["group_id"])
        if group is None:
            return
        if all_ok:
            group.last_success_at = utcnow()
            # Keep last_error / last_error_at visible after later success (do not clear).
            if job.get("claim_daily") and job.get("digest_day"):
                group.last_digest_on = job["digest_day"]
            hold_ids = job.get("hold_ids") or []
            if hold_ids:
                for h in db.scalars(select(RecipientHold).where(RecipientHold.id.in_(hold_ids))).all():
                    db.delete(h)
            # Dedupe markers after successful immediate delivery.
            dedupe_keys: dict = job.get("dedupe_keys") or {}
            if job.get("dedupe_seconds") and dedupe_keys:
                for key, eid in dedupe_keys.items():
                    _hold(db, group.id, eid, HOLD_DEDUPE, key)
            # Mark email-notified when an email destination succeeded (legacy digest retired).
            if any(r.get("ok") and r.get("kind") == DEST_EMAIL for r in succeeded):
                now = utcnow()
                for ev in db.scalars(select(Event).where(Event.id.in_(event_ids), Event.notified_at.is_(None))).all():
                    ev.notified_at = now
        else:
            group.last_error = (last_err or "delivery failed")[:500]
            group.last_error_at = utcnow()
            pending = failed_dest_ids or None
            hold_ids = job.get("hold_ids") or []
            if hold_ids:
                for h in db.scalars(select(RecipientHold).where(RecipientHold.id.in_(hold_ids))).all():
                    _mark_hold_retry(h, pending_dest_ids=pending)
                    if (h.attempts or 0) >= MAX_HOLD_ATTEMPTS:
                        db.delete(h)
            else:
                # Immediate failure: queue retry holds (one per event; pending dests only).
                dedupe_keys = job.get("dedupe_keys") or {}
                key_by_eid = {eid: key for key, eid in dedupe_keys.items()}
                for eid in event_ids:
                    h = db.scalar(
                        select(RecipientHold).where(
                            RecipientHold.group_id == group.id,
                            RecipientHold.event_id == eid,
                        )
                    )
                    if h is None:
                        h = RecipientHold(
                            group_id=group.id,
                            event_id=eid,
                            reason=HOLD_RATE,
                            dedupe_key=key_by_eid.get(eid),
                            attempts=0,
                            pending_dest_ids=pending,
                            created_at=utcnow(),
                        )
                        db.add(h)
                        db.flush()
                    _mark_hold_retry(h, pending_dest_ids=pending)
                    if (h.attempts or 0) >= MAX_HOLD_ATTEMPTS:
                        db.delete(h)
        db.commit()
    except Exception:
        log.exception("channel delivery status write failed for group %s", job.get("group_id"))
        db.rollback()
    finally:
        db.close()


def _send_destinations_concurrent(
    destinations: list[dict],
    cards: list[dict],
    cfg: dict,
    group_name: str,
    *,
    html_pack: tuple[str, str, str] | None,
) -> list[dict]:
    if not destinations:
        return []

    def _one(snap: dict) -> dict:
        kind = snap["kind"]
        dest_id = snap.get("id")
        base = {"ok": True, "kind": kind, "dest_id": dest_id, "error": None}
        try:
            if kind == DEST_EMAIL:
                if not snap.get("target"):
                    return base
                _send_email_events(cfg, snap["target"], cards, group_name=group_name, html_pack=html_pack)
            elif kind == DEST_SLACK:
                if not snap.get("url"):
                    return base
                _post_json(snap["url"], _slack_payload(cards, group_name), secret="")
            elif kind == DEST_TEAMS:
                if not snap.get("url"):
                    return base
                _post_json(snap["url"], _teams_payload(cards, group_name), secret="")
            elif kind == DEST_WEBHOOK:
                if not snap.get("url"):
                    return base
                body = _webhook_body(cards)
                _post_json(snap["url"], None, secret=snap.get("secret") or "", raw=body)
            else:
                return base
            return base
        except Exception as exc:
            log.warning(
                "recipient group dest %s failed for host %s: %s",
                kind,
                _host(snap.get("url") or "") if snap.get("url") else "(email)",
                type(exc).__name__,
            )
            return {"ok": False, "kind": kind, "dest_id": dest_id, "error": str(exc)[:500]}

    results: list[dict] = []
    wait_s = HTTP_DEADLINE + 2
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(8, len(destinations))) as pool:
        fut_to_snap = {pool.submit(_one, snap): snap for snap in destinations}
        pending = dict(fut_to_snap)
        try:
            for fut in concurrent.futures.as_completed(fut_to_snap, timeout=wait_s):
                snap = pending.pop(fut, None)
                try:
                    results.append(fut.result(timeout=0))
                except Exception as exc:
                    results.append(
                        {
                            "ok": False,
                            "kind": (snap or {}).get("kind", "?"),
                            "dest_id": (snap or {}).get("id"),
                            "error": str(exc)[:500],
                        }
                    )
        except TimeoutError:
            # Per-destination deadline: record unfinished work as failed so the
            # scheduler does not resend the same digest every tick, and other
            # groups in this tick are not aborted.
            for fut, snap in list(pending.items()):
                if fut.done():
                    try:
                        results.append(fut.result(timeout=0))
                    except Exception as exc:
                        results.append(
                            {
                                "ok": False,
                                "kind": snap.get("kind", "?"),
                                "dest_id": snap.get("id"),
                                "error": str(exc)[:500],
                            }
                        )
                else:
                    fut.cancel()
                    results.append(
                        {
                            "ok": False,
                            "kind": snap.get("kind", "?"),
                            "dest_id": snap.get("id"),
                            "error": f"delivery timed out after {wait_s:.0f}s",
                        }
                    )
    return results


def _event_card(ev: Event) -> dict:
    return {
        "id": ev.id,
        "type": ev.event_type,
        "severity": ev.severity,
        "ip": ev.ip,
        "port": ev.port,
        "protocol": ev.protocol,
        "message": ev.message,
        "created_at": ev.created_at.isoformat() if ev.created_at else None,
        "notify": bool(ev.notify),
    }


def _webhook_body(payloads: list[dict]) -> bytes:
    if len(payloads) == 1:
        return json.dumps(payloads[0], default=str).encode()
    return json.dumps({"batch": True, "count": len(payloads), "events": payloads}, default=str).encode()


def _slack_payload(payloads: list[dict], group_name: str) -> dict:
    lines = [f"*{group_name}* — {len(payloads)} event{'s' if len(payloads) != 1 else ''}"]
    for p in payloads[:20]:
        sev = (p.get("severity") or "info").upper()
        where = p.get("ip") or ""
        if p.get("port"):
            where = f"{where}:{p['port']}" if where else str(p["port"])
        lines.append(f"• `{sev}` {p.get('type')} — {p.get('message') or where}")
    if len(payloads) > 20:
        lines.append(f"_…and {len(payloads) - 20} more_")
    color = {"high": "#dc2626", "medium": "#d97706", "low": "#2563eb", "info": "#64748b"}.get(
        (payloads[0].get("severity") if payloads else None) or "info",
        "#64748b",
    )
    return {
        "attachments": [
            {
                "color": color,
                "mrkdwn_in": ["text"],
                "text": "\n".join(lines),
                "footer": "PortReveal",
            }
        ],
    }


def _teams_payload(payloads: list[dict], group_name: str) -> dict:
    facts = []
    for p in payloads[:15]:
        where = p.get("ip") or ""
        if p.get("port"):
            where = f"{where} {p.get('protocol') or 'tcp'}/{p['port']}".strip()
        facts.append(
            {
                "name": f"{(p.get('severity') or 'info').upper()} · {p.get('type')}",
                "value": p.get("message") or where or "—",
            }
        )
    return {
        "@type": "MessageCard",
        "@context": "https://schema.org/extensions",
        "summary": f"PortReveal · {group_name}",
        "themeColor": "0F172A",
        "title": f"PortReveal · {group_name}",
        "sections": [
            {
                "activityTitle": f"{len(payloads)} event{'s' if len(payloads) != 1 else ''}",
                "facts": facts,
            }
        ],
    }


def _send_email_events(
    cfg: dict,
    recipient: str,
    payloads: list[dict],
    *,
    group_name: str,
    html_pack: tuple[str, str, str] | None,
) -> None:
    from ..settings_store import NotificationSettings as NS

    local = NS.model_validate({**cfg, "recipients": [recipient], "enabled": True})
    # SMTP timeout must finish inside the concurrent wait (HTTP_DEADLINE + 2).
    smtp_timeout = max(1.0, HTTP_DEADLINE - 0.5)
    if html_pack:
        subject, plain, html_body = html_pack
        # Prefer group name in subject; keep categorized HTML body.
        n = len(payloads)
        subject = f"{SUBJECT_PREFIX} {group_name} — {n} event{'s' if n != 1 else ''}"
        send_email(local, subject, plain, html_body, timeout=smtp_timeout)
        return
    n = len(payloads)
    subject = f"{SUBJECT_PREFIX} {group_name} — {n} event{'s' if n != 1 else ''}"
    lines = [f"PortReveal · {group_name}", f"{n} event{'s' if n != 1 else ''}", ""]
    for p in payloads[:40]:
        lines.append(f"- [{(p.get('severity') or 'info').upper()}] {p.get('type')}: {p.get('message')}")
    if n > 40:
        lines.append(f"…and {n - 40} more")
    send_email(local, subject, "\n".join(lines), timeout=smtp_timeout)


def _post_json(url: str, payload: dict | None, *, secret: str, raw: bytes | None = None) -> None:
    body = raw if raw is not None else json.dumps(payload, default=str).encode()
    headers = {"Content-Type": "application/json", "User-Agent": USER_AGENT}
    if secret:
        headers["X-NF-Signature"] = _sign(secret, body)
    # Log host only — Slack/Teams tokens live in the URL path.
    log.debug("channel POST to %s (%d bytes)", _host(url), len(body))
    status = _http_post(url, body, headers)
    if status >= 400:
        raise RuntimeError(f"HTTP {status} from {_host(url)}")


def send_group_test(group_id: int) -> dict:
    """Send a synthetic test to every enabled destination on the group (no open write lock during I/O)."""
    get_engine()
    with session_scope() as db:
        group = db.scalar(
            select(RecipientGroup).where(RecipientGroup.id == group_id).options(selectinload(RecipientGroup.destinations))
        )
        if group is None:
            raise ValueError("group not found")
        cfg = get_section(db, NotificationSettings)
        destinations = [d for d in (group.destinations or []) if d.enabled]
        if not destinations:
            raise ValueError("group has no enabled destinations")
        job = {
            "group_id": group.id,
            "group_name": group.name,
            "event_ids": [],
            "destinations": _dest_snaps(db, destinations),
            "cfg": _cfg_snap(cfg),
            "hold_ids": [],
        }
        name = group.name
    # Synthetic card — no Event row.
    cards = [
        {
            "id": 0,
            "type": "webhook_test",
            "severity": "info",
            "ip": None,
            "port": None,
            "protocol": None,
            "message": f"PortReveal test for “{name}”",
            "created_at": utcnow().isoformat(),
            "notify": True,
        }
    ]
    results = _send_destinations_concurrent(
        job["destinations"],
        cards,
        job["cfg"],
        name,
        html_pack=None,
    )
    all_ok = all(r["ok"] for r in results) if results else False
    last_err = next((r["error"] for r in results if not r["ok"]), None)
    with session_scope() as db:
        group = db.get(RecipientGroup, group_id)
        if group:
            if all_ok:
                group.last_success_at = utcnow()
            else:
                group.last_error = (last_err or "delivery failed")[:500]
                group.last_error_at = utcnow()
    return {"ok": all_ok, "error": None if all_ok else last_err}


def network_summary_bits(network_ids: list[int] | None, names: dict[int, str]) -> str:
    """Human network scope for card summaries."""
    ids = list(network_ids or [])
    if not ids:
        return "All networks"
    labels = [names.get(i) or f"#{i}" for i in ids]
    if len(labels) == 1:
        return labels[0]
    if len(labels) == 2:
        return f"{labels[0]}, {labels[1]}"
    return f"{labels[0]}, {labels[1]} +{len(labels) - 2}"
