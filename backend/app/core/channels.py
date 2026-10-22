"""Recipient-group (channel) delivery: route events by what / how / when / how much.

Reuses the webhook HTTP helper (8s wall-clock deadline, no DB session during I/O).
Email uses the existing SMTP path. Slack and Teams get native card payloads.
"""
from __future__ import annotations

import hashlib
import json
import logging
import threading
from datetime import datetime, timedelta

from sqlalchemy import delete, select
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
from .notify import SUBJECT_PREFIX, send_email
from .webhooks import USER_AGENT, _host, _http_post, _sign

log = logging.getLogger(__name__)

HOLD_DIGEST = "digest"
HOLD_HOURLY = "hourly"
HOLD_RATE = "rate_cap"
HOLD_QUIET = "quiet"


def schedule_channel_delivery(event_ids: list[int]) -> None:
    """Enqueue channel routing off the caller thread (scan/scheduler stay free)."""
    ids = [i for i in event_ids if i]
    if not ids:
        return
    threading.Thread(
        target=_safe_deliver, args=(ids,), name="channel-delivery", daemon=True,
    ).start()


def deliver_channel_event_ids(event_ids: list[int]) -> None:
    """Synchronous channel routing (tests / wait=True)."""
    _route_event_ids([i for i in event_ids if i])


def _safe_deliver(ids: list[int]) -> None:
    try:
        _route_event_ids(ids)
    except Exception:
        log.exception("recipient-group delivery failed")


def _route_event_ids(event_ids: list[int]) -> None:
    if not event_ids:
        return
    get_engine()
    db = SessionLocal()
    try:
        groups = list(
            db.scalars(
                select(RecipientGroup)
                .where(RecipientGroup.enabled.is_(True))
                .options(selectinload(RecipientGroup.destinations))
                .order_by(RecipientGroup.id)
            ).unique().all()
        )
        if not groups:
            return
        events = list(
            db.scalars(select(Event).where(Event.id.in_(event_ids)).order_by(Event.id)).unique().all()
        )
        if not events:
            return
        cfg = get_section(db, NotificationSettings)
        now = utcnow().astimezone()
        for group in groups:
            for ev in events:
                _route_one(db, group, ev, cfg=cfg, now=now)
        db.commit()
    finally:
        db.close()


def group_matches_event(group: RecipientGroup, ev: Event) -> bool:
    """WHAT filters: event type, min severity, network scope.

    Alert-only (``notify=True``), matching the email digest default — silent/record
    events are never routed to recipient groups.
    """
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


def _is_critical(ev: Event) -> bool:
    return (ev.severity or "") == "high" or ev.event_type == EV_CVE_WATCH_MATCH


def _in_quiet_hours(group: RecipientGroup, now: datetime) -> bool:
    if not group.quiet_start or not group.quiet_end:
        return False
    try:
        sh, sm = (int(x) for x in group.quiet_start.split(":"))
        eh, em = (int(x) for x in group.quiet_end.split(":"))
    except ValueError:
        return False
    mins = now.hour * 60 + now.minute
    start = sh * 60 + sm
    end = eh * 60 + em
    if start == end:
        return False
    if start < end:
        return start <= mins < end
    return mins >= start or mins < end  # wraps midnight


def _dedupe_key(ev: Event) -> str:
    raw = f"{ev.event_type}|{ev.ip}|{ev.port}|{ev.protocol}|{ev.message}"
    return hashlib.sha256(raw.encode()).hexdigest()[:40]


def _hour_bucket(now: datetime) -> str:
    return now.strftime("%Y%m%d%H")


def _route_one(db: Session, group: RecipientGroup, ev: Event, *, cfg: NotificationSettings, now: datetime) -> None:
    if not group_matches_event(group, ev):
        return
    destinations = [d for d in (group.destinations or []) if d.enabled]
    if not destinations:
        return

    # Dedupe window: skip identical events already held/sent recently for this group.
    key = _dedupe_key(ev)
    if group.dedupe_seconds and group.dedupe_seconds > 0:
        cutoff = utcnow() - timedelta(seconds=group.dedupe_seconds)
        recent = db.scalar(
            select(RecipientHold.id).where(
                RecipientHold.group_id == group.id,
                RecipientHold.dedupe_key == key,
                RecipientHold.created_at >= cutoff,
            ).limit(1)
        )
        if recent:
            return

    quiet = _in_quiet_hours(group, now)
    if quiet and not (group.quiet_bypass_critical and _is_critical(ev)):
        _hold(db, group, ev, HOLD_QUIET, key)
        return

    mode = group.delivery_mode or DELIVERY_DAILY
    if mode == DELIVERY_DAILY:
        _hold(db, group, ev, HOLD_DIGEST, key)
        return
    if mode == DELIVERY_HOURLY:
        _hold(db, group, ev, HOLD_HOURLY, key)
        return

    # Immediate — apply rate cap; overflow rolls into digest (not dropped).
    bucket = _hour_bucket(now)
    if group.rate_hour_bucket != bucket:
        group.rate_hour_bucket = bucket
        group.rate_sent = 0
    if group.rate_sent >= max(1, group.max_per_hour or 20):
        _hold(db, group, ev, HOLD_RATE, key)
        return

    ok = _deliver_now(db, group, [ev], destinations, cfg=cfg)
    if ok:
        group.rate_sent = (group.rate_sent or 0) + 1
        group.last_success_at = utcnow()
        group.last_error = None
        group.last_error_at = None
    # Remember dedupe key via a short-lived hold marker? Use hold with reason dedupe cleaned later.
    # Store a hold row that flush_holds will skip for delivery but blocks duplicates.
    if group.dedupe_seconds:
        _hold(db, group, ev, "dedupe", key)


def _hold(db: Session, group: RecipientGroup, ev: Event, reason: str, key: str | None) -> None:
    existing = db.scalar(
        select(RecipientHold.id).where(
            RecipientHold.group_id == group.id, RecipientHold.event_id == ev.id,
        )
    )
    if existing:
        return
    db.add(RecipientHold(
        group_id=group.id, event_id=ev.id, reason=reason, dedupe_key=key, created_at=utcnow(),
    ))
    # Flush so a subsequent event in the same batch can see this row for dedupe.
    db.flush()


def flush_due_holds(*, mode: str | None = None) -> None:
    """Send held events for hourly/daily groups that are due. Called from the scheduler tick.

    Quiet-hour holds are released only when the group is no longer in quiet hours.
    Rate-cap overflow is released on the hourly tick (and on daily for immediate groups).
    """
    get_engine()
    db = SessionLocal()
    try:
        cfg = get_section(db, NotificationSettings)
        now = utcnow().astimezone()
        groups = list(
            db.scalars(
                select(RecipientGroup)
                .where(RecipientGroup.enabled.is_(True))
                .options(selectinload(RecipientGroup.destinations))
            ).unique().all()
        )
        for group in groups:
            reasons: list[str] = []
            do_hourly = mode in (None, "hourly")
            do_daily = mode in (None, "daily")
            if do_hourly and group.delivery_mode == DELIVERY_HOURLY:
                reasons.append(HOLD_HOURLY)
            if do_daily and group.delivery_mode == DELIVERY_DAILY:
                reasons.append(HOLD_DIGEST)
            # Rate-cap overflow rolls into the next digest/hourly flush (never dropped).
            if do_hourly or (do_daily and group.delivery_mode == DELIVERY_IMMEDIATE):
                reasons.append(HOLD_RATE)
            # Release quiet holds only once quiet hours have ended.
            if (do_hourly or do_daily) and not _in_quiet_hours(group, now):
                reasons.append(HOLD_QUIET)
            # Deduplicate while preserving order
            uniq: list[str] = []
            for r in reasons:
                if r not in uniq:
                    uniq.append(r)
            reasons = uniq
            if not reasons:
                continue
            holds = list(
                db.scalars(
                    select(RecipientHold).where(
                        RecipientHold.group_id == group.id,
                        RecipientHold.reason.in_(reasons),
                    ).order_by(RecipientHold.id)
                ).all()
            )
            holds = [h for h in holds if h.reason != "dedupe"]
            if not holds:
                continue
            event_ids = [h.event_id for h in holds]
            events = list(db.scalars(select(Event).where(Event.id.in_(event_ids)).order_by(Event.id)).unique().all())
            destinations = [d for d in (group.destinations or []) if d.enabled]
            if not events or not destinations:
                continue
            ok = _deliver_now(db, group, events, destinations, cfg=cfg)
            for h in holds:
                db.delete(h)
            if ok:
                group.last_success_at = utcnow()
                group.last_error = None
                group.last_error_at = None
            if group.dedupe_seconds:
                cutoff = utcnow() - timedelta(seconds=group.dedupe_seconds)
                db.execute(
                    delete(RecipientHold).where(
                        RecipientHold.group_id == group.id,
                        RecipientHold.reason == "dedupe",
                        RecipientHold.created_at < cutoff,
                    )
                )
        db.commit()
    except Exception:
        log.exception("flush_due_holds failed")
        db.rollback()
    finally:
        db.close()


def _deliver_now(
    db: Session,
    group: RecipientGroup,
    events: list[Event],
    destinations: list[RecipientDestination],
    *,
    cfg: NotificationSettings,
) -> bool:
    """Deliver to all destinations. HTTP/SMTP run with no open write intent beyond this session's
    already-loaded rows; we commit after. Returns True if every destination succeeded."""
    # Snapshot destinations for I/O outside any assumption of lock duration.
    snaps = []
    for d in destinations:
        snaps.append({
            "id": d.id,
            "kind": d.kind,
            "target": d.target,
            "webhook_id": d.webhook_id,
            "url": decrypt_secret(d.url_enc) if d.url_enc else "",
        })
    # Resolve webhook URLs while session is open.
    for snap in snaps:
        if snap["kind"] == DEST_WEBHOOK and snap["webhook_id"]:
            hook = db.get(WebhookEndpoint, snap["webhook_id"])
            if hook and hook.enabled:
                snap["url"] = hook.url
                snap["secret"] = decrypt_secret(hook.secret_enc) if hook.secret_enc else ""
            else:
                snap["url"] = ""

    payloads = [_event_card(ev) for ev in events]
    all_ok = True
    last_err: str | None = None
    email_ok = False
    for snap in snaps:
        try:
            if snap["kind"] == DEST_EMAIL:
                if not snap["target"]:
                    continue
                _send_email_events(cfg, snap["target"], payloads, group_name=group.name)
                email_ok = True
            elif snap["kind"] == DEST_SLACK:
                if not snap["url"]:
                    continue
                _post_json(snap["url"], _slack_payload(payloads, group.name), secret="")
            elif snap["kind"] == DEST_TEAMS:
                if not snap["url"]:
                    continue
                _post_json(snap["url"], _teams_payload(payloads, group.name), secret="")
            elif snap["kind"] == DEST_WEBHOOK:
                if not snap["url"]:
                    continue
                body = _webhook_body(payloads)
                _post_json(snap["url"], None, secret=snap.get("secret") or "", raw=body)
            else:
                continue
        except Exception as exc:
            all_ok = False
            last_err = str(exc)[:500]
            log.warning(
                "recipient group %s dest %s failed: %s",
                group.id, snap["kind"], type(exc).__name__,
            )
    if not all_ok:
        group.last_error = last_err or "delivery failed"
        group.last_error_at = utcnow()
    # Mark email-notified so the legacy daily digest does not double-send the same events.
    if email_ok:
        now = utcnow()
        for ev in events:
            if ev.id and ev.notified_at is None:
                ev.notified_at = now
    return all_ok


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
        (payloads[0].get("severity") if payloads else None) or "info", "#64748b",
    )
    return {
        "attachments": [{
            "color": color,
            "mrkdwn_in": ["text"],
            "text": "\n".join(lines),
            "footer": "PortReveal",
        }],
    }


def _teams_payload(payloads: list[dict], group_name: str) -> dict:
    facts = []
    for p in payloads[:15]:
        where = p.get("ip") or ""
        if p.get("port"):
            where = f"{where} {p.get('protocol') or 'tcp'}/{p['port']}".strip()
        facts.append({
            "name": f"{(p.get('severity') or 'info').upper()} · {p.get('type')}",
            "value": p.get("message") or where or "—",
        })
    return {
        "@type": "MessageCard",
        "@context": "https://schema.org/extensions",
        "summary": f"PortReveal · {group_name}",
        "themeColor": "0F172A",
        "title": f"PortReveal · {group_name}",
        "sections": [{
            "activityTitle": f"{len(payloads)} event{'s' if len(payloads) != 1 else ''}",
            "facts": facts,
        }],
    }


def _send_email_events(cfg: NotificationSettings, recipient: str, payloads: list[dict], *, group_name: str) -> None:
    # Build a one-off cfg with a single recipient without persisting.
    local = cfg.model_copy(update={"recipients": [recipient], "enabled": True})
    n = len(payloads)
    subject = f"{SUBJECT_PREFIX} {group_name} — {n} event{'s' if n != 1 else ''}"
    lines = [f"PortReveal · {group_name}", f"{n} event{'s' if n != 1 else ''}", ""]
    for p in payloads[:40]:
        lines.append(f"- [{(p.get('severity') or 'info').upper()}] {p.get('type')}: {p.get('message')}")
    if n > 40:
        lines.append(f"…and {n - 40} more")
    send_email(local, subject, "\n".join(lines))


def _post_json(url: str, payload: dict | None, *, secret: str, raw: bytes | None = None) -> None:
    body = raw if raw is not None else json.dumps(payload, default=str).encode()
    headers = {"Content-Type": "application/json", "User-Agent": USER_AGENT}
    if secret:
        headers["X-NF-Signature"] = _sign(secret, body)
    status = _http_post(url, body, headers)
    if status >= 400:
        raise RuntimeError(f"HTTP {status} from {_host(url)}")


def send_group_test(group_id: int) -> dict:
    """Send a synthetic test to every enabled destination on the group."""
    get_engine()
    with session_scope() as db:
        group = db.scalar(
            select(RecipientGroup)
            .where(RecipientGroup.id == group_id)
            .options(selectinload(RecipientGroup.destinations))
        )
        if group is None:
            raise ValueError("group not found")
        cfg = get_section(db, NotificationSettings)
        fake = Event(
            id=0, event_type="webhook_test", severity="info",
            message=f"PortReveal test for “{group.name}”", notify=True, created_at=utcnow(),
        )
        destinations = [d for d in (group.destinations or []) if d.enabled]
        if not destinations:
            raise ValueError("group has no enabled destinations")
        # Detach snapshots before HTTP
        ok = _deliver_now(db, group, [fake], destinations, cfg=cfg)
        if ok:
            group.last_success_at = utcnow()
            group.last_error = None
            group.last_error_at = None
        return {"ok": ok, "error": None if ok else group.last_error}
