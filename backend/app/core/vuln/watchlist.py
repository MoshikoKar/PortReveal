"""CVE watchlist: alert when a subscribed CVE appears on a device/port.

Runs after vuln jobs, feed sync, vuln-import, undismiss, and immediately when a CVE is added.
Confirmed and potential findings alert; dismissed never does. Display floor (`min_cvss_display`)
is ignored.

**Delivery (commit-then-deliver):** ``check_watchlist`` only inserts events/alerts (``notify=True``
always). Callers must commit, then call ``schedule_watchlist_delivery(event_ids)`` which runs
email/webhooks in a background thread against a fresh session. Immediate email sets
``notified_at`` so the daily digest does not re-send those events; if immediate email is off or
fails, the digest still includes them via ``ALWAYS_NOTIFY_TYPES``.
"""
from __future__ import annotations

import json
import logging
import re
import threading
from datetime import datetime

from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from ...db import session_scope, utcnow
from ...models import (
    EV_CVE_WATCH_MATCH,
    EVENT_SEVERITY,
    VULN_STATE_CONFIRMED,
    VULN_STATE_DISMISSED,
    VULN_STATE_POTENTIAL,
    CveWatchlistAlert,
    CveWatchlistEntry,
    Device,
    DevicePort,
    DevicePortVuln,
    Event,
    Vulnerability,
)
from ...settings_store import NotificationSettings, get_section
from .display import normalize_cve_id

log = logging.getLogger(__name__)

CVE_ID_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
# Split bulk paste: spaces, commas, newlines, semicolons, and the word "and".
_SPLIT_RE = re.compile(r"(?:,|;|\n|\r|\band\b|\s)+", re.IGNORECASE)

STATUS_PENDING = "pending"
STATUS_NOT_FOUND = "not_found"
STATUS_FOUND = "found"
STATUS_ONLY_DISMISSED = "only_dismissed"


def validate_cve_id(raw: str) -> str:
    """Normalize and validate a CVE id. Raises ValueError with a safe message."""
    cve_id = normalize_cve_id(raw)
    if not cve_id or not CVE_ID_PATTERN.fullmatch(cve_id):
        raise ValueError(f"invalid CVE id: {raw!r}")
    return cve_id


def parse_cve_ids(text: str) -> list[str]:
    """Parse a bulk paste into unique normalized CVE ids (order preserved).

    Raises ValueError listing every invalid token when any fail validation.
    """
    parts = [p for p in _SPLIT_RE.split(text or "") if p]
    if not parts:
        raise ValueError("no CVE ids provided")
    out: list[str] = []
    seen: set[str] = set()
    invalid: list[str] = []
    for part in parts:
        try:
            cve_id = validate_cve_id(part)
        except ValueError:
            invalid.append(part)
            continue
        if cve_id not in seen:
            seen.add(cve_id)
            out.append(cve_id)
    if invalid:
        raise ValueError("invalid CVE id(s): " + ", ".join(repr(x) for x in invalid))
    return out


def _finding_rows(db: Session, *, cve_ids: list[str] | None = None):
    """Active (non-dismissed) findings for enabled watches, optionally limited to specific CVEs."""
    q = (
        select(
            CveWatchlistEntry,
            DevicePortVuln,
            DevicePort,
            Device,
            Vulnerability,
        )
        .join(DevicePortVuln, DevicePortVuln.cve_id == CveWatchlistEntry.cve_id)
        .join(DevicePort, DevicePort.id == DevicePortVuln.device_port_id)
        .join(Device, Device.id == DevicePort.device_id)
        .outerjoin(Vulnerability, Vulnerability.cve_id == DevicePortVuln.cve_id)
        .where(
            CveWatchlistEntry.enabled.is_(True),
            DevicePortVuln.state.in_((VULN_STATE_CONFIRMED, VULN_STATE_POTENTIAL)),
        )
    )
    if cve_ids is not None:
        q = q.where(CveWatchlistEntry.cve_id.in_(cve_ids))
    return db.execute(q).all()


def _prune_stale_alerts(db: Session, *, watch_ids: list[int] | None = None) -> int:
    """Drop alert rows whose finding is gone or dismissed so a reopen can alert again."""
    live = (
        select(
            CveWatchlistEntry.id.label("watch_id"),
            Device.uuid.label("device_uuid"),
            DevicePort.port,
            DevicePort.protocol,
            DevicePortVuln.cve_id,
        )
        .join(DevicePortVuln, DevicePortVuln.cve_id == CveWatchlistEntry.cve_id)
        .join(DevicePort, DevicePort.id == DevicePortVuln.device_port_id)
        .join(Device, Device.id == DevicePort.device_id)
        .where(
            CveWatchlistEntry.enabled.is_(True),
            DevicePortVuln.state != VULN_STATE_DISMISSED,
        )
    )
    if watch_ids is not None:
        live = live.where(CveWatchlistEntry.id.in_(watch_ids))
    live_keys = {
        (w, uuid, port, proto, cve)
        for w, uuid, port, proto, cve in db.execute(live).all()
    }
    alert_q = select(CveWatchlistAlert)
    if watch_ids is not None:
        alert_q = alert_q.where(CveWatchlistAlert.watch_id.in_(watch_ids))
    stale_ids = [
        a.id for a in db.scalars(alert_q).all()
        if (a.watch_id, a.device_uuid, a.port, a.protocol, a.cve_id) not in live_keys
    ]
    if not stale_ids:
        return 0
    db.execute(delete(CveWatchlistAlert).where(CveWatchlistAlert.id.in_(stale_ids)))
    return len(stale_ids)


def _event_message(
    *,
    cve_id: str,
    state: str,
    port: int,
    protocol: str,
    cvss: float | None,
    kev: bool,
) -> tuple[str, str]:
    """Return (message, new_value) for a cve_watch_match event."""
    state_label = "potential" if state == VULN_STATE_POTENTIAL else "confirmed"
    bits = [cve_id, state_label, f"{(protocol or 'tcp').upper()}/{port}"]
    if cvss is not None:
        bits.append(f"CVSS {cvss}")
    if kev:
        bits.append("KEV")
    new_value = " · ".join(bits)
    msg = f"Watched CVE {cve_id} found ({state_label}) on {(protocol or 'tcp').upper()}/{port}"
    if cvss is not None:
        msg += f" (CVSS {cvss}" + (", KEV)" if kev else ")")
    elif kev:
        msg += " (KEV)"
    return msg, new_value


def _detail_payload(
    *,
    cve_id: str,
    device: Device,
    port: int,
    protocol: str,
    state: str,
    cvss: float | None,
    kev: bool,
) -> str:
    """JSON blob stored in Event.old_value for webhook enrichment and UI links."""
    return json.dumps({
        "cve_id": cve_id,
        "device_uuid": device.uuid,
        "hostname": device.hostname,
        "ip": device.current_ip,
        "port": port,
        "protocol": protocol,
        "state": state,
        "cvss": cvss,
        "kev": kev,
    })


def check_watchlist(
    db: Session,
    *,
    cve_ids: list[str] | None = None,
    now: datetime | None = None,
) -> dict:
    """Create events for new watchlist hits. Does not send email/webhooks (commit first).

    Returns ``{"checked": N, "alerted": N, "pruned": N, "event_ids": [...]}``.
    Callers must commit, then ``schedule_watchlist_delivery(event_ids)``.
    """
    now = now or utcnow()
    watches_q = select(CveWatchlistEntry).where(CveWatchlistEntry.enabled.is_(True))
    if cve_ids is not None:
        watches_q = watches_q.where(CveWatchlistEntry.cve_id.in_(cve_ids))
    watches = list(db.scalars(watches_q).all())
    if not watches:
        return {"checked": 0, "alerted": 0, "pruned": 0, "event_ids": []}

    watch_ids = [w.id for w in watches]
    pruned = _prune_stale_alerts(db, watch_ids=watch_ids)
    db.flush()

    existing = {
        (a.watch_id, a.device_uuid, a.port, a.protocol, a.cve_id)
        for a in db.scalars(
            select(CveWatchlistAlert).where(CveWatchlistAlert.watch_id.in_(watch_ids))
        ).all()
    }

    event_ids: list[int] = []
    alerted = 0
    rows = _finding_rows(db, cve_ids=cve_ids)
    for watch, dpv, port_row, device, vuln in rows:
        key = (watch.id, device.uuid, port_row.port, port_row.protocol, dpv.cve_id)
        if key in existing:
            continue
        cvss = vuln.cvss_base if vuln is not None else None
        kev = bool(vuln.kev) if vuln is not None else False
        message, new_value = _event_message(
            cve_id=dpv.cve_id, state=dpv.state, port=port_row.port,
            protocol=port_row.protocol, cvss=cvss, kev=kev,
        )
        ev = Event(
            created_at=now,
            device_id=device.id,
            event_type=EV_CVE_WATCH_MATCH,
            severity=EVENT_SEVERITY[EV_CVE_WATCH_MATCH],
            ip=device.current_ip,
            protocol=port_row.protocol,
            port=port_row.port,
            old_value=_detail_payload(
                cve_id=dpv.cve_id, device=device, port=port_row.port,
                protocol=port_row.protocol, state=dpv.state, cvss=cvss, kev=kev,
            ),
            new_value=new_value,
            message=message,
            notify=True,  # always; immediate email vs digest is controlled via notified_at
        )
        db.add(ev)
        db.flush()
        db.add(CveWatchlistAlert(
            watch_id=watch.id,
            cve_id=dpv.cve_id,
            device_uuid=device.uuid,
            port=port_row.port,
            protocol=port_row.protocol,
            alerted_at=now,
            event_id=ev.id,
        ))
        existing.add(key)
        event_ids.append(ev.id)
        alerted += 1

    db.flush()
    return {
        "checked": len(rows),
        "alerted": alerted,
        "pruned": pruned,
        "event_ids": event_ids,
    }


def check_watchlist_safe(
    db: Session,
    *,
    cve_ids: list[str] | None = None,
    now: datetime | None = None,
) -> dict:
    """Like ``check_watchlist`` but never raises (scan/sync must keep going)."""
    try:
        return check_watchlist(db, cve_ids=cve_ids, now=now)
    except Exception:
        log.exception("CVE watchlist check failed")
        return {"checked": 0, "alerted": 0, "pruned": 0, "event_ids": [], "error": True}


def schedule_watchlist_delivery(event_ids: list[int]) -> None:
    """Best-effort background delivery after the creating transaction has committed."""
    ids = [i for i in event_ids if i]
    if not ids:
        return

    def _run() -> None:
        try:
            deliver_watchlist_alerts(ids)
        except Exception:
            log.exception("CVE watchlist background delivery failed")

    threading.Thread(target=_run, name="cve-watchlist-delivery", daemon=True).start()


def deliver_watchlist_alerts(event_ids: list[int]) -> None:
    """Send immediate email (if enabled) and webhooks for committed watchlist events.

    Immediate success marks ``notified_at`` so the daily digest will not re-send. Failures leave
    ``notified_at`` null so the digest can still pick them up via ALWAYS_NOTIFY_TYPES.
    """
    if not event_ids:
        return
    try:
        with session_scope() as db:
            cfg = get_section(db, NotificationSettings)
            if cfg.watchlist_email_enabled:
                _send_immediate_email(db, cfg, event_ids, now=utcnow())
            if cfg.watchlist_webhooks_enabled:
                from ..webhooks import deliver_event

                for ev in db.scalars(select(Event).where(Event.id.in_(event_ids)).order_by(Event.id)):
                    try:
                        deliver_event(db, ev)
                    except Exception:
                        log.exception("CVE watchlist webhook delivery failed for event %s", ev.id)
    except Exception:
        log.exception("CVE watchlist delivery session failed")


def _send_immediate_email(
    db: Session, cfg: NotificationSettings, event_ids: list[int], *, now: datetime,
) -> None:
    if not cfg.enabled or not cfg.smtp_host or not cfg.recipients:
        return
    try:
        from ..notify import SUBJECT_PREFIX, send_email

        events = list(
            db.scalars(select(Event).where(Event.id.in_(event_ids)).order_by(Event.id)).unique().all()
        )
        # Only events not already emailed (e.g. digest raced); skip already-notified.
        pending = [ev for ev in events if ev.notified_at is None]
        if not pending:
            return
        n = len(pending)
        subject = f"{SUBJECT_PREFIX} CVE watchlist - {n} match{'es' if n != 1 else ''}"
        lines = ["PortReveal CVE watchlist alert", "", f"{n} new match{'es' if n != 1 else ''}:", ""]
        html_items: list[str] = []
        for ev in pending:
            line = ev.message or ev.new_value or EV_CVE_WATCH_MATCH
            if ev.ip:
                line = f"{ev.ip}: {line}"
            lines.append(f"  • {line}")
            html_items.append(f"<li>{_esc(line)}</li>")
        plain = "\n".join(lines) + "\n"
        html_body = (
            "<!DOCTYPE html><html><body style=\"font-family:Segoe UI,Roboto,Helvetica,Arial,sans-serif;\">"
            f"<h2>CVE watchlist alert</h2><p>{n} new match{'es' if n != 1 else ''}.</p>"
            f"<ul>{''.join(html_items)}</ul>"
            "<p style=\"color:#64748b;font-size:12px;\">Full detail is in the Changes page.</p>"
            "</body></html>"
        )
        send_email(cfg, subject, plain, html_body)
        for ev in pending:
            ev.notified_at = now
        db.flush()
        log.info("Sent immediate CVE watchlist email for %d event(s)", n)
    except Exception as exc:
        from ..notify import smtp_failure_reason as _reason
        log.error("Immediate CVE watchlist email failed: %s", _reason(exc))


def _esc(value: str) -> str:
    import html as html_mod
    return html_mod.escape(value or "")


def entries_status(db: Session, entries: list[CveWatchlistEntry]) -> dict[int, dict]:
    """Bulk status for watchlist rows (few queries, not N+1)."""
    if not entries:
        return {}
    cve_ids = [e.cve_id for e in entries]
    watch_ids = [e.id for e in entries]

    known = set(db.scalars(select(Vulnerability.cve_id).where(Vulnerability.cve_id.in_(cve_ids))).all())

    # Per-CVE finding counts by state + distinct devices for open (non-dismissed) findings.
    state_rows = db.execute(
        select(
            DevicePortVuln.cve_id,
            DevicePortVuln.state,
            func.count(DevicePortVuln.id),
            func.count(func.distinct(Device.id)),
        )
        .select_from(DevicePortVuln)
        .join(DevicePort, DevicePort.id == DevicePortVuln.device_port_id)
        .join(Device, Device.id == DevicePort.device_id)
        .where(DevicePortVuln.cve_id.in_(cve_ids))
        .group_by(DevicePortVuln.cve_id, DevicePortVuln.state)
    ).all()
    by_cve: dict[str, dict] = {}
    for cve_id, state, cnt, devices in state_rows:
        slot = by_cve.setdefault(cve_id, {
            "confirmed": 0, "potential": 0, "dismissed": 0,
            "open_devices": 0, "open_findings": 0,
        })
        if state == VULN_STATE_CONFIRMED:
            slot["confirmed"] = int(cnt)
            slot["open_devices"] += int(devices or 0)
            slot["open_findings"] += int(cnt)
        elif state == VULN_STATE_POTENTIAL:
            slot["potential"] = int(cnt)
            slot["open_devices"] += int(devices or 0)
            slot["open_findings"] += int(cnt)
        elif state == VULN_STATE_DISMISSED:
            slot["dismissed"] = int(cnt)

    # Distinct open devices per CVE (state rows above can double-count a device with both
    # confirmed and potential on different ports; recompute cleanly).
    open_device_rows = db.execute(
        select(DevicePortVuln.cve_id, func.count(func.distinct(Device.id)))
        .select_from(DevicePortVuln)
        .join(DevicePort, DevicePort.id == DevicePortVuln.device_port_id)
        .join(Device, Device.id == DevicePort.device_id)
        .where(
            DevicePortVuln.cve_id.in_(cve_ids),
            DevicePortVuln.state.in_((VULN_STATE_CONFIRMED, VULN_STATE_POTENTIAL)),
        )
        .group_by(DevicePortVuln.cve_id)
    ).all()
    open_devices = {cve: int(n or 0) for cve, n in open_device_rows}

    last_alerts = dict(db.execute(
        select(CveWatchlistAlert.watch_id, func.max(CveWatchlistAlert.alerted_at))
        .where(CveWatchlistAlert.watch_id.in_(watch_ids))
        .group_by(CveWatchlistAlert.watch_id)
    ).all())

    out: dict[int, dict] = {}
    for entry in entries:
        counts = by_cve.get(entry.cve_id, {
            "confirmed": 0, "potential": 0, "dismissed": 0,
            "open_devices": 0, "open_findings": 0,
        })
        confirmed = counts["confirmed"]
        potential = counts["potential"]
        dismissed = counts["dismissed"]
        open_n = confirmed + potential
        last_alert = last_alerts.get(entry.id)
        cve_known = entry.cve_id in known
        if open_n > 0:
            status = STATUS_FOUND
        elif dismissed > 0:
            status = STATUS_ONLY_DISMISSED
        elif cve_known:
            status = STATUS_NOT_FOUND
        else:
            status = STATUS_PENDING
        out[entry.id] = {
            "status": status,
            "affected_devices": open_devices.get(entry.cve_id, 0) if open_n else 0,
            "finding_count": open_n,
            "confirmed_count": confirmed,
            "potential_count": potential,
            "dismissed_count": dismissed,
            "last_alert_at": last_alert,
            "cve_known": cve_known or open_n > 0 or dismissed > 0,
            "next_sync_at": None,  # filled for pending rows by list/add responses
        }
    return out


def entry_status(db: Session, entry: CveWatchlistEntry) -> dict:
    """Status for one entry (uses the bulk helper)."""
    return entries_status(db, [entry])[entry.id]


def attach_next_sync(db: Session, statuses: dict[int, dict]) -> None:
    """Set ``next_sync_at`` on pending statuses (one estimate for the whole list)."""
    pending_ids = [wid for wid, s in statuses.items() if s.get("status") == STATUS_PENDING]
    if not pending_ids:
        return
    try:
        from .sync import estimate_next_cve_sync_at
        nxt = estimate_next_cve_sync_at(db)
    except Exception:
        log.exception("Failed to estimate next CVE sync")
        nxt = None
    for wid in pending_ids:
        statuses[wid]["next_sync_at"] = nxt
