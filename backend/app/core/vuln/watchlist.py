"""CVE watchlist: alert when a subscribed CVE appears on a device/port.

Runs after vuln jobs and feed sync (and immediately when a CVE is added). Confirmed and potential
findings alert; dismissed never does. Display floor (`min_cvss_display`) is ignored. Delivery
(email / webhooks) is best-effort and must never fail the scan or sync.
"""
from __future__ import annotations

import logging
import re
from datetime import datetime

from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from ...db import utcnow
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


def validate_cve_id(raw: str) -> str:
    """Normalize and validate a CVE id. Raises ValueError with a safe message."""
    cve_id = normalize_cve_id(raw)
    if not cve_id or not CVE_ID_PATTERN.fullmatch(cve_id):
        raise ValueError(f"invalid CVE id: {raw!r}")
    return cve_id


def parse_cve_ids(text: str) -> list[str]:
    """Parse a bulk paste into unique normalized CVE ids (order preserved). Raises on any invalid."""
    parts = [p for p in _SPLIT_RE.split(text or "") if p]
    if not parts:
        raise ValueError("no CVE ids provided")
    out: list[str] = []
    seen: set[str] = set()
    for part in parts:
        cve_id = validate_cve_id(part)
        if cve_id not in seen:
            seen.add(cve_id)
            out.append(cve_id)
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


def check_watchlist(
    db: Session,
    *,
    cve_ids: list[str] | None = None,
    now: datetime | None = None,
) -> dict:
    """Create events for new watchlist hits. Never raises for delivery failures.

    Returns ``{"checked": N, "alerted": N, "pruned": N, "event_ids": [...]}``.
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

    notify_cfg = get_section(db, NotificationSettings)
    email_on = bool(notify_cfg.watchlist_email_enabled)
    webhooks_on = bool(notify_cfg.watchlist_webhooks_enabled)

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
            old_value=None,
            new_value=new_value,
            message=message,
            notify=email_on,
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

    if event_ids and email_on:
        _send_immediate_email(db, notify_cfg, event_ids, now=now)
    if event_ids and webhooks_on:
        _deliver_webhooks(db, event_ids)

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
        if not events:
            return
        n = len(events)
        subject = f"{SUBJECT_PREFIX} CVE watchlist - {n} match{'es' if n != 1 else ''}"
        lines = ["PortReveal CVE watchlist alert", "", f"{n} new match{'es' if n != 1 else ''}:", ""]
        html_items: list[str] = []
        for ev in events:
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
        for ev in events:
            ev.notified_at = now
        db.flush()
        log.info("Sent immediate CVE watchlist email for %d event(s)", n)
    except Exception as exc:
        from ..notify import smtp_failure_reason as _reason
        log.error("Immediate CVE watchlist email failed: %s", _reason(exc))


def _esc(value: str) -> str:
    import html as html_mod
    return html_mod.escape(value or "")


def _deliver_webhooks(db: Session, event_ids: list[int]) -> None:
    """Deliver from the same session so uncommitted events are visible (no second connection)."""
    try:
        from ..webhooks import deliver_event

        for ev in db.scalars(select(Event).where(Event.id.in_(event_ids)).order_by(Event.id)):
            try:
                deliver_event(db, ev)
            except Exception:
                log.exception("CVE watchlist webhook delivery failed for event %s", ev.id)
    except Exception:
        log.exception("CVE watchlist webhook delivery failed")


def entry_status(db: Session, entry: CveWatchlistEntry) -> dict:
    """Status payload for one watchlist row: pending / not_found / found + counts."""
    known = db.get(Vulnerability, entry.cve_id) is not None
    if not known:
        return {
            "status": "pending",
            "affected_devices": 0,
            "finding_count": 0,
            "last_alert_at": None,
            "cve_known": False,
        }
    finding_q = (
        select(func.count(DevicePortVuln.id), func.count(func.distinct(Device.id)))
        .select_from(DevicePortVuln)
        .join(DevicePort, DevicePort.id == DevicePortVuln.device_port_id)
        .join(Device, Device.id == DevicePort.device_id)
        .where(
            DevicePortVuln.cve_id == entry.cve_id,
            DevicePortVuln.state.in_((VULN_STATE_CONFIRMED, VULN_STATE_POTENTIAL)),
        )
    )
    finding_count, device_count = db.execute(finding_q).one()
    last_alert = db.scalar(
        select(func.max(CveWatchlistAlert.alerted_at)).where(CveWatchlistAlert.watch_id == entry.id)
    )
    if (finding_count or 0) == 0:
        return {
            "status": "not_found",
            "affected_devices": 0,
            "finding_count": 0,
            "last_alert_at": last_alert,
            "cve_known": True,
        }
    return {
        "status": "found",
        "affected_devices": int(device_count or 0),
        "finding_count": int(finding_count or 0),
        "last_alert_at": last_alert,
        "cve_known": True,
    }
