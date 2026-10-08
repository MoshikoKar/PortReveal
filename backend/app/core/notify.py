"""Concise email notifications through an (internal) SMTP relay."""
from __future__ import annotations

import logging
import smtplib
import ssl
from email.message import EmailMessage
from email.utils import formatdate, make_msgid

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db import session_scope, utcnow
from ..models import (
    EV_DEVICE_DISAPPEARED,
    EV_DEVICE_DISCOVERED,
    EV_DEVICE_REAPPEARED,
    EV_IP_CHANGED,
    EV_PORT_CLOSED,
    EV_PORT_OPENED,
    EV_SERVICE_CHANGED,
    EV_SERVICE_DETECTED,
    EV_VERSION_CHANGED,
    Event,
)
from ..security import decrypt_secret
from ..settings_store import NotificationSettings, get_section

log = logging.getLogger(__name__)
SUBJECT_PREFIX = "[Network Monitor]"

TITLES = {
    EV_DEVICE_DISCOVERED: "New device detected",
    EV_DEVICE_DISAPPEARED: "Device no longer detected",
    EV_DEVICE_REAPPEARED: "Device detected again",
    EV_IP_CHANGED: "Device IP address changed",
    EV_PORT_OPENED: "New port detected",
    EV_PORT_CLOSED: "Port closed",
    EV_SERVICE_DETECTED: "Service identified",
    EV_SERVICE_CHANGED: "Service changed",
    EV_VERSION_CHANGED: "Service version changed",
}


def _local(dt) -> str:
    return dt.astimezone().strftime("%Y-%m-%d %H:%M")


def format_event(ev: Event) -> tuple[str, str]:
    dev = ev.device
    name = (dev.hostname if dev and dev.hostname else None) or ev.ip or "unknown"
    lines = [f"Device: {name}", f"IP: {ev.ip}"]
    if dev and dev.mac:
        lines.append(f"MAC: {dev.mac}")
    if ev.port is not None:
        lines.append(f"Port: {(ev.protocol or 'tcp').upper()}/{ev.port}")
    if ev.event_type == EV_IP_CHANGED:
        lines.append(f"Previous IP: {ev.old_value}")
    elif ev.event_type in (EV_SERVICE_CHANGED, EV_VERSION_CHANGED):
        lines.append(f"Change: {ev.old_value} -> {ev.new_value}")
    elif ev.event_type in (EV_PORT_OPENED, EV_SERVICE_DETECTED) and ev.new_value:
        lines.append(f"Service: {ev.new_value}")
    elif ev.event_type == EV_PORT_CLOSED and ev.old_value:
        lines.append(f"Service: {ev.old_value}")
    elif ev.event_type == EV_DEVICE_DISCOVERED and ev.new_value:
        lines.append(f"Open ports: {ev.new_value}")
    lines.append(f"Detected: {_local(ev.created_at)}")
    return f"{SUBJECT_PREFIX} {TITLES.get(ev.event_type, ev.event_type)}", "\n".join(lines) + "\n"


def format_digest(events: list[Event], limit: int = 50) -> tuple[str, str]:
    counts: dict[str, int] = {}
    for ev in events:
        counts[ev.event_type] = counts.get(ev.event_type, 0) + 1
    summary = ", ".join(f"{n} {TITLES.get(t, t).lower()}" for t, n in counts.items())
    lines = [f"{len(events)} network changes detected: {summary}", ""]
    for ev in events[:limit]:
        lines.append(f"{_local(ev.created_at)}  {ev.message}")
    if len(events) > limit:
        lines.append(f"... and {len(events) - limit} more. See the Changes page for details.")
    return f"{SUBJECT_PREFIX} {len(events)} network changes detected", "\n".join(lines) + "\n"


def send_email(cfg: NotificationSettings, subject: str, body: str) -> None:
    if not cfg.smtp_host:
        raise RuntimeError("SMTP host is not configured")
    if not cfg.recipients:
        raise RuntimeError("No recipients configured")
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = cfg.sender
    msg["To"] = ", ".join(cfg.recipients)
    msg["Date"] = formatdate(localtime=True)
    msg["Message-ID"] = make_msgid(domain="network-monitor")
    msg.set_content(body)
    timeout = 20
    if cfg.security == "ssl":
        server: smtplib.SMTP = smtplib.SMTP_SSL(cfg.smtp_host, cfg.smtp_port, timeout=timeout,
                                                context=ssl.create_default_context())
    else:
        server = smtplib.SMTP(cfg.smtp_host, cfg.smtp_port, timeout=timeout)
    try:
        server.ehlo_or_helo_if_needed()
        if cfg.security == "starttls":
            server.starttls(context=ssl.create_default_context())
            server.ehlo()
        password = decrypt_secret(cfg.password_enc)
        if cfg.username and password:
            server.login(cfg.username, password)
        server.send_message(msg)
    finally:
        try:
            server.quit()
        except smtplib.SMTPException:
            server.close()


def notify_events(event_ids: list[int]) -> int:
    """Send notifications for the given events. Never raises; returns emails sent."""
    if not event_ids:
        return 0
    try:
        with session_scope() as db:
            cfg = get_section(db, NotificationSettings)
            if not cfg.enabled:
                return 0
            events = _pending(db, event_ids, cfg)
            if not events:
                return 0
            if len(events) > cfg.max_individual:
                messages = [format_digest(events)]
            else:
                messages = [format_event(ev) for ev in events]
            sent = 0
            for subject, body in messages:
                send_email(cfg, subject, body)
                sent += 1
            now = utcnow()
            for ev in events:
                ev.notified_at = now
            log.info("Sent %d notification email(s) for %d event(s)", sent, len(events))
            return sent
    except Exception as exc:
        log.error("Sending notification email failed: %s", exc)
        return 0


def _pending(db: Session, event_ids: list[int], cfg: NotificationSettings) -> list[Event]:
    rows = db.scalars(
        select(Event).where(Event.id.in_(event_ids), Event.notify.is_(True), Event.notified_at.is_(None))
        .order_by(Event.id)
    ).unique().all()
    return [e for e in rows if e.event_type in cfg.event_types]
