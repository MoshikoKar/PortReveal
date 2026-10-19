"""Daily HTML email summary of network changes through an (internal) SMTP relay."""
from __future__ import annotations

import html
import logging
import re
import smtplib
import socket
import ssl
from collections import defaultdict
from email.message import EmailMessage
from email.utils import formatdate, make_msgid

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db import session_scope, utcnow
from ..models import (
    ALWAYS_NOTIFY_TYPES,
    EV_DEVICE_DISAPPEARED,
    EV_DEVICE_DISCOVERED,
    EV_DEVICE_REAPPEARED,
    EV_IP_CHANGED,
    EV_MONITOR_CHANGE,
    EV_POLICY_VIOLATION,
    EV_PORT_CLOSED,
    EV_PORT_OPENED,
    EV_SERVICE_CHANGED,
    EV_SERVICE_DETECTED,
    EV_TAG_ADDED,
    EV_TAG_REMOVED,
    EV_VERSION_CHANGED,
    EV_WATCH_MATCH,
    Event,
    Network,
)
from ..security import decrypt_secret
from ..settings_store import NotificationSettings, get_section

log = logging.getLogger(__name__)
SUBJECT_PREFIX = "[PortReveal]"
# Keep each category short so the daily mail stays scannable.
MAX_LINES_PER_SECTION = 8
# Cap one digest load so a large notify backlog cannot grow memory unboundedly;
# remaining pending rows stay for the next run.
PENDING_DIGEST_LIMIT = 500

TITLES = {
    EV_DEVICE_DISCOVERED: "New devices",
    EV_DEVICE_DISAPPEARED: "No longer detected",
    EV_DEVICE_REAPPEARED: "Detected again",
    EV_IP_CHANGED: "IP changed",
    EV_PORT_OPENED: "Ports opened",
    EV_PORT_CLOSED: "Ports closed",
    EV_SERVICE_DETECTED: "Services identified",
    EV_SERVICE_CHANGED: "Services changed",
    EV_VERSION_CHANGED: "Versions changed",
    EV_TAG_ADDED: "Tags added",
    EV_TAG_REMOVED: "Tags removed",
    EV_WATCH_MATCH: "Watch matches",
    EV_POLICY_VIOLATION: "Policy violations",
    EV_MONITOR_CHANGE: "Monitored changes",
}

# Ordered categories for the daily summary email.
CATEGORIES: list[tuple[str, list[str]]] = [
    ("Watches", [EV_POLICY_VIOLATION, EV_WATCH_MATCH, EV_MONITOR_CHANGE]),
    ("Devices", [EV_DEVICE_DISCOVERED, EV_DEVICE_DISAPPEARED, EV_DEVICE_REAPPEARED, EV_IP_CHANGED]),
    ("Ports", [EV_PORT_OPENED, EV_PORT_CLOSED]),
    ("Services", [EV_SERVICE_DETECTED, EV_SERVICE_CHANGED, EV_VERSION_CHANGED]),
    ("Tags", [EV_TAG_ADDED, EV_TAG_REMOVED]),
]


def _local_day(dt) -> str:
    return dt.astimezone().strftime("%Y-%m-%d")


def _esc(value: str | None) -> str:
    return html.escape(value or "")


def _device_name(ev: Event) -> str:
    dev = ev.device
    name = (dev.hostname if dev and dev.hostname else None) or ev.ip or "unknown"
    # Prefer short hostname in the email (drop long DNS suffixes).
    if "." in name and not re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", name):
        short = name.split(".")[0]
        if short:
            return short
    return name


def _short(text: str | None, limit: int = 36) -> str:
    if not text:
        return ""
    text = re.sub(r"\s+", " ", text).strip()
    # Prefer product name before parenthetical product/protocol tags.
    m = re.match(r"^(.+?)\s+\([^)]+\)\s*$", text)
    if m and len(m.group(1)) <= limit:
        text = m.group(1)
    if len(text) <= limit:
        return text
    return text[: limit - 1].rstrip() + "…"


def _port_label(ev: Event) -> str:
    if ev.port is None:
        return ""
    return f"{(ev.protocol or 'tcp').upper()}/{ev.port}"


def _line_for(ev: Event) -> str:
    """One short line describing a change (no MAC/network/timestamp)."""
    name = _device_name(ev)
    ip = ev.ip or ""
    who = f"{name} ({ip})" if ip and ip != name else name
    port = _port_label(ev)

    if ev.event_type == EV_DEVICE_DISCOVERED:
        ports = _short(ev.new_value, 28) if ev.new_value else ""
        return f"{who}" + (f" - {ports}" if ports else "")
    if ev.event_type in (EV_DEVICE_DISAPPEARED, EV_DEVICE_REAPPEARED):
        return who
    if ev.event_type == EV_IP_CHANGED:
        return f"{name}: {ev.old_value or '?'} → {ip or '?'}"
    if ev.event_type in (EV_PORT_OPENED, EV_PORT_CLOSED):
        svc = _short(ev.new_value if ev.event_type == EV_PORT_OPENED else ev.old_value, 24)
        return f"{who} - {port}" + (f" {svc}" if svc else "")
    if ev.event_type == EV_SERVICE_DETECTED:
        return f"{who} - {port} {_short(ev.new_value, 28)}".rstrip()
    if ev.event_type in (EV_SERVICE_CHANGED, EV_VERSION_CHANGED):
        return f"{who} - {port}: {_short(ev.old_value, 22)} → {_short(ev.new_value, 22)}"
    if ev.event_type in (EV_WATCH_MATCH, EV_POLICY_VIOLATION, EV_MONITOR_CHANGE):
        return f"{who} - {_short(ev.new_value, 40)}"
    if ev.event_type in (EV_TAG_ADDED, EV_TAG_REMOVED):
        return f"{who} - {_short(ev.new_value or ev.old_value, 30)}"
    return _short(ev.message, 60) or who


def _network_names(db: Session, events: list[Event]) -> dict[int, str]:
    ids = {ev.device.network_id for ev in events if ev.device and ev.device.network_id}
    if not ids:
        return {}
    return {n.id: n.name for n in db.scalars(select(Network).where(Network.id.in_(ids))).all()}


def _section_lines(events: list[Event], etype: str) -> list[str]:
    """Group port/service events by device so one host is one line when possible."""
    group = [e for e in events if e.event_type == etype]
    if not group:
        return []
    if etype in (EV_PORT_OPENED, EV_PORT_CLOSED):
        by_host: dict[str, list[str]] = defaultdict(list)
        order: list[str] = []
        for ev in group:
            name = _device_name(ev)
            ip = ev.ip or ""
            key = f"{name} ({ip})" if ip and ip != name else name
            if key not in by_host:
                order.append(key)
            label = _port_label(ev)
            if label and label not in by_host[key]:
                by_host[key].append(label)
        return [f"{host} - {', '.join(ports)}" for host, ports in ((h, by_host[h]) for h in order)]
    return [_line_for(ev) for ev in group]


def format_daily_digest(events: list[Event], network_names: dict[int, str] | None = None) -> tuple[str, str, str]:
    """Return (subject, plain_text, html) for a short categorized daily summary."""
    del network_names  # kept in signature for callers; details stay host/IP only
    day = _local_day(events[0].created_at) if events else utcnow().astimezone().strftime("%Y-%m-%d")
    counts: dict[str, int] = defaultdict(int)
    for ev in events:
        counts[ev.event_type] += 1

    n = len(events)
    subject = f"{SUBJECT_PREFIX} Daily summary - {n} change{'s' if n != 1 else ''} ({day})"

    count_bits = [f"{counts[t]} {TITLES.get(t, t).lower()}" for t, _ in
                  sorted(((t, TITLES.get(t, t)) for t in counts), key=lambda x: x[1])]
    summary = " · ".join(count_bits)

    # --- plain text ---
    plain_lines = [
        f"PortReveal - {day}",
        f"{n} change{'s' if n != 1 else ''}: {summary}",
        "",
    ]
    for cat_name, types in CATEGORIES:
        cat_events = [e for e in events if e.event_type in types]
        if not cat_events:
            continue
        plain_lines.append(f"{cat_name} ({len(cat_events)})")
        for etype in types:
            lines = _section_lines(cat_events, etype)
            if not lines:
                continue
            plain_lines.append(f"  {TITLES.get(etype, etype)}")
            shown = lines[:MAX_LINES_PER_SECTION]
            for line in shown:
                plain_lines.append(f"    • {line}")
            extra = len(lines) - len(shown)
            if extra > 0:
                plain_lines.append(f"    • …and {extra} more")
        plain_lines.append("")
    plain = "\n".join(plain_lines).rstrip() + "\n"

    # --- HTML ---
    sections: list[str] = []
    for cat_name, types in CATEGORIES:
        cat_events = [e for e in events if e.event_type in types]
        if not cat_events:
            continue
        blocks: list[str] = []
        for etype in types:
            lines = _section_lines(cat_events, etype)
            if not lines:
                continue
            shown = lines[:MAX_LINES_PER_SECTION]
            items = "".join(
                f'<li style="margin:0 0 4px;padding:0;line-height:1.35;">{_esc(line)}</li>'
                for line in shown
            )
            extra = len(lines) - len(shown)
            if extra > 0:
                items += f'<li style="margin:0;padding:0;color:#64748b;">…and {extra} more</li>'
            blocks.append(
                f'<div style="margin:12px 0 0;">'
                f'<div style="font-size:13px;font-weight:600;color:#334155;margin:0 0 4px;">'
                f'{_esc(TITLES.get(etype, etype))} '
                f'<span style="font-weight:500;color:#64748b;">({len(lines)})</span></div>'
                f'<ul style="margin:0;padding:0 0 0 18px;font-size:13px;color:#0f172a;">{items}</ul>'
                f'</div>'
            )
        sections.append(
            f'<div style="margin-top:18px;padding-top:14px;border-top:1px solid #e2e8f0;">'
            f'<div style="font-size:15px;font-weight:600;color:#0f172a;">{_esc(cat_name)} '
            f'<span style="font-weight:500;color:#64748b;font-size:13px;">({len(cat_events)})</span></div>'
            f'{"".join(blocks)}</div>'
        )

    html_body = f"""<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{_esc(subject)}</title></head>
<body style="margin:0;padding:0;background:#f8fafc;font-family:Segoe UI,Roboto,Helvetica,Arial,sans-serif;color:#0f172a;">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#f8fafc;padding:20px 12px;">
<tr><td align="center">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="max-width:560px;background:#ffffff;border:1px solid #e2e8f0;border-radius:8px;overflow:hidden;">
<tr><td style="background:#0f172a;padding:16px 20px;">
  <div style="font-size:11px;letter-spacing:0.06em;text-transform:uppercase;color:#94a3b8;">PortReveal</div>
  <div style="font-size:18px;font-weight:600;color:#ffffff;margin-top:2px;">Daily summary</div>
  <div style="font-size:13px;color:#cbd5e1;margin-top:4px;">{_esc(day)} · {n} change{'s' if n != 1 else ''}</div>
</td></tr>
<tr><td style="padding:16px 20px 4px;">
  <p style="margin:0;font-size:13px;line-height:1.45;color:#475569;">{_esc(summary)}</p>
</td></tr>
<tr><td style="padding:4px 20px 18px;">{"".join(sections)}</td></tr>
<tr><td style="padding:12px 20px;background:#f1f5f9;font-size:12px;color:#64748b;border-top:1px solid #e2e8f0;">
  Full detail is in the Changes page.
</td></tr>
</table>
</td></tr></table>
</body></html>"""
    return subject, plain, html_body


def format_sample_digest() -> tuple[str, str, str]:
    """Sample compact daily summary for the settings test-email action."""
    day = utcnow().astimezone().strftime("%Y-%m-%d")
    subject = f"{SUBJECT_PREFIX} Daily summary - sample ({day})"
    plain = (
        f"PortReveal - {day}\n"
        "1 change: 1 ports opened\n\n"
        "Ports (1)\n"
        "  Ports opened\n"
        "    • server01 (10.0.0.10) - TCP/8080\n"
    )
    html_body = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><title>{_esc(subject)}</title></head>
<body style="margin:0;padding:0;background:#f8fafc;font-family:Segoe UI,Roboto,Helvetica,Arial,sans-serif;color:#0f172a;">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#f8fafc;padding:20px 12px;">
<tr><td align="center">
<table role="presentation" width="100%" style="max-width:560px;background:#ffffff;border:1px solid #e2e8f0;border-radius:8px;">
<tr><td style="background:#0f172a;padding:16px 20px;">
  <div style="font-size:11px;letter-spacing:0.06em;text-transform:uppercase;color:#94a3b8;">PortReveal</div>
  <div style="font-size:18px;font-weight:600;color:#ffffff;margin-top:2px;">Daily summary</div>
  <div style="font-size:13px;color:#cbd5e1;margin-top:4px;">{_esc(day)} · sample</div>
</td></tr>
<tr><td style="padding:16px 20px;">
  <p style="margin:0 0 12px;font-size:13px;color:#475569;">1 ports opened</p>
  <div style="font-size:15px;font-weight:600;">Ports <span style="font-weight:500;color:#64748b;font-size:13px;">(1)</span></div>
  <div style="margin-top:10px;font-size:13px;font-weight:600;color:#334155;">Ports opened <span style="font-weight:500;color:#64748b;">(1)</span></div>
  <ul style="margin:4px 0 0;padding:0 0 0 18px;font-size:13px;"><li>server01 (10.0.0.10) - TCP/8080</li></ul>
</td></tr>
<tr><td style="padding:12px 20px;background:#f1f5f9;font-size:12px;color:#64748b;border-top:1px solid #e2e8f0;">
  Test email from PortReveal settings.
</td></tr>
</table></td></tr></table></body></html>"""
    return subject, plain, html_body


class SmtpConfigError(RuntimeError):
    """Settings are incomplete; the message is safe to show."""


def smtp_failure_reason(exc: BaseException) -> str:
    """A short, stable reason for the UI and audit log. Raw exception text (server replies, host names,
    library internals) stays in the application log only."""
    if isinstance(exc, SmtpConfigError):
        return str(exc)
    if isinstance(exc, smtplib.SMTPAuthenticationError):
        return "authentication failed (check username and password)"
    if isinstance(exc, smtplib.SMTPRecipientsRefused):
        return "the server refused the recipient address"
    if isinstance(exc, smtplib.SMTPSenderRefused):
        return "the server refused the sender address"
    if isinstance(exc, smtplib.SMTPNotSupportedError):
        return "the server does not support the selected security mode or authentication"
    if isinstance(exc, smtplib.SMTPServerDisconnected):
        return "the server closed the connection"
    if isinstance(exc, smtplib.SMTPException):
        return "the server rejected the message"
    if isinstance(exc, ssl.SSLError):
        return "TLS handshake or certificate verification failed"
    if isinstance(exc, TimeoutError):
        return "timed out connecting to the SMTP server"
    if isinstance(exc, socket.gaierror):
        return "the SMTP host name could not be resolved"
    if isinstance(exc, ConnectionRefusedError):
        return "the SMTP server refused the connection"
    if isinstance(exc, OSError):
        return "could not connect to the SMTP server"
    return "unexpected error (details in the application log)"


def send_email(cfg: NotificationSettings, subject: str, body: str, html_body: str | None = None) -> None:
    if not cfg.smtp_host:
        raise SmtpConfigError("SMTP host is not configured")
    if not cfg.recipients:
        raise SmtpConfigError("No recipients configured")
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = cfg.sender
    msg["To"] = ", ".join(cfg.recipients)
    msg["Date"] = formatdate(localtime=True)
    msg["Message-ID"] = make_msgid(domain="network-monitor")
    msg.set_content(body)
    if html_body:
        msg.add_alternative(html_body, subtype="html")
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


def send_daily_digest() -> str:
    """Send one categorized daily summary for all pending events.

    Never raises. Returns ``"sent"``, ``"empty"`` (nothing pending), ``"disabled"``, or ``"failed"``.
    """
    try:
        with session_scope() as db:
            cfg = get_section(db, NotificationSettings)
            if not cfg.enabled:
                return "disabled"
            events = _pending_all(db, cfg)
            if not events:
                return "empty"
            network_names = _network_names(db, events)
            subject, plain, html_body = format_daily_digest(events, network_names)
            event_ids = [ev.id for ev in events]

        send_email(cfg, subject, plain, html_body)

        with session_scope() as db:
            now = utcnow()
            rows = db.scalars(select(Event).where(Event.id.in_(event_ids), Event.notified_at.is_(None))).all()
            for ev in rows:
                ev.notified_at = now
            log.info("Sent daily notification email for %d event(s)", len(rows))
        return "sent"
    except Exception as exc:
        log.error("Sending daily notification email failed: %s", exc)
        return "failed"


def _pending_all(db: Session, cfg: NotificationSettings) -> list[Event]:
    allowed = sorted(set(cfg.event_types) | set(ALWAYS_NOTIFY_TYPES))
    if not allowed:
        return []
    return list(
        db.scalars(
            select(Event)
            .where(
                Event.notify.is_(True),
                Event.notified_at.is_(None),
                Event.event_type.in_(allowed),
            )
            .order_by(Event.created_at, Event.id)
            .limit(PENDING_DIGEST_LIMIT)
        ).unique().all()
    )
