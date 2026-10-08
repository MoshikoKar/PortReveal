"""Daily HTML email summary of network changes through an (internal) SMTP relay."""
from __future__ import annotations

import html
import logging
import smtplib
import ssl
from collections import defaultdict
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
    Network,
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

# Ordered categories for the daily summary email.
CATEGORIES: list[tuple[str, list[str]]] = [
    ("Devices", [EV_DEVICE_DISCOVERED, EV_DEVICE_DISAPPEARED, EV_DEVICE_REAPPEARED, EV_IP_CHANGED]),
    ("Ports", [EV_PORT_OPENED, EV_PORT_CLOSED]),
    ("Services", [EV_SERVICE_DETECTED, EV_SERVICE_CHANGED, EV_VERSION_CHANGED]),
]


def _local(dt) -> str:
    return dt.astimezone().strftime("%Y-%m-%d %H:%M")


def _esc(value: str | None) -> str:
    return html.escape(value or "")


def _device_name(ev: Event) -> str:
    dev = ev.device
    return (dev.hostname if dev and dev.hostname else None) or ev.ip or "unknown"


def _event_details(ev: Event) -> str:
    parts: list[str] = []
    if ev.port is not None:
        parts.append(f"{(ev.protocol or 'tcp').upper()}/{ev.port}")
    if ev.event_type == EV_IP_CHANGED and ev.old_value:
        parts.append(f"previous IP {ev.old_value}")
    elif ev.event_type in (EV_SERVICE_CHANGED, EV_VERSION_CHANGED):
        parts.append(f"{ev.old_value or '—'} → {ev.new_value or '—'}")
    elif ev.event_type in (EV_PORT_OPENED, EV_SERVICE_DETECTED) and ev.new_value:
        parts.append(str(ev.new_value))
    elif ev.event_type == EV_PORT_CLOSED and ev.old_value:
        parts.append(str(ev.old_value))
    elif ev.event_type == EV_DEVICE_DISCOVERED and ev.new_value:
        parts.append(f"open ports: {ev.new_value}")
    return " · ".join(parts) if parts else (ev.message or "—")


def _network_names(db: Session, events: list[Event]) -> dict[int, str]:
    ids = {ev.device.network_id for ev in events if ev.device and ev.device.network_id}
    if not ids:
        return {}
    return {n.id: n.name for n in db.scalars(select(Network).where(Network.id.in_(ids))).all()}


def format_daily_digest(events: list[Event], network_names: dict[int, str] | None = None) -> tuple[str, str, str]:
    """Return (subject, plain_text, html) for a categorized daily summary."""
    network_names = network_names or {}
    day = _local(events[0].created_at).split(" ")[0] if events else utcnow().astimezone().strftime("%Y-%m-%d")
    counts: dict[str, int] = defaultdict(int)
    for ev in events:
        counts[ev.event_type] += 1

    subject = f"{SUBJECT_PREFIX} Daily summary — {len(events)} change{'s' if len(events) != 1 else ''} ({day})"

    # --- plain text ---
    plain_lines = [
        f"Network Finder daily summary for {day}",
        f"{len(events)} change{'s' if len(events) != 1 else ''} since the last notification.",
        "",
    ]
    for cat_name, types in CATEGORIES:
        cat_events = [e for e in events if e.event_type in types]
        if not cat_events:
            continue
        plain_lines.append(f"=== {cat_name} ({len(cat_events)}) ===")
        for etype in types:
            group = [e for e in cat_events if e.event_type == etype]
            if not group:
                continue
            plain_lines.append(f"  {TITLES.get(etype, etype)} ({len(group)})")
            for ev in group:
                net = ""
                if ev.device and ev.device.network_id and ev.device.network_id in network_names:
                    net = f" [{network_names[ev.device.network_id]}]"
                mac = f"  MAC {_device_mac(ev)}" if _device_mac(ev) else ""
                plain_lines.append(
                    f"    {_local(ev.created_at)}  {_device_name(ev)}{net}  {ev.ip or '—'}  {_event_details(ev)}{mac}"
                )
            plain_lines.append("")
    plain = "\n".join(plain_lines).rstrip() + "\n"

    # --- HTML ---
    summary_chips = "".join(
        f'<span style="display:inline-block;margin:0 8px 8px 0;padding:4px 10px;background:#eef2f7;'
        f'border-radius:4px;font-size:13px;color:#334155;">'
        f'<strong>{counts[t]}</strong> {_esc(TITLES.get(t, t).lower())}</span>'
        for t in counts
    )
    sections: list[str] = []
    for cat_name, types in CATEGORIES:
        cat_events = [e for e in events if e.event_type in types]
        if not cat_events:
            continue
        blocks: list[str] = []
        for etype in types:
            group = [e for e in cat_events if e.event_type == etype]
            if not group:
                continue
            rows = "".join(_html_row(ev, network_names) for ev in group)
            blocks.append(
                f'<h3 style="margin:20px 0 8px;font-size:15px;color:#0f172a;font-weight:600;">'
                f'{_esc(TITLES.get(etype, etype))} '
                f'<span style="color:#64748b;font-weight:500;">({len(group)})</span></h3>'
                f'<table role="presentation" width="100%" cellpadding="0" cellspacing="0" '
                f'style="border-collapse:collapse;font-size:13px;margin-bottom:8px;">'
                f'<thead><tr style="background:#f1f5f9;text-align:left;">'
                f'<th style="padding:8px 10px;border-bottom:1px solid #cbd5e1;color:#475569;">Time</th>'
                f'<th style="padding:8px 10px;border-bottom:1px solid #cbd5e1;color:#475569;">Device</th>'
                f'<th style="padding:8px 10px;border-bottom:1px solid #cbd5e1;color:#475569;">Network</th>'
                f'<th style="padding:8px 10px;border-bottom:1px solid #cbd5e1;color:#475569;">IP</th>'
                f'<th style="padding:8px 10px;border-bottom:1px solid #cbd5e1;color:#475569;">Details</th>'
                f'</tr></thead><tbody>{rows}</tbody></table>'
            )
        sections.append(
            f'<div style="margin-top:28px;">'
            f'<h2 style="margin:0 0 4px;font-size:18px;color:#0f172a;border-bottom:2px solid #2563eb;'
            f'padding-bottom:6px;">{_esc(cat_name)} '
            f'<span style="color:#64748b;font-weight:500;font-size:14px;">({len(cat_events)})</span></h2>'
            f'{"".join(blocks)}</div>'
        )

    html_body = f"""<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{_esc(subject)}</title></head>
<body style="margin:0;padding:0;background:#f8fafc;font-family:Segoe UI,Roboto,Helvetica,Arial,sans-serif;color:#0f172a;">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#f8fafc;padding:24px 12px;">
<tr><td align="center">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="max-width:720px;background:#ffffff;border:1px solid #e2e8f0;border-radius:8px;overflow:hidden;">
<tr><td style="background:#0f172a;padding:20px 24px;">
  <div style="font-size:12px;letter-spacing:0.06em;text-transform:uppercase;color:#94a3b8;">Network Finder</div>
  <div style="font-size:22px;font-weight:600;color:#ffffff;margin-top:4px;">Daily network summary</div>
  <div style="font-size:14px;color:#cbd5e1;margin-top:6px;">{_esc(day)} · {len(events)} change{'s' if len(events) != 1 else ''}</div>
</td></tr>
<tr><td style="padding:20px 24px 8px;">
  <p style="margin:0 0 12px;font-size:14px;line-height:1.5;color:#334155;">
    Here is a categorized summary of network changes detected since the last daily notification.
  </p>
  <div>{summary_chips}</div>
</td></tr>
<tr><td style="padding:0 24px 28px;">{"".join(sections)}</td></tr>
<tr><td style="padding:14px 24px;background:#f1f5f9;font-size:12px;color:#64748b;border-top:1px solid #e2e8f0;">
  Sent once per day by Network Finder. Open the Changes page in the app for full history.
</td></tr>
</table>
</td></tr></table>
</body></html>"""
    return subject, plain, html_body


def _device_mac(ev: Event) -> str | None:
    return ev.device.mac if ev.device and ev.device.mac else None


def _html_row(ev: Event, network_names: dict[int, str]) -> str:
    net = "—"
    if ev.device and ev.device.network_id and ev.device.network_id in network_names:
        net = network_names[ev.device.network_id]
    device = _device_name(ev)
    mac = _device_mac(ev)
    device_cell = _esc(device)
    if mac:
        device_cell += f'<br><span style="color:#64748b;font-size:12px;">MAC {_esc(mac)}</span>'
    return (
        f'<tr style="border-bottom:1px solid #e2e8f0;">'
        f'<td style="padding:8px 10px;vertical-align:top;white-space:nowrap;color:#475569;">{_esc(_local(ev.created_at))}</td>'
        f'<td style="padding:8px 10px;vertical-align:top;">{device_cell}</td>'
        f'<td style="padding:8px 10px;vertical-align:top;">{_esc(net)}</td>'
        f'<td style="padding:8px 10px;vertical-align:top;font-family:Consolas,Menlo,monospace;">{_esc(ev.ip or "—")}</td>'
        f'<td style="padding:8px 10px;vertical-align:top;">{_esc(_event_details(ev))}</td>'
        f'</tr>'
    )


def format_sample_digest() -> tuple[str, str, str]:
    """Sample HTML daily summary for the settings test-email action."""
    day = utcnow().astimezone().strftime("%Y-%m-%d")
    subject = f"{SUBJECT_PREFIX} Daily summary — sample ({day})"
    plain = (
        f"Network Finder daily summary sample for {day}\n"
        "This is a test of the daily HTML notification format.\n"
        "No real network changes are included.\n"
    )
    html_body = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><title>{_esc(subject)}</title></head>
<body style="margin:0;padding:0;background:#f8fafc;font-family:Segoe UI,Roboto,Helvetica,Arial,sans-serif;color:#0f172a;">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#f8fafc;padding:24px 12px;">
<tr><td align="center">
<table role="presentation" width="100%" style="max-width:720px;background:#ffffff;border:1px solid #e2e8f0;border-radius:8px;">
<tr><td style="background:#0f172a;padding:20px 24px;">
  <div style="font-size:12px;letter-spacing:0.06em;text-transform:uppercase;color:#94a3b8;">Network Finder</div>
  <div style="font-size:22px;font-weight:600;color:#ffffff;margin-top:4px;">Daily network summary</div>
  <div style="font-size:14px;color:#cbd5e1;margin-top:6px;">{_esc(day)} · sample email</div>
</td></tr>
<tr><td style="padding:24px;">
  <p style="margin:0 0 16px;font-size:14px;line-height:1.5;color:#334155;">
    This is a test of the daily notification format. When enabled, Network Finder sends one categorized HTML
    summary per day covering devices, ports and services that changed.
  </p>
  <h2 style="margin:0 0 8px;font-size:18px;color:#0f172a;border-bottom:2px solid #2563eb;padding-bottom:6px;">Ports (1)</h2>
  <h3 style="margin:12px 0 8px;font-size:15px;">New port detected <span style="color:#64748b;font-weight:500;">(1)</span></h3>
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="border-collapse:collapse;font-size:13px;">
    <thead><tr style="background:#f1f5f9;text-align:left;">
      <th style="padding:8px 10px;border-bottom:1px solid #cbd5e1;color:#475569;">Time</th>
      <th style="padding:8px 10px;border-bottom:1px solid #cbd5e1;color:#475569;">Device</th>
      <th style="padding:8px 10px;border-bottom:1px solid #cbd5e1;color:#475569;">Network</th>
      <th style="padding:8px 10px;border-bottom:1px solid #cbd5e1;color:#475569;">IP</th>
      <th style="padding:8px 10px;border-bottom:1px solid #cbd5e1;color:#475569;">Details</th>
    </tr></thead>
    <tbody><tr style="border-bottom:1px solid #e2e8f0;">
      <td style="padding:8px 10px;color:#475569;">{_esc(day)} 08:00</td>
      <td style="padding:8px 10px;">server01<br><span style="color:#64748b;font-size:12px;">MAC 00:11:22:33:44:55</span></td>
      <td style="padding:8px 10px;">Example LAN</td>
      <td style="padding:8px 10px;font-family:Consolas,Menlo,monospace;">10.20.15.22</td>
      <td style="padding:8px 10px;">TCP/8080 · http</td>
    </tr></tbody>
  </table>
</td></tr>
<tr><td style="padding:14px 24px;background:#f1f5f9;font-size:12px;color:#64748b;border-top:1px solid #e2e8f0;">
  Test email from Network Finder settings.
</td></tr>
</table></td></tr></table></body></html>"""
    return subject, plain, html_body


def send_email(cfg: NotificationSettings, subject: str, body: str, html_body: str | None = None) -> None:
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
    rows = db.scalars(
        select(Event).where(Event.notify.is_(True), Event.notified_at.is_(None))
        .order_by(Event.created_at, Event.id)
    ).unique().all()
    allowed = set(cfg.event_types)
    return [e for e in rows if e.event_type in allowed]
