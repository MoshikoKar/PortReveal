"""Daily HTML email summary of network changes through an (internal) SMTP relay."""

from __future__ import annotations

import html
import logging
import re
import smtplib
import socket
import ssl
from collections import defaultdict
from datetime import timedelta
from email.message import EmailMessage
from email.utils import formatdate, make_msgid
from urllib.parse import urlencode

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db import session_scope, utcnow
from ..models import (
    ALWAYS_NOTIFY_TYPES,
    DOMAIN_EVENT_TYPES,
    EV_CVE_WATCH_MATCH,
    EV_DEVICE_DISAPPEARED,
    EV_DEVICE_DISCOVERED,
    EV_DEVICE_REAPPEARED,
    EV_GEO_MISMATCH,
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
    Device,
    Event,
    Network,
)
from ..security import decrypt_secret
from ..settings_store import DEFAULT_SENSITIVE_PORTS, NotificationSettings, get_section

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
    EV_GEO_MISMATCH: "Geo mismatches",
    EV_CVE_WATCH_MATCH: "CVE watchlist matches",
    "subdomain_new": "New subdomains",
    "subdomain_gone": "Subdomains gone",
    "subdomain_ip_changed": "Subdomain addresses changed",
    "subdomain_exposure_changed": "Subdomain exposure changed",
    "internal_name_exposed": "Internal names exposed",
    "wildcard_detected": "Wildcard DNS detected",
    "wildcard_removed": "Wildcard DNS removed",
    "zone_transfer_open": "Zone transfers open",
}

# Ordered categories for the main body of the summary email.
CATEGORIES: list[tuple[str, list[str]]] = [
    ("Watches", [EV_POLICY_VIOLATION, EV_WATCH_MATCH, EV_MONITOR_CHANGE, EV_CVE_WATCH_MATCH]),
    ("Geo", [EV_GEO_MISMATCH]),
    ("Devices", [EV_DEVICE_DISCOVERED, EV_DEVICE_DISAPPEARED, EV_DEVICE_REAPPEARED, EV_IP_CHANGED]),
    ("Ports", [EV_PORT_OPENED, EV_PORT_CLOSED]),
    ("Services", [EV_SERVICE_DETECTED]),
    ("Tags", [EV_TAG_ADDED, EV_TAG_REMOVED]),
    ("Domains", list(DOMAIN_EVENT_TYPES)),
]
# Banner/product churn is lower signal: it goes last and is collapsed to a few sample rows.
OTHER_CATEGORY = ("Other changes", [EV_SERVICE_CHANGED, EV_VERSION_CHANGED])
OTHER_SAMPLE_ROWS = 3
OTHER_NOTE = "Service banner and version churn. A few samples; the rest is in Changes."
WATCH_ATTENTION = {
    EV_CVE_WATCH_MATCH: "CVE watchlist",
    EV_POLICY_VIOLATION: "Policy violation",
    EV_WATCH_MATCH: "Watch match",
    EV_MONITOR_CHANGE: "Monitored change",
}
DEVICE_ATTENTION = {
    EV_DEVICE_DISCOVERED: "New device",
    EV_DEVICE_DISAPPEARED: "No longer detected",
    EV_DEVICE_REAPPEARED: "Detected again",
}
MAX_ATTENTION_LINES = 10
MAX_PORTS_PER_CELL = 5
# One primary label per delivery mode, shared by subject, HTML header and plain text.
DIGEST_TITLES = {"daily": "Daily summary", "hourly": "Hourly summary", "immediate": "Change alert"}
MAX_SUBJECT_LEN = 78

# A cell is plain text, or (text, link_text, href) where href is None without a base URL.
Cell = str | tuple[str, str, str | None]


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


def _short_keep_version(text: str | None, limit: int = 40) -> str:
    """Shorten a product/banner label but keep its version number visible."""
    if not text:
        return ""
    text = re.sub(r"\s+", " ", text).strip()
    m = re.match(r"^(.+?)\s+\([^)]*\)\s*$", text)
    if len(text) > limit and m:
        text = m.group(1)
    if len(text) <= limit:
        return text
    ver = re.search(r"\bv?\d+(?:\.\d+)+[\w.\-+~]*", text)
    if ver and ver.start() > 0:
        version = ver.group(0)[:16]
        room = max(8, limit - len(version) - 1)
        head = text[: ver.start()].strip()
        if len(head) > room:
            head = head[: room - 1].rstrip() + "…"
        return f"{head} {version}"
    return text[: limit - 1].rstrip() + "…"


def _port_label(ev: Event) -> str:
    if ev.port is None:
        return ""
    return f"{(ev.protocol or 'tcp').upper()}/{ev.port}"


def _network_names(db: Session, events: list[Event]) -> dict[int, str]:
    ids = {ev.device.network_id for ev in events if ev.device and ev.device.network_id}
    if not ids:
        return {}
    return {n.id: n.name for n in db.scalars(select(Network).where(Network.id.in_(ids))).all()}


def _range_for(events: list[Event]) -> str:
    """Smallest Changes-page range that covers every event in the digest."""
    if not events:
        return "24h"
    age = utcnow() - min(ev.created_at for ev in events)
    for key, days in (("24h", 1), ("7d", 7), ("30d", 30)):
        if age <= timedelta(days=days):
            return key
    return "all"


class _Ctx:
    """Per-digest settings shared by the row builders."""

    def __init__(self, events: list[Event], network_names: dict[int, str], base_url: str, sensitive: set[int]):
        self.base_url = (base_url or "").rstrip("/")
        self.range = _range_for(events)
        self.sensitive = sensitive
        self.network_names = network_names
        net_ids = {ev.device.network_id for ev in events if ev.device and ev.device.network_id}
        self.multi_network = len(net_ids) > 1

    def link(self, **params: str) -> str | None:
        if not self.base_url:
            return None
        return f"{self.base_url}/changes?{urlencode({**params, 'range': self.range})}"

    def network(self, ev: Event) -> str:
        if ev.device and ev.device.network_id:
            return self.network_names.get(ev.device.network_id, "")
        return ""

    def is_sensitive(self, ev: Event) -> bool:
        return ev.port is not None and ev.port in self.sensitive


def _host_key(ev: Event) -> tuple[str, str]:
    return _device_name(ev), ev.ip or ""


def _ports_cell(ctx: _Ctx, evs: list[Event], etype: str, ip: str) -> Cell:
    """Sensitive ports first, then by number; long lists end in a "+N more" link."""
    seen: dict[str, Event] = {}
    for ev in evs:
        label = _port_label(ev)
        if label and label not in seen:
            seen[label] = ev
    ordered = sorted(seen.items(), key=lambda kv: (not ctx.is_sensitive(kv[1]), kv[1].port or 0))
    labels = [label for label, _ in ordered]
    shown = ", ".join(labels[:MAX_PORTS_PER_CELL])
    extra = len(labels) - MAX_PORTS_PER_CELL
    if extra <= 0:
        return shown
    href = ctx.link(type=etype, q=ip) if ip else ctx.link(type=etype)
    return (shown, f"+{extra} more", href)


def _rows_for(ctx: _Ctx, group: list[Event], etype: str) -> tuple[list[str], list[list[Cell]]]:
    """Columns and rows for one event type; port events collapse to one row per host."""
    if etype in (EV_PORT_OPENED, EV_PORT_CLOSED):
        by_host: dict[tuple[str, str], list[Event]] = defaultdict(list)
        for ev in group:
            by_host[_host_key(ev)].append(ev)
        cols = ["Host", "IP", "Ports"]
        rows: list[list[Cell]] = [[name, ip, _ports_cell(ctx, evs, etype, ip)] for (name, ip), evs in by_host.items()]
        firsts = [evs[0] for evs in by_host.values()]
    else:
        firsts = group
        if etype in DEVICE_ATTENTION:
            cols = ["Host", "IP"]
            rows = [[_device_name(ev), ev.ip or ""] for ev in group]
            if etype == EV_DEVICE_DISCOVERED:
                cols.append("Ports")
                for row, ev in zip(rows, group, strict=True):
                    row.append(_short(ev.new_value, 40))
        elif etype == EV_IP_CHANGED:
            cols = ["Host", "From", "To"]
            rows = [[_device_name(ev), ev.old_value or "?", ev.ip or "?"] for ev in group]
        elif etype == EV_SERVICE_DETECTED:
            cols = ["Host", "Port", "Service"]
            rows = [[_device_name(ev), _port_label(ev), _short_keep_version(ev.new_value, 48)] for ev in group]
        elif etype in (EV_SERVICE_CHANGED, EV_VERSION_CHANGED):
            cols = ["Host", "Port", "From", "To"]
            rows = [
                [_device_name(ev), _port_label(ev), _short_keep_version(ev.old_value), _short_keep_version(ev.new_value)]
                for ev in group
            ]
        elif etype in WATCH_ATTENTION:
            cols = ["Host", "IP", "Detail"]
            rows = [[_device_name(ev), ev.ip or "", _short(ev.new_value or ev.message, 60)] for ev in group]
        elif etype in (EV_TAG_ADDED, EV_TAG_REMOVED):
            cols = ["Host", "Tag"]
            rows = [[_device_name(ev), _short(ev.new_value or ev.old_value, 30)] for ev in group]
        else:
            cols = ["Host", "Detail"]
            rows = [[ev.hostname or (_device_name(ev) if ev.device or ev.ip else ""), _short(ev.message, 80)] for ev in group]
    if ctx.multi_network:
        cols.append("Network")
        for row, ev in zip(rows, firsts, strict=True):
            row.append(ctx.network(ev))
    return cols, rows


def _count_label(etype: str, n_events: int, n_rows: int) -> str:
    """Explain both numbers when grouping makes fewer rows than events."""
    if etype in (EV_PORT_OPENED, EV_PORT_CLOSED) and n_rows != n_events:
        return f"{n_rows} host{'s' if n_rows != 1 else ''} · {n_events} ports"
    return str(n_events)


def _attention_rows(ctx: _Ctx, events: list[Event]) -> list[list[Cell]]:
    """High-signal rows shown first. Each item also stays under its normal category below."""
    rows: list[list[Cell]] = []
    for etype, label in WATCH_ATTENTION.items():
        rows += [[label, _device_name(ev), _short(ev.new_value or ev.message, 50)] for ev in events if ev.event_type == etype]
    for etype, label in DEVICE_ATTENTION.items():
        rows += [[label, _device_name(ev), ev.ip or ""] for ev in events if ev.event_type == etype]
    by_host: dict[tuple[str, str], set[int]] = defaultdict(set)
    proto: dict[tuple[str, str, int], str] = {}
    for ev in events:
        if ev.event_type == EV_PORT_OPENED and ctx.is_sensitive(ev):
            by_host[_host_key(ev)].add(ev.port)
            proto[(*_host_key(ev), ev.port)] = _port_label(ev)
    for (name, ip), ports in by_host.items():
        labels = ", ".join(proto[(name, ip, p)] for p in sorted(ports))
        rows.append(["Sensitive port opened", name, f"{labels} ({ip})" if ip else labels])
    return rows


def _subject(title: str, day: str, counts: dict[str, int], sensitive_opened: int) -> str:
    """Strongest signals first (new/gone devices, CVE/watch, sensitive ports, ports), kept inbox-short."""
    signals: list[str] = []
    if counts.get(EV_DEVICE_DISCOVERED):
        signals.append(f"{counts[EV_DEVICE_DISCOVERED]} new")
    if counts.get(EV_DEVICE_DISAPPEARED):
        signals.append(f"{counts[EV_DEVICE_DISAPPEARED]} gone")
    if counts.get(EV_CVE_WATCH_MATCH):
        signals.append(f"{counts[EV_CVE_WATCH_MATCH]} CVE")
    watches = sum(counts.get(t, 0) for t in (EV_WATCH_MATCH, EV_POLICY_VIOLATION, EV_MONITOR_CHANGE))
    if watches:
        signals.append(f"{watches} watch")
    if sensitive_opened:
        signals.append(f"{sensitive_opened} sensitive")
    if counts.get(EV_PORT_OPENED):
        signals.append(f"{counts[EV_PORT_OPENED]} port{'s' if counts[EV_PORT_OPENED] != 1 else ''}")
    total = sum(counts.values())
    if not signals:
        signals.append(f"{total} change{'s' if total != 1 else ''}" if total else "no changes")
    parts = signals[:3]
    while True:
        subject = f"{SUBJECT_PREFIX} {title} · {' · '.join(parts)} · {day}"
        if len(subject) <= MAX_SUBJECT_LEN or len(parts) == 1:
            return subject
        parts = parts[:-1]


def _cell_text(cell: Cell) -> str:
    if isinstance(cell, tuple):
        text, more, href = cell
        return f"{text} {more}" + (f" ({href})" if href else "")
    return cell


def _link_html(text: str, href: str | None) -> str:
    if not href:
        return f'<span style="color:#64748b;">{_esc(text)}</span>'
    return f'<a href="{_esc(href)}" style="color:#2563eb;text-decoration:none;">{_esc(text)}</a>'


def _cell_html(cell: Cell) -> str:
    if isinstance(cell, tuple):
        text, more, href = cell
        return f"{_esc(text)} {_link_html(more, href)}"
    return _esc(cell)


TD = "padding:8px 10px;border-bottom:1px solid #e2e8f0;vertical-align:top;font-size:13px;line-height:1.35;color:#0f172a;"
TH = (
    "padding:6px 10px;text-align:left;font-size:11px;font-weight:600;color:#64748b;"
    "text-transform:uppercase;letter-spacing:0.04em;border-bottom:1px solid #cbd5e1;"
)


def _table_html(columns: list[str], rows: list[list[Cell]], extra: int, more_href: str | None) -> str:
    head = "".join(f'<th align="left" style="{TH}">{_esc(c)}</th>' for c in columns)
    body = []
    for i, row in enumerate(rows):
        bg = "#ffffff" if i % 2 == 0 else "#f8fafc"
        body.append(f'<tr style="background:{bg};">' + "".join(f'<td style="{TD}">{_cell_html(c)}</td>' for c in row) + "</tr>")
    if extra > 0:
        body.append(f'<tr><td colspan="{len(columns)}" style="{TD}">{_link_html(f"…and {extra} more", more_href)}</td></tr>')
    return (
        '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" '
        f'style="border-collapse:collapse;margin:4px 0 0;"><tr>{head}</tr>{"".join(body)}</table>'
    )


def _plain_rows(rows: list[list[Cell]], indent: str) -> list[str]:
    return [indent + "• " + " | ".join(t for t in (_cell_text(c) for c in row) if t) for row in rows]


def format_daily_digest(
    events: list[Event],
    network_names: dict[int, str] | None = None,
    *,
    base_url: str = "",
    sensitive_ports: list[int] | None = None,
    title: str = DIGEST_TITLES["daily"],
    group_name: str | None = None,
) -> tuple[str, str, str]:
    """Return (subject, plain_text, html) for a short categorized summary.

    ``base_url`` (public app URL) turns the footer and each "…and N more" into Changes links;
    empty keeps plain text. A Network column appears only when the batch spans several networks.
    """
    sensitive = set(DEFAULT_SENSITIVE_PORTS if sensitive_ports is None else sensitive_ports)
    ctx = _Ctx(events, network_names or {}, base_url, sensitive)
    day = _local_day(events[0].created_at) if events else utcnow().astimezone().strftime("%Y-%m-%d")
    counts: dict[str, int] = defaultdict(int)
    for ev in events:
        counts[ev.event_type] += 1
    n = len(events)
    sensitive_opened = sum(1 for ev in events if ev.event_type == EV_PORT_OPENED and ctx.is_sensitive(ev))
    subject = _subject(title, day, counts, sensitive_opened)

    count_bits = [
        f"{counts[t]} {TITLES.get(t, t).lower()}" for t, _ in sorted(((t, TITLES.get(t, t)) for t in counts), key=lambda x: x[1])
    ]
    summary = " · ".join(count_bits)
    subtitle_bits = [day, f"{n} change{'s' if n != 1 else ''}"]
    if group_name and group_name.strip().lower() != title.lower():
        subtitle_bits.append(group_name.strip())
    subtitle = " · ".join(subtitle_bits)

    plain_lines = [f"PortReveal {title}", subtitle, summary, ""]
    html_sections: list[str] = []

    attention = _attention_rows(ctx, events)
    if attention:
        shown = attention[:MAX_ATTENTION_LINES]
        extra = len(attention) - len(shown)
        plain_lines += ["Attention", *_plain_rows(shown, "  ")]
        if extra > 0:
            plain_lines.append(f"  • …and {extra} more")
        plain_lines.append("")
        html_sections.append(
            '<div style="margin-top:14px;padding:10px 12px;background:#fff7ed;border:1px solid #fed7aa;border-radius:6px;">'
            '<div style="font-size:15px;font-weight:600;color:#9a3412;">Attention</div>'
            f"{_table_html(['What', 'Host', 'Detail'], shown, extra, ctx.link())}</div>"
        )

    sections = [(cat, MAX_LINES_PER_SECTION, "") for cat in CATEGORIES] + [(OTHER_CATEGORY, OTHER_SAMPLE_ROWS, OTHER_NOTE)]
    for (cat_name, types), limit, note in sections:
        cat_events = [e for e in events if e.event_type in types]
        if not cat_events:
            continue
        plain_lines.append(f"{cat_name} ({len(cat_events)})")
        blocks: list[str] = []
        for etype in types:
            group = [e for e in cat_events if e.event_type == etype]
            if not group:
                continue
            cols, rows = _rows_for(ctx, group, etype)
            shown = rows[:limit]
            extra = len(rows) - len(shown)
            more_href = ctx.link(type=etype)
            sub_title = TITLES.get(etype, etype)
            count = _count_label(etype, len(group), len(rows))
            plain_lines.append(f"  {sub_title} ({count})")
            plain_lines += _plain_rows(shown, "    ")
            if extra > 0:
                plain_lines.append(f"    • …and {extra} more" + (f" ({more_href})" if more_href else ""))
            blocks.append(
                f'<div style="font-size:13px;font-weight:600;color:#334155;margin:14px 0 2px;">{_esc(sub_title)} '
                f'<span style="font-weight:500;color:#64748b;">({_esc(count)})</span></div>'
                + _table_html(cols, shown, extra, more_href)
            )
        plain_lines.append("")
        note_html = f'<div style="font-size:12px;color:#64748b;margin-top:2px;">{_esc(note)}</div>' if note else ""
        html_sections.append(
            f'<div style="margin-top:18px;padding-top:14px;border-top:1px solid #e2e8f0;">'
            f'<div style="font-size:15px;font-weight:600;color:#0f172a;">{_esc(cat_name)} '
            f'<span style="font-weight:500;color:#64748b;font-size:13px;">({len(cat_events)})</span></div>'
            f"{note_html}{''.join(blocks)}</div>"
        )

    changes_href = ctx.link()
    if changes_href:
        plain_lines.append(f"Open Changes: {changes_href}")
        footer = (
            f'<a href="{_esc(changes_href)}" style="display:inline-block;padding:8px 14px;background:#0f172a;'
            'color:#ffffff;border-radius:6px;text-decoration:none;font-weight:600;font-size:13px;">Open Changes</a>'
        )
    else:
        plain_lines.append("Full detail is in the Changes page.")
        footer = (
            "Full detail is in the Changes page. Set the public app URL under Settings → Notifications → Email to get links here."
        )
    plain = "\n".join(plain_lines).rstrip() + "\n"

    html_body = f"""<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{_esc(subject)}</title></head>
<body style="margin:0;padding:0;background:#f8fafc;font-family:Segoe UI,Roboto,Helvetica,Arial,sans-serif;color:#0f172a;">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#f8fafc;padding:20px 12px;">
<tr><td align="center">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="max-width:660px;background:#ffffff;border:1px solid #e2e8f0;border-radius:8px;overflow:hidden;">
<tr><td style="background:#0f172a;padding:16px 20px;">
  <div style="font-size:11px;letter-spacing:0.06em;text-transform:uppercase;color:#94a3b8;">PortReveal</div>
  <div style="font-size:18px;font-weight:600;color:#ffffff;margin-top:2px;">{_esc(title)}</div>
  <div style="font-size:13px;color:#cbd5e1;margin-top:4px;">{_esc(subtitle)}</div>
</td></tr>
<tr><td style="padding:16px 20px 4px;">
  <p style="margin:0;font-size:13px;line-height:1.45;color:#475569;">{_esc(summary)}</p>
</td></tr>
<tr><td style="padding:4px 20px 18px;">{"".join(html_sections)}</td></tr>
<tr><td style="padding:12px 20px;background:#f1f5f9;font-size:12px;color:#64748b;border-top:1px solid #e2e8f0;">
  {footer}
</td></tr>
</table>
</td></tr></table>
</body></html>"""
    return subject, plain, html_body


def format_sample_digest(base_url: str = "", sensitive_ports: list[int] | None = None) -> tuple[str, str, str]:
    """Sample summary for the settings test-email action, built by the production formatter."""
    now = utcnow()
    server = Device(hostname="server01", network_id=None)
    sample = [
        Event(
            id=1,
            created_at=now,
            event_type=EV_DEVICE_DISCOVERED,
            ip="10.0.0.20",
            new_value="TCP/22, TCP/443",
            message="New device",
            device=Device(hostname="printer02", network_id=None),
        ),
        Event(
            id=2,
            created_at=now,
            event_type=EV_PORT_OPENED,
            ip="10.0.0.10",
            protocol="tcp",
            port=8080,
            message="Port opened",
            device=server,
        ),
        Event(
            id=3,
            created_at=now,
            event_type=EV_PORT_OPENED,
            ip="10.0.0.10",
            protocol="tcp",
            port=3389,
            message="Port opened",
            device=server,
        ),
        Event(
            id=4,
            created_at=now,
            event_type=EV_VERSION_CHANGED,
            ip="10.0.0.10",
            protocol="tcp",
            port=443,
            old_value="nginx 1.24.0",
            new_value="nginx 1.26.2",
            message="Version changed",
            device=server,
        ),
    ]
    subject, plain, html_body = format_daily_digest(sample, base_url=base_url, sensitive_ports=sensitive_ports)
    return subject.replace(SUBJECT_PREFIX, f"{SUBJECT_PREFIX} [test]", 1), plain, html_body


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


def send_email(
    cfg: NotificationSettings,
    subject: str,
    body: str,
    html_body: str | None = None,
    *,
    timeout: float | None = None,
    message_id: str | None = None,
) -> None:
    if not cfg.smtp_host:
        raise SmtpConfigError("SMTP host is not configured")
    if not cfg.recipients:
        raise SmtpConfigError("No recipients configured")
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = cfg.sender
    msg["To"] = ", ".join(cfg.recipients)
    msg["Date"] = formatdate(localtime=True)
    # Stable id (channel retries) lets some MTAs drop a duplicate after a late accept.
    msg["Message-ID"] = message_id or make_msgid(domain="network-monitor")
    msg.set_content(body)
    if html_body:
        msg.add_alternative(html_body, subtype="html")
    # Default 8s so channel delivery finishes inside the concurrent wait (HTTP_DEADLINE+2).
    timeout = 8.0 if timeout is None else float(timeout)
    if cfg.security == "ssl":
        server: smtplib.SMTP = smtplib.SMTP_SSL(
            cfg.smtp_host, cfg.smtp_port, timeout=timeout, context=ssl.create_default_context()
        )
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
            subject, plain, html_body = format_daily_digest(
                events, network_names, base_url=cfg.public_base_url, sensitive_ports=cfg.digest_sensitive_ports
            )
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
        )
        .unique()
        .all()
    )
