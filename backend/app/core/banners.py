"""Service banner history: store truncated probe/nmap text; new row only when hash changes."""
from __future__ import annotations

import hashlib
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db import utcnow
from ..models import (
    EV_BANNER_CHANGED,
    EVENT_SEVERITY,
    Device,
    DevicePort,
    Event,
    ServiceBanner,
)

BANNER_MAX = 4096


def banner_hash(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()


def truncate_banner(text: str | None) -> str | None:
    if not text:
        return None
    t = text.strip()
    if not t:
        return None
    return t if len(t) <= BANNER_MAX else t[: BANNER_MAX - 1] + "…"


def record_banner(
    db: Session,
    port: DevicePort,
    raw: str | None,
    *,
    device: Device | None = None,
    scan_id: int | None = None,
    now: datetime | None = None,
    emit_event: bool = True,
) -> ServiceBanner | None:
    """Write a banner row when content is new. Returns the row when one was created."""
    text = truncate_banner(raw)
    if not text or port.id is None:
        return None
    now = now or utcnow()
    h = banner_hash(text)
    latest = db.scalar(
        select(ServiceBanner)
        .where(ServiceBanner.device_port_id == port.id)
        .order_by(ServiceBanner.seen_at.desc(), ServiceBanner.id.desc())
        .limit(1)
    )
    if latest is not None and latest.hash == h:
        return None
    row = ServiceBanner(device_port_id=port.id, hash=h, raw_truncated=text, seen_at=now)
    db.add(row)
    if emit_event and latest is not None and device is not None:
        db.add(Event(
            created_at=now, scan_id=scan_id, device=device,
            event_type=EV_BANNER_CHANGED, severity=EVENT_SEVERITY[EV_BANNER_CHANGED],
            ip=device.current_ip, protocol=port.protocol, port=port.port,
            old_value=latest.raw_truncated[:200], new_value=text[:200],
            message=f"Banner changed on {port.protocol.upper()}/{port.port} of {device.current_ip}",
            notify=False,
        ))
    return row


def sync_nmap_banners(db: Session, ports: list[DevicePort], *, device: Device, scan_id: int | None,
                      now: datetime) -> None:
    """Record banners from DevicePort.extra_info (nmap extrainfo / script snippets)."""
    for p in ports:
        if not p.is_open or not p.extra_info:
            continue
        if p.id is None:
            db.flush()
        record_banner(db, p, p.extra_info, device=device, scan_id=scan_id, now=now)
