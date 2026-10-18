"""Device availability % over a trailing window (spec section 6).

Missed scans must count as down: ``scan_hosts`` only has rows for hosts that were seen, so the
denominator is completed/partial scans on the device's network that should have covered it
(finished after the device was first seen). A ``port_scan_failed`` observation still means the
host answered discovery — it is up for availability purposes (scan health is separate).
"""
from __future__ import annotations

from datetime import datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import SCAN_COMPLETED, SCAN_PARTIAL, Device, Scan, ScanHost

AVAILABILITY_WINDOW_DAYS = 30
_DONE = (SCAN_COMPLETED, SCAN_PARTIAL)
# Host was reached; port-stage failure is not "host down".
_SEEN_UP = frozenset({"up", "port_scan_failed"})


def availability_pct(db: Session, device_id: int, *, now: datetime, days: int = AVAILABILITY_WINDOW_DAYS) -> float | None:
    """Percentage (0-100) of expected scans that found the device, or None without history."""
    device = db.get(Device, device_id)
    if device is None or device.network_id is None:
        return None
    window_start = now - timedelta(days=days)
    scans = db.execute(
        select(Scan.id, Scan.created_at, Scan.finished_at).where(
            Scan.network_id == device.network_id,
            Scan.status.in_(_DONE),
            Scan.created_at >= window_start,
        )
    ).all()
    # A scan's created_at is before apply_outcome stamps device.first_seen, so use finished_at
    # (or created_at as fallback) when deciding whether the device already existed.
    expected: list[int] = []
    for sid, created_at, finished_at in scans:
        stamp = finished_at or created_at
        if device.first_seen and stamp < device.first_seen:
            continue
        expected.append(sid)
    if not expected:
        return None
    seen_rows = {
        row.scan_id: row.status
        for row in db.scalars(
            select(ScanHost).where(ScanHost.device_id == device_id, ScanHost.scan_id.in_(expected))
        ).all()
    }
    up = sum(1 for sid in expected if seen_rows.get(sid) in _SEEN_UP)
    return round(up * 100.0 / len(expected), 1)
