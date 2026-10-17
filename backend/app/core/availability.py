"""Device availability % over a trailing window, computed from scan_hosts (spec section 6).

No dedicated column: `scan_hosts` already has one row per device per scan that covered it, and
`retention.py` already caps how long that history lives.
"""
from __future__ import annotations

from datetime import datetime, timedelta

from sqlalchemy import case, func, select
from sqlalchemy.orm import Session

from ..models import ScanHost

AVAILABILITY_WINDOW_DAYS = 30


def availability_pct(db: Session, device_id: int, *, now: datetime, days: int = AVAILABILITY_WINDOW_DAYS) -> float | None:
    """Percentage (0-100) of scans in the window that found the device up, or None without history."""
    since = now - timedelta(days=days)
    total, up = db.execute(
        select(func.count(ScanHost.id), func.sum(case((ScanHost.status == "up", 1), else_=0)))
        .where(ScanHost.device_id == device_id, ScanHost.created_at >= since)
    ).one()
    if not total:
        return None
    return round((up or 0) * 100.0 / total, 1)
