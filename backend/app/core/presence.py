"""Correlated absence: night inventory scan + daytime presence scans.

A device accumulates one absence day only when, on that local calendar day, the network's
night standard scan completed and every presence scan completed, and none of them (nor any
other scan) saw the device. Any sighting resets the streak (see core/compare.py). When the
streak reaches `PresenceSettings.absence_days` a notifying `device_disappeared` event is
recorded; the matching `device_reappeared` is notified on the next sighting.
"""
from __future__ import annotations

import logging
from datetime import date, datetime, time, timedelta

from sqlalchemy import select

from ..models import (
    DEVICE_NOT_DETECTED,
    EV_DEVICE_DISAPPEARED,
    EVENT_SEVERITY,
    SCAN_ACTIVE_STATES,
    SCAN_COMPLETED,
    SCAN_DISCOVERY,
    SCAN_STANDARD,
    TRIGGER_PRESENCE,
    TRIGGER_SCHEDULED,
    Device,
    Event,
    Network,
    Scan,
)
from ..netutils import AddressSet
from ..settings_store import PresenceSettings
from .compare import device_label
from .runner import exclusion_set

log = logging.getLogger(__name__)


def _local_day_bounds(day: date) -> tuple[datetime, datetime]:
    return datetime.combine(day, time.min).astimezone(), datetime.combine(day + timedelta(days=1), time.min).astimezone()


def presence_scan_active(db) -> bool:
    q = select(Scan.id).where(Scan.trigger == TRIGGER_PRESENCE, Scan.status.in_(SCAN_ACTIVE_STATES))
    return db.scalar(q.limit(1)) is not None


def _day_scans(db, network_id: int, trigger: str, scan_type: str, start: datetime, end: datetime) -> list[Scan]:
    return list(db.scalars(
        select(Scan).where(Scan.network_id == network_id, Scan.trigger == trigger, Scan.scan_type == scan_type,
                           Scan.created_at >= start, Scan.created_at < end)
        .order_by(Scan.id)
    ).all())


def evaluate_absence(db, cfg: PresenceSettings, day: date, now_utc: datetime) -> int:
    """Count one correlated absence day for `day` (idempotent). Returns notifying events created."""
    start, end = _local_day_bounds(day)
    excluded = exclusion_set(db)
    alerts = 0
    for net in db.scalars(select(Network).where(Network.enabled.is_(True)).order_by(Network.id)).all():
        if net.baseline_scan_id is None:
            continue
        night = _day_scans(db, net.id, TRIGGER_SCHEDULED, SCAN_STANDARD, start, end)
        presence = _day_scans(db, net.id, TRIGGER_PRESENCE, SCAN_DISCOVERY, start, end)
        if not any(s.status == SCAN_COMPLETED for s in night):
            log.info("absence not evaluated for %s on %s: no completed night scan", net.name, day)
            continue
        if not presence or any(s.status != SCAN_COMPLETED for s in presence):
            log.info("absence not evaluated for %s on %s: presence scans missing or incomplete", net.name, day)
            continue
        targets = AddressSet.from_specs(net.cidr).subtract(excluded)
        for d in db.scalars(select(Device).where(Device.network_id == net.id)).all():
            if d.current_ip not in targets or d.absence_counted_on == day:
                continue
            if d.last_seen.astimezone().date() >= day:
                continue
            d.absence_days = (d.absence_days or 0) + 1
            d.absence_counted_on = day
            if d.absence_days >= cfg.absence_days and not d.absence_alerted:
                d.absence_alerted = True
                d.status = DEVICE_NOT_DETECTED
                db.add(Event(
                    created_at=now_utc,
                    scan_id=presence[-1].id,
                    device=d,
                    event_type=EV_DEVICE_DISAPPEARED,
                    severity=EVENT_SEVERITY[EV_DEVICE_DISAPPEARED],
                    ip=d.current_ip,
                    message=f"{device_label(d)} ({d.current_ip}) has not been detected for {d.absence_days} "
                            "days (night and daytime scans)",
                    notify=True,
                ))
                alerts += 1
    db.flush()
    log.info("correlated absence evaluated for %s: %d disappearance alert(s)", day, alerts)
    return alerts
