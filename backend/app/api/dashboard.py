from __future__ import annotations

from datetime import timedelta

from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..auth.deps import current_user
from ..core.mockdata import device_visible, event_visible, snapshot_visible
from ..db import get_db, utcnow
from ..models import (
    DEVICE_ACTIVE,
    EV_DEVICE_DISCOVERED,
    EV_PORT_CLOSED,
    EV_PORT_OPENED,
    EV_SERVICE_CHANGED,
    EV_VERSION_CHANGED,
    Device,
    DevicePort,
    Event,
    Network,
    Snapshot,
    User,
)
from .common import event_out, network_out
from .system import scan_summary

router = APIRouter(prefix="/api", tags=["dashboard"])


def _event_counts(db: Session, since) -> dict[str, int]:
    rows = db.execute(
        select(Event.event_type, func.count(Event.id)).where(Event.created_at >= since, event_visible(db))
        .group_by(Event.event_type)
    ).all()
    return {t: n for t, n in rows}


@router.get("/dashboard")
def dashboard(db: Session = Depends(get_db), user: User = Depends(current_user)):
    now = utcnow()
    dev_ok = device_visible(db)
    status_counts = dict(db.execute(select(Device.status, func.count(Device.id)).where(dev_ok)
                                    .group_by(Device.status)).all())
    total = sum(status_counts.values())
    open_ports = db.scalar(
        select(func.count(DevicePort.id)).join(Device, Device.id == DevicePort.device_id)
        .where(DevicePort.is_open.is_(True), dev_ok)
    ) or 0
    exposed_hosts = db.scalar(
        select(func.count(func.distinct(DevicePort.device_id))).join(Device, Device.id == DevicePort.device_id)
        .where(DevicePort.is_open.is_(True), dev_ok)
    ) or 0
    c24 = _event_counts(db, now - timedelta(hours=24))
    c7 = _event_counts(db, now - timedelta(days=7))

    def pick(counts, *types):
        return sum(counts.get(t, 0) for t in types)

    recent = db.scalars(select(Event).where(event_visible(db)).order_by(Event.id.desc()).limit(30)).unique().all()

    top_services = db.execute(
        select(func.coalesce(DevicePort.service, "unknown"), func.count(DevicePort.id))
        .join(Device, Device.id == DevicePort.device_id)
        .where(DevicePort.is_open.is_(True), dev_ok)
        .group_by(func.coalesce(DevicePort.service, "unknown"))
        .order_by(func.count(DevicePort.id).desc())
        .limit(10)
    ).all()
    top_ports = db.execute(
        select(DevicePort.protocol, DevicePort.port, func.count(DevicePort.id), func.max(DevicePort.service))
        .join(Device, Device.id == DevicePort.device_id)
        .where(DevicePort.is_open.is_(True), dev_ok)
        .group_by(DevicePort.protocol, DevicePort.port)
        .order_by(func.count(DevicePort.id).desc(), DevicePort.port)
        .limit(12)
    ).all()

    since_day = (now - timedelta(days=30)).date()
    trend_rows = db.execute(
        select(Snapshot.snapshot_date, func.sum(Snapshot.hosts_active), func.sum(Snapshot.open_ports))
        .where(Snapshot.snapshot_date >= since_day, snapshot_visible(db))
        .group_by(Snapshot.snapshot_date)
        .order_by(Snapshot.snapshot_date)
    ).all()

    per_net = dict(db.execute(select(Device.network_id, func.count(Device.id)).where(dev_ok)
                              .group_by(Device.network_id)).all())
    per_net_active = dict(
        db.execute(
            select(Device.network_id, func.count(Device.id)).where(Device.status == DEVICE_ACTIVE, dev_ok)
            .group_by(Device.network_id)
        ).all()
    )
    networks = [
        network_out(n, per_net.get(n.id, 0), per_net_active.get(n.id, 0))
        for n in db.scalars(select(Network).order_by(Network.name)).all()
    ]

    return {
        "devices": {
            "total": total,
            "active": status_counts.get("active", 0),
            "unknown": status_counts.get("unknown", 0),
            "not_detected": status_counts.get("not_detected", 0),
            "exposed": exposed_hosts,
        },
        "open_ports_total": open_ports,
        "last_24h": {
            "changes": sum(c24.values()),
            "new_hosts": pick(c24, EV_DEVICE_DISCOVERED),
            "new_ports": pick(c24, EV_PORT_OPENED),
            "closed_ports": pick(c24, EV_PORT_CLOSED),
            "service_changes": pick(c24, EV_SERVICE_CHANGED, EV_VERSION_CHANGED),
            "by_type": c24,
        },
        "last_7d": {
            "changes": sum(c7.values()),
            "new_hosts": pick(c7, EV_DEVICE_DISCOVERED),
            "new_ports": pick(c7, EV_PORT_OPENED),
            "closed_ports": pick(c7, EV_PORT_CLOSED),
            "service_changes": pick(c7, EV_SERVICE_CHANGED, EV_VERSION_CHANGED),
            "by_type": c7,
        },
        "recent_events": [event_out(e) for e in recent],
        "top_services": [{"service": s, "count": n} for s, n in top_services],
        "top_ports": [{"protocol": p, "port": port, "count": n, "service": svc} for p, port, n, svc in top_ports],
        "trend": [{"date": d.isoformat(), "hosts_active": int(a or 0), "open_ports": int(o or 0)} for d, a, o in trend_rows],
        "networks": networks,
        "scans": scan_summary(db),
    }
