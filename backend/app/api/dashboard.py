from __future__ import annotations

from datetime import timedelta

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, literal_column, select
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
    SCAN_ACTIVE_STATES,
    Device,
    DevicePort,
    Event,
    Network,
    Scan,
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


EXPOSED_PORTS_DEFAULT_LIMIT = 1000
EXPOSED_PORTS_MAX_LIMIT = 5000


def _open_port_conds(db: Session, network_id: int | None) -> list:
    conds = [DevicePort.is_open.is_(True), device_visible(db)]
    if network_id is not None:
        conds.append(Device.network_id == network_id)
    return conds


def count_exposed_ports(db: Session, network_id: int | None = None) -> int:
    """Distinct open protocol/port pairs (the size of the uncapped exposed_ports() list)."""
    distinct_ports = (
        select(DevicePort.protocol, DevicePort.port)
        .join(Device, Device.id == DevicePort.device_id)
        .where(*_open_port_conds(db, network_id))
        .group_by(DevicePort.protocol, DevicePort.port)
        .subquery()
    )
    return db.scalar(select(func.count()).select_from(distinct_ports)) or 0


def exposed_ports(db: Session, network_id: int | None = None, limit: int | None = None) -> list[dict]:
    """Open ports ranked by host count, labelled with the service most hosts report for them.
    With `limit`, only the top-ranked ports are aggregated per service (ranking done in SQL)."""
    conds = _open_port_conds(db, network_id)
    # literal_column: keeps the SELECT and GROUP BY coalesce() identical on PostgreSQL (see dashboard)
    svc = func.coalesce(DevicePort.service, literal_column("'unknown'"))
    q = (
        select(DevicePort.protocol, DevicePort.port, svc, func.count(DevicePort.id))
        .join(Device, Device.id == DevicePort.device_id)
        .where(*conds)
        .group_by(DevicePort.protocol, DevicePort.port, svc)
    )
    top: set[tuple[str, int]] | None = None
    if limit is not None:
        # Rank in its own query, then aggregate only those ports. Joining the ranked subquery instead
        # made SQLite re-run it per row (~15 s on a few thousand ports).
        top = set(db.execute(
            select(DevicePort.protocol, DevicePort.port)
            .join(Device, Device.id == DevicePort.device_id)
            .where(*conds)
            .group_by(DevicePort.protocol, DevicePort.port)
            .order_by(func.count(DevicePort.id).desc(), DevicePort.protocol, DevicePort.port)
            .limit(limit)
        ).tuples().all())
        if not top:
            return []
        q = q.where(DevicePort.port.in_({port for _, port in top}))
    by_port: dict[tuple[str, int], dict] = {}
    for proto, port, service, n in db.execute(q).all():
        if top is not None and (proto, port) not in top:
            continue  # same port number, other protocol, outside the top set
        # one row per device/protocol/port, so per-service counts add up to the host count
        row = by_port.setdefault((proto, port), {"protocol": proto, "port": port, "count": 0, "services": []})
        row["services"].append({"service": service, "count": n})
        row["count"] += n
    for row in by_port.values():
        row["services"].sort(key=lambda x: (-x["count"], x["service"]))
        named = [x for x in row["services"] if x["service"] not in ("unknown", "tcpwrapped")]
        row["service"] = (named or row["services"])[0]["service"]
    return sorted(by_port.values(), key=lambda r: (-r["count"], r["protocol"], r["port"]))


@router.get("/exposed-ports")
def list_exposed_ports(network_id: int | None = Query(None),
                       limit: int = Query(EXPOSED_PORTS_DEFAULT_LIMIT, ge=1, le=EXPOSED_PORTS_MAX_LIMIT),
                       db: Session = Depends(get_db), user: User = Depends(current_user)):
    """Top `limit` ports by host count; `total` counts every distinct open port, `truncated` flags the cut."""
    ports = exposed_ports(db, network_id, limit=limit)
    total = count_exposed_ports(db, network_id) if len(ports) >= limit else len(ports)
    return {"ports": ports, "total": total, "truncated": total > len(ports)}


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

    # literal_column: PostgreSQL rejects GROUP BY when the SELECT and GROUP BY coalesce()
    # use different bind parameters; a literal keeps both expressions identical.
    service_name = func.coalesce(DevicePort.service, literal_column("'unknown'"))
    top_services = db.execute(
        select(service_name, func.count(DevicePort.id))
        .join(Device, Device.id == DevicePort.device_id)
        .where(DevicePort.is_open.is_(True), dev_ok)
        .group_by(service_name)
        .order_by(func.count(DevicePort.id).desc())
        .limit(10)
    ).all()
    top_ports = exposed_ports(db, limit=12)

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
    scanning = set(db.scalars(select(Scan.network_id).where(Scan.status.in_(SCAN_ACTIVE_STATES))).all())
    networks = [
        {**network_out(n, per_net.get(n.id, 0), per_net_active.get(n.id, 0)), "scan_active": n.id in scanning}
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
        "top_ports": [{k: r[k] for k in ("protocol", "port", "count", "service")} for r in top_ports],
        "exposed_ports_total": count_exposed_ports(db),
        "trend": [{"date": d.isoformat(), "hosts_active": int(a or 0), "open_ports": int(o or 0)} for d, a, o in trend_rows],
        "networks": networks,
        "scans": scan_summary(db),
    }
