from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import or_, select
from sqlalchemy.orm import Session, selectinload

from ..auth.deps import client_ip, current_user, require_admin
from ..core.audit import audit
from ..core.mockdata import device_visible, event_visible, scan_visible
from ..db import get_db
from ..models import Device, DeviceIP, DevicePort, Event, Network, Scan, ScanHost, User
from ..netutils import ip_sort_key
from .common import Paging, device_summary, event_out, like_pattern, paged, port_out

router = APIRouter(prefix="/api/devices", tags=["devices"])

SORTS = {
    "ip": lambda d: ip_sort_key(d.current_ip),
    "hostname": lambda d: (d.hostname or "~", ip_sort_key(d.current_ip)),
    "last_seen": lambda d: d.last_seen,
    "first_seen": lambda d: d.first_seen,
    "open_ports": lambda d: (sum(1 for p in d.ports if p.is_open), -ip_sort_key(d.current_ip)),
    "status": lambda d: (d.status, ip_sort_key(d.current_ip)),
}

# Soft cap for bulk UUID selection (web capture / scans). Matches settings max_addresses ceiling.
MAX_UUIDS = 4096


def search_conditions(q: str):
    q = q.strip()
    like = like_pattern(q)
    open_ports = select(DevicePort.device_id).where(DevicePort.is_open.is_(True))
    conds = [
        Device.current_ip.like(like, escape="\\"),
        Device.hostname.ilike(like, escape="\\"),
        Device.dns_name.ilike(like, escape="\\"),
        Device.vendor.ilike(like, escape="\\"),
        Device.os_name.ilike(like, escape="\\"),
        Device.mac.ilike(like_pattern(q.replace("-", ":").upper()), escape="\\"),
        Device.id.in_(select(DeviceIP.device_id).where(DeviceIP.ip.like(like, escape="\\"))),
        Device.id.in_(open_ports.where(or_(DevicePort.service.ilike(like, escape="\\"),
                                           DevicePort.product.ilike(like, escape="\\")))),
    ]
    port_txt = q.lower().removeprefix("tcp/").removeprefix("port:")
    if port_txt.isdigit():
        conds.append(Device.id.in_(open_ports.where(DevicePort.port == int(port_txt))))
    return or_(*conds)


def _filtered_devices(
    db: Session,
    *,
    q: str | None,
    status: str | None,
    network_id: int | None,
    port: int | None,
    service: str | None,
    sort: str,
    order: str,
    load_ports: bool = True,
) -> list[Device]:
    stmt = select(Device).where(device_visible(db))
    if load_ports:
        stmt = stmt.options(selectinload(Device.ports))
    if q:
        stmt = stmt.where(search_conditions(q))
    if status:
        stmt = stmt.where(Device.status == status)
    if network_id is not None:
        stmt = stmt.where(Device.network_id == network_id)
    if port is not None:
        stmt = stmt.where(Device.id.in_(select(DevicePort.device_id).where(DevicePort.is_open.is_(True),
                                                                          DevicePort.port == port)))
    if service:
        stmt = stmt.where(Device.id.in_(select(DevicePort.device_id).where(DevicePort.is_open.is_(True),
                                                                          DevicePort.service == service)))
    devices = list(db.scalars(stmt).all())
    devices.sort(key=SORTS[sort], reverse=order == "desc")
    return devices


@router.get("")
def list_devices(
    q: str | None = Query(None, max_length=200),
    status: str | None = Query(None, pattern="^(active|unknown|not_detected)$"),
    network_id: int | None = None,
    port: int | None = Query(None, ge=1, le=65535),
    service: str | None = Query(None, max_length=100),
    sort: str = Query("ip", pattern="^(ip|hostname|last_seen|first_seen|open_ports|status)$"),
    order: str = Query("asc", pattern="^(asc|desc)$"),
    paging: Paging = Depends(),
    db: Session = Depends(get_db),
    user: User = Depends(current_user),
):
    devices = _filtered_devices(
        db, q=q, status=status, network_id=network_id, port=port, service=service, sort=sort, order=order,
    )
    names = {n.id: n.name for n in db.scalars(select(Network)).all()}
    page = devices[paging.offset:paging.offset + paging.page_size]
    return paged([device_summary(d, network_name=names.get(d.network_id)) for d in page], len(devices), paging)


@router.get("/uuids")
def list_device_uuids(
    q: str | None = Query(None, max_length=200),
    status: str | None = Query(None, pattern="^(active|unknown|not_detected)$"),
    network_id: int | None = None,
    port: int | None = Query(None, ge=1, le=65535),
    service: str | None = Query(None, max_length=100),
    sort: str = Query("ip", pattern="^(ip|hostname|last_seen|first_seen|open_ports|status)$"),
    order: str = Query("asc", pattern="^(asc|desc)$"),
    db: Session = Depends(get_db),
    user: User = Depends(current_user),
):
    """All device UUIDs matching the same filters as the list endpoint (for bulk select)."""
    devices = _filtered_devices(
        db, q=q, status=status, network_id=network_id, port=port, service=service, sort=sort, order=order,
        load_ports=False,
    )
    total = len(devices)
    if total > MAX_UUIDS:
        raise HTTPException(422, f"Too many matching devices ({total}); maximum selectable is {MAX_UUIDS}")
    return {"uuids": [d.uuid for d in devices], "total": total}


def _get(db: Session, uuid: str) -> Device:
    d = db.scalar(select(Device).where(Device.uuid == uuid).options(selectinload(Device.ports),
                                                                    selectinload(Device.ips)))
    if d is None:
        raise HTTPException(404, "Device not found")
    return d


@router.get("/{uuid}")
def get_device(uuid: str, db: Session = Depends(get_db), user: User = Depends(current_user)):
    d = _get(db, uuid)
    net = db.get(Network, d.network_id) if d.network_id else None
    out = device_summary(d, network_name=net.name if net else None)
    out.update({
        "dns_name": d.dns_name,
        "missed_scans": d.missed_scans,
        "last_port_scan_at": d.last_port_scan_at,
        "full_scanned_at": d.full_scanned_at,
        "ports": [port_out(p) for p in sorted(d.ports, key=lambda p: (not p.is_open, p.port))],
        "ips": [{"ip": i.ip, "first_seen": i.first_seen, "last_seen": i.last_seen} for i in d.ips],
        "previous_ips": [i.ip for i in d.ips if i.ip != d.current_ip],
    })
    return out


@router.get("/{uuid}/events")
def device_events(uuid: str, paging: Paging = Depends(), db: Session = Depends(get_db),
                  user: User = Depends(current_user)):
    d = _get(db, uuid)
    conds = (Event.device_id == d.id, event_visible(db))
    base = select(Event).where(*conds)
    total = len(db.scalars(select(Event.id).where(*conds)).all())
    rows = db.scalars(base.order_by(Event.id.desc()).offset(paging.offset).limit(paging.page_size)).unique().all()
    return paged([event_out(e) for e in rows], total, paging)


@router.get("/{uuid}/scans")
def device_scans(uuid: str, paging: Paging = Depends(), db: Session = Depends(get_db),
                 user: User = Depends(current_user)):
    d = _get(db, uuid)
    conds = (ScanHost.device_id == d.id, scan_visible(db))
    total = len(db.scalars(select(ScanHost.id).join(Scan, Scan.id == ScanHost.scan_id).where(*conds)).all())
    rows = db.execute(
        select(ScanHost, Scan).join(Scan, Scan.id == ScanHost.scan_id).where(*conds)
        .order_by(ScanHost.id.desc()).offset(paging.offset).limit(paging.page_size)
    ).all()
    items = [{
        "scan_id": s.id, "scan_type": s.scan_type, "scan_status": s.status, "scanner_mode": s.scanner_mode,
        "created_at": sh.created_at, "ip": sh.ip, "status": sh.status, "open_ports": sh.open_ports,
    } for sh, s in rows]
    return paged(items, total, paging)


@router.delete("/{uuid}")
def delete_device(uuid: str, request: Request, db: Session = Depends(get_db), user: User = Depends(require_admin)):
    d = _get(db, uuid)
    audit(db, user.username, "device.delete", d.hostname or d.current_ip, {"uuid": d.uuid, "ip": d.current_ip},
          client_ip(request))
    db.delete(d)
    db.commit()
    return {"ok": True}
