from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import BigInteger, Integer, cast, func, literal, or_, select
from sqlalchemy.orm import Session, selectinload
from sqlalchemy.sql.elements import ColumnElement

from ..auth.deps import client_ip, current_user, require_admin
from ..core.audit import audit
from ..core.mockdata import device_visible, event_visible, scan_visible
from ..db import get_db
from ..models import Device, DeviceIP, DevicePort, Event, Network, Scan, ScanHost, User
from .common import Paging, device_summary, event_out, like_pattern, paged, port_out

router = APIRouter(prefix="/api/devices", tags=["devices"])

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


def _device_filter_conds(
    db: Session,
    *,
    q: str | None,
    status: str | None,
    network_id: int | None,
    port: int | None,
    service: str | None,
) -> list:
    conds: list = [device_visible(db)]
    if q:
        conds.append(search_conditions(q))
    if status:
        conds.append(Device.status == status)
    if network_id is not None:
        conds.append(Device.network_id == network_id)
    if port is not None:
        conds.append(Device.id.in_(select(DevicePort.device_id).where(DevicePort.is_open.is_(True),
                                                                      DevicePort.port == port)))
    if service:
        conds.append(Device.id.in_(select(DevicePort.device_id).where(DevicePort.is_open.is_(True),
                                                                      DevicePort.service == service)))
    return conds


def _ipv4_int_expr(db: Session, col) -> ColumnElement:
    """Numeric IPv4 ORDER BY key (matches netutils.ip_sort_key) for SQLite and PostgreSQL."""
    if db.get_bind().dialect.name == "postgresql":
        expr = (
            cast(func.nullif(func.split_part(col, ".", 1), ""), BigInteger) * 16777216
            + cast(func.nullif(func.split_part(col, ".", 2), ""), BigInteger) * 65536
            + cast(func.nullif(func.split_part(col, ".", 3), ""), BigInteger) * 256
            + cast(func.nullif(func.split_part(col, ".", 4), ""), BigInteger)
        )
    else:
        dot = literal(".")
        o1 = cast(func.substr(col, 1, func.instr(col, dot) - 1), Integer)
        r1 = func.substr(col, func.instr(col, dot) + 1)
        o2 = cast(func.substr(r1, 1, func.instr(r1, dot) - 1), Integer)
        r2 = func.substr(r1, func.instr(r1, dot) + 1)
        o3 = cast(func.substr(r2, 1, func.instr(r2, dot) - 1), Integer)
        o4 = cast(func.substr(r2, func.instr(r2, dot) + 1), Integer)
        expr = o1 * 16777216 + o2 * 65536 + o3 * 256 + o4
    return func.coalesce(expr, 0)


def _open_port_count_expr():
    return (
        select(func.count(DevicePort.id))
        .where(DevicePort.device_id == Device.id, DevicePort.is_open.is_(True))
        .correlate(Device)
        .scalar_subquery()
    )


def _device_order_by(db: Session, sort: str, order: str) -> list:
    desc = order == "desc"
    ip_key = _ipv4_int_expr(db, Device.current_ip)

    def directed(expr, *, flip: bool = False):
        use_desc = desc ^ flip
        return expr.desc() if use_desc else expr.asc()

    if sort == "hostname":
        host = func.coalesce(func.nullif(Device.hostname, ""), "~")
        return [directed(host), directed(ip_key), directed(Device.id)]
    if sort == "last_seen":
        return [directed(Device.last_seen), directed(Device.id)]
    if sort == "first_seen":
        return [directed(Device.first_seen), directed(Device.id)]
    if sort == "open_ports":
        # Python key was (open_count, -ip); reverse flips both → IP tiebreak opposite primary.
        return [directed(_open_port_count_expr()), directed(ip_key, flip=True), directed(Device.id)]
    if sort == "status":
        return [directed(Device.status), directed(ip_key), directed(Device.id)]
    return [directed(ip_key), directed(Device.id)]


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
    conds = _device_filter_conds(db, q=q, status=status, network_id=network_id, port=port, service=service)
    total = db.scalar(select(func.count(Device.id)).where(*conds)) or 0
    devices = list(db.scalars(
        select(Device)
        .where(*conds)
        .order_by(*_device_order_by(db, sort, order))
        .offset(paging.offset)
        .limit(paging.page_size)
        .options(selectinload(Device.ports))
    ).unique().all())
    names = {n.id: n.name for n in db.scalars(select(Network)).all()}
    return paged([device_summary(d, network_name=names.get(d.network_id)) for d in devices], total, paging)


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
    conds = _device_filter_conds(db, q=q, status=status, network_id=network_id, port=port, service=service)
    # LIMIT cap+1 in SQL: never materializes more than the cap; one extra row detects overflow,
    # and the COUNT only runs then (for the error message).
    uuids = list(db.scalars(
        select(Device.uuid).where(*conds).order_by(*_device_order_by(db, sort, order)).limit(MAX_UUIDS + 1)
    ).all())
    if len(uuids) > MAX_UUIDS:
        total = db.scalar(select(func.count(Device.id)).where(*conds)) or 0
        raise HTTPException(422, f"Too many matching devices ({total}); maximum selectable is {MAX_UUIDS}")
    return {"uuids": uuids, "total": len(uuids)}


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
