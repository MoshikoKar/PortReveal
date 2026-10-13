from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..auth.deps import client_ip, current_user, require_admin
from ..core.audit import audit
from ..core.manager import create_scan, manager, network_has_active_scan
from ..core.mockdata import scan_visible
from ..db import get_db
from ..models import SCAN_ACTIVE_STATES, SCAN_FULL, SCAN_QUEUED, SCAN_RUNNING, SCAN_TYPES, Device, Event, Network, Scan, User
from ..netutils import MAX_SCAN_ADDRESSES, AddressSet, TargetError
from ..scanner import scanner_status
from .common import Paging, event_out, paged, scan_out

router = APIRouter(prefix="/api/scans", tags=["scans"])


class ScanRequest(BaseModel):
    scan_type: str = Field(pattern="^(discovery|standard|full)$")
    network_ids: list[int] | None = None
    targets: str | None = Field(None, max_length=10000)
    device_uuids: list[str] | None = Field(None, max_length=5000)
    criteria: str | None = Field(None, max_length=1000)


def _names(db: Session) -> dict[int, str]:
    return {n.id: n.name for n in db.scalars(select(Network)).all()}


@router.get("")
def list_scans(
    status: str | None = Query(None, pattern="^(queued|running|completed|partial|failed|cancelled)$"),
    scan_type: str | None = Query(None, pattern="^(discovery|standard|full)$"),
    paging: Paging = Depends(),
    db: Session = Depends(get_db),
    user: User = Depends(current_user),
):
    conds = [scan_visible(db)]
    if status:
        conds.append(Scan.status == status)
    if scan_type:
        conds.append(Scan.scan_type == scan_type)
    total = db.scalar(select(func.count(Scan.id)).where(*conds)) or 0
    rows = db.scalars(select(Scan).where(*conds).order_by(Scan.id.desc()).offset(paging.offset)
                      .limit(paging.page_size)).all()
    names = _names(db)
    return paged([scan_out(s, names.get(s.network_id)) for s in rows], total, paging)


@router.get("/active")
def active_scans(db: Session = Depends(get_db), user: User = Depends(current_user)):
    names = _names(db)
    rows = db.scalars(select(Scan).where(Scan.status.in_(SCAN_ACTIVE_STATES)).order_by(Scan.id)).all()
    return {
        "running": [scan_out(s, names.get(s.network_id)) for s in rows if s.status == SCAN_RUNNING],
        "queued": [scan_out(s, names.get(s.network_id)) for s in rows if s.status == SCAN_QUEUED],
    }


@router.get("/{scan_id}")
def get_scan(scan_id: int, db: Session = Depends(get_db), user: User = Depends(current_user)):
    s = db.get(Scan, scan_id)
    if s is None:
        raise HTTPException(404, "Scan not found")
    return scan_out(s, _names(db).get(s.network_id))


@router.get("/{scan_id}/events")
def scan_events(scan_id: int, paging: Paging = Depends(), db: Session = Depends(get_db),
                user: User = Depends(current_user)):
    """Change events recorded by one scan, oldest first."""
    if db.get(Scan, scan_id) is None:
        raise HTTPException(404, "Scan not found")
    total = db.scalar(select(func.count(Event.id)).where(Event.scan_id == scan_id)) or 0
    rows = db.scalars(select(Event).where(Event.scan_id == scan_id).order_by(Event.id)
                      .offset(paging.offset).limit(paging.page_size)).unique().all()
    return paged([event_out(e) for e in rows], total, paging)


@router.post("")
def start_scan(body: ScanRequest, request: Request, db: Session = Depends(get_db),
               user: User = Depends(require_admin)):
    if body.scan_type not in SCAN_TYPES:
        raise HTTPException(422, "invalid scan type")
    given = [x for x in (body.network_ids, body.targets, body.device_uuids) if x]
    if len(given) != 1:
        raise HTTPException(422, "Specify exactly one of: network_ids, targets, device_uuids")
    st = scanner_status()
    if st.effective_mode == "unavailable":
        raise HTTPException(409, st.message)

    criteria = (body.criteria or "").strip() or None
    created: list[Scan] = []
    if body.network_ids:
        for nid in dict.fromkeys(body.network_ids):
            net = db.get(Network, nid)
            if net is None:
                raise HTTPException(404, f"Network {nid} not found")
            if network_has_active_scan(db, net.id, body.scan_type):
                raise HTTPException(409, f"A {body.scan_type} scan of {net.name} is already queued or running")
            created.append(create_scan(db, body.scan_type, network=net, requested_by=user.username,
                                       criteria=criteria))
        target_desc = ", ".join(db.get(Network, n).name for n in dict.fromkeys(body.network_ids))
    else:
        if body.device_uuids:
            ips = db.scalars(select(Device.current_ip).where(Device.uuid.in_(body.device_uuids))).all()
            if not ips:
                raise HTTPException(404, "No matching devices")
            spec = ",".join(ips)
        else:
            spec = body.targets or ""
        try:
            targets = AddressSet.from_specs(spec, allow_hostname=True)
        except TargetError as exc:
            raise HTTPException(422, str(exc)) from exc
        if not targets:
            raise HTTPException(422, "No targets given")
        if len(targets) > MAX_SCAN_ADDRESSES:
            raise HTTPException(422, f"Too many addresses ({len(targets)}); maximum is {MAX_SCAN_ADDRESSES}")
        created.append(create_scan(db, body.scan_type, targets=targets, requested_by=user.username,
                                   criteria=criteria))
        target_desc = targets.describe()

    action = "scan.full_port" if body.scan_type == SCAN_FULL else f"scan.{body.scan_type}"
    audit(db, user.username, action, target_desc, {"scan_ids": [s.id for s in created]}, client_ip(request))
    db.commit()
    manager.wake()
    names = _names(db)
    return {"scans": [scan_out(s, names.get(s.network_id)) for s in created]}


@router.post("/{scan_id}/cancel")
def cancel_scan(scan_id: int, request: Request, db: Session = Depends(get_db), user: User = Depends(require_admin)):
    s = db.get(Scan, scan_id)
    if s is None:
        raise HTTPException(404, "Scan not found")
    if s.status not in SCAN_ACTIVE_STATES:
        raise HTTPException(409, f"Scan is already {s.status}")
    db.rollback()  # end the read transaction; the manager updates the row in its own session
    ok = manager.cancel(scan_id)
    audit(db, user.username, "scan.cancel", f"scan {scan_id}", None, client_ip(request))
    db.commit()
    return {"ok": ok}
