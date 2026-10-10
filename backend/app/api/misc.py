"""Audit log, snapshots and development helpers."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from ..auth.deps import client_ip, current_user, require_admin
from ..config import get_settings
from ..core.audit import audit
from ..core.mockdata import mock_counts, mock_hidden, set_mock_hidden, snapshot_visible
from ..core.runner import mock_step_key
from ..core.snapshots import load_snapshot
from ..db import get_db
from ..models import AuditLog, Network, Snapshot, User
from ..scanner import scanner_status
from ..scanner.mock_scanner import LAST_STEP, STEP_NOTES
from ..settings_store import get_value, set_value
from .common import Paging, like_pattern, paged

router = APIRouter(prefix="/api", tags=["misc"])


@router.post("/inventory/ad-sync")
def ad_computer_sync(db: Session = Depends(get_db), user: User = Depends(require_admin)):
    """Read AD computer objects (LDAP) and tag matching inventory hosts as `in-ad`."""
    from ..core.ad_inventory import sync_ad_tags
    return sync_ad_tags(db)


@router.get("/audit")
def list_audit(q: str | None = Query(None, max_length=200), paging: Paging = Depends(),
               db: Session = Depends(get_db), user: User = Depends(require_admin)):
    conds = []
    if q:
        like = like_pattern(q)
        conds.append(or_(AuditLog.action.ilike(like, escape="\\"), AuditLog.username.ilike(like, escape="\\"),
                         AuditLog.target.ilike(like, escape="\\")))
    total = db.scalar(select(func.count(AuditLog.id)).where(*conds)) or 0
    rows = db.scalars(select(AuditLog).where(*conds).order_by(AuditLog.id.desc()).offset(paging.offset)
                      .limit(paging.page_size)).all()
    return paged([{
        "id": a.id, "created_at": a.created_at, "username": a.username, "action": a.action,
        "target": a.target, "details": a.details, "ip": a.ip,
    } for a in rows], total, paging)


@router.get("/snapshots")
def list_snapshots(network_id: int | None = None, paging: Paging = Depends(), db: Session = Depends(get_db),
                   user: User = Depends(current_user)):
    conds = [snapshot_visible(db)]
    if network_id is not None:
        conds.append(Snapshot.network_id == network_id)
    total = db.scalar(select(func.count(Snapshot.id)).where(*conds)) or 0
    names = {n.id: n.name for n in db.scalars(select(Network)).all()}
    rows = db.scalars(select(Snapshot).where(*conds).order_by(Snapshot.snapshot_date.desc(), Snapshot.id.desc())
                      .offset(paging.offset).limit(paging.page_size)).all()
    return paged([{
        "id": s.id, "network_id": s.network_id, "network_name": names.get(s.network_id),
        "snapshot_date": s.snapshot_date, "scan_id": s.scan_id, "created_at": s.created_at,
        "hosts_total": s.hosts_total, "hosts_active": s.hosts_active, "open_ports": s.open_ports,
        "size_bytes": len(s.data or b""),
    } for s in rows], total, paging)


@router.get("/snapshots/{snapshot_id}")
def get_snapshot(snapshot_id: int, db: Session = Depends(get_db), user: User = Depends(current_user)):
    s = db.get(Snapshot, snapshot_id)
    if s is None:
        raise HTTPException(404, "Snapshot not found")
    return load_snapshot(s)


# --- development helpers -------------------------------------------------------------
@router.get("/dev/mock")
def mock_state(db: Session = Depends(get_db), user: User = Depends(current_user)):
    st = scanner_status()
    nets = db.scalars(select(Network).order_by(Network.id)).all()
    return {
        "mock_active": st.effective_mode == "mock",
        "last_step": LAST_STEP,
        "steps": STEP_NOTES,
        "networks": [{"id": n.id, "name": n.name, "step": int(get_value(db, mock_step_key(n.id), 0))} for n in nets],
    }


@router.post("/dev/mock/reset")
def mock_reset(request: Request, db: Session = Depends(get_db), user: User = Depends(require_admin)):
    if not get_settings().is_dev and scanner_status().effective_mode != "mock":
        raise HTTPException(403, "Only available in development or mock mode")
    for n in db.scalars(select(Network)).all():
        set_value(db, mock_step_key(n.id), 0)
    audit(db, user.username, "dev.mock_reset", None, None, client_ip(request))
    db.commit()
    return {"ok": True}


# --- simulated (mock scanner) data visibility --------------------------------------
class MockDataVisibility(BaseModel):
    hidden: bool


def _mock_data_out(db: Session) -> dict:
    return {"hidden": mock_hidden(db), **mock_counts(db)}


@router.get("/mock-data")
def mock_data_state(db: Session = Depends(get_db), user: User = Depends(current_user)):
    return _mock_data_out(db)


@router.put("/mock-data")
def set_mock_data_visibility(body: MockDataVisibility, request: Request, db: Session = Depends(get_db),
                             user: User = Depends(require_admin)):
    set_mock_hidden(db, body.hidden)
    audit(db, user.username, "mock_data.hide" if body.hidden else "mock_data.show", None, None, client_ip(request))
    db.commit()
    return _mock_data_out(db)
