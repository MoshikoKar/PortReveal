from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..auth.deps import client_ip, current_user, require_admin
from ..core.audit import audit
from ..core.intel import refresh_devices
from ..core.mockdata import device_visible
from ..db import get_db, utcnow
from ..models import DEVICE_ACTIVE, NETWORK_ZONES, Device, Network, User
from ..netutils import TargetError, validate_network_cidr
from .common import FULL_REPLACE, UNPAGED_LIST, Row, network_out

router = APIRouter(prefix="/api/networks", tags=["networks"])


class NetworkIn(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    cidr: str = Field(min_length=7, max_length=64)
    description: str | None = Field(None, max_length=1000)
    enabled: bool = True
    zone: str | None = None
    vpn_s2s: bool = False

    @field_validator("zone")
    @classmethod
    def _zone(cls, v: str | None) -> str | None:
        v = (v or "").strip().lower() or None
        if v is not None and v not in NETWORK_ZONES:
            raise ValueError(f"zone must be one of: {', '.join(NETWORK_ZONES)}")
        return v

    @field_validator("name")
    @classmethod
    def _name(cls, v: str) -> str:
        return v.strip()

    @field_validator("cidr")
    @classmethod
    def _cidr(cls, v: str) -> str:
        try:
            return validate_network_cidr(v)
        except TargetError as exc:
            raise ValueError(str(exc)) from exc


def _counts(db: Session):
    ok = device_visible(db, include_archived=True)
    total = dict(db.execute(select(Device.network_id, func.count(Device.id)).where(ok)
                            .group_by(Device.network_id)).all())
    active = dict(db.execute(select(Device.network_id, func.count(Device.id)).where(Device.status == DEVICE_ACTIVE, ok)
                             .group_by(Device.network_id)).all())
    return total, active


@router.get("", response_model=list[Row], description=UNPAGED_LIST)
def list_networks(include_archived: bool = False, db: Session = Depends(get_db),
                  user: User = Depends(current_user)):
    total, active = _counts(db)
    q = select(Network).order_by(Network.name)
    if not include_archived:
        q = q.where(Network.archived_at.is_(None))
    return [network_out(n, total.get(n.id, 0), active.get(n.id, 0)) for n in db.scalars(q).all()]


def _active_network(db: Session, network_id: int) -> Network:
    net = db.get(Network, network_id)
    if net is None or net.archived_at is not None:
        raise HTTPException(404, "Network not found")
    return net


def _check_name(db: Session, name: str, exclude_id: int | None = None) -> None:
    q = select(Network).where(func.lower(Network.name) == name.lower())
    if exclude_id is not None:
        q = q.where(Network.id != exclude_id)
    clash = db.scalar(q)
    if clash is not None:
        hint = " (archived; restore it instead)" if clash.archived_at is not None else ""
        raise HTTPException(409, f"A network named '{name}' already exists{hint}")


@router.post("", status_code=201)
def create_network(body: NetworkIn, request: Request, db: Session = Depends(get_db),
                   user: User = Depends(require_admin)):
    _check_name(db, body.name)
    net = Network(name=body.name, cidr=body.cidr, description=body.description, enabled=body.enabled,
                  zone=body.zone, vpn_s2s=body.vpn_s2s)
    db.add(net)
    db.flush()
    audit(db, user.username, "network.create", net.name, body.model_dump(), client_ip(request))
    db.commit()
    return network_out(net, 0, 0)


@router.put("/{network_id}", description=FULL_REPLACE)
def update_network(network_id: int, body: NetworkIn, request: Request, db: Session = Depends(get_db),
                   user: User = Depends(require_admin)):
    net = _active_network(db, network_id)
    _check_name(db, body.name, network_id)
    before = {"name": net.name, "cidr": net.cidr, "enabled": net.enabled, "zone": net.zone,
              "vpn_s2s": net.vpn_s2s}
    if net.cidr != body.cidr:
        # A different scope needs a fresh baseline, otherwise every host in the new range would alert
        net.baseline_scan_id = None
        net.baseline_at = None
    net.name, net.cidr, net.description, net.enabled = body.name, body.cidr, body.description, body.enabled
    net.vpn_s2s = body.vpn_s2s
    zone_changed = net.zone != body.zone
    net.zone = body.zone
    audit(db, user.username, "network.update", net.name, {"before": before, "after": body.model_dump()},
          client_ip(request))
    if zone_changed:
        db.flush()
        refresh_devices(db, db.scalars(select(Device.id).where(Device.network_id == net.id)).all())
    db.commit()
    total, active = _counts(db)
    return network_out(net, total.get(net.id, 0), active.get(net.id, 0))


@router.post("/{network_id}/reset-baseline")
def reset_baseline(network_id: int, request: Request, db: Session = Depends(get_db),
                   user: User = Depends(require_admin)):
    net = _active_network(db, network_id)
    net.baseline_scan_id = None
    net.baseline_at = None
    audit(db, user.username, "network.reset_baseline", net.name, None, client_ip(request))
    db.commit()
    return {"ok": True}


@router.delete("/{network_id}", status_code=204,
               description="Archives the network: it stops being scanned and its devices, events and "
                           "scans are kept but hidden from default views. Restore with POST .../restore.")
def delete_network(network_id: int, request: Request, db: Session = Depends(get_db),
                   user: User = Depends(require_admin)):
    net = _active_network(db, network_id)
    audit(db, user.username, "network.archive", net.name, {"cidr": net.cidr}, client_ip(request))
    net.archived_at = utcnow()
    net.enabled = False
    net.baseline_scan_id = None
    net.baseline_at = None
    db.commit()


@router.post("/{network_id}/restore")
def restore_network(network_id: int, request: Request, db: Session = Depends(get_db),
                    user: User = Depends(require_admin)):
    net = db.get(Network, network_id)
    if net is None:
        raise HTTPException(404, "Network not found")
    if net.archived_at is None:
        raise HTTPException(409, f"Network '{net.name}' is not archived")
    net.archived_at = None
    audit(db, user.username, "network.restore", net.name, {"cidr": net.cidr}, client_ip(request))
    db.commit()
    total, active = _counts(db)
    return network_out(net, total.get(net.id, 0), active.get(net.id, 0))
