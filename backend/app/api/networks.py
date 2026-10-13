from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..auth.deps import client_ip, current_user, require_admin
from ..core.audit import audit
from ..core.intel import refresh_devices
from ..core.mockdata import device_visible
from ..db import get_db
from ..models import DEVICE_ACTIVE, NETWORK_ZONES, Device, Network, User
from ..netutils import TargetError, validate_network_cidr
from .common import FULL_REPLACE, network_out

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
    ok = device_visible(db)
    total = dict(db.execute(select(Device.network_id, func.count(Device.id)).where(ok)
                            .group_by(Device.network_id)).all())
    active = dict(db.execute(select(Device.network_id, func.count(Device.id)).where(Device.status == DEVICE_ACTIVE, ok)
                             .group_by(Device.network_id)).all())
    return total, active


@router.get("")
def list_networks(db: Session = Depends(get_db), user: User = Depends(current_user)):
    total, active = _counts(db)
    return [network_out(n, total.get(n.id, 0), active.get(n.id, 0))
            for n in db.scalars(select(Network).order_by(Network.name)).all()]


def _check_name(db: Session, name: str, exclude_id: int | None = None) -> None:
    q = select(Network.id).where(func.lower(Network.name) == name.lower())
    if exclude_id is not None:
        q = q.where(Network.id != exclude_id)
    if db.scalar(q):
        raise HTTPException(409, f"A network named '{name}' already exists")


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
    net = db.get(Network, network_id)
    if net is None:
        raise HTTPException(404, "Network not found")
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
    net = db.get(Network, network_id)
    if net is None:
        raise HTTPException(404, "Network not found")
    net.baseline_scan_id = None
    net.baseline_at = None
    audit(db, user.username, "network.reset_baseline", net.name, None, client_ip(request))
    db.commit()
    return {"ok": True}


@router.delete("/{network_id}", status_code=204)
def delete_network(network_id: int, request: Request, db: Session = Depends(get_db),
                   user: User = Depends(require_admin)):
    net = db.get(Network, network_id)
    if net is None:
        raise HTTPException(404, "Network not found")
    audit(db, user.username, "network.delete", net.name, {"cidr": net.cidr}, client_ip(request))
    db.delete(net)
    db.commit()
