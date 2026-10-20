from __future__ import annotations

import ipaddress
import re
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field, field_validator, model_validator
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..auth.deps import client_ip, current_user, require_admin
from ..core.arp_snmp import AUTH_PROTOCOLS, PRIV_PROTOCOLS, fetch_arp_table, target_from_config
from ..core.audit import audit
from ..core.geo import normalize_expected
from ..core.intel import refresh_devices
from ..core.mockdata import device_visible
from ..db import get_db, utcnow
from ..models import DEVICE_ACTIVE, NETWORK_ZONES, Device, Network, User
from ..netutils import AddressSet, TargetError, validate_network_cidr
from ..security import encrypt_secret
from .common import FULL_REPLACE, UNPAGED_LIST, Row, network_out

router = APIRouter(prefix="/api/networks", tags=["networks"])


_LABEL = r"[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
_HOSTNAME = re.compile(rf"^(?=.{{1,253}}$){_LABEL}(\.{_LABEL})*$")
_SECRETS = ("community", "auth_key", "priv_key")


class ArpSnmpIn(BaseModel):
    """Remote gateway to read the ARP table from. Secrets are write-only: omit (null) to keep the
    stored value, "" to clear it."""

    host: str = Field(min_length=1, max_length=253, description="Router / firewall / L3 switch IPv4 address or hostname")
    port: int = Field(161, ge=1, le=65535)
    version: Literal["2c", "3"] = "2c"
    community: str | None = Field(None, max_length=128, description="v2c read-only community; omit to keep")
    user: str | None = Field(None, max_length=64, description="v3 security name")
    auth_protocol: Literal[AUTH_PROTOCOLS] | None = None  # type: ignore[valid-type]
    auth_key: str | None = Field(None, max_length=128, description="v3 auth passphrase; omit to keep")
    priv_protocol: Literal[PRIV_PROTOCOLS] | None = None  # type: ignore[valid-type]
    priv_key: str | None = Field(None, max_length=128, description="v3 privacy passphrase; omit to keep")

    @field_validator("host")
    @classmethod
    def _host(cls, v: str) -> str:
        v = v.strip()
        try:
            return str(ipaddress.IPv4Address(v))
        except ValueError:
            if _HOSTNAME.match(v) and not v.replace(".", "").isdigit():
                return v.lower()
        raise ValueError("must be an IPv4 address or a hostname")

    @model_validator(mode="after")
    def _v3(self) -> ArpSnmpIn:
        if self.version == "3":
            if not (self.user or "").strip():
                raise ValueError("SNMPv3 needs a user name")
            if self.priv_protocol and not self.auth_protocol:
                raise ValueError("SNMPv3 privacy (encryption) requires an auth protocol")
        for key in ("auth_key", "priv_key"):
            value = getattr(self, key)
            if value and len(value) < 8:
                raise ValueError(f"{key} must be at least 8 characters (SNMPv3 rule)")
        return self


class NetworkIn(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    cidr: str = Field(min_length=7, max_length=64)
    description: str | None = Field(None, max_length=1000)
    enabled: bool = True
    zone: str | None = None
    vpn_s2s: bool = False
    expected_countries: list[str] = Field(default_factory=list,
                                          description="ISO 3166-1 alpha-2 codes this network is expected to live in")
    arp_snmp: ArpSnmpIn | None = Field(None, description="Read MACs from this gateway's ARP table over SNMP; "
                                                         "null removes it")

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

    @field_validator("expected_countries")
    @classmethod
    def _countries(cls, v: list[str] | None) -> list[str]:
        codes = normalize_expected(v)
        if v and not codes:
            raise ValueError("expected_countries must be 2-letter country codes")
        if len(codes) > 20:
            raise ValueError("at most 20 expected countries")
        return codes


def _arp_snmp_stored(body: ArpSnmpIn | None, current: dict | None) -> dict | None:
    """Column value for `body`, keeping each stored secret the request omitted."""
    if body is None:
        return None
    current = current or {}
    out = body.model_dump(exclude=set(_SECRETS))
    # Secrets of the other SNMP version are dropped, not kept dormant.
    used = ("community",) if body.version == "2c" else ("auth_key", "priv_key")
    for key in _SECRETS:
        value = getattr(body, key)
        stored = current.get(f"{key}_enc") if value is None else (encrypt_secret(value) or None)
        out[f"{key}_enc"] = stored if key in used else None
    if body.version == "2c":
        out.update(user=None, auth_protocol=None, priv_protocol=None)
    if body.version == "2c" and not out["community_enc"]:
        raise HTTPException(422, "SNMPv2c needs a community string")
    if body.version == "3":
        if body.auth_protocol and not out["auth_key_enc"]:
            raise HTTPException(422, "SNMPv3 auth protocol set but no auth passphrase")
        if body.priv_protocol and not out["priv_key_enc"]:
            raise HTTPException(422, "SNMPv3 privacy protocol set but no privacy passphrase")
    return out


def _audit_body(body: NetworkIn) -> dict:
    return body.model_dump(exclude={"arp_snmp": set(_SECRETS)})


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
                  zone=body.zone, vpn_s2s=body.vpn_s2s, expected_countries=body.expected_countries or None,
                  arp_snmp=_arp_snmp_stored(body.arp_snmp, None))
    db.add(net)
    db.flush()
    audit(db, user.username, "network.create", net.name, _audit_body(body), client_ip(request))
    db.commit()
    return network_out(net, 0, 0)


@router.put("/{network_id}", description=FULL_REPLACE)
def update_network(network_id: int, body: NetworkIn, request: Request, db: Session = Depends(get_db),
                   user: User = Depends(require_admin)):
    net = _active_network(db, network_id)
    _check_name(db, body.name, network_id)
    before = {"name": net.name, "cidr": net.cidr, "enabled": net.enabled, "zone": net.zone,
              "vpn_s2s": net.vpn_s2s, "expected_countries": list(net.expected_countries or []),
              "arp_snmp_host": (net.arp_snmp or {}).get("host")}
    if net.cidr != body.cidr:
        # A different scope needs a fresh baseline, otherwise every host in the new range would alert
        net.baseline_scan_id = None
        net.baseline_at = None
    net.name, net.cidr, net.description, net.enabled = body.name, body.cidr, body.description, body.enabled
    net.vpn_s2s = body.vpn_s2s
    net.expected_countries = body.expected_countries or None
    net.arp_snmp = _arp_snmp_stored(body.arp_snmp, net.arp_snmp)
    zone_changed = net.zone != body.zone
    net.zone = body.zone
    audit(db, user.username, "network.update", net.name, {"before": before, "after": _audit_body(body)},
          client_ip(request))
    if zone_changed:
        db.flush()
        refresh_devices(db, db.scalars(select(Device.id).where(Device.network_id == net.id)).all())
    db.commit()
    total, active = _counts(db)
    return network_out(net, total.get(net.id, 0), active.get(net.id, 0))


@router.post("/{network_id}/arp-snmp/test",
             description="Reads the saved gateway's ARP table once. Returns how many usable entries it "
                         "has and how many fall inside this network; nothing is stored.")
def probe_arp_snmp(network_id: int, request: Request, db: Session = Depends(get_db),
                  user: User = Depends(require_admin)):
    net = _active_network(db, network_id)
    target = target_from_config(net.arp_snmp)
    if target is None:
        raise HTTPException(409, "No ARP source (SNMP) is configured for this network")
    audit(db, user.username, "network.arp_snmp_test", net.name, {"host": target.host}, client_ip(request))
    db.commit()
    try:
        table = fetch_arp_table(target)
    except Exception as exc:
        return {"ok": False, "error": str(exc) or type(exc).__name__}
    scope = AddressSet.from_specs(net.cidr)
    return {"ok": True, "entries": len(table), "in_network": sum(1 for ip in table if ip in scope)}


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
