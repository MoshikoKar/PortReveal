"""What the app already knows about an address: configured network, inventory device, ASN / provider."""
from __future__ import annotations

import logging
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from ...db import utcnow
from ...models import Device, Network
from ...netutils import AddressSet, TargetError
from ...settings_store import GeoSettings, get_section
from .classify import hosting_entry, is_private_ip

log = logging.getLogger(__name__)


@dataclass
class InventoryContext:
    networks: list[tuple[str, AddressSet]] = field(default_factory=list)
    devices: dict[str, dict] = field(default_factory=dict)  # ip -> {"id", "uuid", "label"}
    asn: dict[str, tuple[int | None, str | None]] = field(default_factory=dict)

    def in_networks(self, ip: str) -> bool:
        return any(ip in s for _, s in self.networks)

    def network_name(self, ip: str) -> str | None:
        return next((name for name, s in self.networks if ip in s), None)

    def hosting(self, ips: Iterable[str]) -> list[dict]:
        out = []
        for ip in sorted(set(ips)):
            asn, org = self.asn.get(ip, (None, None))
            out.append(hosting_entry(ip, in_networks=self.in_networks, network_name=self.network_name(ip),
                                     device=self.devices.get(ip), asn=asn, as_org=org))
        return out

    def device_id(self, ips: Iterable[str]) -> int | None:
        for ip in sorted(set(ips)):
            dev = self.devices.get(ip)
            if dev:
                return dev["id"]
        return None


def configured_networks(db: Session) -> list[tuple[str, AddressSet]]:
    out = []
    for net in db.scalars(select(Network).where(Network.archived_at.is_(None)).order_by(Network.id)).all():
        try:
            out.append((net.name, AddressSet.from_specs(net.cidr)))
        except TargetError:
            log.warning("network %s has an invalid CIDR; ignored for domain hosting", net.id)
    return out


def _asn_lookup(db: Session, ips: list[str]) -> dict[str, tuple[int | None, str | None]]:
    """ASN / organisation from the local geo databases (DB-IP Lite), when they are present."""
    if not ips:
        return {}
    try:
        from ..geo import build_lookup, lookup_ip_cached

        cfg = get_section(db, GeoSettings)
        lookup = build_lookup(cfg)
        if lookup is None:
            return {}
        now = utcnow()
        ttl = timedelta(hours=cfg.cache_ttl_hours)
        out = {}
        for ip in ips:
            rec = lookup_ip_cached(db, ip, now, ttl, lookup)
            if rec is not None:
                out[ip] = (rec.asn, rec.as_org)
        return out
    except Exception:
        log.warning("ASN lookup for domain hosting failed", exc_info=True)
        return {}


def load_context(db: Session, ips: Iterable[str]) -> InventoryContext:
    ips = sorted(set(ips))
    ctx = InventoryContext(networks=configured_networks(db))
    if ips:
        for dev in db.scalars(select(Device).where(Device.current_ip.in_(ips))).all():
            ctx.devices.setdefault(dev.current_ip, {"id": dev.id, "uuid": dev.uuid,
                                                    "label": dev.hostname or dev.current_ip})
    external = [ip for ip in ips if not is_private_ip(ip) and not ctx.in_networks(ip)]
    ctx.asn = _asn_lookup(db, external)
    return ctx
