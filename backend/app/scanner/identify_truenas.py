"""Identify TrueNAS / FreeNAS hosts from observation or inventory fields.

Used to decide whether TrueNAS Apps catalog host ports should be scanned.
Identity comes from hostname, OS, vendor, or nmap service product strings -
never from an open 3XXXX port alone.
"""
from __future__ import annotations

from .types import HostObservation, PortObservation

_MARKERS = ("truenas", "freenas", "ixsystems")


def _blob(*parts: str | None) -> str:
    return " ".join(p for p in parts if p).lower()


def looks_like_truenas(
    *,
    hostname: str | None = None,
    dns_name: str | None = None,
    os_name: str | None = None,
    vendor: str | None = None,
    ports: list[PortObservation] | None = None,
) -> bool:
    """True when host/device text evidence indicates TrueNAS or FreeNAS."""
    if any(m in _blob(hostname, dns_name, os_name, vendor) for m in _MARKERS):
        return True
    for po in ports or ():
        text = _blob(po.service, po.product, po.version, po.extra_info)
        if any(m in text for m in _MARKERS):
            return True
    return False


def host_looks_like_truenas(host: HostObservation | None) -> bool:
    if host is None:
        return False
    return looks_like_truenas(
        hostname=host.hostname,
        os_name=host.os_name,
        vendor=host.vendor,
        ports=host.ports,
    )
