"""Which hosts a capture may follow a redirect to besides its own target.

Internal web apps routinely send the browser to a sibling host: an SPA on
``app.corp:443`` redirects (in JavaScript) to the single sign-on login at
``sso.corp:8400``, an HTTP port 301s to the canonical front-end. A user's browser
lands there; blocking it left the capture on Chromium's error page ("browser could
not load the page") or a dead "redirects outside the target" tile.

A redirect is followed when its host resolves to an address inside a configured
network or belongs to a device in the inventory - never to an excluded address,
and never to the internet.
"""
from __future__ import annotations

import ipaddress
import logging
import socket
from functools import lru_cache
from urllib.parse import urlsplit

from sqlalchemy import select
from sqlalchemy.orm import Session

from ...models import Device, Network
from ...netutils import AddressSet

log = logging.getLogger(__name__)


@lru_cache(maxsize=512)
def _resolve(host: str) -> tuple[str, ...]:
    try:
        infos = socket.getaddrinfo(host, None, socket.AF_INET, socket.SOCK_STREAM)
    except (OSError, UnicodeError):
        return ()
    return tuple(dict.fromkeys(str(i[4][0]) for i in infos))


class InternalHosts:
    def __init__(self, networks: AddressSet, device_ips: set[str], excluded: AddressSet):
        self.networks = networks
        self.device_ips = device_ips
        self.excluded = excluded

    @classmethod
    def load(cls, db: Session, excluded: AddressSet) -> InternalHosts:
        nets = AddressSet()
        for (cidr,) in db.execute(select(Network.cidr)).all():
            try:
                nets = nets.union(AddressSet.from_specs(cidr))
            except Exception:  # validated on save; one bad row must not stop captures
                log.debug("network %r ignored for redirect scope", cidr)
        ips = {ip for (ip,) in db.execute(select(Device.current_ip)).all() if ip}
        return cls(nets, ips, excluded)

    def _ip_ok(self, ip: str) -> bool:
        if ip in self.excluded:
            return False
        return ip in self.device_ips or ip in self.networks

    def allows(self, url: str) -> bool:
        try:
            host = (urlsplit(url).hostname or "").strip().lower()
        except ValueError:
            return False
        if not host or urlsplit(url).scheme not in ("http", "https"):
            return False
        try:
            ipaddress.IPv4Address(host)
            addrs: tuple[str, ...] = (host,)
        except ValueError:
            addrs = _resolve(host)
        # Every address the name resolves to must be internal (no split-horizon escape).
        return bool(addrs) and all(self._ip_ok(ip) for ip in addrs)
