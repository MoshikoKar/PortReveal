"""Passive mDNS (Bonjour) listening for device names (spec section 9.2).

Local-only: joins the mDNS multicast group on the LAN and listens for announcements already being
broadcast by other devices on the segment. Sends nothing by default beyond standard multicast group
membership at the OS level; nothing ever leaves the LAN (multicast is not routed), and this never
touches nmap or its -sU-is-banned argument-building code at all -- it is a wholly separate channel
with its own tiny "allow-list" (PTR/SRV target names only, see dns_names.py).
"""
from __future__ import annotations

import logging
import socket
import time
from collections.abc import Callable, Iterable

from .dns_names import parse_answers

log = logging.getLogger(__name__)

MDNS_GROUP = "224.0.0.251"
MDNS_PORT = 5353

Listener = Callable[[float], Iterable[tuple[bytes, tuple]]]


def _clean_name(target: str) -> str | None:
    name = target.rstrip(".")
    if name.endswith(".local"):
        name = name[: -len(".local")]
    # Service instance PTR targets look like "Office Printer._ipp._tcp"; keep the instance label.
    name = name.split("._")[0].strip()
    return name or None


def _listen_live(timeout: float) -> Iterable[tuple[bytes, tuple]]:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("", MDNS_PORT))
        mreq = socket.inet_aton(MDNS_GROUP) + socket.inet_aton("0.0.0.0")
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
        sock.settimeout(0.5)
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                data, addr = sock.recvfrom(4096)
            except TimeoutError:
                continue
            yield data, addr
    finally:
        sock.close()


def collect_mdns_names(*, timeout: float = 2.0, listen: Listener | None = None) -> dict[str, str]:
    """{ip: device name}, best-effort. `listen` is injectable for tests (no real socket needed)."""
    results: dict[str, str] = {}
    try:
        for data, addr in (listen or _listen_live)(timeout):
            ip = addr[0]
            if ip in results:
                continue
            for ans in parse_answers(data):
                target = ans.get("target")
                if not target:
                    continue
                name = _clean_name(target)
                if name:
                    results[ip] = name
                    break
    except OSError as exc:
        log.debug("mDNS discovery unavailable: %s", exc)
    return results
