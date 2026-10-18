"""Local-only device-naming discovery (spec section 9.2): mDNS, SSDP, NetBIOS.

Nothing here is an nmap scan and nothing here sends anything off the LAN: mDNS/SSDP use multicast
groups that routers never forward past the local segment, and NetBIOS is one UDP unicast query per
already-known device (a "focused query", not a sweep). Each source is independently best-effort --
a failure in one never blocks the others, and a failure here never affects a scan's result.
"""
from __future__ import annotations

import logging

from .mdns import collect_mdns_names
from .netbios import query_netbios_names
from .ssdp import collect_ssdp_names

log = logging.getLogger(__name__)

# Preference order when more than one source answers for the same IP: NetBIOS gives the exact
# Windows/Samba computer name (most authoritative); mDNS gives a real device/service instance
# name; SSDP only gives a (often generic) SERVER header string.
_SOURCE_PRIORITY = {"ssdp": 0, "mdns": 1, "netbios": 2}

# A live NetBIOS unicast query per host bounds worst-case wall time; cap the batch so a single
# refresh pass can never stall on a very large device list (spec section 11: thousands of devices).
MAX_NETBIOS_QUERIES_PER_PASS = 100

# Round-robin cursor so the NetBIOS budget rotates across the inventory instead of always hitting
# the first N IPs (large LANs would otherwise never query hosts past the cap).
_netbios_cursor = 0


def reset_netbios_cursor() -> None:
    """Test helper: restart fair NetBIOS rotation from the beginning of the sorted IP list."""
    global _netbios_cursor
    _netbios_cursor = 0


def select_netbios_batch(ips: list[str], *, limit: int = MAX_NETBIOS_QUERIES_PER_PASS) -> list[str]:
    """Return up to ``limit`` IPs, advancing a process-wide round-robin cursor each call."""
    global _netbios_cursor
    ordered = sorted({ip for ip in ips if ip})
    if not ordered:
        return []
    n = len(ordered)
    start = _netbios_cursor % n
    batch = [ordered[(start + i) % n] for i in range(min(limit, n))]
    _netbios_cursor = (start + len(batch)) % n
    return batch


def collect_local_names(ips: list[str], *, mdns: bool = True, ssdp: bool = True, netbios: bool = True,
                        timeout: float = 2.0, netbios_timeout: float = 0.5) -> dict[str, tuple[str, str]]:
    """{ip: (name, source)} for every ip in `ips` that answered. Best-effort and silent on error;
    callers should also skip this entirely in mock-scanner mode (no real network to listen on)."""
    if not ips:
        return {}
    wanted = set(ips)
    out: dict[str, tuple[str, str]] = {}

    def _merge(found: dict[str, str], source: str) -> None:
        for ip, name in found.items():
            if ip not in wanted or not name:
                continue
            current = out.get(ip)
            if current is None or _SOURCE_PRIORITY[source] >= _SOURCE_PRIORITY[current[1]]:
                out[ip] = (name, source)

    if ssdp:
        try:
            _merge(collect_ssdp_names(timeout=timeout), "ssdp")
        except Exception:
            log.debug("SSDP discovery failed", exc_info=True)
    if mdns:
        try:
            _merge(collect_mdns_names(timeout=timeout), "mdns")
        except Exception:
            log.debug("mDNS discovery failed", exc_info=True)
    if netbios:
        batch = select_netbios_batch(ips)
        if len(ips) > MAX_NETBIOS_QUERIES_PER_PASS:
            log.info("NetBIOS discovery: querying %d of %d devices this pass (round-robin)",
                     len(batch), len(ips))
        try:
            _merge(query_netbios_names(batch, timeout=netbios_timeout), "netbios")
        except Exception:
            log.debug("NetBIOS discovery failed", exc_info=True)
    return out
