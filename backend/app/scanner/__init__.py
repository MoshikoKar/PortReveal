"""Scanner selection and status."""
from __future__ import annotations

import ipaddress
import logging
import shutil
import time
from dataclasses import dataclass

from ..config import get_settings
from .nmap_iface import list_nmap_interfaces
from .nmap_scanner import nmap_is_privileged, nmap_version

log = logging.getLogger(__name__)


@dataclass
class ScannerStatus:
    configured_mode: str
    effective_mode: str  # nmap | mock | unavailable
    nmap_detected: bool
    nmap_version: str | None
    nmap_path: str
    privileged: bool
    message: str


_cache: tuple[float, ScannerStatus] | None = None


def scanner_status(refresh: bool = False) -> ScannerStatus:
    global _cache
    if _cache and not refresh and time.monotonic() - _cache[0] < 60:
        return _cache[1]
    s = get_settings()
    version = nmap_version(s.nmap_path)
    detected = version is not None
    privileged = nmap_is_privileged(s.nmap_privileged)
    if s.scanner_mode == "mock":
        mode, msg = "mock", "Mock scanner active: results are SIMULATED."
    elif s.scanner_mode == "nmap":
        if detected:
            note = "" if privileged else " (unprivileged: TCP connect scans, no ARP/ICMP)"
            mode, msg = "nmap", f"nmap {version} ready{note}"
        else:
            mode, msg = "unavailable", f"nmap not found ({s.nmap_path}). Install nmap to run real scans."
    else:  # auto
        if detected:
            mode, msg = "nmap", f"nmap {version} ready (auto)"
        else:
            mode, msg = "mock", "nmap not found: auto mode fell back to the mock scanner (SIMULATED data)."
    status = ScannerStatus(s.scanner_mode, mode, detected, version, s.nmap_path, privileged, msg)
    _cache = (time.monotonic(), status)
    return status


def scanner_host_ips() -> frozenset[str]:
    """IPv4 addresses of the machine PortReveal scans from: its own interfaces as nmap sees them,
    plus SCANNER_HOST_IPS (a bridged Docker container cannot see the host's LAN address)."""
    s = get_settings()
    ips: set[str] = set()
    for raw in s.scanner_host_ips.split(","):
        raw = raw.strip()
        if not raw:
            continue
        try:
            ips.add(str(ipaddress.IPv4Address(raw)))
        except ValueError:
            log.warning("ignoring invalid SCANNER_HOST_IPS entry: %r", raw[:40])
    if scanner_status().effective_mode == "nmap" and (exe := shutil.which(s.nmap_path)):
        ips.update(str(i.address) for i in list_nmap_interfaces(exe) if i.up)
    return frozenset(ips)
