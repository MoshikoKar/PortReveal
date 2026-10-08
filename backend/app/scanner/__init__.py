"""Scanner selection and status."""
from __future__ import annotations

import time
from dataclasses import dataclass

from ..config import get_settings
from .nmap_scanner import nmap_is_privileged, nmap_version


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
