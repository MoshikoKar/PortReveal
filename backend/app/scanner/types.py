"""Normalized scan result structures shared by every scanner implementation."""
from __future__ import annotations

import logging
import subprocess
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

log = logging.getLogger(__name__)

# Service identified by PortReveal from a response (nmap servicefp or its own request).
VERIFIED_METHOD = "verified"


@dataclass
class PortObservation:
    port: int
    protocol: str = "tcp"
    service: str | None = None
    product: str | None = None
    version: str | None = None
    extra_info: str | None = None
    method: str | None = None  # nmap: probed | table; PortReveal: verified (see verify_services)
    confidence: int | None = None
    cpe: str | None = None  # space-separated CPE strings nmap matched
    tunnel: str | None = None  # "ssl" when nmap found the service inside TLS
    # NSE script id -> output, for the phase-4 allow-listed vulnerability-script stage only
    # (core/vuln/runner.py). Empty for the main discovery/port-scan stages, which never run scripts.
    scripts: dict[str, str] = field(default_factory=dict)

    @property
    def reliable(self) -> bool:
        """True when the service came from a response (not just a port-number guess)."""
        return self.method in ("probed", VERIFIED_METHOD) or (self.confidence or 0) >= 8


@dataclass
class HostObservation:
    ip: str
    mac: str | None = None
    vendor: str | None = None
    hostname: str | None = None
    os_name: str | None = None
    os_accuracy: int | None = None  # set only when os_name came from nmap -O (osmatch), not a fallback guess
    rtt_ms: float | None = None  # nmap <times srtt=...> (smoothed round-trip time), in milliseconds
    # nmap <status reason="..."> from host discovery (e.g. arp-response, reset)
    reason: str | None = None
    # None = no port data for this host in this stage/scan
    ports: list[PortObservation] | None = None
    port_scan_failed: bool = False
    # TCP ports probed only on this host (e.g. TrueNAS Apps catalog). Not part of
    # the scan-wide port_scope — compare uses these for per-host closure coverage.
    extra_tcp_ports: tuple[int, ...] | None = None
    # <hostscript> NSE results (phase-4 vulnerability-script stage only; see `scripts` above).
    host_scripts: dict[str, str] = field(default_factory=dict)

    def merge(self, other: HostObservation) -> None:
        """Merge information from another stage of the same scan."""
        self.mac = self.mac or other.mac
        self.vendor = self.vendor or other.vendor
        self.hostname = self.hostname or other.hostname
        if other.os_name:
            self.os_name = other.os_name
            self.os_accuracy = other.os_accuracy
        if other.rtt_ms is not None:
            self.rtt_ms = other.rtt_ms
        self.reason = self.reason or other.reason
        if other.extra_tcp_ports:
            merged = set(self.extra_tcp_ports or ())
            merged.update(other.extra_tcp_ports)
            self.extra_tcp_ports = tuple(sorted(merged))
        if other.ports is not None:
            self.ports = other.ports
            # Preserve failure when the port stage returned partial results (host-timeout).
            self.port_scan_failed = other.port_scan_failed
        elif other.port_scan_failed and self.ports is None:
            self.port_scan_failed = True


@dataclass
class StageResult:
    hosts: list[HostObservation] = field(default_factory=list)
    port_scope: str | None = None


@dataclass
class PortProfile:
    """What the port stage should scan. Built only from validated settings."""

    full: bool
    top_ports: int = 3000
    timing: str = "normal"
    host_timeout_minutes: int = 15
    os_detection: bool = False
    batch_size: int = 32
    max_rate: int | None = None  # packets/s cap for every nmap run of the stage (VPN S2S networks)


class ScanCancelled(Exception):
    pass


class ScanStageError(Exception):
    """One chunk/batch of a scan failed (nmap error, timeout, unparsable output)."""


class ScanContext:
    """Per-scan runtime state: cancellation and tracking of child processes."""

    def __init__(self, scan_id: int, raw_dir: Path | None = None):
        self.scan_id = scan_id
        self.raw_dir = raw_dir
        self.cancel_event = threading.Event()
        self._procs: set[subprocess.Popen] = set()
        self._lock = threading.Lock()
        # Current IPs of inventory devices already identified as TrueNAS / FreeNAS.
        self.known_truenas_ips: set[str] = set()
        # Network is reached over a site-to-site VPN: discovery uses the rate-capped VPN profile.
        self.vpn_s2s = False

    @property
    def cancelled(self) -> bool:
        return self.cancel_event.is_set()

    def check_cancelled(self) -> None:
        if self.cancelled:
            raise ScanCancelled()

    def register(self, proc: subprocess.Popen) -> None:
        with self._lock:
            self._procs.add(proc)
        if self.cancelled:
            self._kill(proc)

    def unregister(self, proc: subprocess.Popen) -> None:
        with self._lock:
            self._procs.discard(proc)

    def cancel(self) -> None:
        self.cancel_event.set()
        with self._lock:
            procs = list(self._procs)
        for p in procs:
            self._kill(p)

    @staticmethod
    def _kill(proc: subprocess.Popen) -> None:
        try:
            proc.kill()
        except OSError:
            pass


class Scanner(Protocol):
    """The only thing that differs between real and simulated scanning."""

    mode: str  # "nmap" | "mock"

    def discover(self, targets: list[str], ctx: ScanContext) -> StageResult:
        """Host discovery for a chunk of CIDRs/IPs. Returns live hosts only."""
        ...

    def scan_ports(self, ips: list[str], profile: PortProfile, ctx: ScanContext) -> StageResult:
        """Port/service scan of known-live IPs. Every returned host has ports set
        (possibly empty) or port_scan_failed=True. port_scope = ports covered."""
        ...
