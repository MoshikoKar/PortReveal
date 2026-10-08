"""Normalized scan result structures shared by every scanner implementation."""
from __future__ import annotations

import logging
import subprocess
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

log = logging.getLogger(__name__)


@dataclass
class PortObservation:
    port: int
    protocol: str = "tcp"
    service: str | None = None
    product: str | None = None
    version: str | None = None
    extra_info: str | None = None
    method: str | None = None  # probed | table
    confidence: int | None = None
    version_checked: bool = False  # -sV ran on this port in this scan (refreshes the version cache)
    scripts: dict[str, dict] = field(default_factory=dict)  # kept NSE output: id -> {output, data}

    @property
    def reliable(self) -> bool:
        """True when nmap actually fingerprinted the service (not just a port-number guess)."""
        return self.method == "probed" or (self.confidence or 0) >= 8


@dataclass
class HostObservation:
    ip: str
    mac: str | None = None
    vendor: str | None = None
    hostname: str | None = None
    os_name: str | None = None
    # None = no port data for this host in this stage/scan
    ports: list[PortObservation] | None = None
    port_scan_failed: bool = False
    failure_reason: str | None = None  # why the port scan of this host failed (with port_scan_failed)
    scripts: dict[str, dict] = field(default_factory=dict)  # kept NSE hostscript output

    def merge(self, other: HostObservation) -> None:
        """Merge information from another stage of the same scan."""
        self.mac = self.mac or other.mac
        self.vendor = self.vendor or other.vendor
        self.hostname = self.hostname or other.hostname
        self.os_name = other.os_name or self.os_name
        self.scripts = {**self.scripts, **other.scripts}
        if other.ports is not None:
            self.ports = other.ports
            self.port_scan_failed = False
            self.failure_reason = None
        elif other.port_scan_failed and self.ports is None:
            self.port_scan_failed = True
            self.failure_reason = other.failure_reason or self.failure_reason


@dataclass
class StageResult:
    hosts: list[HostObservation] = field(default_factory=list)
    port_scope: str | None = None
    extra_ports: tuple[int, ...] = ()  # profile ports scanned on top of port_scope for these hosts
    notes: list[str] = field(default_factory=list)  # non-fatal problems (e.g. version detection failed)


@dataclass
class PortProfile:
    """What the port stage should scan. Built only from validated settings."""

    full: bool
    top_ports: int = 1000
    timing: str = "normal"
    host_timeout_minutes: int = 15
    os_detection: bool = False
    batch_size: int = 32
    # ip -> open TCP ports whose last -sV result is still fresh; those ports skip -sV this scan
    version_cache: dict[str, frozenset[int]] = field(default_factory=dict)
    # Device port-profile ports for this batch (standard scans only; every host in the batch has the profile)
    extra_ports: tuple[int, ...] = ()


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
