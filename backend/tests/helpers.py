"""Test helpers: a scripted scanner and shortcuts to run scans through the real pipeline."""
from __future__ import annotations

import copy

from sqlalchemy import select

from app.core.manager import create_scan
from app.core.runner import run_scan
from app.db import session_scope
from app.models import Device, Event, Network, Scan
from app.netutils import AddressSet
from app.scanner.identify_truenas import looks_like_truenas
from app.scanner.known_ports import TRUENAS_APPS_TCP_PORTS
from app.scanner.types import (
    HostObservation,
    PortObservation,
    PortProfile,
    ScanContext,
    ScanStageError,
    StageResult,
)

STANDARD_SCOPE = "1-10000"


def port(n: int, service: str = "http", product: str | None = None, version: str | None = None) -> PortObservation:
    return PortObservation(port=n, service=service, product=product, version=version, method="probed", confidence=10)


def host(ip: str, ports: list[PortObservation] | None = None, mac: str | None = None,
         hostname: str | None = None) -> HostObservation:
    return HostObservation(ip=ip, mac=mac, hostname=hostname, vendor="TestVendor" if mac else None,
                           ports=ports if ports is not None else [])


class ScriptedScanner:
    """Returns exactly the hosts it is given. Can simulate failing chunks/batches."""

    mode = "mock"

    def __init__(self, hosts: list[HostObservation], fail_discovery: bool = False, fail_ports: bool = False,
                 fail_all: bool = False):
        self.hosts = {h.ip: h for h in hosts}
        self.fail_discovery = fail_discovery
        self.fail_ports = fail_ports
        self.fail_all = fail_all
        self.discovery_targets: list[list[str]] = []
        self.port_targets: list[list[str]] = []
        self._disc_calls = 0

    def discover(self, targets: list[str], ctx: ScanContext) -> StageResult:
        self.discovery_targets.append(targets)
        self._disc_calls += 1
        if self.fail_all or (self.fail_discovery and self._disc_calls == 1):
            raise ScanStageError("simulated discovery failure")
        aset = AddressSet.from_specs(targets)
        return StageResult(hosts=[HostObservation(ip=h.ip, mac=h.mac, vendor=h.vendor, hostname=h.hostname)
                                  for h in self.hosts.values() if h.ip in aset])

    def scan_ports(self, ips: list[str], profile: PortProfile, ctx: ScanContext) -> StageResult:
        self.port_targets.append(ips)
        if self.fail_ports:
            raise ScanStageError("simulated port scan failure")
        scope = "1-65535" if profile.full else STANDARD_SCOPE
        known_truenas = ctx.known_truenas_ips or set()
        out = []
        for ip in ips:
            h = copy.deepcopy(self.hosts[ip])
            if h.ports is not None:
                limit = 65535 if profile.full else 10000
                extras = set(h.extra_tcp_ports or ())
                if not profile.full and (
                    ip in known_truenas
                    or looks_like_truenas(
                        hostname=h.hostname, os_name=h.os_name, vendor=h.vendor, ports=h.ports,
                    )
                ):
                    h.extra_tcp_ports = TRUENAS_APPS_TCP_PORTS
                    extras.update(TRUENAS_APPS_TCP_PORTS)
                h.ports = [p for p in h.ports if p.port <= limit or p.port in extras]
            out.append(h)
        return StageResult(hosts=out, port_scope=scope)


def make_network(db, cidr: str = "10.0.0.0/24", name: str = "Test Net") -> Network:
    net = Network(name=name, cidr=cidr)
    db.add(net)
    db.commit()
    return net


def scan(scanner, scan_type: str = "standard", network_id: int | None = None, targets: str | None = None) -> Scan:
    with session_scope() as db:
        if network_id is not None:
            s = create_scan(db, scan_type, network=db.get(Network, network_id))
        else:
            s = create_scan(db, scan_type, targets=AddressSet.from_specs(targets or ""))
        scan_id = s.id
    run_scan(scan_id, ScanContext(scan_id), scanner=scanner)
    with session_scope() as db:
        return db.get(Scan, scan_id)


def events(db, scan_id: int | None = None) -> list[Event]:
    db.expire_all()
    q = select(Event).order_by(Event.id)
    if scan_id is not None:
        q = q.where(Event.scan_id == scan_id)
    return list(db.scalars(q).unique().all())


def event_types(db, scan_id: int | None = None) -> list[str]:
    return [e.event_type for e in events(db, scan_id)]


def devices(db) -> list[Device]:
    db.expire_all()
    return list(db.scalars(select(Device).order_by(Device.id)).all())


def device_by_ip(db, ip: str) -> Device:
    db.expire_all()
    return db.scalar(select(Device).where(Device.current_ip == ip))
