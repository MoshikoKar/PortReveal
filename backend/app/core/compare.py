"""Change detection: apply one scan's observations to the known network state.

This is the single comparison engine for both real (nmap) and simulated (mock)
scans. Rules:

* Alerts only on state transitions (port X open->closed, etc). Unchanged state
  never produces events, so repeated scans do not duplicate notifications.
* A network's first complete standard scan is its baseline: nothing found
  while a network has no baseline produces events.
* A port is only reported as "opened" if a previous successful port scan of
  that device covered that port. Ports seen for the first time on a new device,
  or by a device's first full-port scan, are recorded silently.
* Removals (port closed, device not detected) only happen when the scan was
  complete. Partial/failed scans can add and refresh, never remove, so a broken
  scan cannot replace the last known-good state.
* A device is only reported as gone after `disappear_after_missed` consecutive
  complete scans that covered its IP missed it ("unknown" until then). While
  presence correlation is enabled these per-scan disappear/reappear events are
  recorded without email; emails come from the correlated absence streak
  (core/presence.py), and any sighting resets that streak.
* Mass-change guard: if a scan would mark a large share of devices as gone, or
  close a large share of ports at once, the removals are skipped and the scan
  is flagged as partial (likely a scanner/network problem, not real change).
"""
from __future__ import annotations

import logging
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from ..db import utcnow
from ..models import (
    DEVICE_ACTIVE,
    DEVICE_NOT_DETECTED,
    DEVICE_UNKNOWN,
    EV_DEVICE_DISAPPEARED,
    EV_DEVICE_DISCOVERED,
    EV_DEVICE_REAPPEARED,
    EV_IP_CHANGED,
    EV_PORT_CLOSED,
    EV_PORT_OPENED,
    EV_SERVICE_CHANGED,
    EV_SERVICE_DETECTED,
    EV_VERSION_CHANGED,
    EVENT_SEVERITY,
    SCAN_FULL,
    SCAN_STANDARD,
    Device,
    DeviceIP,
    DevicePort,
    Event,
    Network,
    Scan,
    ScanHost,
)
from ..netutils import AddressSet, PortScope, ip_sort_key
from ..scanner.types import HostObservation, PortObservation
from ..settings_store import PresenceSettings, ScanSettings, get_section
from .identity import match_hosts, normalize_hostname, normalize_mac

log = logging.getLogger(__name__)

MASS_GUARD_MIN = 10  # never trip the guard below this many removals


@dataclass
class ScanOutcome:
    scan_type: str
    targets: AddressSet
    hosts: dict[str, HostObservation]
    port_scope: str | None = None  # None when the scan had no port stage
    discovery_complete: bool = True
    port_stage_complete: bool = True

    @property
    def complete(self) -> bool:
        return self.discovery_complete and self.port_stage_complete


@dataclass(slots=True)
class _DeviceKey:
    """A device's identity columns only: all `match_hosts` reads, without ORM rows, ports or IPs."""
    id: int
    current_ip: str
    mac: str | None
    hostname: str | None
    status: str
    last_seen: datetime | None


# Device ids per `IN (...)` when loading the scoped devices (well under SQLite's bound-parameter limit).
_LOAD_CHUNK = 1000


@dataclass
class ApplyResult:
    events: list[Event] = field(default_factory=list)
    baseline_created: bool = False
    guard_tripped: bool = False
    notes: list[str] = field(default_factory=list)
    hosts_failed: int = 0


def describe_service(service: str | None, product: str | None, version: str | None) -> str:
    parts = [p for p in (product, version) if p]
    if parts:
        return " ".join(parts) + (f" ({service})" if service else "")
    return service or "unknown"


def device_label(d: Device) -> str:
    return d.hostname or d.current_ip


def _norm(v: str | None) -> str:
    return (v or "").strip().lower()


def _is_reliable(method: str | None, confidence: int | None) -> bool:
    return method == "probed" or (confidence or 0) >= 8


class _Applier:
    def __init__(self, db: Session, scan: Scan, outcome: ScanOutcome, cfg: ScanSettings, now: datetime,
                 correlate: bool = False):
        self.db, self.scan, self.outcome, self.cfg, self.now = db, scan, outcome, cfg, now
        self.correlate = correlate
        self.result = ApplyResult()
        self.networks = [(n, AddressSet.from_specs(n.cidr)) for n in db.scalars(select(Network)).all()]
        self._scope_cache: dict[int, PortScope | None] = {}
        self.scope = PortScope(outcome.port_scope) if outcome.port_scope else None

    # --- helpers -------------------------------------------------------------
    def network_for(self, ip: str) -> Network | None:
        best: tuple[int, Network] | None = None
        for net, aset in self.networks:
            if ip in aset and (best is None or len(aset) < best[0]):
                best = (len(aset), net)
        return best[1] if best else None

    @staticmethod
    def mode_for(net: Network | None) -> str:
        """silent: network has no baseline yet; alert: normal; record: outside any network (no email)."""
        if net is None:
            return "record"
        return "alert" if net.baseline_scan_id is not None else "silent"

    def prefetch_scopes(self, scan_ids: set[int]) -> None:
        """Load the port scopes of many prior scans in one query (instead of one per scan id)."""
        missing = [i for i in scan_ids if i not in self._scope_cache]
        if not missing:
            return
        found = dict(self.db.execute(select(Scan.id, Scan.port_scope).where(Scan.id.in_(missing))).tuples().all())
        for scan_id in missing:
            text = found.get(scan_id)
            self._scope_cache[scan_id] = PortScope(text) if text else None

    def prior_scope(self, scan_id: int | None) -> PortScope | None:
        if scan_id is None:
            return None
        if scan_id not in self._scope_cache:
            text = self.db.scalar(select(Scan.port_scope).where(Scan.id == scan_id))
            self._scope_cache[scan_id] = PortScope(text) if text else None
        return self._scope_cache[scan_id]

    def emit(self, device: Device, etype: str, mode: str, message: str, *, ip: str | None = None,
             protocol: str | None = None, port: int | None = None, old: str | None = None,
             new: str | None = None, quiet: bool = False) -> None:
        if mode == "silent":
            return
        ev = Event(
            created_at=self.now,
            scan_id=self.scan.id,
            device=device,
            event_type=etype,
            severity=EVENT_SEVERITY[etype],
            ip=ip or device.current_ip,
            protocol=protocol,
            port=port,
            old_value=old,
            new_value=new,
            message=message,
            notify=mode == "alert" and not quiet,
        )
        self.db.add(ev)
        self.result.events.append(ev)

    def load_devices(self, hosts: list[HostObservation]) -> tuple[list[Device], dict[str, Device | None]]:
        """Load only the devices this scan can touch, with their ports and IPs.

        Identity matching (MAC / IP / moved hostname) runs over every known device, but on a light
        column projection. Full rows are then loaded for the matched devices plus the active/unknown
        devices inside the scan targets (the candidates for "not detected"); devices elsewhere in
        the inventory are never materialized.
        """
        keys = [_DeviceKey(*row) for row in self.db.execute(
            select(Device.id, Device.current_ip, Device.mac, Device.hostname, Device.status, Device.last_seen)
            .order_by(Device.id)
        ).tuples()]
        key_matches = match_hosts(hosts, keys)
        targets = self.outcome.targets
        wanted = {k.id for k in key_matches.values() if k is not None}
        wanted.update(k.id for k in keys if k.status in (DEVICE_ACTIVE, DEVICE_UNKNOWN) and k.current_ip in targets)
        ids = sorted(wanted)
        devices: list[Device] = []
        for i in range(0, len(ids), _LOAD_CHUNK):
            devices += self.db.scalars(
                select(Device).where(Device.id.in_(ids[i:i + _LOAD_CHUNK])).order_by(Device.id)
                .options(selectinload(Device.ports), selectinload(Device.ips))
            ).all()
        by_id = {d.id: d for d in devices}
        matches = {ip: (by_id[k.id] if k is not None else None) for ip, k in key_matches.items()}
        return devices, matches

    # --- main ----------------------------------------------------------------
    def run(self) -> ApplyResult:
        outcome, now = self.outcome, self.now
        hosts = sorted(outcome.hosts.values(), key=lambda h: ip_sort_key(h.ip))
        mac_counts = Counter(m for h in hosts if (m := normalize_mac(h.mac)))
        devices, matches = self.load_devices(hosts)
        if self.scope is not None:
            self.prefetch_scopes({d.last_port_scan_id for d in matches.values() if d and d.last_port_scan_id is not None})

        seen_devices: dict[str, Device] = {}  # ip -> device
        pending_closures: list[tuple[Device, DevicePort, str]] = []
        open_ports_scanned = 0

        for h in hosts:
            net = self.network_for(h.ip)
            mode = self.mode_for(net)
            mac = normalize_mac(h.mac)
            if mac and mac_counts[mac] > 1:
                mac = None
            hostname = normalize_hostname(h.hostname)
            dev = matches.get(h.ip)
            is_new = dev is None
            if dev is None:
                dev = Device(
                    current_ip=h.ip, mac=mac, vendor=h.vendor if mac else None, hostname=hostname,
                    dns_name=hostname, os_name=h.os_name, status=DEVICE_ACTIVE, first_seen=now,
                    last_seen=now, missed_scans=0, network_id=net.id if net else None,
                    port_scan_failed=False,
                )
                dev.ports = []
                dev.ips = [DeviceIP(ip=h.ip, first_seen=now, last_seen=now)]
                self.db.add(dev)
            else:
                label = device_label(dev)
                if dev.current_ip != h.ip:
                    self.emit(dev, EV_IP_CHANGED, mode, f"{label} changed IP address {dev.current_ip} -> {h.ip}",
                              ip=h.ip, old=dev.current_ip, new=h.ip)
                    dev.current_ip = h.ip
                if dev.status == DEVICE_NOT_DETECTED:
                    self.emit(dev, EV_DEVICE_REAPPEARED, mode, f"{label} ({h.ip}) is detected again", ip=h.ip,
                              quiet=self.correlate and not dev.absence_alerted)
                if mac and not dev.mac:
                    dev.mac = mac
                if mac and h.vendor:
                    dev.vendor = h.vendor
                if hostname:
                    dev.hostname = hostname
                    dev.dns_name = hostname
                if h.os_name:
                    dev.os_name = h.os_name
                dev.status = DEVICE_ACTIVE
                dev.missed_scans = 0
                dev.absence_days, dev.absence_counted_on, dev.absence_alerted = 0, None, False
                dev.last_seen = now
                if net is not None:
                    dev.network_id = net.id
                ip_row = next((r for r in dev.ips if r.ip == h.ip), None)
                if ip_row is None:
                    dev.ips.append(DeviceIP(ip=h.ip, first_seen=now, last_seen=now))
                else:
                    ip_row.last_seen = now
            seen_devices[h.ip] = dev

            if h.ports is not None and self.scope is not None:
                open_ports_scanned += sum(
                    1 for p in dev.ports if p.is_open and p.protocol == "tcp" and p.port in self.scope
                )
                pending_closures += self._process_ports(dev, h.ports, is_new, mode)
                dev.port_scan_failed = False
                dev.last_port_scan_id = self.scan.id
                dev.last_port_scan_at = now
                if outcome.scan_type == SCAN_FULL:
                    dev.full_scanned_at = now
            elif h.port_scan_failed:
                dev.port_scan_failed = True
                self.result.hosts_failed += 1

            if is_new:
                open_list = ", ".join(f"{p.protocol.upper()}/{p.port}" for p in dev.ports if p.is_open)
                self.emit(
                    dev, EV_DEVICE_DISCOVERED, mode,
                    f"New device {device_label(dev)} ({h.ip})" + (f" with open ports {open_list}" if open_list else ""),
                    ip=h.ip, new=open_list or None,
                )

        self._apply_closures(pending_closures, open_ports_scanned)
        self._apply_disappearance(devices, {id(d) for d in seen_devices.values()})
        self.db.flush()

        for ip, dev in seen_devices.items():
            h = outcome.hosts[ip]
            self.db.add(ScanHost(
                scan_id=self.scan.id, device_id=dev.id, ip=ip, created_at=now,
                status="port_scan_failed" if h.port_scan_failed else "up",
                open_ports=len(h.ports) if h.ports is not None else None,
            ))

        self._maybe_baseline()
        return self.result

    def _process_ports(self, dev: Device, observed: list[PortObservation], is_new: bool, mode: str):
        now, scope = self.now, self.scope
        assert scope is not None
        rows = {(r.protocol, r.port): r for r in dev.ports}
        label = device_label(dev)
        last_scope = self.prior_scope(dev.last_port_scan_id)
        full_before = dev.full_scanned_at is not None

        def previously_covered(port: int) -> bool:
            if is_new:
                return False
            return full_before or (last_scope is not None and port in last_scope)

        seen: set[tuple[str, int]] = set()
        for po in observed:
            key = (po.protocol, po.port)
            seen.add(key)
            row = rows.get(key)
            svc = describe_service(po.service, po.product, po.version)
            if row is None:
                row = DevicePort(
                    protocol=po.protocol, port=po.port, is_open=True, service=po.service, product=po.product,
                    version=po.version, extra_info=po.extra_info, method=po.method, confidence=po.confidence,
                    first_seen=now, last_seen=now, opened_at=now,
                )
                dev.ports.append(row)
                rows[key] = row
                if previously_covered(po.port):
                    self.emit(dev, EV_PORT_OPENED, mode,
                              f"New open port {po.protocol.upper()}/{po.port} ({svc}) on {label} ({dev.current_ip})",
                              protocol=po.protocol, port=po.port, new=svc)
            elif not row.is_open:
                row.is_open, row.opened_at, row.closed_at, row.last_seen = True, now, None, now
                self._set_service(row, po, force=True)
                self.emit(dev, EV_PORT_OPENED, mode,
                          f"Port {po.protocol.upper()}/{po.port} ({svc}) opened again on {label} ({dev.current_ip})",
                          protocol=po.protocol, port=po.port, new=svc)
            else:
                row.last_seen = now
                self._compare_service(dev, row, po, mode)

        closures = []
        for key, row in rows.items():
            if row.is_open and key not in seen and row.protocol == "tcp" and row.port in scope:
                closures.append((dev, row, mode))
        return closures

    @staticmethod
    def _set_service(row: DevicePort, po: PortObservation, force: bool = False) -> None:
        if force or po.reliable or not row.service:
            row.service = po.service or row.service
            if po.product or force:
                row.product = po.product
                row.version = po.version
            elif po.version and row.product:
                row.version = po.version
            row.extra_info = po.extra_info or row.extra_info
            row.method = po.method
            row.confidence = po.confidence

    def _compare_service(self, dev: Device, row: DevicePort, po: PortObservation, mode: str) -> None:
        if not po.reliable:
            if not row.service and po.service:
                self._set_service(row, po)
            return
        label = device_label(dev)
        port_txt = f"{row.protocol.upper()}/{row.port}"
        old = describe_service(row.service, row.product, row.version)
        new_product = po.product or row.product
        new_version = po.version if po.product else (po.version or row.version)
        new = describe_service(po.service or row.service, new_product, new_version)
        old_reliable = _is_reliable(row.method, row.confidence)
        op, np_ = _norm(row.product), _norm(po.product)
        etype = None
        if old_reliable:
            if op and np_ and op != np_:
                etype = EV_SERVICE_CHANGED
            elif row.service and po.service and _norm(row.service) != _norm(po.service) and not (op and op == np_):
                etype = EV_SERVICE_CHANGED
            elif op and op == np_ and row.version and po.version and _norm(row.version) != _norm(po.version):
                etype = EV_VERSION_CHANGED
            elif not op and np_:
                etype = EV_SERVICE_DETECTED
        elif np_ or (po.service and _norm(po.service) != _norm(row.service)):
            etype = EV_SERVICE_DETECTED

        if etype == EV_SERVICE_CHANGED:
            msg = f"Service on {port_txt} of {label} changed: {old} -> {new}"
        elif etype == EV_VERSION_CHANGED:
            msg = f"Service version on {port_txt} of {label} changed: {old} -> {new}"
        elif etype == EV_SERVICE_DETECTED:
            msg = f"Service identified on {port_txt} of {label}: {new}"
        if etype:
            self.emit(dev, etype, mode, msg, protocol=row.protocol, port=row.port, old=old, new=new)
        self._set_service(row, po)

    def _apply_closures(self, pending: list[tuple[Device, DevicePort, str]], open_scanned: int) -> None:
        if not pending:
            return
        if not self.outcome.complete:
            self.result.notes.append(f"Partial scan: {len(pending)} possible port closure(s) not applied.")
            return
        pct = self.cfg.mass_change_guard_percent
        if len(pending) >= MASS_GUARD_MIN and len(pending) * 100 > pct * max(open_scanned, 1):
            self.result.guard_tripped = True
            self.result.notes.append(
                f"Mass-change guard: {len(pending)} of {open_scanned} open ports would close at once; "
                "closures not applied (verify scanner connectivity)."
            )
            return
        for dev, row, mode in pending:
            svc = describe_service(row.service, row.product, row.version)
            row.is_open = False
            row.closed_at = self.now
            self.emit(dev, EV_PORT_CLOSED, mode,
                      f"Port {row.protocol.upper()}/{row.port} ({svc}) closed on {device_label(dev)} ({dev.current_ip})",
                      protocol=row.protocol, port=row.port, old=svc)

    def _apply_disappearance(self, devices: list[Device], seen_ids: set[int]) -> None:
        if not self.outcome.complete:
            return
        targets = self.outcome.targets
        in_scope = [d for d in devices if d.status in (DEVICE_ACTIVE, DEVICE_UNKNOWN) and d.current_ip in targets]
        missing = [d for d in in_scope if id(d) not in seen_ids]
        if not missing:
            return
        pct = self.cfg.mass_change_guard_percent
        if len(missing) >= MASS_GUARD_MIN and len(missing) * 100 > pct * len(in_scope):
            self.result.guard_tripped = True
            self.result.notes.append(
                f"Mass-change guard: {len(missing)} of {len(in_scope)} known devices were not detected; "
                "presence changes not applied (verify scanner connectivity)."
            )
            return
        threshold = self.cfg.disappear_after_missed
        for d in missing:
            d.missed_scans = (d.missed_scans or 0) + 1
            if d.missed_scans >= threshold:
                d.status = DEVICE_NOT_DETECTED
                net = self.network_for(d.current_ip)
                self.emit(d, EV_DEVICE_DISAPPEARED, self.mode_for(net),
                          f"{device_label(d)} ({d.current_ip}) is no longer detected "
                          f"(missed {d.missed_scans} consecutive scans)", quiet=self.correlate)
            else:
                d.status = DEVICE_UNKNOWN

    def _maybe_baseline(self) -> None:
        scan = self.scan
        if scan.network_id is None or scan.scan_type != SCAN_STANDARD:
            return
        if not self.outcome.complete or self.result.guard_tripped:
            return
        net = self.db.get(Network, scan.network_id)
        if net is not None and net.baseline_scan_id is None:
            net.baseline_scan_id = scan.id
            net.baseline_at = self.now
            scan.is_baseline = True
            self.result.baseline_created = True
            self.result.notes.append("Baseline created: the current state is now the known state (no alerts).")


def apply_outcome(db: Session, scan: Scan, outcome: ScanOutcome, cfg: ScanSettings,
                  now: datetime | None = None) -> ApplyResult:
    correlate = get_section(db, PresenceSettings).enabled
    return _Applier(db, scan, outcome, cfg, now or utcnow(), correlate=correlate).run()

