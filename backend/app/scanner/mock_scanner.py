"""Simulated scanner for development, demos and tests.

It only replaces the *data source*: results flow through exactly the same
orchestration, identity matching, comparison, alerting and snapshot code as
real nmap results.

The simulated network follows a deterministic scenario. Each completed
network-wide scan advances that network's scenario step by one:

  step 0  baseline
  step 1  srv-web01 opens 8080/http, ws-finance07 closes 3389, new host ws-temp25 (445/smb)
  step 2  srv-intranet Apache -> nginx, srv-db01 OpenSSH 8.9p1 -> 9.6p1,
          ws-dev12 changes IP (same MAC), cam-lobby stops answering
  step 3  srv-web01 opens 9000; cam-lobby missed twice -> reported as disappeared
  step 4  cam-lobby reappears; srv-web01 closes 9000
  step 5  srv-web01 opens 9000 again (a new event, by design)
  step 6+ no changes (verifies that unchanged state produces no duplicate events)
"""
from __future__ import annotations

import copy
import ipaddress
from dataclasses import dataclass, field

from ..netutils import AddressSet, PortScope
from .identify_truenas import looks_like_truenas
from .known_ports import TRUENAS_APPS_TCP_PORTS, mock_standard_scope
from .types import (
    HostObservation,
    PortObservation,
    PortProfile,
    ScanCancelled,
    ScanContext,
    StageResult,
)

MOCK_STANDARD_SCOPE = mock_standard_scope("1-10000")
MOCK_FULL_SCOPE = "1-65535"
LAST_STEP = 6

STEP_NOTES = [
    "Baseline state",
    "srv-web01 opens TCP/8080, ws-finance07 closes TCP/3389, new host ws-temp25 (TCP/445)",
    "srv-intranet Apache -> nginx, srv-db01 OpenSSH version change, ws-dev12 IP change, cam-lobby missing",
    "srv-web01 opens TCP/9000, cam-lobby confirmed not detected",
    "cam-lobby reappears, srv-web01 closes TCP/9000",
    "srv-web01 opens TCP/9000 again",
    "No changes (steady state)",
]

Svc = tuple[str, str | None, str | None]  # service, product, version


@dataclass
class MockHost:
    index: int
    offset: int
    name: str | None
    vendor: str
    os: str | None
    ports: dict[int, Svc]
    high_ports: dict[int, Svc] = field(default_factory=dict)  # only visible to full scans
    has_mac: bool = True
    present: bool = True


def _base_hosts() -> dict[str, MockHost]:
    return {
        "gw": MockHost(0, 1, "gw-core", "Fortinet", "FortiOS",
                       {22: ("ssh", "FortiSSH", None), 53: ("domain", "dnsmasq", "2.89"),
                        443: ("https", "FortiGate httpsd", None)}),
        "dc": MockHost(1, 5, "dc01", "Microsoft", "Windows Server 2022",
                       {53: ("domain", "Simple DNS Plus", None),
                        88: ("kerberos-sec", "Microsoft Windows Kerberos", None),
                        135: ("msrpc", "Microsoft Windows RPC", None),
                        389: ("ldap", "Microsoft Windows Active Directory LDAP", None),
                        445: ("microsoft-ds", None, None), 636: ("ldapssl", None, None),
                        3389: ("ms-wbt-server", "Microsoft Terminal Services", None)},
                       high_ports={49667: ("msrpc", "Microsoft Windows RPC", None)}),
        "A": MockHost(2, 10, "srv-web01", "VMware", "Linux 5.x",
                      {22: ("ssh", "OpenSSH", "8.9p1 Ubuntu 3ubuntu0.10"), 443: ("https", "nginx", "1.24.0")}),
        "B": MockHost(3, 11, "ws-finance07", "Dell", "Windows 11",
                      {135: ("msrpc", "Microsoft Windows RPC", None), 445: ("microsoft-ds", None, None),
                       3389: ("ms-wbt-server", "Microsoft Terminal Services", None)},
                      high_ports={49664: ("msrpc", "Microsoft Windows RPC", None)}),
        "D": MockHost(4, 12, "srv-intranet", "VMware", "Linux 5.x",
                      {22: ("ssh", "OpenSSH", "9.2p1 Debian 2"), 80: ("http", "Apache httpd", "2.4.57")}),
        "E": MockHost(5, 13, "srv-db01", "VMware", "Linux 5.x",
                      {22: ("ssh", "OpenSSH", "8.9p1"), 5432: ("postgresql", "PostgreSQL DB", "15.4")}),
        "F": MockHost(6, 20, "printer-3f", "Hewlett Packard", None,
                      {80: ("http", "HP Embedded Web Server", None), 631: ("ipp", "HP ipp", None),
                       9100: ("jetdirect", None, None)}),
        "G": MockHost(7, 21, "nas01", "Synology", "Linux 4.x",
                      {22: ("ssh", "OpenSSH", "8.2"), 445: ("microsoft-ds", "Samba smbd", "4"), 5000: ("http", "nginx", None)},
                      high_ports={50002: ("unknown", None, None)}),
        "TN": MockHost(16, 22, "truenas", "iXsystems", "TrueNAS SCALE",
                       {22: ("ssh", "OpenSSH", "9.2p1"), 80: ("http", "nginx", None), 443: ("https", "nginx", None),
                        30013: ("http", "Jellyfin", None)},
                       high_ports={30041: ("http", "Immich", None)}),
        "H": MockHost(8, 30, "sw-core01", "Cisco Systems", "Cisco IOS",
                      {22: ("ssh", "Cisco SSH", "1.25"), 443: ("https", "Cisco IOS http config", None)}),
        "I": MockHost(9, 40, "ws-dev12", "Intel Corporate", "Windows 11",
                      {3389: ("ms-wbt-server", "Microsoft Terminal Services", None)}),
        "J": MockHost(10, 50, "cam-lobby", "Hikvision", None,
                      {80: ("http", "Hikvision IP camera httpd", None), 554: ("rtsp", "Hikvision rtspd", None)}),
        "K": MockHost(11, 60, None, "Raspberry Pi Trading", "Linux 6.x",
                      {22: ("ssh", "OpenSSH", "9.2p1"), 1883: ("mqtt", None, None)}),
        "R": MockHost(12, 70, "srv-backup", "Unknown", "Linux 5.x",
                      {22: ("ssh", "OpenSSH", "8.4p1"), 873: ("rsync", None, "31")}, has_mac=False),
        "L": MockHost(14, 80, "srv-ollama", "VMware", "Linux 6.x",
                      {22: ("ssh", "OpenSSH", "9.6p1"),
                       11434: ("http", "Ollama", None)}),
        "M": MockHost(15, 81, "ws-lmstudio", "Dell", "Windows 11",
                      {1234: ("http", "LM Studio", None),
                       3389: ("ms-wbt-server", "Microsoft Terminal Services", None)}),
    }


def scenario(step: int) -> dict[str, MockHost]:
    """Cumulative network state for a scenario step."""
    hosts = copy.deepcopy(_base_hosts())
    if step >= 1:
        hosts["A"].ports[8080] = ("http", "Apache Tomcat", "9.0.80")
        del hosts["B"].ports[3389]
        hosts["C"] = MockHost(13, 25, "ws-temp25", "Lenovo", "Windows 10", {445: ("microsoft-ds", None, None)})
    if step >= 2:
        hosts["D"].ports[80] = ("http", "nginx", "1.24.0")
        hosts["E"].ports[22] = ("ssh", "OpenSSH", "9.6p1")
        hosts["I"].offset = 41
        hosts["J"].present = False
    if step >= 3:
        hosts["A"].ports[9000] = ("http", "Golang net/http server", None)
    if step >= 4:
        hosts["J"].present = True
        del hosts["A"].ports[9000]
    if step >= 5:
        hosts["A"].ports[9000] = ("http", "Golang net/http server", None)
    return hosts


def mock_mac(network_id: int, index: int) -> str:
    return f"02:4E:{network_id & 0xFF:02X}:00:{index & 0xFF:02X}:10"


class MockScanner:
    mode = "mock"

    def __init__(self, networks: list[tuple[int, str, int]], delay: float = 0.0):
        """networks: (network_id, cidr, scenario_step) for every configured network."""
        self.delay = delay
        self._hosts: dict[str, tuple[MockHost, int]] = {}
        for net_id, cidr, step in networks:
            net = ipaddress.ip_network(cidr, strict=False)
            for host in scenario(step).values():
                if not host.present or host.offset >= net.num_addresses:
                    continue
                ip = str(net.network_address + host.offset)
                self._hosts.setdefault(ip, (host, net_id))

    def _pause(self, ctx: ScanContext) -> None:
        if self.delay > 0 and ctx.cancel_event.wait(self.delay):
            raise ScanCancelled()
        ctx.check_cancelled()

    def _observation(self, ip: str, host: MockHost, net_id: int) -> HostObservation:
        return HostObservation(
            ip=ip,
            mac=mock_mac(net_id, host.index) if host.has_mac else None,
            vendor=host.vendor if host.has_mac else None,
            hostname=f"{host.name}.net{net_id}.lab.local" if host.name else None,
        )

    def discover(self, targets: list[str], ctx: ScanContext) -> StageResult:
        self._pause(ctx)
        target_set = AddressSet.from_specs(targets)
        hosts = [self._observation(ip, h, n) for ip, (h, n) in self._hosts.items() if ip in target_set]
        return StageResult(hosts=hosts)

    def scan_ports(self, ips: list[str], profile: PortProfile, ctx: ScanContext) -> StageResult:
        self._pause(ctx)
        scope_text = MOCK_FULL_SCOPE if profile.full else MOCK_STANDARD_SCOPE
        scope = PortScope(scope_text)
        result = StageResult(port_scope=scope_text)
        known_truenas = ctx.known_truenas_ips or set()
        for ip in ips:
            entry = self._hosts.get(ip)
            if entry is None:
                result.hosts.append(HostObservation(ip=ip, ports=[]))
                continue
            host, net_id = entry
            obs = self._observation(ip, host, net_id)
            if profile.os_detection and host.os:
                obs.os_name = host.os
                obs.os_accuracy = 95  # simulated -O fingerprint confidence
            is_truenas = (
                ip in known_truenas
                or looks_like_truenas(hostname=obs.hostname, vendor=host.vendor, os_name=host.os)
            )
            all_ports = {**host.ports, **(host.high_ports if profile.full else {})}
            if is_truenas:
                obs.os_name = obs.os_name or host.os
                obs.extra_tcp_ports = TRUENAS_APPS_TCP_PORTS
                truenas_set = set(TRUENAS_APPS_TCP_PORTS)
                obs.ports = [
                    PortObservation(port=p, service=s, product=prod, version=ver, method="probed", confidence=10)
                    for p, (s, prod, ver) in sorted(all_ports.items())
                    if p in scope or p in truenas_set
                ]
            else:
                obs.ports = [
                    PortObservation(port=p, service=s, product=prod, version=ver, method="probed", confidence=10)
                    for p, (s, prod, ver) in sorted(all_ports.items())
                    if p in scope
                ]
            result.hosts.append(obs)
        return result
