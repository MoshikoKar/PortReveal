"""Pick the nmap bind device (-e) from local interfaces that overlap scan targets.

When a VPN/tunnel (e.g. Tailscale) steals the OS route for a LAN subnet, privileged
nmap tries ARP on that non-ethernet device and quits. Binding to the overlapping
local ethernet device forces packets onto the correct NIC, and that NIC's own address
is used as the source (-S): with -e alone nmap keeps the OS default-route source (the
VPN address), so replies to TCP/ICMP probes never come back and every port looks filtered.
"""
from __future__ import annotations

import ipaddress
import logging
import re
import subprocess
import time
from dataclasses import dataclass

log = logging.getLogger(__name__)

_IFLIST_CACHE_S = 30.0
_DEV_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_-]{0,31}$")
# DEV (SHORT) IP/MASK TYPE UP MTU [MAC]
_IFACE_LINE = re.compile(
    r"^(?P<dev>\S+)\s+\(\S+\)\s+(?P<ipmask>\S+)\s+(?P<type>\S+)\s+(?P<up>up|down)\b",
    re.IGNORECASE,
)

_cache: tuple[float, str, tuple["NmapIface", ...]] | None = None


@dataclass(frozen=True)
class NmapIface:
    dev: str
    network: ipaddress.IPv4Network
    type: str  # ethernet | other | loopback | ...
    up: bool
    address: ipaddress.IPv4Address | None = None  # this host's address on the interface

    @property
    def is_ethernet(self) -> bool:
        return self.type.lower() == "ethernet"

    @property
    def is_loopback(self) -> bool:
        return self.type.lower() == "loopback" or self.network.is_loopback

    @property
    def is_link_local(self) -> bool:
        return self.network.is_link_local


@dataclass(frozen=True)
class BindChoice:
    """How to run nmap for a target set given local interfaces."""

    device: str | None
    privileged: bool
    source: str | None = None  # source address for -S (the bound device's own address)


def parse_nmap_iflist(text: str) -> list[NmapIface]:
    """Parse the INTERFACES table from `nmap --iflist` stdout."""
    out: list[NmapIface] = []
    in_table = False
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        if "INTERFACES" in line and line.startswith("*"):
            in_table = True
            continue
        if in_table and line.startswith("*"):
            break
        if not in_table:
            continue
        if line.upper().startswith("DEV"):
            continue
        m = _IFACE_LINE.match(line)
        if not m:
            continue
        ipmask = m.group("ipmask")
        if ipmask in (".", "none", "(none)") or ":" in ipmask:
            continue  # skip IPv6 / empty
        try:
            # Host bits may be set (e.g. 192.168.69.102/24); strict=False accepts that.
            network = ipaddress.ip_network(ipmask, strict=False)
            address = ipaddress.ip_interface(ipmask).ip
        except ValueError:
            continue
        if network.version != 4:
            continue
        dev = m.group("dev")
        if not _DEV_RE.match(dev):
            continue
        out.append(
            NmapIface(
                dev=dev,
                network=network,
                type=m.group("type").lower(),
                up=m.group("up").lower() == "up",
                address=address,
            )
        )
    return out


def _target_networks(targets: list[str]) -> list[ipaddress.IPv4Network]:
    nets: list[ipaddress.IPv4Network] = []
    for t in targets:
        t = t.strip()
        if not t:
            continue
        try:
            if "/" in t:
                nets.append(ipaddress.ip_network(t, strict=False))
            else:
                addr = ipaddress.ip_address(t)
                if addr.version == 4:
                    nets.append(ipaddress.ip_network(f"{addr}/32"))
        except ValueError:
            continue  # hostname or invalid — ignore for bind selection
    return [n for n in nets if n.version == 4]


def _overlaps(iface: NmapIface, targets: list[ipaddress.IPv4Network]) -> bool:
    return any(iface.network.overlaps(t) for t in targets)


def _score(iface: NmapIface) -> tuple:
    """Higher is better. Prefer ethernet, up, non-link-local, more specific prefix."""
    return (
        1 if iface.is_ethernet else 0,
        0 if iface.is_link_local else 1,
        iface.network.prefixlen,
        1 if iface.up else 0,
    )


def choose_bind(targets: list[str], ifaces: list[NmapIface], privileged: bool) -> BindChoice:
    """Select nmap -e device and whether privileged mode is safe for these targets."""
    wanted = _target_networks(targets)
    if not wanted or not ifaces:
        return BindChoice(device=None, privileged=privileged)

    overlapping = [i for i in ifaces if i.up and not i.is_loopback and _overlaps(i, wanted)]
    if not overlapping:
        return BindChoice(device=None, privileged=privileged)

    overlapping.sort(key=_score, reverse=True)
    best = overlapping[0]
    if best.is_ethernet:
        return BindChoice(device=best.dev, privileged=privileged,
                          source=str(best.address) if best.address is not None else None)
    # Overlap only via tunnel/VPN ("other"): ARP/raw ethernet probes cannot work.
    if privileged:
        log.info(
            "targets overlap non-ethernet device %s (%s); using unprivileged nmap",
            best.dev, best.network,
        )
        return BindChoice(device=None, privileged=False)
    return BindChoice(device=None, privileged=False)


def list_nmap_interfaces(nmap_exe: str, refresh: bool = False) -> list[NmapIface]:
    """Run `nmap --iflist` (cached briefly) and return parsed IPv4 interfaces."""
    global _cache
    now = time.monotonic()
    if (
        not refresh
        and _cache is not None
        and _cache[1] == nmap_exe
        and now - _cache[0] < _IFLIST_CACHE_S
    ):
        return list(_cache[2])
    try:
        proc = subprocess.run(
            [nmap_exe, "--iflist"],
            capture_output=True,
            text=True,
            timeout=20,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        log.warning("nmap --iflist failed: %s", exc)
        return []
    text = (proc.stdout or "") + "\n" + (proc.stderr or "")
    ifaces = tuple(parse_nmap_iflist(text))
    _cache = (now, nmap_exe, ifaces)
    return list(ifaces)


def resolve_bind(nmap_exe: str, targets: list[str], privileged: bool) -> BindChoice:
    return choose_bind(targets, list_nmap_interfaces(nmap_exe), privileged)


def off_segment_networks(nmap_exe: str, cidrs: list[str]) -> list[str]:
    """Scan networks with no local ethernet interface on them: nmap cannot see MAC addresses there
    (routed subnet, VPN, or a container on a Docker bridge network)."""
    ifaces = [i for i in list_nmap_interfaces(nmap_exe) if i.up and i.is_ethernet and not i.is_loopback]
    off = []
    for spec in cidrs:
        nets = _target_networks(re.split(r"[\s,;]+", spec))
        if nets and not any(_overlaps(i, nets) for i in ifaces):
            off.append(spec)
    return off
