"""Device identity matching: which known device (if any) is this observed host?

IP address alone is not an identity. Matching is done in passes, strongest
signal first, and every device can be claimed by at most one host per scan:

  1. MAC address (only when the MAC is unique within this scan; proxy-ARP
     style duplicates are ignored).
  2. Same IP as a known device, unless the evidence says it is a different
     machine (different MAC, or different non-generic hostname).
  3. Same non-generic hostname as exactly one unclaimed known device whose MAC
     does not contradict -> the device moved to a new IP.
  4. Otherwise: a new device. When identity is uncertain we prefer creating a
     new device over wrongly merging two machines.
"""
from __future__ import annotations

import re
from collections import Counter
from collections.abc import Callable
from typing import Any, Protocol

from ..scanner.types import HostObservation

# MAC sources that are a snapshot of someone else's table, not the device's own reply.
WEAK_MAC_SOURCES = frozenset({"snmp"})


class DeviceLike(Protocol):
    id: Any
    current_ip: str
    mac: str | None
    hostname: str | None
    status: str
    last_seen: Any


def normalize_mac(mac: str | None) -> str | None:
    if not mac:
        return None
    hexchars = re.sub(r"[^0-9A-Fa-f]", "", mac)
    if len(hexchars) != 12:
        return None
    return ":".join(hexchars[i:i + 2] for i in range(0, 12, 2)).upper()


# Reverse-DNS answers invented by the container runtime the scanner runs in (Docker Desktop
# answers "host.docker.internal" for the host's address). They name the scanner's view, not the
# device, so they are never stored or used as identity.
_SYNTHETIC_HOST_SUFFIXES = (".docker.internal", ".containers.internal")


def normalize_hostname(name: str | None) -> str | None:
    if not name:
        return None
    name = name.strip().rstrip(".").lower()
    if name == "localhost" or name.endswith(_SYNTHETIC_HOST_SUFFIXES):
        return None
    return _collapse_repeated_suffix(name) or None


def _collapse_repeated_suffix(name: str) -> str:
    """``host.corp.com.corp.com`` -> ``host.corp.com``.

    A PTR record entered without its trailing dot gets the zone appended a second time
    (common in Windows DNS). Only a repeat of two or more labels is collapsed, so
    ``a.b.b`` style names are left alone.
    """
    labels = name.split(".")
    changed = True
    while changed:
        changed = False
        for k in range(len(labels) // 2, 1, -1):  # k = labels in the repeated suffix, >= 2
            if labels[-k:] == labels[-2 * k:-k]:
                labels = labels[:-k]
                changed = True
                break
    return ".".join(labels)


def is_generic_hostname(hostname: str | None, ip: str) -> bool:
    """Hostnames derived from the IP (e.g. 10-0-0-5.dhcp.corp) do not identify a device."""
    if not hostname:
        return True
    octets = ip.split(".")
    patterns = {"-".join(octets), ".".join(octets), "-".join(reversed(octets)), ".".join(reversed(octets)),
                "_".join(octets), "".join(o.zfill(3) for o in octets)}
    return any(p in hostname for p in patterns)


def identity_hostname(hostname: str | None, ip: str) -> str | None:
    h = normalize_hostname(hostname)
    return None if h is None or is_generic_hostname(h, ip) else h


def match_hosts(
    hosts: list[HostObservation], devices: list[DeviceLike], network_of: Callable[[str], Any] | None = None,
) -> dict[str, DeviceLike | None]:
    """Return {host.ip: matched device or None (new device)}."""
    return {ip: (m[0] if m else None) for ip, m in match_hosts_detailed(hosts, devices, network_of).items()}


def match_hosts_detailed(
    hosts: list[HostObservation], devices: list[DeviceLike], network_of: Callable[[str], Any] | None = None,
) -> dict[str, tuple[DeviceLike, str] | None]:
    """Return {host.ip: (matched device, pass name) or None (new device)}.

    `network_of(ip)` gives the network id of an address (or None). It is only a tie-breaker: a
    device in another network is not excluded, because real devices move between networks.
    """
    result: dict[str, tuple[DeviceLike, str]] = {}
    claimed: set[int] = set()

    mac_counts = Counter(normalize_mac(h.mac) for h in hosts if normalize_mac(h.mac))
    usable_mac = {h.ip: m for h in hosts if (m := normalize_mac(h.mac)) and mac_counts[m] == 1}

    def recency(d: DeviceLike):
        return (d.status == "active", d.last_seen)

    def net_of(ip: str) -> Any:
        return network_of(ip) if network_of else None

    def same_network(d: DeviceLike, ip: str) -> bool:
        dn, hn = getattr(d, "network_id", None), net_of(ip)
        return dn is not None and hn is not None and dn == hn

    def other_network(d: DeviceLike, ip: str) -> bool:
        dn, hn = getattr(d, "network_id", None), net_of(ip)
        return dn is not None and hn is not None and dn != hn

    by_mac: dict[str, DeviceLike] = {}
    by_ip: dict[str, list[DeviceLike]] = {}
    by_name: dict[str, list[DeviceLike]] = {}
    for d in devices:
        if (m := normalize_mac(d.mac)) and (m not in by_mac or recency(d) > recency(by_mac[m])):
            by_mac[m] = d
        by_ip.setdefault(d.current_ip, []).append(d)
        if (hn := identity_hostname(d.hostname, d.current_ip)):
            by_name.setdefault(hn, []).append(d)

    # Pass 1: MAC. A MAC from a router's ARP table is only a snapshot; when it names a different
    # non-generic hostname than the device's, it is treated as stale and not used.
    for h in hosts:
        m = usable_mac.get(h.ip)
        d = by_mac.get(m) if m else None
        if d is None or id(d) in claimed:
            continue
        if h.mac_source in WEAK_MAC_SOURCES and _names_conflict(h, d):
            continue
        result[h.ip] = (d, "mac")
        claimed.add(id(d))

    # Pass 2: same IP, no contradicting evidence
    for h in hosts:
        if h.ip in result:
            continue
        candidates = sorted(
            (d for d in by_ip.get(h.ip, []) if id(d) not in claimed),
            key=lambda d: (same_network(d, h.ip), recency(d)),
            reverse=True,
        )
        if not candidates:
            continue
        d = candidates[0]
        # Overlapping RFC1918 ranges: an IP alone is never evidence across networks, even when only
        # one side has a MAC (one-sided MAC). Cross-network continuity needs pass 1 (MAC) or pass 3.
        if other_network(d, h.ip):
            continue
        host_mac, dev_mac = usable_mac.get(h.ip), normalize_mac(d.mac)
        if host_mac and dev_mac:
            if host_mac != dev_mac:
                continue  # a different machine now uses this IP
        else:
            if _names_conflict(h, d):
                continue
            if host_mac and not dev_mac and host_mac in by_mac:
                continue  # MAC belongs to another known device (already handled or claimed)
        result[h.ip] = (d, "ip")
        claimed.add(id(d))

    # Pass 3: hostname moved to a new IP
    for h in hosts:
        if h.ip in result:
            continue
        hn = identity_hostname(h.hostname, h.ip)
        if not hn:
            continue
        host_mac = usable_mac.get(h.ip)
        candidates = [
            d for d in by_name.get(hn, [])
            if id(d) not in claimed
            and not (host_mac and normalize_mac(d.mac) and normalize_mac(d.mac) != host_mac)
            and not _held_by_other_machine(d, host_mac, usable_mac)
        ]
        if len(candidates) == 1:
            result[h.ip] = (candidates[0], "hostname")
            claimed.add(id(candidates[0]))

    for h in hosts:
        result.setdefault(h.ip, None)
    return result


def match_evidence(via: str, h: HostObservation) -> dict[str, str]:
    """Compact evidence for the pass that kept a device. Uses only fields already in inventory."""
    out: dict[str, str] = {"via": via}
    if via == "mac":
        if (m := normalize_mac(h.mac)):
            out["mac"] = m
        if h.mac_source:
            out["mac_source"] = h.mac_source
    elif via == "hostname":
        if (hn := identity_hostname(h.hostname, h.ip)):
            out["hostname"] = hn
    elif via == "ip":
        out["ip"] = h.ip
        if (m := normalize_mac(h.mac)):
            out["mac"] = m
        if h.mac_source:
            out["mac_source"] = h.mac_source
    return out


def _names_conflict(h: HostObservation, d: DeviceLike) -> bool:
    hn_host = identity_hostname(h.hostname, h.ip)
    hn_dev = identity_hostname(d.hostname, d.current_ip)
    return bool(hn_host and hn_dev and hn_host != hn_dev)


def _held_by_other_machine(d: DeviceLike, host_mac: str | None, usable_mac: dict[str, str]) -> bool:
    """A hostname move needs evidence that the device left its address. If its old address now answers
    with a different MAC and neither side has a MAC that would settle it, the device may still be
    elsewhere (offline, or cloned name), so a new device is safer than a merge."""
    dev_mac = normalize_mac(d.mac)
    if host_mac or not dev_mac:
        return False
    other = usable_mac.get(d.current_ip)
    return other is not None and other != dev_mac
