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
from typing import Any, Protocol

from ..scanner.types import HostObservation


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


def normalize_hostname(name: str | None) -> str | None:
    if not name:
        return None
    name = name.strip().rstrip(".").lower()
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


def match_hosts(hosts: list[HostObservation], devices: list[DeviceLike]) -> dict[str, DeviceLike | None]:
    """Return {host.ip: matched device or None (new device)}."""
    result: dict[str, DeviceLike | None] = {}
    claimed: set[int] = set()

    mac_counts = Counter(normalize_mac(h.mac) for h in hosts if normalize_mac(h.mac))
    usable_mac = {h.ip: m for h in hosts if (m := normalize_mac(h.mac)) and mac_counts[m] == 1}

    def recency(d: DeviceLike):
        return (d.status == "active", d.last_seen)

    by_mac: dict[str, DeviceLike] = {}
    by_ip: dict[str, list[DeviceLike]] = {}
    by_name: dict[str, list[DeviceLike]] = {}
    for d in devices:
        if (m := normalize_mac(d.mac)) and (m not in by_mac or recency(d) > recency(by_mac[m])):
            by_mac[m] = d
        by_ip.setdefault(d.current_ip, []).append(d)
        if (hn := identity_hostname(d.hostname, d.current_ip)):
            by_name.setdefault(hn, []).append(d)

    # Pass 1: MAC
    for h in hosts:
        m = usable_mac.get(h.ip)
        d = by_mac.get(m) if m else None
        if d is not None and id(d) not in claimed:
            result[h.ip] = d
            claimed.add(id(d))

    # Pass 2: same IP, no contradicting evidence
    for h in hosts:
        if h.ip in result:
            continue
        candidates = sorted(
            (d for d in by_ip.get(h.ip, []) if id(d) not in claimed), key=recency, reverse=True
        )
        if not candidates:
            continue
        d = candidates[0]
        host_mac, dev_mac = usable_mac.get(h.ip), normalize_mac(d.mac)
        if host_mac and dev_mac:
            if host_mac != dev_mac:
                continue  # a different machine now uses this IP
        else:
            hn_host = identity_hostname(h.hostname, h.ip)
            hn_dev = identity_hostname(d.hostname, d.current_ip)
            if hn_host and hn_dev and hn_host != hn_dev:
                continue
            if host_mac and not dev_mac and host_mac in by_mac:
                continue  # MAC belongs to another known device (already handled or claimed)
        result[h.ip] = d
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
        ]
        if len(candidates) == 1:
            result[h.ip] = candidates[0]
            claimed.add(id(candidates[0]))

    for h in hosts:
        result.setdefault(h.ip, None)
    return result
