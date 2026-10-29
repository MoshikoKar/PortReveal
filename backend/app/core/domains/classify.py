"""Classification rules for domain-scan results (pure functions, no I/O).

Exposure (per name, from the two resolver views):
  external   resolves on the public resolvers only
  internal   resolves on the internal resolvers only
  both       resolves on both (split DNS)
  unresolved resolves nowhere (kept only when AXFR or an operator vouches for the name)

Flags:
  private_ip_public      the public answer contains a private (RFC1918 / non-global) address
  internal_ip_public     the public answer contains a public address inside a configured network
  internal_authorized    the name was found only through the authorized zone transfer (ground truth)
  internal_name_exposed  an AXFR name that is also visible publicly (passive sources or public DNS)
                         while it resolves to internal ranges
Wildcard: a view's answer is a wildcard match when every address equals the wildcard probe answer
of that view. Results are marked, never filtered.
"""
from __future__ import annotations

import ipaddress
from collections.abc import Callable, Iterable

from ...models import (
    EXPOSURE_BOTH,
    EXPOSURE_EXTERNAL,
    EXPOSURE_INTERNAL,
    EXPOSURE_UNRESOLVED,
    FLAG_INTERNAL_AUTHORIZED,
    FLAG_INTERNAL_IP_PUBLIC,
    FLAG_INTERNAL_NAME_EXPOSED,
    FLAG_PRIVATE_IP_PUBLIC,
    SOURCE_AXFR,
    SOURCE_PASSIVE,
)
from ...netutils import AddressSet

InNetworks = Callable[[str], bool]

# Same convention as core/geo.py: RFC1918, CGNAT and ULA are private; documentation (TEST-NET)
# ranges count as public so tests can stand in for real public addresses.
_PRIVATE_NETS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("fc00::/7"),
)


def is_private_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if addr.is_loopback or addr.is_link_local or addr.is_unspecified or addr.is_multicast:
        return True
    return any(addr in net for net in _PRIVATE_NETS)


def is_internal_ip(ip: str, in_networks: InNetworks | None = None) -> bool:
    """Private / non-global, or inside one of the configured networks."""
    return is_private_ip(ip) or bool(in_networks and in_networks(ip))


def networks_matcher(networks: Iterable[AddressSet]) -> InNetworks:
    nets = [n for n in networks if n]

    def match(ip: str) -> bool:
        return any(ip in n for n in nets)

    return match


def classify_exposure(internal_ips: Iterable[str], public_ips: Iterable[str]) -> str:
    i, p = bool(list(internal_ips)), bool(list(public_ips))
    if i and p:
        return EXPOSURE_BOTH
    if p:
        return EXPOSURE_EXTERNAL
    if i:
        return EXPOSURE_INTERNAL
    return EXPOSURE_UNRESOLVED


def is_wildcard_match(ips: Iterable[str], wildcard_ips: Iterable[str]) -> bool:
    got, wc = set(ips), set(wildcard_ips)
    return bool(got) and bool(wc) and got <= wc


def wildcard_marked(internal_ips: Iterable[str], public_ips: Iterable[str],
                    wildcard: dict[str, list[str]] | None) -> bool:
    """True when every resolving view of the name answers exactly like that view's wildcard."""
    wildcard = wildcard or {}
    views = [(list(internal_ips), wildcard.get("internal") or []), (list(public_ips), wildcard.get("public") or [])]
    resolving = [(ips, wc) for ips, wc in views if ips]
    return bool(resolving) and all(is_wildcard_match(ips, wc) for ips, wc in resolving)


def compute_flags(sources: Iterable[str], exposure: str, internal_ips: Iterable[str], public_ips: Iterable[str],
                  in_networks: InNetworks | None = None) -> list[str]:
    srcs = set(sources)
    internal_ips, public_ips = list(internal_ips), list(public_ips)
    flags: list[str] = []
    private_public = any(is_private_ip(ip) for ip in public_ips)
    network_public = bool(in_networks) and any(not is_private_ip(ip) and in_networks(ip) for ip in public_ips)
    if private_public:
        flags.append(FLAG_PRIVATE_IP_PUBLIC)
    if network_public:
        flags.append(FLAG_INTERNAL_IP_PUBLIC)
    if srcs == {SOURCE_AXFR}:
        flags.append(FLAG_INTERNAL_AUTHORIZED)
    if SOURCE_AXFR in srcs and (SOURCE_PASSIVE in srcs or public_ips):
        internal_only = exposure == EXPOSURE_INTERNAL and any(is_internal_ip(ip, in_networks) for ip in internal_ips)
        if private_public or network_public or internal_only:
            flags.append(FLAG_INTERNAL_NAME_EXPOSED)
    return flags


def exposed_publicly(flags: Iterable[str]) -> bool:
    """The critical condition: an internal name / address is visible from the outside."""
    f = set(flags)
    return FLAG_INTERNAL_NAME_EXPOSED in f or FLAG_PRIVATE_IP_PUBLIC in f or FLAG_INTERNAL_IP_PUBLIC in f


def hosting_entry(ip: str, *, in_networks: InNetworks, network_name: str | None = None,
                  device: dict | None = None, asn: int | None = None, as_org: str | None = None) -> dict:
    """Where one address lives: inside a configured network (linked device), a private range we do not
    manage, or external (ASN / provider when the local geo database knows it)."""
    if in_networks(ip):
        kind = "network"
    elif is_private_ip(ip):
        kind = "private"
    else:
        kind = "external"
    out = {"ip": ip, "kind": kind, "network": network_name, "device_uuid": None, "device_label": None,
           "asn": asn, "as_org": as_org}
    if device:
        out["device_uuid"] = device.get("uuid")
        out["device_label"] = device.get("label")
    return out


def records_summary(internal: dict | None, public: dict | None) -> str:
    """Short text for tables: 'A 2 · AAAA 1 · CNAME' (union of both views)."""
    parts = []
    for key, label in (("a", "A"), ("aaaa", "AAAA"), ("cname", "CNAME")):
        vals = set((internal or {}).get(key) or []) | set((public or {}).get(key) or [])
        if vals:
            parts.append(label if key == "cname" else f"{label} {len(vals)}")
    return " · ".join(parts) or "-"
