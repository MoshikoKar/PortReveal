"""Snapshot diff between two domain scans -> change events with severity.

Severity follows exposure. "high" is the critical tier (delivered immediately, see core/channels.py):
  * an internal name / private address visible publicly (internal_name_exposed event),
  * a zone transfer open to the scan host on a public authoritative server,
  * a new external subdomain whose public answer points inside a configured network,
  * an exposure change from internal to external / both.
Everything else is "normal" (low / medium / info) and goes to the recipient group's digest.

The first scan of a domain is its baseline: only the critical conditions are reported, not every
name as "new".
"""
from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field

from ...models import (
    EV_INTERNAL_NAME_EXPOSED,
    EV_SUBDOMAIN_EXPOSURE_CHANGED,
    EV_SUBDOMAIN_GONE,
    EV_SUBDOMAIN_IP_CHANGED,
    EV_SUBDOMAIN_NEW,
    EV_WILDCARD_DETECTED,
    EV_WILDCARD_REMOVED,
    EV_ZONE_TRANSFER_OPEN,
    EVENT_SEVERITY,
    EXPOSURE_BOTH,
    EXPOSURE_EXTERNAL,
    EXPOSURE_INTERNAL,
)
from .classify import InNetworks, exposed_publicly

CRITICAL = "high"


@dataclass(frozen=True)
class Snap:
    name: str
    exposure: str
    ips: frozenset[str] = frozenset()
    public_ips: frozenset[str] = frozenset()
    wildcard: bool = False
    flags: frozenset[str] = frozenset()


@dataclass
class Change:
    event_type: str
    hostname: str | None
    message: str
    severity: str
    old_value: str | None = None
    new_value: str | None = None
    ip: str | None = None
    extra: dict = field(default_factory=dict)


def _ips(v: Iterable[str]) -> str:
    return ", ".join(sorted(v)) or "-"


def _first_ip(v: Iterable[str]) -> str | None:
    ips = sorted(v)
    return ips[0] if ips else None


def new_subdomain_severity(s: Snap, in_networks: InNetworks) -> str:
    if s.exposure in (EXPOSURE_EXTERNAL, EXPOSURE_BOTH) and any(in_networks(ip) for ip in s.public_ips):
        return CRITICAL
    return EVENT_SEVERITY[EV_SUBDOMAIN_NEW]


def exposure_change_severity(old: str, new: str) -> str:
    if old == EXPOSURE_INTERNAL and new in (EXPOSURE_EXTERNAL, EXPOSURE_BOTH):
        return CRITICAL
    return EVENT_SEVERITY[EV_SUBDOMAIN_EXPOSURE_CHANGED]


def diff_snapshots(prev: dict[str, Snap] | None, cur: dict[str, Snap], in_networks: InNetworks) -> list[Change]:
    """Per-name changes for the names this scan verified (`cur`). `prev` None = baseline scan
    (critical conditions only). Names missing from `cur` produce nothing here: "gone" needs two
    consecutive complete scans (gone_change), and names a scan could not check are simply absent."""
    out: list[Change] = []
    baseline = prev is None
    prev = prev or {}
    for name in sorted(cur):
        s = cur[name]
        p = prev.get(name)
        newly_exposed = exposed_publicly(s.flags) and (p is None or not exposed_publicly(p.flags))
        if newly_exposed:
            out.append(Change(
                EV_INTERNAL_NAME_EXPOSED, name,
                f"{name}: internal name or address visible publicly ({_ips(s.public_ips or s.ips)})",
                CRITICAL, new_value=_ips(s.public_ips or s.ips), ip=_first_ip(s.public_ips or s.ips),
            ))
        if baseline:
            continue
        if p is None:
            sev = new_subdomain_severity(s, in_networks)
            out.append(Change(
                EV_SUBDOMAIN_NEW, name, f"New subdomain {name} ({s.exposure}, {_ips(s.ips)})", sev,
                new_value=f"{s.exposure}: {_ips(s.ips)}", ip=_first_ip(s.public_ips or s.ips),
            ))
            continue
        if p.exposure != s.exposure:
            out.append(Change(
                EV_SUBDOMAIN_EXPOSURE_CHANGED, name, f"{name}: exposure {p.exposure} -> {s.exposure}",
                exposure_change_severity(p.exposure, s.exposure), old_value=p.exposure, new_value=s.exposure,
                ip=_first_ip(s.public_ips or s.ips),
            ))
        if p.ips and s.ips and p.ips != s.ips:
            out.append(Change(
                EV_SUBDOMAIN_IP_CHANGED, name, f"{name}: addresses {_ips(p.ips)} -> {_ips(s.ips)}",
                EVENT_SEVERITY[EV_SUBDOMAIN_IP_CHANGED], old_value=_ips(p.ips), new_value=_ips(s.ips),
                ip=_first_ip(s.ips),
            ))
    return out


def gone_change(name: str, exposure: str, ips) -> Change:
    """A name missed by two consecutive complete scans (decided in runner.persist, never by one scan)."""
    return Change(EV_SUBDOMAIN_GONE, name, f"Subdomain {name} no longer resolves", EVENT_SEVERITY[EV_SUBDOMAIN_GONE],
                  old_value=f"{exposure}: {_ips(ips)}", ip=_first_ip(ips))


def wildcard_changes(domain: str, prev: dict | None, cur: dict | None) -> list[Change]:
    """Wildcard detected / removed per resolver view (internal, public)."""
    out: list[Change] = []
    prev, cur = prev or {}, cur or {}
    for view in ("internal", "public"):
        was, now = sorted(prev.get(view) or []), sorted(cur.get(view) or [])
        if now and not was:
            out.append(Change(EV_WILDCARD_DETECTED, f"*.{domain}",
                              f"Wildcard DNS detected for *.{domain} ({view} resolvers: {_ips(now)})",
                              EVENT_SEVERITY[EV_WILDCARD_DETECTED], new_value=f"{view}: {_ips(now)}"))
        elif was and not now:
            out.append(Change(EV_WILDCARD_REMOVED, f"*.{domain}",
                              f"Wildcard DNS removed for *.{domain} ({view} resolvers)",
                              EVENT_SEVERITY[EV_WILDCARD_REMOVED], old_value=f"{view}: {_ips(was)}"))
    return out


def zone_transfer_changes(domain: str, prev_open: Iterable[str], cur_open: Iterable[str]) -> list[Change]:
    """A public authoritative server newly allowing AXFR to the scan host."""
    newly = sorted(set(cur_open) - set(prev_open))
    if not newly:
        return []
    return [Change(EV_ZONE_TRANSFER_OPEN, domain,
                   f"Zone transfer open: {', '.join(newly)} answered AXFR for {domain} from the scan host",
                   CRITICAL, new_value=", ".join(newly))]
