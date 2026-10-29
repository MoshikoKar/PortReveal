"""Manual lookup of one host name inside a configured domain: resolve now against the domain's
internal and public resolvers, classify, show hosting; optionally add it to the inventory."""
from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from ...db import utcnow
from ...models import (
    SCAN_COMPLETED,
    SCAN_PARTIAL,
    SOURCE_MANUAL,
    SUBDOMAIN_ACTIVE,
    Domain,
    DomainScan,
    Subdomain,
)
from ...settings_store import DomainDiscoverySettings, get_section
from .classify import classify_exposure, compute_flags, wildcard_marked
from .dnsops import DnsClient
from .inventory import load_context
from .mock import MockDns
from .runner import DEFAULT_PUBLIC_RESOLVERS
from .validate import DomainError, in_domain, normalize_hostname


def find_domain(db: Session, name: str) -> Domain:
    """The configured domain `name` belongs to (most specific match). DomainError when none."""
    best: Domain | None = None
    for d in db.scalars(select(Domain)).all():
        if in_domain(name, d.name) and (best is None or len(d.name) > len(best.name)):
            best = d
    if best is None:
        raise DomainError(f"{name} is not inside any configured domain")
    return best


def make_dns(domain: Domain, public: list[str], cfg: DomainDiscoverySettings):
    """Real resolver client, or the simulated one in mock scanner mode (no DNS traffic)."""
    from ...scanner import scanner_status

    if scanner_status().effective_mode == "mock":
        return MockDns(domain.name, public, advanced=True)
    return DnsClient(timeout=cfg.dns_timeout_seconds)


def lookup_host(db: Session, raw: str, dns: DnsClient | None = None) -> dict:
    name = normalize_hostname(raw, allow_underscore=True)
    domain = find_domain(db, name)
    cfg = get_section(db, DomainDiscoverySettings)
    public_ns = list(domain.public_resolvers or []) or list(DEFAULT_PUBLIC_RESOLVERS)
    dns = dns or make_dns(domain, public_ns, cfg)
    internal = dns.resolve(name, list(domain.internal_resolvers or []) or None)
    public = dns.resolve(name, public_ns)
    last = db.scalar(select(DomainScan).where(DomainScan.domain_id == domain.id,
                                              DomainScan.status.in_((SCAN_COMPLETED, SCAN_PARTIAL)))
                     .order_by(DomainScan.id.desc()).limit(1))
    row = db.scalar(select(Subdomain).where(Subdomain.domain_id == domain.id, Subdomain.name == name))
    ips = sorted(set(internal.ips) | set(public.ips))
    inv = load_context(db, ips)
    sources = sorted(set((row.sources if row else None) or []) | {SOURCE_MANUAL})
    exposure = classify_exposure(internal.ips, public.ips)
    return {
        "hostname": name,
        "domain_id": domain.id,
        "domain": domain.name,
        "internal": internal.as_dict(),
        "public": public.as_dict(),
        "ips": ips,
        "exposure": exposure,
        "wildcard": wildcard_marked(internal.ips, public.ips, last.wildcard if last else None),
        "flags": compute_flags(sources, exposure, internal.ips, public.ips, inv.in_networks),
        "hosting": inv.hosting(ips),
        "in_inventory": row is not None and row.status == SUBDOMAIN_ACTIVE,
    }


def add_to_inventory(db: Session, result: dict) -> Subdomain:
    """Store a lookup result as an inventory row (source: manual). Kept until a scan finds it gone."""
    now = utcnow()
    row = db.scalar(select(Subdomain).where(Subdomain.domain_id == result["domain_id"],
                                            Subdomain.name == result["hostname"]))
    if row is None:
        row = Subdomain(domain_id=result["domain_id"], name=result["hostname"], first_seen=now)
        db.add(row)
    inv = load_context(db, result["ips"])
    row.sources = sorted(set(row.sources or []) | {SOURCE_MANUAL})
    row.exposure = result["exposure"]
    row.records = {"internal": result["internal"], "public": result["public"]}
    row.ips = result["ips"]
    row.wildcard = bool(result["wildcard"])
    row.flags = result["flags"]
    row.hosting = result["hosting"]
    row.device_id = inv.device_id(result["ips"])
    row.status = SUBDOMAIN_ACTIVE
    row.missed_scans, row.unverified, row.in_progress = 0, False, False
    if result["ips"]:
        row.last_seen = now
    db.flush()
    return row
