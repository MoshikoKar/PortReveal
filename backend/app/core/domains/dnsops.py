"""In-process DNS with dnspython: dual-resolver lookups, AXFR, NS discovery, wildcard probes.

All queries of one job share a RateLimiter so internal DNS servers are never flooded. The
`DnsClient` interface is small on purpose: tests replace it with a fake (no real network).
"""
from __future__ import annotations

import secrets
import threading
import time
from dataclasses import dataclass, field

import dns.exception
import dns.query
import dns.rdatatype
import dns.resolver
import dns.xfr
import dns.zone

from ...scanner.types import ScanContext

STATUS_OK = "ok"
STATUS_NXDOMAIN = "nxdomain"
STATUS_NODATA = "nodata"
STATUS_TIMEOUT = "timeout"
STATUS_ERROR = "error"
# The view could not be checked: the name's state there is unknown (not "does not exist").
UNCHECKED_STATUSES = (STATUS_TIMEOUT, STATUS_ERROR)


@dataclass
class Answer:
    """A/AAAA/CNAME answer for one name from one resolver view."""

    a: list[str] = field(default_factory=list)
    aaaa: list[str] = field(default_factory=list)
    cname: list[str] = field(default_factory=list)
    status: str = STATUS_NODATA

    @property
    def ips(self) -> list[str]:
        return sorted(set(self.a) | set(self.aaaa))

    @property
    def resolved(self) -> bool:
        return bool(self.a or self.aaaa)

    @property
    def checked(self) -> bool:
        return self.status not in UNCHECKED_STATUSES

    def as_dict(self) -> dict:
        return {"a": sorted(set(self.a)), "aaaa": sorted(set(self.aaaa)), "cname": list(dict.fromkeys(self.cname)),
                "status": self.status}


@dataclass
class ZoneRecord:
    name: str
    rdtype: str  # A | AAAA | CNAME
    value: str


class AxfrRefused(Exception):
    """The server refused the transfer, timed out, or answered without a usable zone."""


class RateLimiter:
    """Token bucket shared by every query of one job (thread-safe, cancel-aware)."""

    def __init__(self, per_second: float, ctx: ScanContext | None = None):
        self.per_second = max(0.1, float(per_second))
        self.ctx = ctx
        self._lock = threading.Lock()
        self._next = time.monotonic()

    def acquire(self) -> None:
        with self._lock:
            now = time.monotonic()
            wait = self._next - now
            self._next = max(now, self._next) + 1.0 / self.per_second
        if wait > 0:
            if self.ctx is not None:
                if self.ctx.cancel_event.wait(wait):
                    self.ctx.check_cancelled()
            else:
                time.sleep(wait)


def random_label() -> str:
    """Label for wildcard probes: random enough never to exist."""
    return f"nf-wc-{secrets.token_hex(8)}"


class DnsClient:
    """dnspython-backed resolver used by domain scans and manual lookups."""

    def __init__(self, timeout: float = 3.0, limiter: RateLimiter | None = None):
        self.timeout = timeout
        self.limiter = limiter
        self._resolvers: dict[tuple[str, ...], dns.resolver.Resolver] = {}
        self._lock = threading.Lock()
        self.queries = 0  # sent so far (progress: queries per second)

    def _resolver(self, nameservers: list[str] | None) -> dns.resolver.Resolver:
        key = tuple(nameservers or ())
        with self._lock:
            r = self._resolvers.get(key)
            if r is None:
                r = dns.resolver.Resolver(configure=not nameservers)
                if nameservers:
                    r.nameservers = list(nameservers)
                r.timeout = self.timeout
                r.lifetime = self.timeout * 2
                r.cache = None
                self._resolvers[key] = r
        return r

    def system_nameservers(self) -> list[str]:
        try:
            return [str(ns) for ns in self._resolver(None).nameservers]
        except Exception:
            return []

    def _query(self, name: str, rdtype: str, nameservers: list[str] | None):
        if self.limiter is not None:
            self.limiter.acquire()
        self.queries += 1
        return self._resolver(nameservers).resolve(name, rdtype, raise_on_no_answer=False, search=False)

    def resolve(self, name: str, nameservers: list[str] | None) -> Answer:
        ans = Answer()
        statuses: list[str] = []
        for rdtype in ("A", "AAAA"):
            try:
                res = self._query(name, rdtype, nameservers)
            except dns.resolver.NXDOMAIN:
                statuses.append(STATUS_NXDOMAIN)
                break  # the name does not exist: no point asking for AAAA
            except dns.exception.Timeout:
                statuses.append(STATUS_TIMEOUT)
                continue
            except dns.exception.DNSException:
                statuses.append(STATUS_ERROR)
                continue
            statuses.append(STATUS_OK)
            for rrset in res.response.answer:
                if rrset.rdtype == dns.rdatatype.CNAME:
                    ans.cname.extend(r.target.to_text().rstrip(".").lower() for r in rrset)
                elif rrset.rdtype == dns.rdatatype.A and rdtype == "A":
                    ans.a.extend(r.address for r in rrset)
                elif rrset.rdtype == dns.rdatatype.AAAA and rdtype == "AAAA":
                    ans.aaaa.extend(r.address for r in rrset)
        # A lookup that failed for one record type is not proof that the name has no address.
        if ans.resolved:
            ans.status = STATUS_OK
        elif STATUS_NXDOMAIN in statuses:
            ans.status = STATUS_NXDOMAIN
        elif STATUS_TIMEOUT in statuses:
            ans.status = STATUS_TIMEOUT
        elif STATUS_ERROR in statuses:
            ans.status = STATUS_ERROR
        else:
            ans.status = STATUS_NODATA
        return ans

    def nameservers(self, domain: str, resolvers: list[str] | None) -> dict[str, list[str]]:
        """Authoritative NS host names of `domain` (as the given resolvers see them) and their IPs."""
        try:
            res = self._query(domain, "NS", resolvers)
        except dns.exception.DNSException:
            return {}
        out: dict[str, list[str]] = {}
        for rrset in res.response.answer:
            if rrset.rdtype != dns.rdatatype.NS:
                continue
            for r in rrset:
                host = r.target.to_text().rstrip(".").lower()
                out[host] = self.resolve(host, resolvers).ips
        return out

    def axfr(self, zone: str, server: str, timeout: float) -> list[ZoneRecord]:
        """Full zone transfer from `server` (IP). A/AAAA/CNAME owners only."""
        if self.limiter is not None:
            self.limiter.acquire()
        self.queries += 1
        try:
            z = dns.zone.from_xfr(dns.query.xfr(server, zone, timeout=timeout, lifetime=timeout * 2),
                                  relativize=False)
        except (dns.xfr.TransferError, dns.exception.DNSException, EOFError, OSError, ValueError) as exc:
            raise AxfrRefused(type(exc).__name__) from exc
        out: list[ZoneRecord] = []
        for name, node in z.nodes.items():
            fqdn = name.to_text().rstrip(".").lower()
            for rdataset in node.rdatasets:
                if rdataset.rdtype == dns.rdatatype.A:
                    out.extend(ZoneRecord(fqdn, "A", r.address) for r in rdataset)
                elif rdataset.rdtype == dns.rdatatype.AAAA:
                    out.extend(ZoneRecord(fqdn, "AAAA", r.address) for r in rdataset)
                elif rdataset.rdtype == dns.rdatatype.CNAME:
                    out.extend(ZoneRecord(fqdn, "CNAME", r.target.to_text().rstrip(".").lower()) for r in rdataset)
        if not out and not z.nodes:
            raise AxfrRefused("empty zone")
        return out
