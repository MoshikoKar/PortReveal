"""One domain scan, in phases (core/domains/progress.py):
passive (subfinder) -> wordlist (dnsx, internal then public resolvers, in batches) -> authorized AXFR ->
public AXFR check -> resolve & classify (both views) -> diff & events -> port-scan queueing.

Network work runs without a long-lived database session. Discovered names are written to the
inventory as they are found (marked in progress) so the domain page updates while the scan runs;
classification, snapshot, events and "gone" are settled in one short transaction at the end.

A source that errors or times out makes the scan partial. A partial scan never moves a name towards
"gone" and never reports changes for names it could not check; a name is gone only after two
consecutive complete scans miss it. Cancelling keeps what was found so far (partial).
"""
from __future__ import annotations

import ipaddress
import logging
import time
from dataclasses import dataclass, field

from sqlalchemy import select

from ...db import session_scope, utcnow
from ...models import (
    EXPOSURE_UNRESOLVED,
    EXPOSURES,
    INTERNAL_ERROR,
    SCAN_COMPLETED,
    SCAN_FAILED,
    SCAN_PARTIAL,
    SCAN_QUEUED,
    SCAN_RUNNING,
    SOURCE_AXFR,
    SOURCE_MANUAL,
    SOURCE_PASSIVE,
    SOURCE_WORDLIST,
    SUBDOMAIN_ACTIVE,
    SUBDOMAIN_GONE,
    WORDLIST_MODE_CUSTOM,
    WORDLIST_MODE_LIBRARY,
    Domain,
    DomainScan,
    Event,
    Subdomain,
    SubdomainObservation,
    Wordlist,
)
from ...netutils import AddressSet
from ...scanner.types import ScanCancelled, ScanContext
from ...settings_store import DomainDiscoverySettings, get_section
from . import tools
from .classify import classify_exposure, compute_flags, is_private_ip, wildcard_marked
from .diff import Snap, diff_snapshots, gone_change, wildcard_changes, zone_transfer_changes
from .dnsops import Answer, AxfrRefused, DnsClient, RateLimiter, random_label
from .inventory import InventoryContext, load_context
from .mock import MOCK_NOTE, MockDns, mock_passive
from .progress import DONE, FAILED, QUERIES_PER_CANDIDATE, Progress
from .providers import provider_keys, write_provider_config
from .validate import candidates, discovered_name

log = logging.getLogger(__name__)

DEFAULT_PUBLIC_RESOLVERS = ["1.1.1.1", "8.8.8.8"]
MAX_PUBLIC_NS_PROBES = 8  # authoritative server addresses tried for the open-AXFR check
GONE_AFTER_MISSES = 2  # consecutive complete scans that must miss a name before it is "gone"


@dataclass
class Plan:
    """Everything a run needs from the database, captured before any network work."""

    scan_id: int
    domain_id: int
    domain: str
    passive: bool
    words: list[str]
    axfr_enabled: bool
    axfr_servers: list[str]
    internal_resolvers: list[str]  # empty = system resolver
    public_resolvers: list[str]
    known: dict[str, list[str]]  # active inventory names -> sources
    known_ips: set[str]
    prev: dict[str, Snap] | None  # verified inventory state before the scan; None = baseline
    prev_wildcard: dict | None
    prev_open_axfr: list[str]
    started_at: object = None  # datetime the scan started (rows created after it belong to this scan)
    simulate: bool = False  # mock scanner mode: core/domains/mock.py answers, nothing is sent


@dataclass
class Outcome:
    sources: dict[str, set[str]] = field(default_factory=dict)  # name -> sources found this run
    answers: dict[str, tuple[Answer, Answer]] = field(default_factory=dict)  # name -> (internal, public)
    wildcard: dict[str, list[str]] = field(default_factory=lambda: {"internal": [], "public": []})
    wildcard_checked: dict[str, bool] = field(default_factory=lambda: {"internal": True, "public": True})
    axfr: dict[str, dict] = field(default_factory=lambda: {"authorized": {}, "public": {}})
    open_axfr: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    partial_reasons: list[str] = field(default_factory=list)
    counters: dict[str, int] = field(default_factory=dict)
    cancelled: bool = False

    @property
    def partial(self) -> bool:
        return bool(self.partial_reasons) or self.cancelled

    def make_partial(self, reason: str) -> None:
        if reason not in self.partial_reasons:
            self.partial_reasons.append(reason)

    def add(self, name: str, source: str) -> bool:
        """Record a discovery; True when the name is new to this run."""
        new = name not in self.sources
        self.sources.setdefault(name, set()).add(source)
        return new


def _finish(scan_id: int, status: str, *, error: str | None = None, notes: list[str] | None = None,
            progress: Progress | None = None) -> None:
    with session_scope() as db:
        job = db.get(DomainScan, scan_id)
        if job is None:
            return
        if progress is not None:
            job.phases = progress.snapshot()
        job.status = status
        job.finished_at = utcnow()
        job.stage = None
        if status in (SCAN_COMPLETED, SCAN_PARTIAL):
            job.progress = 1.0
        if error:
            job.error = error
        if notes:
            job.notes = "\n".join(dict.fromkeys(notes))


# --- plan ---------------------------------------------------------------------------------------
def _read_words(db, domain: Domain, limit: int) -> list[str]:
    if domain.wordlist_mode == WORDLIST_MODE_CUSTOM:
        return list(domain.custom_words or [])[:limit]
    if domain.wordlist_mode == WORDLIST_MODE_LIBRARY and domain.wordlist_id:
        w = db.get(Wordlist, domain.wordlist_id)
        if w is None:
            return []
        from ..wordlists import WordlistError, stored_path

        words: list[str] = []
        try:
            with open(stored_path(w.storage_name), encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        words.append(line)
                        if len(words) >= limit:
                            break
        except (OSError, WordlistError):
            log.warning("domain scan: wordlist %s could not be read", w.id)
        return words
    return []


def _snap(name: str, exposure: str, records: dict | None, ips: list | None, wildcard: bool,
          flags: list | None) -> Snap:
    public = set(((records or {}).get("public") or {}).get("a") or []) | set(
        ((records or {}).get("public") or {}).get("aaaa") or [])
    return Snap(name, exposure, frozenset(ips or []), frozenset(public), bool(wildcard), frozenset(flags or []))


def build_plan(db, job: DomainScan, domain: Domain, cfg: DomainDiscoverySettings) -> Plan:
    rows = db.scalars(select(Subdomain).where(Subdomain.domain_id == domain.id)).all()
    known = {s.name: list(s.sources or []) for s in rows if s.status == SUBDOMAIN_ACTIVE}
    known_ips = {ip for s in rows for ip in (s.ips or [])}
    prev_job = db.scalar(
        select(DomainScan).where(DomainScan.domain_id == domain.id, DomainScan.id != job.id,
                                 DomainScan.status.in_((SCAN_COMPLETED, SCAN_PARTIAL)))
        .order_by(DomainScan.id.desc()).limit(1)
    )
    prev = None
    prev_open: list[str] = []
    if prev_job is not None:
        # Diff base: what the inventory last verified (not the previous snapshot only), so a name one
        # scan could not check is neither "gone" then nor "new" when it is checked again.
        prev = {s.name: _snap(s.name, s.exposure, s.records, s.ips, s.wildcard, s.flags)
                for s in rows if s.status == SUBDOMAIN_ACTIVE and s.last_scan_id is not None}
        prev_open = [k for k, v in ((prev_job.axfr or {}).get("public") or {}).items() if v.get("status") == "open"]
    return Plan(
        scan_id=job.id, domain_id=domain.id, domain=domain.name, passive=bool(domain.passive_enabled),
        words=_read_words(db, domain, cfg.max_wordlist_entries), axfr_enabled=bool(domain.axfr_enabled),
        axfr_servers=list(domain.axfr_servers or []), internal_resolvers=list(domain.internal_resolvers or []),
        public_resolvers=list(domain.public_resolvers or []) or list(DEFAULT_PUBLIC_RESOLVERS),
        known=known, known_ips=known_ips, prev=prev,
        prev_wildcard=prev_job.wildcard if prev_job is not None else None, prev_open_axfr=prev_open,
    )


# --- live inventory writes ---------------------------------------------------------------------
def write_discovered(plan: Plan, names: list[str], source: str) -> None:
    """Insert names found by a source that the inventory does not have yet (in progress, unclassified)."""
    if not names:
        return
    now = utcnow()
    with session_scope() as db:
        have = set(db.scalars(select(Subdomain.name).where(Subdomain.domain_id == plan.domain_id,
                                                           Subdomain.name.in_(names))))
        for name in names:
            if name not in have:
                db.add(Subdomain(domain_id=plan.domain_id, name=name, exposure=EXPOSURE_UNRESOLVED, sources=[source],
                                 status=SUBDOMAIN_ACTIVE, in_progress=True, first_seen=now, last_seen=now))


def write_resolved(plan: Plan, batch: dict[str, tuple[Answer, Answer]], wildcard: dict) -> None:
    """Provisional exposure / records for names just resolved (counters and table update live)."""
    checked = {n: a for n, a in batch.items() if a[0].checked and a[1].checked and (a[0].resolved or a[1].resolved)}
    if not checked:
        return
    with session_scope() as db:
        rows = {s.name: s for s in db.scalars(select(Subdomain).where(Subdomain.domain_id == plan.domain_id,
                                                                     Subdomain.name.in_(list(checked))))}
        for name, (ri, rp) in checked.items():
            row = rows.get(name)
            if row is None or row.status != SUBDOMAIN_ACTIVE:
                continue
            row.exposure = classify_exposure(ri.ips, rp.ips)
            row.records = {"internal": ri.as_dict(), "public": rp.as_dict()}
            row.ips = sorted(set(ri.ips) | set(rp.ips))
            row.wildcard = wildcard_marked(ri.ips, rp.ips, wildcard)
            row.in_progress = True


def release_in_progress(domain_id: int, started_at) -> None:
    """After a crash / restart: drop rows a run created but never classified, clear the flag elsewhere."""
    with session_scope() as db:
        for row in db.scalars(select(Subdomain).where(Subdomain.domain_id == domain_id,
                                                      Subdomain.in_progress.is_(True))).all():
            if row.last_scan_id is None and started_at is not None and row.first_seen >= started_at:
                db.delete(row)
            else:
                row.in_progress = False


# --- tools --------------------------------------------------------------------------------------
def run_subfinder(domain: str, cfg: DomainDiscoverySettings, ctx: ScanContext, tmp: tools.TempInputs,
                  out: Outcome, pg: Progress) -> list[str]:
    exe = tools.resolve_tool("subfinder")
    if exe is None:
        pg.skip("passive", "subfinder not installed")
        out.notes.append("subfinder is not installed: passive enumeration skipped (see System health).")
        return []
    pg.start("passive", unit="names")
    domains_file = tmp.write_lines("domains.txt", [domain])
    provider_config = write_provider_config(tmp.path, provider_keys(cfg))
    try:
        cmd = tools.build_subfinder_cmd(exe, domains_file, provider_config=provider_config,
                                        max_minutes=cfg.subfinder_timeout_minutes)
        res = tools.run_jsonl_tool(cmd, ctx, timeout_s=cfg.subfinder_timeout_minutes * 60 + 30)
    finally:
        if provider_config is not None:
            provider_config.unlink(missing_ok=True)  # keys never outlive the run
    if res.bad_lines:
        out.notes.append(f"subfinder: {res.bad_lines} malformed output line(s) ignored.")
    names = sorted({n for n in (discovered_name(r.get("host"), domain) for r in res.records) if n})
    out.counters["passive_raw"] = len(res.records)
    pg.update("passive", found=len(names))
    if res.timed_out:
        reason = f"timed out after {cfg.subfinder_timeout_minutes} min"
        pg.finish("passive", FAILED, reason)
        out.make_partial(f"Passive (subfinder) {reason}")
    elif res.returncode not in (0, None) and not res.records:
        reason = f"exit code {res.returncode}" + (f": {res.stderr_tail.strip()[-120:]}" if res.stderr_tail.strip() else "")
        pg.finish("passive", FAILED, reason)
        out.make_partial(f"Passive (subfinder) failed ({reason})")
    else:
        pg.finish("passive")
    return names


def batch_size(cfg: DomainDiscoverySettings) -> int:
    """Candidates per dnsx run: about three seconds of work at the configured rate (progress cadence)."""
    return max(50, min(5000, cfg.dns_rate_per_second * 3))


def run_dnsx(names: list[str], resolvers: list[str], label: str, cfg: DomainDiscoverySettings,
             ctx: ScanContext, tmp: tools.TempInputs, domain: str, out: Outcome,
             timeout_s: float | None = None, batch: int = 0) -> tuple[list[str], bool]:
    """One dnsx run over `names`. Returns (resolving names, timed out)."""
    exe = tools.resolve_tool("dnsx")
    if exe is None or not names or not resolvers:
        return [], False
    hosts = tmp.write_lines(f"candidates-{label}-{batch}.txt", names)
    res_file = tmp.path / f"resolvers-{label}.txt"
    if not res_file.exists():
        tmp.write_lines(res_file.name, resolvers)
    cmd = tools.build_dnsx_cmd(exe, hosts, res_file, rate_per_second=cfg.dns_rate_per_second)
    res = tools.run_jsonl_tool(cmd, ctx, timeout_s=timeout_s if timeout_s is not None else cfg.dnsx_timeout_minutes * 60)
    if res.bad_lines:
        out.counters["dnsx_bad_lines"] = out.counters.get("dnsx_bad_lines", 0) + res.bad_lines
    found = []
    for r in res.records:
        if not (r.get("a") or r.get("aaaa") or r.get("cname")):
            continue
        name = discovered_name(r.get("host"), domain)
        if name:
            found.append(name)
    return sorted(set(found)), res.timed_out


# --- execution ----------------------------------------------------------------------------------
def _probe_wildcard(dns: DnsClient, domain: str, resolvers: list[str] | None) -> tuple[list[str], bool]:
    """Two random labels: a wildcard answers both. Returns (union of their addresses, check succeeded)."""
    first = dns.resolve(f"{random_label()}.{domain}", resolvers)
    if not first.resolved:
        return [], first.checked
    second = dns.resolve(f"{random_label()}.{domain}", resolvers)
    return (sorted(set(first.ips) | set(second.ips)) if second.resolved else []), second.checked


def _axfr_names(records, domain: str) -> set[str]:
    return {n for n in (discovered_name(r.name, domain) for r in records) if n}


def _wordlist_phase(key: str, view: str, cands: list[str], resolvers: list[str] | list | None, plan: Plan,
                    cfg: DomainDiscoverySettings, ctx: ScanContext, dns, tmp: tools.TempInputs, out: Outcome,
                    pg: Progress) -> None:
    pg.start(key, total=len(cands), unit="candidates")
    budget_end = time.monotonic() + cfg.dnsx_timeout_minutes * 60
    found_names: set[str] = set()
    size = batch_size(cfg)
    for i in range(0, len(cands), size):
        ctx.check_cancelled()
        chunk = cands[i:i + size]
        remaining = budget_end - time.monotonic()
        if remaining <= 0:
            timed_out = True
            found = []
        elif plan.simulate:
            found = [n for n in chunk if dns.resolve(n, resolvers).resolved]
            timed_out = False
        else:
            found, timed_out = run_dnsx(chunk, list(resolvers or []), view, cfg, ctx, tmp, plan.domain, out,
                                        timeout_s=remaining, batch=i // size)
        fresh = [n for n in found if out.add(n, SOURCE_WORDLIST)]
        write_discovered(plan, fresh, SOURCE_WORDLIST)
        found_names.update(found)
        processed = min(len(cands), i + len(chunk))
        pg.update(key, processed=processed, found=len(found_names), queries=processed * QUERIES_PER_CANDIDATE)
        if timed_out:
            reason = f"timed out after {cfg.dnsx_timeout_minutes} min ({processed:,} of {len(cands):,} candidates)"
            pg.finish(key, FAILED, reason)
            out.make_partial(f"Wordlist ({view} resolvers) {reason}")
            return
    pg.finish(key)


def execute(plan: Plan, cfg: DomainDiscoverySettings, ctx: ScanContext, dns, out: Outcome, pg: Progress) -> None:
    deadline = time.monotonic() + cfg.max_job_minutes * 60
    internal = plan.internal_resolvers or None  # None = system resolver
    public = plan.public_resolvers
    domain = plan.domain

    wi, wi_ok = _probe_wildcard(dns, domain, internal)
    wp, wp_ok = _probe_wildcard(dns, domain, public)
    out.wildcard, out.wildcard_checked = {"internal": wi, "public": wp}, {"internal": wi_ok, "public": wp_ok}
    ctx.check_cancelled()

    with tools.TempInputs(f"domain-scan-{plan.scan_id}") as tmp:
        # Passive
        if not plan.passive:
            pg.skip("passive", "turned off for this domain")
        elif plan.simulate:
            pg.start("passive", unit="names")
            names = mock_passive(domain, advanced=plan.prev is not None)
            pg.update("passive", found=len(names))
            pg.finish("passive")
        else:
            names = run_subfinder(domain, cfg, ctx, tmp, out, pg)
        if plan.passive:
            fresh = [n for n in names if out.add(n, SOURCE_PASSIVE)]
            write_discovered(plan, fresh, SOURCE_PASSIVE)
        ctx.check_cancelled()

        # Wordlist (dnsx), internal then public resolvers
        cands = candidates(domain, plan.words, cfg.max_wordlist_entries) if plan.words else []
        out.counters["wordlist_candidates"] = len(cands)
        if not cands:
            for key in ("wordlist_internal", "wordlist_public"):
                pg.skip(key, "no wordlist selected")
        elif not plan.simulate and tools.resolve_tool("dnsx") is None:
            for key in ("wordlist_internal", "wordlist_public"):
                pg.skip(key, "dnsx not installed")
            out.notes.append("dnsx is not installed: wordlist brute force skipped (see System health).")
        else:
            internal_list = (internal if plan.simulate else (plan.internal_resolvers or dns.system_nameservers()))
            _wordlist_phase("wordlist_internal", "internal", cands, internal_list, plan, cfg, ctx, dns, tmp, out, pg)
            _wordlist_phase("wordlist_public", "public", cands, public, plan, cfg, ctx, dns, tmp, out, pg)
        if out.counters.get("dnsx_bad_lines"):
            out.notes.append(f"dnsx: {out.counters['dnsx_bad_lines']} malformed output line(s) ignored.")

    # Authorized zone transfer (ground truth)
    if not plan.axfr_enabled:
        pg.skip("axfr", "turned off for this domain")
    else:
        servers = plan.axfr_servers or plan.internal_resolvers or dns.system_nameservers()
        pg.start("axfr", total=len(servers), unit="servers")
        failed: list[str] = []
        found = 0
        for i, server in enumerate(servers):
            ctx.check_cancelled()
            try:
                recs = dns.axfr(domain, server, cfg.axfr_timeout_seconds)
            except AxfrRefused as exc:
                out.axfr["authorized"][server] = {"status": "refused", "detail": str(exc)[:100]}
                failed.append(server)
                pg.update("axfr", processed=i + 1)
                continue
            names = sorted(_axfr_names(recs, domain))
            out.axfr["authorized"][server] = {"status": "ok", "names": len(names)}
            found += len(names)
            write_discovered(plan, [n for n in names if out.add(n, SOURCE_AXFR)], SOURCE_AXFR)
            pg.update("axfr", processed=i + 1, found=found)
        if failed:
            reason = f"refused or failed on {', '.join(failed)}"
            pg.finish("axfr", FAILED, reason)
            out.make_partial(f"Zone transfer {reason}")
        else:
            pg.finish("axfr")

    # Attacker view: can the scan host transfer the zone from its public authoritative servers?
    pg.start("public_axfr", unit="servers")
    targets = [(h, ip) for h, ips in sorted(dns.nameservers(domain, public).items()) for ip in ips][:MAX_PUBLIC_NS_PROBES]
    pg.update("public_axfr", total=len(targets))
    for i, (host, ip) in enumerate(targets):
        ctx.check_cancelled()
        key = f"{host} ({ip})"
        try:
            recs = dns.axfr(domain, ip, cfg.axfr_timeout_seconds)
        except AxfrRefused:
            out.axfr["public"][key] = {"status": "refused"}
            pg.update("public_axfr", processed=i + 1)
            continue
        names = sorted(_axfr_names(recs, domain))
        out.axfr["public"][key] = {"status": "open", "names": len(names)}
        out.open_axfr.append(key)
        write_discovered(plan, [n for n in names if out.add(n, SOURCE_AXFR)], SOURCE_AXFR)
        pg.update("public_axfr", processed=i + 1, found=len(out.open_axfr))
    pg.finish("public_axfr", reason=None if targets else "no public name servers found")

    # Resolve & classify (both views), provisional rows written in batches
    names = sorted(set(out.sources) | set(plan.known))
    pg.start("resolve", total=len(names), unit="names")
    pending: dict[str, tuple[Answer, Answer]] = {}
    q0 = getattr(dns, "queries", None)
    for i, name in enumerate(names):
        ctx.check_cancelled()
        if time.monotonic() > deadline:
            reason = f"time limit ({cfg.max_job_minutes} min) reached after {i:,} of {len(names):,} names"
            write_resolved(plan, pending, out.wildcard)
            pg.finish("resolve", FAILED, reason)
            out.make_partial(f"Resolve {reason}")
            return
        out.answers[name] = pending[name] = (dns.resolve(name, internal), dns.resolve(name, public))
        if pg.due():
            write_resolved(plan, pending, out.wildcard)
            pending.clear()
            queries = (dns.queries - q0) if q0 is not None else (i + 1) * 4
            pg.update("resolve", processed=i + 1, found=sum(1 for a in out.answers.values() if a[0].resolved or a[1].resolved),
                      queries=queries, force=True)
    write_resolved(plan, pending, out.wildcard)
    errors = {view: sum(1 for a in out.answers.values() if not a[idx].checked) for idx, view in ((0, "internal"), (1, "public"))}
    out.counters["internal_resolver_errors"], out.counters["public_resolver_errors"] = errors["internal"], errors["public"]
    pg.update("resolve", processed=len(names),
              found=sum(1 for a in out.answers.values() if a[0].resolved or a[1].resolved),
              queries=(dns.queries - q0) if q0 is not None else len(names) * 4)
    bad = [f"{view} resolver: {n:,} name(s) timed out / failed" for view, n in errors.items() if n]
    if bad:
        reason = "; ".join(bad)
        pg.finish("resolve", DONE, reason)
        out.make_partial(f"Resolve: {reason} (left unverified)")
    else:
        pg.finish("resolve")


# --- persistence --------------------------------------------------------------------------------
def _ipv4(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).version == 4
    except ValueError:
        return False


def queue_port_scan(db, ips: list[str], inv: InventoryContext, scan_type: str, *, requested_by: str,
                    criteria: str) -> tuple[int | None, list[str], str | None]:
    """Port scan for addresses that belong to names inside a configured domain, in the normal scan
    queue (existing profiles and exclusions). Addresses inside configured networks and public ones are
    allowed; private addresses outside every configured network are not probed. IPv4 only (nmap
    profiles here are IPv4). Returns (scan id, queued addresses, reason when nothing was queued)."""
    from ...scanner import scanner_status
    from ..manager import create_scan
    from ..runner import exclusion_set

    candidates_ = sorted({ip for ip in ips if _ipv4(ip)}, key=lambda v: tuple(int(p) for p in v.split(".")))
    if not candidates_:
        return None, [], "no IPv4 addresses"
    excluded = exclusion_set(db)
    allowed = [ip for ip in candidates_ if ip not in excluded and (inv.in_networks(ip) or not is_private_ip(ip))]
    if not allowed:
        return None, [], "all addresses are excluded or private outside the configured networks"
    if scanner_status().effective_mode == "unavailable":
        return None, [], "scanner unavailable"
    scan = create_scan(db, scan_type, targets=AddressSet.from_specs(allowed), requested_by=requested_by,
                       criteria=criteria)
    return scan.id, allowed, None


def persist(db, plan: Plan, out: Outcome, cfg: DomainDiscoverySettings, pg: Progress) -> tuple[list[int], int | None]:
    """Settle inventory, snapshot, events and stats. Returns (event ids, queued port-scan id)."""
    now = utcnow()
    job = db.get(DomainScan, plan.scan_id)
    domain = db.get(Domain, plan.domain_id)
    if job is None or domain is None:
        return [], None
    # This transaction writes the job itself: progress must not open a second writer meanwhile.
    pg.write = False
    pg.start("diff", total=len(out.answers), unit="names")
    all_ips = {ip for ri, rp in out.answers.values() for ip in (*ri.ips, *rp.ips)}
    inv = load_context(db, all_ips)
    rows = {s.name: s for s in db.scalars(select(Subdomain).where(Subdomain.domain_id == domain.id)).all()}
    cur: dict[str, Snap] = {}
    missing: list[str] = []  # checked on both views, resolves nowhere, not in a zone transfer
    unverified = 0
    exposure_counts = dict.fromkeys(EXPOSURES, 0)
    source_counts = {SOURCE_PASSIVE: 0, SOURCE_WORDLIST: 0, SOURCE_AXFR: 0}
    wildcard_count = 0
    for name, (ri, rp) in sorted(out.answers.items()):
        found_now = out.sources.get(name, set())
        row = rows.get(name)
        if row is not None and found_now:
            row.sources = sorted(set(row.sources or []) | found_now)
        if not (ri.checked and rp.checked):
            if row is not None:  # state kept as is; last_seen untouched
                row.unverified, row.in_progress = True, False
                unverified += 1
            continue
        exposure = classify_exposure(ri.ips, rp.ips)
        if exposure == EXPOSURE_UNRESOLVED and SOURCE_AXFR not in found_now:
            missing.append(name)
            continue
        sources = sorted(set(row.sources or []) | found_now) if row else sorted(found_now)
        ips = sorted(set(ri.ips) | set(rp.ips))
        wildcard = wildcard_marked(ri.ips, rp.ips, out.wildcard)
        flags = compute_flags(sources, exposure, ri.ips, rp.ips, inv.in_networks)
        records = {"internal": ri.as_dict(), "public": rp.as_dict()}
        if row is None:
            row = Subdomain(domain_id=domain.id, name=name, first_seen=now)
            db.add(row)
            rows[name] = row
        row.exposure, row.records, row.ips, row.sources = exposure, records, ips, sources
        row.wildcard, row.flags, row.hosting = wildcard, flags, inv.hosting(ips)
        row.device_id = inv.device_id(ips)
        row.status, row.last_seen, row.last_scan_id = SUBDOMAIN_ACTIVE, now, job.id
        row.missed_scans, row.unverified, row.in_progress = 0, False, False
        db.flush()
        db.add(SubdomainObservation(domain_scan_id=job.id, subdomain_id=row.id, name=name, exposure=exposure,
                                    records=records, ips=ips, sources=sources, wildcard=wildcard, flags=flags))
        cur[name] = Snap(name, exposure, frozenset(ips), frozenset(rp.ips), wildcard, frozenset(flags))
        exposure_counts[exposure] += 1
        wildcard_count += int(wildcard)
        for s in found_now:
            if s in source_counts:
                source_counts[s] += 1

    # Names the scan never got to (cancel / time limit): unverified, kept as they were.
    for name, row in rows.items():
        if row.status == SUBDOMAIN_ACTIVE and name not in out.answers and (row.in_progress or name in plan.known):
            row.unverified, row.in_progress = True, False
            unverified += 1

    gone_changes = []
    for name in missing:
        row = rows.get(name)
        if row is None:
            continue
        never_verified = row.last_scan_id is None and SOURCE_MANUAL not in (row.sources or [])
        if never_verified:
            db.delete(row)  # a passive / wordlist hit that never resolved: not inventory
            del rows[name]
            continue
        row.in_progress = False
        if out.partial:
            continue  # a partial scan never moves a name towards "gone"
        row.missed_scans = (row.missed_scans or 0) + 1
        row.unverified = False
        if row.missed_scans >= GONE_AFTER_MISSES and row.status == SUBDOMAIN_ACTIVE:
            row.status = SUBDOMAIN_GONE
            gone_changes.append(gone_change(name, row.exposure, row.ips or []))

    changes = diff_snapshots(plan.prev, cur, inv.in_networks) + gone_changes
    if plan.prev is not None:
        prev_wc = plan.prev_wildcard or {}
        # A view whose wildcard probe failed keeps its previous answer: no detected/removed noise.
        out.wildcard = {v: (out.wildcard[v] if out.wildcard_checked.get(v, True) else list(prev_wc.get(v) or []))
                        for v in ("internal", "public")}
        changes += wildcard_changes(domain.name, prev_wc, out.wildcard)
    changes += zone_transfer_changes(domain.name, plan.prev_open_axfr, out.open_axfr)
    events = []
    for c in changes:
        ev = Event(created_at=now, event_type=c.event_type, severity=c.severity, ip=c.ip, old_value=c.old_value,
                   new_value=c.new_value, message=c.message[:2000], notify=True, domain_id=domain.id,
                   domain_scan_id=job.id, hostname=(c.hostname or "")[:255] or None)
        db.add(ev)
        events.append(ev)
    db.flush()
    pg.update("diff", processed=len(out.answers), found=len(events))
    pg.finish("diff")

    port_scan_id = None
    new_ips = sorted({ip for name in cur for ip in cur[name].ips if ip not in plan.known_ips})
    queued: list[str] = []
    if out.cancelled:
        pg.skip("port_scan", "scan cancelled")
    elif not cfg.auto_port_scan:
        pg.skip("port_scan", "automatic port scans are off")
    elif not new_ips:
        pg.start("port_scan", total=0, unit="addresses")
        pg.finish("port_scan", reason="no new addresses")
    else:
        pg.start("port_scan", total=len(new_ips), unit="addresses")
        port_scan_id, queued, port_note = queue_port_scan(
            db, new_ips, inv, cfg.port_scan_type, requested_by=f"domain scan #{job.id}",
            criteria=f"New addresses from the domain scan of {domain.name}",
        )
        job.port_scan_id = port_scan_id
        pg.update("port_scan", found=len(queued))
        pg.finish("port_scan", reason=port_note)
        if port_note:
            out.notes.append(f"No port scan queued for new addresses: {port_note}.")

    for row in rows.values():
        row.in_progress = False
    new_names = 0 if plan.prev is None else len(set(cur) - set(plan.prev))
    job.wildcard = out.wildcard
    job.axfr = out.axfr
    phase = {p["key"]: p["status"] for p in pg.phases}
    job.phases = pg.snapshot()
    job.progress = max(job.progress or 0.0, pg.compute_percent())
    job.stats = {
        "total": len(cur), "new": new_names, "gone": len(gone_changes), "baseline": plan.prev is None,
        "changed": sum(1 for c in changes if c.event_type not in ("subdomain_new", "subdomain_gone")),
        **{f"exposure_{k}": v for k, v in exposure_counts.items()},
        "wildcard": wildcard_count, **{f"source_{k}": v for k, v in source_counts.items()},
        "unresolved_dropped": len(missing), "unverified": unverified, "events": len(events),
        "new_ips": len(new_ips), "port_scan_targets": len(queued), "zone_transfer_open": len(out.open_axfr),
        "partial_reasons": list(out.partial_reasons),
        # Did each source / resolver deliver? (fix: a partial scan never decides "gone")
        "checks": {
            "passive": phase.get("passive"),
            "internal_resolver": "errors" if out.counters.get("internal_resolver_errors") else "ok",
            "public_resolver": "errors" if out.counters.get("public_resolver_errors") else "ok",
            "axfr": phase.get("axfr"),
        },
        **{k: v for k, v in out.counters.items() if not k.endswith("-missing")},
    }
    return [e.id for e in events], port_scan_id


# --- entry point --------------------------------------------------------------------------------
def run_domain_scan(scan_id: int, ctx: ScanContext, dns: DnsClient | None = None,
                    progress_interval: float = 2.0) -> None:
    """Run one queued job. `dns` is injected by tests; otherwise the real client, or the simulated
    backend when the scanner runs in mock mode (no DNS traffic, no tools)."""
    from ...scanner import scanner_status

    simulate = dns is None and scanner_status().effective_mode == "mock"
    with session_scope() as db:
        job = db.get(DomainScan, scan_id)
        if job is None or job.status != SCAN_QUEUED:
            return
        domain = db.get(Domain, job.domain_id)
        cfg = get_section(db, DomainDiscoverySettings)
        if domain is None:
            job.status, job.finished_at, job.error = SCAN_FAILED, utcnow(), "domain no longer exists"
            return
        plan = build_plan(db, job, domain, cfg)
        plan.simulate = simulate
        job.status, job.started_at, job.stage, job.progress = SCAN_RUNNING, utcnow(), "starting", 0.0
        plan.started_at = job.started_at
    log.info("domain scan %s started for %s", scan_id, plan.domain)
    if simulate:
        dns = MockDns(plan.domain, plan.public_resolvers, advanced=plan.prev is not None)
    dns = dns or DnsClient(timeout=cfg.dns_timeout_seconds, limiter=RateLimiter(cfg.dns_rate_per_second, ctx))
    n_cands = len(candidates(plan.domain, plan.words, cfg.max_wordlist_entries)) if plan.words else 0
    pg = Progress(scan_id, interval=progress_interval, estimates={
        "wordlist_internal": n_cands, "wordlist_public": n_cands, "resolve": max(1, len(plan.known) + n_cands // 20)})
    out = Outcome()
    if simulate:
        out.notes.append(MOCK_NOTE)
    try:
        try:
            execute(plan, cfg, ctx, dns, out, pg)
        except ScanCancelled:
            # Keep what was found so far: settle it as a partial scan.
            cur = pg.current
            out.cancelled = True
            out.make_partial(f"Cancelled during {cur['label'] if cur else 'the scan'}")
            pg.stop_all("cancelled")
            log.info("domain scan %s cancelled: keeping partial results", scan_id)
        with session_scope() as db:
            event_ids, port_scan_id = persist(db, plan, out, cfg, pg)
    except Exception:
        log.exception("domain scan %s failed", scan_id)
        pg.stop_all("internal error")
        release_in_progress(plan.domain_id, plan.started_at)
        _finish(scan_id, SCAN_FAILED, error=INTERNAL_ERROR, notes=["The previous inventory was kept."], progress=pg)
        return
    notes = [*out.notes, *[f"Partial: {r}" for r in out.partial_reasons]]
    _finish(scan_id, SCAN_PARTIAL if out.partial else SCAN_COMPLETED, notes=notes, progress=pg)
    log.info("domain scan %s finished: %s events, port scan %s", scan_id, len(event_ids), port_scan_id)
    if event_ids:
        try:
            from ..webhooks import schedule_event_delivery

            schedule_event_delivery(event_ids)
        except Exception:
            log.exception("domain scan %s: event delivery failed", scan_id)
    if port_scan_id is not None:
        from ..manager import manager

        manager.wake()
