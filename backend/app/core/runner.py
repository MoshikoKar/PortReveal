"""Scan orchestration: targets -> discovery -> port/service scan -> compare -> notify -> snapshot.

Large networks are split into chunks (discovery) and batches (port scan) that
run through a bounded thread pool, so at most `parallelism` nmap processes run
at once, each with a timeout. A failed chunk/batch makes the scan *partial*;
partial scans never remove state (see core/compare.py).
"""
from __future__ import annotations

import logging
import time
from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait
from dataclasses import dataclass, field

from sqlalchemy import select

from .. import metrics
from ..config import get_settings
from ..db import session_scope, utcnow
from ..models import (
    SCAN_CANCELLED,
    SCAN_COMPLETED,
    SCAN_DISCOVERY,
    SCAN_FAILED,
    SCAN_FULL,
    SCAN_PARTIAL,
    SCAN_RUNNING,
    SCAN_STANDARD,
    TRIGGER_PRESENCE,
    Device,
    Exclusion,
    Network,
    Scan,
)
from ..netutils import MAX_SCAN_ADDRESSES, AddressSet, TargetError, ip_sort_key
from ..scanner import scanner_status
from ..scanner.identify_truenas import looks_like_truenas
from ..scanner.mock_scanner import LAST_STEP, MockScanner
from ..scanner.nmap_scanner import NmapScanner, nmap_is_privileged
from ..scanner.types import (
    HostObservation,
    PortProfile,
    ScanCancelled,
    ScanContext,
    Scanner,
    ScanStageError,
    StageResult,
)
from ..settings_store import ScanSettings, get_section, get_value, set_value
from .compare import ScanOutcome, apply_outcome
from .intel import after_scan, run_watches
from .snapshots import create_snapshot
from .web_capture.auto import maybe_enqueue_auto_web_capture
from .web_capture.manager import web_capture_manager

log = logging.getLogger(__name__)


def exclusion_set(db) -> AddressSet:
    specs: list[str] = []
    for ex in db.scalars(select(Exclusion).where(Exclusion.enabled.is_(True))).all():
        specs.append(ex.value)
    try:
        return AddressSet.from_specs(specs)
    except TargetError as exc:  # validated on save; defensive
        log.error("Invalid exclusion ignored: %s", exc)
        return AddressSet()


def scan_targets(db, scan: Scan) -> AddressSet:
    if scan.network_id is not None:
        net = db.get(Network, scan.network_id)
        if net is None:
            raise ScanStageError("network no longer exists")
        base = AddressSet.from_specs(net.cidr)
    else:
        base = AddressSet.from_specs(scan.targets or "")
    return base.subtract(exclusion_set(db))


def mock_step_key(network_id: int) -> str:
    return f"mock_step:{network_id}"


def build_scanner(db, cfg: ScanSettings) -> Scanner:
    settings = get_settings()
    status = scanner_status()
    if status.effective_mode == "mock":
        nets = [(n.id, n.cidr, int(get_value(db, mock_step_key(n.id), 0))) for n in db.scalars(select(Network)).all()]
        return MockScanner(nets, delay=settings.mock_scan_delay)
    if status.effective_mode == "nmap":
        return NmapScanner(
            settings.nmap_path,
            nmap_is_privileged(settings.nmap_privileged),
            cfg.timing,
            settings.data_path / "tmp",
        )
    raise ScanStageError(status.message)


def _update(scan_id: int, **fields) -> None:
    with session_scope() as db:
        scan = db.get(Scan, scan_id)
        if scan is not None:
            for k, v in fields.items():
                setattr(scan, k, v)


@dataclass
class _StageRun:
    results: list[StageResult] = field(default_factory=list)
    failures: list[str] = field(default_factory=list)
    failed_items: list[list[str]] = field(default_factory=list)


def _run_parallel(items: list[list[str]], fn, parallelism: int, ctx: ScanContext, on_done) -> _StageRun:
    out = _StageRun()
    if not items:
        return out
    with ThreadPoolExecutor(max_workers=parallelism, thread_name_prefix=f"scan{ctx.scan_id}") as pool:
        pending: dict[Future, list[str]] = {pool.submit(fn, item): item for item in items}
        try:
            while pending:
                done, _ = wait(pending, timeout=1.0, return_when=FIRST_COMPLETED)
                if ctx.cancelled:
                    raise ScanCancelled()
                for fut in done:
                    item = pending.pop(fut)
                    try:
                        out.results.append(fut.result())
                    except ScanCancelled:
                        raise
                    except ScanStageError as exc:
                        log.warning("scan %s: %s", ctx.scan_id, exc)
                        out.failures.append(str(exc))
                        out.failed_items.append(item)
                    except Exception as exc:  # unexpected - keep the scan going, mark partial
                        log.exception("scan %s: stage task crashed", ctx.scan_id)
                        out.failures.append(f"internal error: {exc}")
                        out.failed_items.append(item)
                    on_done(out)
        except ScanCancelled:
            ctx.cancel()
            for fut in pending:
                fut.cancel()
            raise
    return out


def run_scan(scan_id: int, ctx: ScanContext | None = None, scanner: Scanner | None = None) -> str:
    """Execute a queued scan synchronously. Returns the final status."""
    started = time.monotonic()
    status = _run_scan(scan_id, ctx, scanner)
    with session_scope() as db:
        scan_type = db.scalar(select(Scan.scan_type).where(Scan.id == scan_id)) or "unknown"
    metrics.observe_scan(scan_type, status, time.monotonic() - started)
    return status


def _run_scan(scan_id: int, ctx: ScanContext | None, scanner: Scanner | None) -> str:
    settings = get_settings()
    ctx = ctx or ScanContext(scan_id)
    started = time.monotonic()
    try:
        with session_scope() as db:
            scan = db.get(Scan, scan_id)
            if scan is None:
                return SCAN_FAILED
            cfg = get_section(db, ScanSettings)
            targets = scan_targets(db, scan)
            if not targets:
                raise ScanStageError("no addresses to scan (all targets are excluded or empty)")
            if len(targets) > MAX_SCAN_ADDRESSES:
                raise ScanStageError(f"too many target addresses ({len(targets)} > {MAX_SCAN_ADDRESSES})")
            scanner = scanner or build_scanner(db, cfg)
            scan_type, network_id, trigger = scan.scan_type, scan.network_id, scan.trigger
            # Prior inventory: re-scan TrueNAS Apps catalog ports on known TrueNAS hosts.
            ctx.known_truenas_ips = {
                d.current_ip
                for d in db.scalars(select(Device)).all()
                if d.current_ip in targets
                and looks_like_truenas(
                    hostname=d.hostname, dns_name=d.dns_name, os_name=d.os_name, vendor=d.vendor,
                )
            }
            scan.status, scan.started_at, scan.scanner_mode = SCAN_RUNNING, utcnow(), scanner.mode
            scan.target_count, scan.stage, scan.progress, scan.error = len(targets), "discovery", 0.0, None
        if cfg.keep_raw_xml and scanner.mode == "nmap":
            ctx.raw_dir = settings.data_path / "raw" / f"scan_{scan_id}"
        log.info("scan %s started: %s, %d addresses, scanner=%s", scan_id, scan_type, len(targets), scanner.mode)

        has_ports = scan_type in (SCAN_STANDARD, SCAN_FULL)
        disc_weight = 0.2 if has_ports else 1.0

        # ---- Stage 1: discovery ------------------------------------------------
        chunks = targets.chunks(cfg.discovery_chunk_size)
        live: dict[str, HostObservation] = {}

        merged: list[StageResult] = []

        def disc_done(run: _StageRun) -> None:
            for r in run.results[len(merged):]:
                merged.append(r)
                for h in r.hosts:
                    if h.ip not in targets:  # never report anything outside targets/exclusions
                        continue
                    if h.ip in live:
                        live[h.ip].merge(h)
                    else:
                        live[h.ip] = h
            done_n = len(run.results) + len(run.failures)
            _update(scan_id, progress=disc_weight * done_n / len(chunks), hosts_discovered=len(live))

        disc = _run_parallel(chunks, lambda c: scanner.discover(c, ctx), cfg.parallelism, ctx, disc_done)
        if disc.failures and not disc.results:
            raise ScanStageError("discovery failed: " + disc.failures[0])
        discovery_complete = not disc.failures

        # ---- Stage 2: port / service scan ---------------------------------------
        port_scope: str | None = None
        port_stage_complete = True
        failures = list(disc.failures)
        if has_ports and live:
            full = scan_type == SCAN_FULL
            profile = PortProfile(
                full=full,
                top_ports=cfg.top_ports,
                timing=cfg.timing,
                host_timeout_minutes=cfg.full_host_timeout_minutes if full else cfg.host_timeout_minutes,
                os_detection=cfg.os_detection,
                batch_size=min(cfg.port_batch_size, 16) if full else cfg.port_batch_size,
            )
            ips = sorted(live, key=ip_sort_key)
            batches = [ips[i:i + profile.batch_size] for i in range(0, len(ips), profile.batch_size)]
            _update(scan_id, stage="full port scan" if full else "service scan", progress=disc_weight,
                    hosts_discovered=len(live))
            def port_done(run: _StageRun) -> None:
                done_hosts = sum(len(r.hosts) for r in run.results) + sum(len(i) for i in run.failed_items)
                _update(scan_id, hosts_scanned=done_hosts,
                        progress=disc_weight + (1 - disc_weight) * done_hosts / max(len(ips), 1))

            ports = _run_parallel(batches, lambda b: scanner.scan_ports(b, profile, ctx), cfg.parallelism, ctx, port_done)
            for r in ports.results:
                port_scope = port_scope or r.port_scope
                for h in r.hosts:
                    if h.ip in live:
                        live[h.ip].merge(h)
            for item in ports.failed_items:
                for ip in item:
                    live[ip].merge(HostObservation(ip=ip, port_scan_failed=True))
            port_stage_complete = not ports.failures
            failures += ports.failures
            if port_scope is None:
                # no port data at all: treat hosts as not port-scanned
                for h in live.values():
                    h.ports = None

        ctx.check_cancelled()
        outcome = ScanOutcome(
            scan_type=scan_type,
            targets=targets,
            hosts=live,
            port_scope=port_scope,
            discovery_complete=discovery_complete,
            port_stage_complete=port_stage_complete,
        )

        # ---- Compare, store, snapshot -----------------------------------------
        _update(scan_id, stage="comparing")
        auto_capture_id: int | None = None
        with session_scope() as db:
            scan = db.get(Scan, scan_id)
            res = apply_outcome(db, scan, outcome, cfg)
            db.flush()
            tag_events = after_scan(db, scan, res.events)
            event_ids = [e.id for e in res.events]
            status = SCAN_COMPLETED if outcome.complete and not res.guard_tripped else SCAN_PARTIAL
            notes = list(res.notes)
            if failures:
                notes.append(f"{len(failures)} scan task(s) failed: " + "; ".join(failures[:3]))
            scan.status = status
            scan.port_scope = port_scope
            scan.finished_at = utcnow()
            scan.progress = 1.0
            scan.stage = None
            scan.hosts_discovered = len(live)
            scan.hosts_scanned = sum(1 for h in live.values() if h.ports is not None)
            scan.hosts_failed = res.hosts_failed
            scan.events_count = len(res.events) + tag_events
            scan.notes = "\n".join(notes) or None
            if status == SCAN_PARTIAL and failures:
                scan.error = failures[0]
            if network_id is not None and status == SCAN_COMPLETED:
                net = db.get(Network, network_id)
                if scan_type == SCAN_STANDARD and net is not None:
                    create_snapshot(db, net, scan, utcnow())
                if (scanner.mode == "mock" and scan_type in (SCAN_STANDARD, SCAN_DISCOVERY)
                        and trigger != TRIGGER_PRESENCE):
                    key = mock_step_key(network_id)
                    set_value(db, key, min(int(get_value(db, key, 0)) + 1, LAST_STEP))
            if has_ports and status in (SCAN_COMPLETED, SCAN_PARTIAL):
                auto_capture_id = maybe_enqueue_auto_web_capture(
                    db, scan, baseline_created=res.baseline_created,
                )
        log.info(
            "scan %s %s in %.1fs: %d live hosts, %d events%s",
            scan_id, status, time.monotonic() - started, len(live), len(event_ids),
            " (baseline created)" if res.baseline_created else "",
        )
        run_watches(scan_id=scan_id)
        if auto_capture_id is not None:
            web_capture_manager.wake()
        return status

    except ScanCancelled:
        log.info("scan %s cancelled", scan_id)
        _update(scan_id, status=SCAN_CANCELLED, finished_at=utcnow(), stage=None,
                notes="Cancelled by user. No state changes were applied.")
        return SCAN_CANCELLED
    except (ScanStageError, TargetError) as exc:
        log.error("scan %s failed: %s", scan_id, exc)
        _update(scan_id, status=SCAN_FAILED, finished_at=utcnow(), stage=None, error=str(exc),
                notes="Scan failed. The previous known state was preserved.")
        return SCAN_FAILED
    except Exception as exc:
        log.exception("scan %s crashed", scan_id)
        _update(scan_id, status=SCAN_FAILED, finished_at=utcnow(), stage=None, error=f"internal error: {exc}",
                notes="Scan failed. The previous known state was preserved.")
        return SCAN_FAILED
