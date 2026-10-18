"""Post-scan / post-capture inventory intelligence: tags, device types, exposure scores, watches.

Every entry point here is best-effort. Failures are logged and never change a scan's or a
capture's status.
"""
from __future__ import annotations

import logging
from collections.abc import Iterable

from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import metrics
from ..db import session_scope, utcnow
from ..models import VULN_JOB_TRIGGER_AFTER_SCAN, Device, Event, Scan, ScanHost
from ..settings_store import VulnSettings, get_section
from .exposure import apply_scores, unique_services
from .ip_assignment import apply_ip_assignment
from .tagging import apply_tags, load_facts
from .vuln.manager import enqueue_vuln_job
from .vuln.score import apply_risk_scores
from .watches import evaluate_all
from .web_capture.inventory_sync import clear_stale_hypervisor_http

log = logging.getLogger(__name__)

REFRESH_CHUNK = 500
# Single probe failures are normal (host went away, odd TLS stack) and stay at debug. This many in one
# scan points at a systemic problem (egress filtering, broken TLS library) and is logged as a warning.
ENRICH_WARN_THRESHOLD = 5


def refresh_devices(db: Session, device_ids: Iterable[int], *, scan_id: int | None = None,
                    report_ids: set[int] | None = None) -> int:
    """Recompute tags, type and exposure score for these devices. Returns the tag events created.

    With `report_ids`, only those devices may emit tag events (the rest are re-tagged silently)."""
    ids = sorted(set(device_ids))
    if not ids:
        return 0
    now = utcnow()
    nets: set[int] = set()
    for i in range(0, len(ids), REFRESH_CHUNK):
        nets.update(db.scalars(select(Device.network_id).where(Device.id.in_(ids[i:i + REFRESH_CHUNK]),
                                                              Device.network_id.isnot(None)).distinct()))
    unique = unique_services(db, nets)
    events = 0
    for i in range(0, len(ids), REFRESH_CHUNK):
        chunk = ids[i:i + REFRESH_CHUNK]
        # Drop PortHttp that still claims ESXi/Proxmox after the port's product says otherwise
        # (stale capture), so classification is not stuck on hypervisor until a re-capture.
        clear_stale_hypervisor_http(db, chunk)
        facts = load_facts(db, chunk)
        events += len(apply_tags(db, facts, now=now, scan_id=scan_id, report_ids=report_ids))
        apply_scores(db, facts, unique, now=now)
        apply_ip_assignment(db, facts, now=now)
        # Flush first: apply_scores may have just inserted this pass's DeviceProfile rows, and
        # apply_risk_scores re-queries DeviceProfile by device_id -- it must see them to avoid
        # inserting a second row for the same device (device_profiles.device_id is unique).
        db.flush()
        # Re-scores risk/combined from whatever device_port_vulns already holds (no CPE matching,
        # no network): combined_score depends on exposure_score, which just changed above.
        apply_risk_scores(db, [f.device.id for f in facts], now=now)
        db.flush()
    return events


def _enrich_open_services(db: Session, device_ids: list[int], *, scan_id: int | None = None) -> None:
    """Best-effort TLS / banner / CPE / SSH enrichment for devices touched by a scan (TCP only)."""
    from ..models import Device, DevicePort
    from ..scanner import scanner_status
    from .banners import sync_nmap_banners
    from .cpe import sync_nmap_cpes
    from .ssh_keys import enrich_device_ssh
    from .tls_probe import enrich_device_tls

    if not device_ids:
        return
    # Live probes (TLS/SSH) need real sockets — skip in mock/tests so scripts stay fast.
    live = scanner_status().effective_mode != "mock"
    devices = {d.id: d for d in db.scalars(select(Device).where(Device.id.in_(device_ids)))}
    failures = {"tls": 0, "ssh": 0}
    for did, dev in devices.items():
        if live:
            for probe, enrich in (("tls", enrich_device_tls), ("ssh", enrich_device_ssh)):
                try:
                    enrich(db, did, dev.current_ip)
                except Exception:
                    failures[probe] += 1
                    metrics.observe_enrich_failure(probe)
                    log.debug("%s enrich failed for device %s", probe, did, exc_info=True)
        ports = db.scalars(select(DevicePort).where(
            DevicePort.device_id == did, DevicePort.is_open.is_(True),
        )).all()
        sync_nmap_banners(db, ports, device=dev, scan_id=None, now=utcnow())
        for p in ports:
            sync_nmap_cpes(db, p)
    for probe, n in failures.items():
        if n >= ENRICH_WARN_THRESHOLD:
            log.warning("scan %s: %s enrichment failed for %d of %d devices (enable DEBUG for details)",
                        scan_id, probe.upper(), n, len(devices))
    if live:
        try:
            _enrich_local_names(db, devices)
        except Exception:
            log.debug("scan %s: local discovery (mDNS/SSDP/NetBIOS) failed", scan_id, exc_info=True)


# How long a previously heard local discovery name is kept when later passes miss the host
# (short mDNS/SSDP windows or NetBIOS budget). Past this, the name ages out.
DISCOVERY_NAME_TTL_DAYS = 14


def _enrich_local_names(db: Session, devices: dict[int, Device]) -> None:
    """Local-only mDNS/SSDP/NetBIOS device names (spec 9.2): a weighted type-classification signal,
    and a fallback display name. Never touches nmap; skipped entirely when disabled or in mock mode
    (the caller already checks `live`, i.e. a real scanner is configured).

    Names persist across passes and age out after ``DISCOVERY_NAME_TTL_DAYS`` without a hear —
    they are not wiped when a single pass misses the host (NetBIOS cap / quiet mDNS window).
    """
    from datetime import timedelta

    from ..db import utcnow
    from ..settings_store import DiscoverySettings
    from .discovery import collect_local_names

    cfg = get_section(db, DiscoverySettings)
    if not cfg.enabled or not devices:
        return
    found = collect_local_names(
        [d.current_ip for d in devices.values() if d.current_ip],
        mdns=cfg.mdns, ssdp=cfg.ssdp, netbios=cfg.netbios,
        timeout=cfg.timeout_seconds,
    )
    now = utcnow()
    ttl = timedelta(days=DISCOVERY_NAME_TTL_DAYS)
    for dev in devices.values():
        hit = found.get(dev.current_ip) if dev.current_ip else None
        if hit:
            dev.discovery_name, dev.discovery_source = hit
            dev.discovery_name_seen_at = now
            continue
        if not dev.discovery_name:
            continue
        # Pre-TTL rows (no seen_at): start the clock now so a single quiet pass does not wipe them.
        if dev.discovery_name_seen_at is None:
            dev.discovery_name_seen_at = now
            continue
        if now - dev.discovery_name_seen_at > ttl:
            dev.discovery_name = None
            dev.discovery_source = None
            dev.discovery_name_seen_at = None


def after_scan(db: Session, scan: Scan, changed: Iterable[Event]) -> int:
    """Inside the scan's transaction, after apply_outcome. Returns the tag events created.

    Tag changes are reported only for devices with a reported change in `changed` (the scan's
    events): what the comparison recorded silently (baseline, first coverage) stays silent here."""
    try:
        with db.begin_nested():
            ids = list(db.scalars(select(ScanHost.device_id).where(ScanHost.scan_id == scan.id)).all())
            try:
                _enrich_open_services(db, ids, scan_id=scan.id)
            except Exception:
                log.exception("scan %s: service enrichment failed", scan.id)
            report = {e.device.id for e in changed if e.device is not None and e.device.id is not None}
            events = refresh_devices(db, ids, scan_id=scan.id, report_ids=report)
            try:
                _enqueue_vuln_job_after_scan(db, scan, ids)
            except Exception:
                log.exception("scan %s: could not enqueue vulnerability check job", scan.id)
            return events
    except Exception:
        log.exception("scan %s: tagging / exposure scoring failed", scan.id)
        return 0


def _enqueue_vuln_job_after_scan(db: Session, scan: Scan, device_ids: list[int]) -> None:
    """Spec 8.2: queue the background vuln-check pipeline and return immediately -- the main scan
    is already done and saved. Only queued when the feature is enabled; never blocks the scan.

    Waking the worker is left to the caller (core/runner.py), once this scan's own transaction has
    committed -- waking it from inside this still-open transaction could have it look for a job
    before the row is visible.
    """
    if not device_ids or not get_section(db, VulnSettings).enabled:
        return
    enqueue_vuln_job(db, trigger=VULN_JOB_TRIGGER_AFTER_SCAN, scan_id=scan.id, device_ids=device_ids)


def run_watches(*, scan_id: int | None = None) -> None:
    try:
        with session_scope() as db:
            n = evaluate_all(db, scan_id=scan_id)
        if n:
            log.info("saved searches raised %d alert(s)", n)
    except Exception:
        log.exception("saved search evaluation failed")


def after_web_capture(capture_id: int) -> None:
    """Copy HTTP metadata into the inventory, then re-tag / re-score the hosts and run watches."""
    from .web_capture.inventory_sync import sync_port_http

    try:
        with session_scope() as db:
            refresh_devices(db, sync_port_http(db, capture_id))
    except Exception:
        log.exception("web capture %s: inventory sync failed", capture_id)
    run_watches()
