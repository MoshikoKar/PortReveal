"""Post-scan / post-capture inventory intelligence: tags, device types, exposure scores, watches.

Every entry point here is best-effort. Failures are logged and never change a scan's or a
capture's status.
"""
from __future__ import annotations

import logging
from collections.abc import Iterable

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db import session_scope, utcnow
from ..models import Device, Event, Scan, ScanHost
from .exposure import apply_scores, unique_services
from .tagging import apply_tags, load_facts
from .watches import evaluate_all

log = logging.getLogger(__name__)

REFRESH_CHUNK = 500


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
        facts = load_facts(db, ids[i:i + REFRESH_CHUNK])
        events += len(apply_tags(db, facts, now=now, scan_id=scan_id, report_ids=report_ids))
        apply_scores(db, facts, unique, now=now)
        db.flush()
    return events


def _enrich_open_services(db: Session, device_ids: list[int]) -> None:
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
    for did, dev in devices.items():
        if live:
            try:
                enrich_device_tls(db, did, dev.current_ip)
            except Exception:
                log.debug("tls enrich failed for device %s", did, exc_info=True)
            try:
                enrich_device_ssh(db, did, dev.current_ip)
            except Exception:
                log.debug("ssh enrich failed for device %s", did, exc_info=True)
        ports = db.scalars(select(DevicePort).where(
            DevicePort.device_id == did, DevicePort.is_open.is_(True),
        )).all()
        sync_nmap_banners(db, ports, device=dev, scan_id=None, now=utcnow())
        for p in ports:
            sync_nmap_cpes(db, p)


def after_scan(db: Session, scan: Scan, changed: Iterable[Event]) -> int:
    """Inside the scan's transaction, after apply_outcome. Returns the tag events created.

    Tag changes are reported only for devices with a reported change in `changed` (the scan's
    events): what the comparison recorded silently (baseline, first coverage) stays silent here."""
    try:
        with db.begin_nested():
            ids = list(db.scalars(select(ScanHost.device_id).where(ScanHost.scan_id == scan.id)).all())
            try:
                _enrich_open_services(db, ids)
            except Exception:
                log.exception("scan %s: service enrichment failed", scan.id)
            report = {e.device.id for e in changed if e.device is not None and e.device.id is not None}
            return refresh_devices(db, ids, scan_id=scan.id, report_ids=report)
    except Exception:
        log.exception("scan %s: tagging / exposure scoring failed", scan.id)
        return 0


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
