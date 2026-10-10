"""Queue Web Capture jobs automatically after nmap scans find web/RTSP services."""
from __future__ import annotations

import logging

from sqlalchemy import select
from sqlalchemy.orm import Session

from ...models import (
    EV_DEVICE_DISCOVERED,
    EV_PORT_OPENED,
    SCAN_FULL,
    SCAN_STANDARD,
    WEB_CAPTURE_ACTIVE_STATES,
    WEB_CAPTURE_QUEUED,
    Event,
    Scan,
    ScanHost,
    WebCapture,
    WebPage,
)
from ...scanner import scanner_status
from ...settings_store import WebCaptureSettings, get_section
from .inventory import COMMON_RTSP_PORTS, COMMON_WEB_PORTS, find_web_endpoints, is_rtsp_service, is_web_service

log = logging.getLogger(__name__)

AUTO_REQUESTED_BY = "auto-scan"


def _port_looks_web(service: str | None, port: int | None) -> bool:
    if is_rtsp_service(service) or is_web_service(service):
        return True
    if port is None:
        return False
    if not service and port in COMMON_RTSP_PORTS:
        return True
    return port in COMMON_WEB_PORTS


def _candidate_ips(db: Session, scan: Scan, cfg: WebCaptureSettings, *, baseline_created: bool) -> set[str]:
    """IPs from this scan that should be auto-captured."""
    host_ips = {
        ip for ip in db.scalars(select(ScanHost.ip).where(ScanHost.scan_id == scan.id)).all() if ip
    }
    if not host_ips:
        return set()

    endpoints, _ = find_web_endpoints(db, host_ips, max_endpoints=cfg.max_endpoints)
    if not endpoints:
        return set()

    web_ips = {e.ip for e in endpoints}
    if not cfg.auto_only_new_or_changed:
        return web_ips

    interesting: set[str] = set()
    events = db.scalars(select(Event).where(Event.scan_id == scan.id)).all()
    for ev in events:
        if not ev.ip or ev.ip not in web_ips:
            continue
        if ev.event_type == EV_DEVICE_DISCOVERED:
            interesting.add(ev.ip)
        elif ev.event_type == EV_PORT_OPENED and _port_looks_web(ev.new_value, ev.port):
            interesting.add(ev.ip)

    # Never-captured endpoints (covers silent baseline adds and first-time enrichment)
    captured_ports = set(
        db.scalars(
            select(WebPage.device_port_id).where(
                WebPage.device_port_id.in_([e.device_port_id for e in endpoints]),
            )
        ).all()
    )
    for e in endpoints:
        if e.device_port_id not in captured_ports:
            interesting.add(e.ip)

    if baseline_created:
        interesting |= web_ips

    return interesting


def maybe_enqueue_auto_web_capture(db: Session, scan: Scan, *, baseline_created: bool = False) -> int | None:
    """If settings allow, queue one Web Capture for web/RTSP hosts found by this scan.

    Returns the new capture id, or None when nothing was queued.
    """
    if scan.scan_type not in (SCAN_STANDARD, SCAN_FULL):
        return None

    cfg = get_section(db, WebCaptureSettings)
    if not cfg.enabled or not cfg.auto_after_scan:
        return None

    # Avoid stacking while a capture (any) is already queued/running
    if db.scalar(select(WebCapture.id).where(WebCapture.status.in_(WEB_CAPTURE_ACTIVE_STATES)).limit(1)):
        log.info("auto web capture skipped after scan %s: a capture is already active", scan.id)
        return None

    ips = sorted(_candidate_ips(db, scan, cfg, baseline_created=baseline_created))
    if not ips:
        return None

    if len(ips) > cfg.max_addresses:
        log.info(
            "auto web capture after scan %s: truncating %d hosts to max_addresses=%d",
            scan.id, len(ips), cfg.max_addresses,
        )
        ips = ips[: cfg.max_addresses]

    target_text = ",".join(ips)
    job = WebCapture(
        status=WEB_CAPTURE_QUEUED,
        targets=target_text,
        target_count=len(ips),
        requested_by=AUTO_REQUESTED_BY,
        mock_mode=scanner_status().effective_mode == "mock" or cfg.force_mock,
        notes=f"Auto-queued after scan {scan.id} ({scan.scan_type}).",
    )
    db.add(job)
    db.flush()
    log.info("auto web capture %s queued after scan %s for %d host(s)", job.id, scan.id, len(ips))
    return job.id
