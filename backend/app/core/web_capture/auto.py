"""Queue Web Capture jobs automatically after nmap scans find web/RTSP services."""
from __future__ import annotations

import logging

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ...models import (
    EV_DEVICE_DISCOVERED,
    EV_PORT_OPENED,
    EV_SERVICE_CHANGED,
    EV_SERVICE_DETECTED,
    SCAN_FULL,
    SCAN_STANDARD,
    SCREENSHOT_CAPTURED,
    WEB_CAPTURE_QUEUED,
    DevicePort,
    Event,
    PortHttp,
    Scan,
    ScanHost,
    WebCapture,
    WebPage,
)
from ...netutils import ip_sort_key
from ...scanner import scanner_status
from ...settings_store import WebCaptureSettings, get_section
from ..web_storage import resolve_screenshot
from .classify import UNAVAILABLE_PREFIX
from .inventory import COMMON_RTSP_PORTS, COMMON_WEB_PORTS, find_web_endpoints, is_rtsp_service, is_web_service
from .inventory_sync import _http_claims_hypervisor, _product_conflicts_hypervisor

log = logging.getLogger(__name__)

AUTO_REQUESTED_BY = "auto-scan"
ALL_ENDPOINTS = 1_000_000


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

    # Candidates are judged over every host; the job itself splits into follow-up jobs when large.
    endpoints, _ = find_web_endpoints(db, host_ips, max_endpoints=ALL_ENDPOINTS)
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
        elif ev.event_type in (EV_SERVICE_CHANGED, EV_SERVICE_DETECTED):
            # Re-identified service (e.g. a mislabelled "rtsp" port now known to be HTTP)
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

    # Stale captures: the newest page of an endpoint was taken with another scheme (the port was
    # re-identified, e.g. rtsp -> http) or claims a screenshot whose file is gone. Without this
    # such hosts keep a dead tile forever, since "unchanged" hosts are never captured again.
    latest_ids = select(func.max(WebPage.id)).where(
        WebPage.device_port_id.in_([e.device_port_id for e in endpoints])
    ).group_by(WebPage.device_port_id)
    latest = {p.device_port_id: p for p in db.scalars(select(WebPage).where(WebPage.id.in_(latest_ids))).all()}
    for e in endpoints:
        page = latest.get(e.device_port_id)
        if page is None:
            continue
        if page.scheme != e.scheme or (page.capture_error or "").startswith(UNAVAILABLE_PREFIX) or (
            page.screenshot_status == SCREENSHOT_CAPTURED and page.screenshot_relpath
            and resolve_screenshot(page.screenshot_relpath) is None
        ):
            interesting.add(e.ip)

    # Stale hypervisor PortHttp: title/server still say ESXi/Proxmox while nmap product
    # clearly identifies another service - re-capture so type and tiles can recover.
    port_ids = [e.device_port_id for e in endpoints]
    ip_by_port = {e.device_port_id: e.ip for e in endpoints}
    if port_ids:
        for http, port in db.execute(
            select(PortHttp, DevicePort)
            .join(DevicePort, DevicePort.id == PortHttp.device_port_id)
            .where(PortHttp.device_port_id.in_(port_ids))
        ).all():
            if _http_claims_hypervisor(http.title, http.server) and _product_conflicts_hypervisor(
                port.product, port.service, port.cpe,
            ):
                ip = ip_by_port.get(port.id)
                if ip:
                    interesting.add(ip)

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

    ips = sorted(_candidate_ips(db, scan, cfg, baseline_created=baseline_created), key=ip_sort_key)
    if not ips:
        return None

    # Never drop hosts: a capture already waiting in the queue absorbs these (no stacking of
    # duplicate jobs); otherwise queue new job(s) of at most max_addresses hosts each, so a big
    # subnet is covered in order instead of losing the same tail of addresses on every scan.
    waiting = db.scalar(
        select(WebCapture).where(WebCapture.status == WEB_CAPTURE_QUEUED,
                                 WebCapture.requested_by == AUTO_REQUESTED_BY)
        .order_by(WebCapture.id.desc()).limit(1)
    )
    if waiting is not None:
        merged = sorted(set(waiting.targets.split(",")) | set(ips), key=ip_sort_key)
        if len(merged) <= cfg.max_addresses:
            waiting.targets, waiting.target_count = ",".join(merged), len(merged)
            log.info("auto web capture after scan %s merged into queued capture %s (%d host(s))",
                     scan.id, waiting.id, len(merged))
            return waiting.id
        ips = [ip for ip in ips if ip not in set(waiting.targets.split(","))]

    first_id = None
    mock = scanner_status().effective_mode == "mock" or cfg.force_mock
    for start in range(0, len(ips), cfg.max_addresses):
        chunk = ips[start:start + cfg.max_addresses]
        job = WebCapture(
            status=WEB_CAPTURE_QUEUED,
            targets=",".join(chunk),
            target_count=len(chunk),
            requested_by=AUTO_REQUESTED_BY,
            mock_mode=mock,
            notes=f"Auto-queued after scan {scan.id} ({scan.scan_type}).",
        )
        db.add(job)
        db.flush()
        first_id = first_id or job.id
        log.info("auto web capture %s queued after scan %s for %d host(s)", job.id, scan.id, len(chunk))
    return first_id
