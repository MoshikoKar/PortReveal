"""CVE-centric vulnerability dashboard (spec section 5.7): the summary endpoint backing every
card/facet/chart/top-list, the filterable/paginated finding list, and the per-CVE detail page.
Report-only: dismiss/undismiss stay on the existing device-scoped endpoints in api/devices.py.
"""
from __future__ import annotations

import csv
import io
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import StreamingResponse
from sqlalchemy import and_, func, literal_column, or_, select
from sqlalchemy.orm import Session

from ..auth.deps import current_user
from ..core.mockdata import device_visible
from ..core.vuln.buckets import severity_bucket, severity_bucket_expr
from ..core.vuln.display import is_visible
from ..core.vuln.score import DEFAULT_CVSS, RISK_BANDS, RISK_HIGH_THRESHOLD, RISK_MEDIUM_THRESHOLD
from ..core.vuln.summary import get_vuln_summary
from ..db import SessionLocal, get_db, utcnow
from ..models import (
    VULN_STATE_DISMISSED,
    VULN_STATE_POTENTIAL,
    VULN_STATES,
    Device,
    DevicePort,
    DevicePortVuln,
    Network,
    User,
    VulnCpeMatch,
    Vulnerability,
    VulnFindingLifecycle,
)
from ..settings_store import VulnSettings, get_section
from .common import Paging, cve_out, paged, vuln_finding_out

router = APIRouter(prefix="/api/vulns", tags=["vulns"])

AGE_BUCKETS = ("under_30d", "30_90d", "90_365d", "over_365d", "unknown")
AGE_BUCKET_PATTERN = "^(" + "|".join(AGE_BUCKETS) + ")$"
SEVERITY_PATTERN = "^(critical|high|medium|low|unknown)$"
RISK_BAND_PATTERN = "^(" + "|".join(RISK_BANDS) + ")$"
STATE_PATTERN = "^(" + "|".join(VULN_STATES) + ")$"


@router.get("/summary")
def vuln_summary_route(db: Session = Depends(get_db), user: User = Depends(current_user)):
    """Severity/KEV/EPSS/confirmed-potential counts, high-risk device levels, feed staleness,
    facet breakdowns, the weekly new/resolved/dismissed trend and top-10 CVEs/devices. Self-
    populating on a cold cache; otherwise served straight from it (invalidated after every scan
    or feed sync)."""
    return get_vuln_summary(db, now=utcnow())


@dataclass
class FindingFilters:
    severity: str | None = None
    kev: bool | None = None
    epss_min: float | None = None
    network_id: int | None = None
    service: str | None = None
    port: int | None = None
    os_name: str | None = None
    device_type: str | None = None
    state: str | None = None
    cve_age: str | None = None
    exposure_duration: str | None = None
    risk_band: str | None = None
    vendor: str | None = None
    product: str | None = None


def _lifecycle_join_cond():
    return and_(
        VulnFindingLifecycle.device_uuid == Device.uuid,
        VulnFindingLifecycle.port == DevicePort.port,
        VulnFindingLifecycle.protocol == DevicePort.protocol,
        VulnFindingLifecycle.cve_id == DevicePortVuln.cve_id,
    )


def _rows_base():
    return (
        select(DevicePortVuln, DevicePort, Device, Vulnerability, Network.name, VulnFindingLifecycle.first_seen_at)
        .join(DevicePort, DevicePort.id == DevicePortVuln.device_port_id)
        .join(Device, Device.id == DevicePort.device_id)
        .join(Vulnerability, Vulnerability.cve_id == DevicePortVuln.cve_id)
        .outerjoin(Network, Network.id == Device.network_id)
        .outerjoin(VulnFindingLifecycle, _lifecycle_join_cond())
    )


def _count_base():
    return (
        select(func.count(DevicePortVuln.id))
        .join(DevicePort, DevicePort.id == DevicePortVuln.device_port_id)
        .join(Device, Device.id == DevicePort.device_id)
        .join(Vulnerability, Vulnerability.cve_id == DevicePortVuln.cve_id)
        .outerjoin(Network, Network.id == Device.network_id)
        .outerjoin(VulnFindingLifecycle, _lifecycle_join_cond())
    )


def _age_bucket_cond(col, bucket: str, now: datetime):
    d30, d90, d365 = now - timedelta(days=30), now - timedelta(days=90), now - timedelta(days=365)
    if bucket == "unknown":
        return col.is_(None)
    if bucket == "under_30d":
        return and_(col.isnot(None), col >= d30)
    if bucket == "30_90d":
        return and_(col.isnot(None), col < d30, col >= d90)
    if bucket == "90_365d":
        return and_(col.isnot(None), col < d90, col >= d365)
    return and_(col.isnot(None), col < d365)  # over_365d


def _apply_filters(q, db: Session, cfg: VulnSettings, f: FindingFilters, now: datetime):
    q = q.where(device_visible(db))
    if f.state:
        q = q.where(DevicePortVuln.state == f.state)
    else:
        q = q.where(DevicePortVuln.state != VULN_STATE_DISMISSED)
        if not cfg.include_potential:
            q = q.where(DevicePortVuln.state != VULN_STATE_POTENTIAL)
        effective_cvss = func.coalesce(Vulnerability.cvss_base, literal_column(str(DEFAULT_CVSS)))
        q = q.where(or_(Vulnerability.kev.is_(True), effective_cvss >= cfg.min_cvss_display))
    if f.severity:
        q = q.where(severity_bucket_expr(Vulnerability.cvss_base) == f.severity)
    if f.kev is not None:
        q = q.where(Vulnerability.kev.is_(f.kev))
    if f.epss_min is not None:
        q = q.where(Vulnerability.epss.isnot(None), Vulnerability.epss >= f.epss_min)
    if f.network_id is not None:
        q = q.where(Device.network_id == f.network_id)
    if f.service is not None:
        q = q.where(DevicePort.service == f.service)
    if f.port is not None:
        q = q.where(DevicePort.port == f.port)
    if f.os_name is not None:
        q = q.where(Device.os_name == f.os_name)
    if f.device_type is not None:
        q = q.where(Device.device_type == f.device_type)
    if f.cve_age is not None:
        q = q.where(_age_bucket_cond(Vulnerability.published_at, f.cve_age, now))
    if f.exposure_duration is not None:
        q = q.where(_age_bucket_cond(VulnFindingLifecycle.first_seen_at, f.exposure_duration, now))
    if f.risk_band is not None:
        # Same combined-score bands as summary._risk_device_levels / score.RISK_*_THRESHOLD.
        if f.risk_band == "high":
            q = q.where(Device.combined_score >= RISK_HIGH_THRESHOLD)
        elif f.risk_band == "medium":
            q = q.where(
                Device.combined_score >= RISK_MEDIUM_THRESHOLD,
                Device.combined_score < RISK_HIGH_THRESHOLD,
            )
        else:  # low
            q = q.where(Device.combined_score < RISK_MEDIUM_THRESHOLD)
    if f.vendor is not None or f.product is not None:
        q = q.where(_vendor_product_cond(f.vendor, f.product))
    return q


def _cpe_match_exists(*extra):
    """True when a vuln_cpe_match row pairs this finding's (cve_id, matched_cpe)."""
    return (
        select(VulnCpeMatch.id)
        .where(
            VulnCpeMatch.cve_id == DevicePortVuln.cve_id,
            VulnCpeMatch.cpe23 == DevicePortVuln.matched_cpe,
            *extra,
        )
        .exists()
    )


def _vendor_product_cond(vendor: str | None, product: str | None):
    """Match the summary's vendor/product facet keys (`vendor:product`, or `unknown`)."""
    if vendor == "unknown" and not product:
        return or_(DevicePortVuln.matched_cpe.is_(None), ~_cpe_match_exists())
    extras = []
    if vendor and product:
        extras.append(VulnCpeMatch.vendor_product == f"{vendor}:{product}")
    elif vendor:
        extras.append(VulnCpeMatch.vendor_product.like(f"{vendor}:%"))
    elif product:
        extras.append(VulnCpeMatch.vendor_product.like(f"%:{product}"))
    return _cpe_match_exists(*extras)


def _filters_from_query(
    *,
    severity: str | None,
    kev: bool | None,
    epss_min: float | None,
    network_id: int | None,
    service: str | None,
    port: int | None,
    os_name: str | None,
    device_type: str | None,
    state: str | None,
    cve_age: str | None,
    exposure_duration: str | None,
    risk_band: str | None,
    vendor: str | None = None,
    product: str | None = None,
) -> FindingFilters:
    return FindingFilters(
        severity=severity, kev=kev, epss_min=epss_min, network_id=network_id,
        service=service, port=port, os_name=os_name, device_type=device_type,
        state=state, cve_age=cve_age, exposure_duration=exposure_duration,
        risk_band=risk_band, vendor=vendor, product=product,
    )


@router.get("")
def list_vulns(
    severity: str | None = Query(None, pattern=SEVERITY_PATTERN),
    kev: bool | None = None,
    epss_min: float | None = Query(None, ge=0.0, le=1.0),
    network_id: int | None = None,
    service: str | None = Query(None, max_length=100),
    port: int | None = Query(None, ge=1, le=65535),
    os_name: str | None = Query(None, max_length=255),
    device_type: str | None = Query(None, max_length=40),
    state: str | None = Query(None, pattern=STATE_PATTERN),
    cve_age: str | None = Query(None, pattern=AGE_BUCKET_PATTERN),
    exposure_duration: str | None = Query(None, pattern=AGE_BUCKET_PATTERN),
    risk_band: str | None = Query(None, pattern=RISK_BAND_PATTERN),
    vendor: str | None = Query(None, max_length=100),
    product: str | None = Query(None, max_length=100),
    paging: Paging = Depends(),
    db: Session = Depends(get_db),
    user: User = Depends(current_user),
):
    """Filterable, paginated, CVE-centric finding list -- every card/facet on `/vulnerabilities`
    links here with matching query params, so the URL is shareable (spec UX)."""
    cfg = get_section(db, VulnSettings)
    now = utcnow()
    filters = _filters_from_query(
        severity=severity, kev=kev, epss_min=epss_min, network_id=network_id,
        service=service, port=port, os_name=os_name, device_type=device_type,
        state=state, cve_age=cve_age, exposure_duration=exposure_duration, risk_band=risk_band,
        vendor=vendor, product=product,
    )
    total = db.scalar(_apply_filters(_count_base(), db, cfg, filters, now)) or 0
    rows = db.execute(
        _apply_filters(_rows_base(), db, cfg, filters, now)
        .order_by(Vulnerability.kev.desc(), Vulnerability.cvss_base.desc().nulls_last(), DevicePortVuln.id)
        .offset(paging.offset).limit(paging.page_size)
    ).all()
    items = [
        vuln_finding_out(dpv, port_row, device, vuln, network_name, first_seen_at)
        for dpv, port_row, device, vuln, network_name, first_seen_at in rows
    ]
    return paged(items, total, paging)


CSV_COLUMNS = [
    "cve_id", "device_ip", "device_hostname", "network", "port", "protocol", "service",
    "cvss_base", "severity", "kev", "epss", "state", "first_seen", "matched_at",
]


def _export_row(dpv: DevicePortVuln, port_row: DevicePort, device: Device, vuln: Vulnerability,
                network_name: str | None, first_seen_at: datetime | None) -> list:
    return [
        vuln.cve_id, device.current_ip, device.hostname or "", network_name or "",
        port_row.port, port_row.protocol, port_row.service or "",
        vuln.cvss_base if vuln.cvss_base is not None else "", severity_bucket(vuln.cvss_base),
        vuln.kev, vuln.epss if vuln.epss is not None else "", dpv.state,
        first_seen_at.isoformat() if first_seen_at else "",
        dpv.matched_at.isoformat() if dpv.matched_at else "",
    ]


def _export_lines(filters: FindingFilters, now: datetime) -> Iterator[str]:
    db = SessionLocal()
    try:
        cfg = get_section(db, VulnSettings)
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(CSV_COLUMNS)
        rows = db.execute(
            _apply_filters(_rows_base(), db, cfg, filters, now)
            .order_by(Vulnerability.kev.desc(), Vulnerability.cvss_base.desc().nulls_last(), DevicePortVuln.id)
        )
        for dpv, port_row, device, vuln, network_name, first_seen_at in rows:
            writer.writerow(_export_row(dpv, port_row, device, vuln, network_name, first_seen_at))
            if buf.tell() > 64_000:
                yield buf.getvalue()
                buf.seek(0)
                buf.truncate()
        yield buf.getvalue()
    finally:
        db.close()


@router.get("/export")
def export_vulns(
    severity: str | None = Query(None, pattern=SEVERITY_PATTERN),
    kev: bool | None = None,
    epss_min: float | None = Query(None, ge=0.0, le=1.0),
    network_id: int | None = None,
    service: str | None = Query(None, max_length=100),
    port: int | None = Query(None, ge=1, le=65535),
    os_name: str | None = Query(None, max_length=255),
    device_type: str | None = Query(None, max_length=40),
    state: str | None = Query(None, pattern=STATE_PATTERN),
    cve_age: str | None = Query(None, pattern=AGE_BUCKET_PATTERN),
    exposure_duration: str | None = Query(None, pattern=AGE_BUCKET_PATTERN),
    risk_band: str | None = Query(None, pattern=RISK_BAND_PATTERN),
    vendor: str | None = Query(None, max_length=100),
    product: str | None = Query(None, max_length=100),
    user: User = Depends(current_user),
):
    """Same filters as GET /api/vulns, no pagination: every matching row, streamed as CSV."""
    filters = _filters_from_query(
        severity=severity, kev=kev, epss_min=epss_min, network_id=network_id,
        service=service, port=port, os_name=os_name, device_type=device_type,
        state=state, cve_age=cve_age, exposure_duration=exposure_duration, risk_band=risk_band,
        vendor=vendor, product=product,
    )
    stamp = datetime.now().strftime("%Y%m%d-%H%M")
    return StreamingResponse(
        _export_lines(filters, utcnow()),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="portreveal-vulns-{stamp}.csv"'},
    )


@router.get("/{cve_id}")
def cve_detail(cve_id: str, db: Session = Depends(get_db), user: User = Depends(current_user)):
    """Metadata, visibility-filtered affected devices/services, and first-seen (the earliest
    lifecycle first_seen_at across those devices) for one CVE.

    404 only when the CVE is absent from the local cache. A known CVE with no visible
    affected devices (none matched, filtered by min_cvss_display, or on hidden devices)
    still returns metadata with an empty ``affected_devices`` list.
    """
    vuln = db.get(Vulnerability, cve_id)
    if vuln is None:
        raise HTTPException(404, "Unknown CVE")
    cfg = get_section(db, VulnSettings)
    rows = db.execute(
        select(DevicePortVuln, DevicePort, Device, Network.name, VulnFindingLifecycle.first_seen_at)
        .join(DevicePort, DevicePort.id == DevicePortVuln.device_port_id)
        .join(Device, Device.id == DevicePort.device_id)
        .outerjoin(Network, Network.id == Device.network_id)
        .outerjoin(VulnFindingLifecycle, _lifecycle_join_cond())
        .where(device_visible(db), DevicePortVuln.cve_id == cve_id)
    ).all()
    visible = [r for r in rows if is_visible(r[0].state, vuln.kev, vuln.cvss_base, cfg)]
    affected_devices = [
        {"device_uuid": device.uuid, "device_ip": device.current_ip, "device_hostname": device.hostname,
         "network": network_name, "port": port_row.port, "protocol": port_row.protocol,
         "service": port_row.service, "product": port_row.product, "version": port_row.version,
         "state": dpv.state, "matched_at": dpv.matched_at, "first_seen_at": first_seen_at}
        for dpv, port_row, device, network_name, first_seen_at in visible
    ]
    seen_dates = [r[4] for r in visible if r[4] is not None]
    first_seen_at = min(seen_dates) if seen_dates else None
    return cve_out(vuln, affected_devices, first_seen_at)
