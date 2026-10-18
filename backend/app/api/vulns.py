"""CVE-centric vulnerability dashboard (spec section 5.7): the summary endpoint backing every
card/facet/chart/top-list, the filterable/paginated finding list, and the per-CVE detail page.
Report-only: dismiss/undismiss stay on the existing device-scoped endpoints in api/devices.py.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import and_, func, literal_column, or_, select
from sqlalchemy.orm import Session

from ..auth.deps import current_user
from ..core.mockdata import device_visible
from ..core.vuln.buckets import severity_bucket_expr
from ..core.vuln.display import is_visible
from ..core.vuln.score import DEFAULT_CVSS
from ..core.vuln.summary import get_vuln_summary
from ..db import get_db, utcnow
from ..models import (
    VULN_STATE_DISMISSED,
    VULN_STATE_POTENTIAL,
    VULN_STATES,
    Device,
    DevicePort,
    DevicePortVuln,
    Network,
    User,
    Vulnerability,
    VulnFindingLifecycle,
)
from ..settings_store import VulnSettings, get_section
from .common import Paging, cve_out, paged, vuln_finding_out

router = APIRouter(prefix="/api/vulns", tags=["vulns"])

AGE_BUCKETS = ("under_30d", "30_90d", "90_365d", "over_365d", "unknown")
AGE_BUCKET_PATTERN = "^(" + "|".join(AGE_BUCKETS) + ")$"
SEVERITY_PATTERN = "^(critical|high|medium|low)$"
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
    return q


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
    paging: Paging = Depends(),
    db: Session = Depends(get_db),
    user: User = Depends(current_user),
):
    """Filterable, paginated, CVE-centric finding list -- every card/facet on `/vulnerabilities`
    links here with matching query params, so the URL is shareable (spec UX)."""
    cfg = get_section(db, VulnSettings)
    now = utcnow()
    filters = FindingFilters(severity=severity, kev=kev, epss_min=epss_min, network_id=network_id,
                             service=service, port=port, os_name=os_name, device_type=device_type,
                             state=state, cve_age=cve_age, exposure_duration=exposure_duration)
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


@router.get("/{cve_id}")
def cve_detail(cve_id: str, db: Session = Depends(get_db), user: User = Depends(current_user)):
    """Metadata, visibility-filtered affected devices/services, and first-seen (the earliest
    lifecycle first_seen_at across those devices) for one CVE."""
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
    if not visible:
        raise HTTPException(404, "Unknown CVE")
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
