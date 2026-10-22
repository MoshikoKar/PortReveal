"""CVE-centric vulnerability dashboard (spec section 5.7): the summary endpoint backing every
card/facet/chart/top-list, the filterable/paginated finding list, and the per-CVE detail page.
Report-only: dismiss/undismiss stay on the existing device-scoped endpoints in api/devices.py.
"""
from __future__ import annotations

import csv
import io
from collections.abc import Iterator
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import StreamingResponse
from sqlalchemy import and_, func, literal_column, or_, select
from sqlalchemy.orm import Session

from ..auth.deps import current_user
from ..core.mockdata import device_visible
from ..core.query.sqlfn import ipv4_int_expr
from ..core.vuln.buckets import severity_bucket, severity_bucket_expr
from ..core.vuln.display import is_visible, normalize_cve_id
from ..core.vuln.filters import (
    NETWORK_UNASSIGNED,
    FindingFilters,
    content_disposition_attachment,
    csv_safe_cell,
    parse_network_id_param,
    sanitize_filename_part,
)
from ..core.vuln.score import DEFAULT_CVSS, RISK_BANDS, RISK_HIGH_THRESHOLD, RISK_MEDIUM_THRESHOLD
from ..core.vuln.summary import get_vuln_summary
from ..db import SessionLocal, get_db, utcnow
from ..models import (
    SCAN_COMPLETED,
    SCAN_PARTIAL,
    VULN_STATE_DISMISSED,
    VULN_STATE_POTENTIAL,
    VULN_STATES,
    Device,
    DevicePort,
    DevicePortVuln,
    Network,
    Scan,
    User,
    VulnCpeMatch,
    Vulnerability,
    VulnFeedState,
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
NEW_SINCE_PATTERN = "^(scan|db)$"
FINDING_SORTS = ("risk", "cve", "device", "network", "port", "cvss", "state", "first_seen")
FINDING_SORT_PATTERN = "^(" + "|".join(FINDING_SORTS) + ")$"

CVE_NVD_URL = "https://nvd.nist.gov/vuln/detail/{cve_id}"


def _parse_network_id_param(raw: str | None) -> str | None:
    """Accept a numeric network id or the facet sentinel ``unassigned``; reject other strings."""
    try:
        return parse_network_id_param(raw)
    except ValueError as exc:
        raise HTTPException(422, "network_id must be an integer or 'unassigned'") from exc


def _finding_filters_from_request(
    *,
    severity: str | None = None,
    kev: bool | None = None,
    epss_min: float | None = None,
    network_id: str | None = None,
    service: str | None = None,
    port: int | None = None,
    os_name: str | None = None,
    device_type: str | None = None,
    state: str | None = None,
    cve_age: str | None = None,
    exposure_duration: str | None = None,
    risk_band: str | None = None,
    vendor: str | None = None,
    product: str | None = None,
    cve_id: str | None = None,
    device_uuid: str | None = None,
    new_since: str | None = None,
) -> FindingFilters:
    """Shared query→FindingFilters mapping for list, export, and summary."""
    return FindingFilters(
        severity=severity, kev=kev, epss_min=epss_min, network_id=_parse_network_id_param(network_id),
        service=service, port=port, os_name=os_name, device_type=device_type,
        state=state, cve_age=cve_age, exposure_duration=exposure_duration,
        risk_band=risk_band, vendor=vendor, product=product,
        cve_id=cve_id, device_uuid=device_uuid, new_since=new_since,
    )


@router.get("/summary")
def vuln_summary_route(
    severity: str | None = Query(None, pattern=SEVERITY_PATTERN),
    kev: bool | None = None,
    epss_min: float | None = Query(None, ge=0.0, le=1.0),
    network_id: str | None = Query(None, max_length=32),
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
    cve_id: str | None = Query(None, max_length=32),
    device_uuid: str | None = Query(None, max_length=64),
    new_since: str | None = Query(None, pattern=NEW_SINCE_PATTERN),
    db: Session = Depends(get_db),
    user: User = Depends(current_user),
):
    """Severity/KEV/EPSS/confirmed-potential counts, high-risk device levels, feed staleness,
    facet breakdowns, the weekly new/resolved/dismissed trend and top-10 CVEs/devices.

    Accepts the same filters as GET /api/vulns so the dashboard cards/charts scope with the page.
    Unfiltered responses are cached; filtered responses recompute and leave the cache alone.
    """
    filters = _finding_filters_from_request(
        severity=severity, kev=kev, epss_min=epss_min, network_id=network_id,
        service=service, port=port, os_name=os_name, device_type=device_type,
        state=state, cve_age=cve_age, exposure_duration=exposure_duration, risk_band=risk_band,
        vendor=vendor, product=product, cve_id=cve_id, device_uuid=device_uuid,
        new_since=new_since,
    )
    return get_vuln_summary(db, now=utcnow(), filters=filters)


def _new_since_cutoff(db: Session, kind: str) -> datetime | None:
    if kind == "scan":
        return db.scalar(
            select(Scan.finished_at)
            .where(Scan.status.in_((SCAN_COMPLETED, SCAN_PARTIAL)), Scan.finished_at.isnot(None))
            .order_by(Scan.finished_at.desc()).limit(1)
        )
    # "db": newest last_synced_at among the sources enabled in settings (same as summary feed).
    cfg = get_section(db, VulnSettings)
    timestamps = list(db.scalars(
        select(VulnFeedState.last_synced_at).where(
            VulnFeedState.source.in_(cfg.sources),
            VulnFeedState.last_synced_at.isnot(None),
        )
    ))
    return max(timestamps) if timestamps else None


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
        if f.network_id == NETWORK_UNASSIGNED:
            q = q.where(Device.network_id.is_(None))
        else:
            q = q.where(Device.network_id == int(f.network_id))
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
    if f.cve_id is not None:
        q = q.where(DevicePortVuln.cve_id == normalize_cve_id(f.cve_id))
    if f.device_uuid is not None:
        q = q.where(Device.uuid == f.device_uuid)
    if f.new_since is not None:
        cutoff = _new_since_cutoff(db, f.new_since)
        if cutoff is None:
            q = q.where(literal_column("0") == 1)
        else:
            seen_at = func.coalesce(VulnFindingLifecycle.first_seen_at, DevicePortVuln.matched_at)
            q = q.where(seen_at.isnot(None), seen_at >= cutoff)
    return q


def _findings_order_by(db: Session, sort: str, order: str) -> list:
    """ORDER BY for the finding list. `risk` (default) is the triage order -- KEV first, then highest
    CVSS -- and ignores `order`; every other column is directed, then falls back to that order."""
    triage = [Vulnerability.kev.desc(), Vulnerability.cvss_base.desc().nulls_last(), DevicePortVuln.id]
    if sort == "risk":
        return triage
    keys = {
        "cve": Vulnerability.cve_id,
        "device": ipv4_int_expr(db.get_bind().dialect.name, Device.current_ip),
        "network": Network.name,
        "port": DevicePort.port,
        "cvss": Vulnerability.cvss_base,
        "state": DevicePortVuln.state,
        "first_seen": func.coalesce(VulnFindingLifecycle.first_seen_at, DevicePortVuln.matched_at),
    }
    key = keys[sort]
    return [(key.desc() if order == "desc" else key.asc()).nulls_last(), *triage]


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


@router.get("")
def list_vulns(
    severity: str | None = Query(None, pattern=SEVERITY_PATTERN),
    kev: bool | None = None,
    epss_min: float | None = Query(None, ge=0.0, le=1.0),
    network_id: str | None = Query(None, max_length=32),
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
    cve_id: str | None = Query(None, max_length=32),
    device_uuid: str | None = Query(None, max_length=64),
    new_since: str | None = Query(None, pattern=NEW_SINCE_PATTERN),
    sort: str = Query("risk", pattern=FINDING_SORT_PATTERN),
    order: str = Query("asc", pattern="^(asc|desc)$"),
    paging: Paging = Depends(),
    db: Session = Depends(get_db),
    user: User = Depends(current_user),
):
    """Filterable, sortable, paginated, CVE-centric finding list -- every card/facet on `/vulnerabilities`
    links here with matching query params, so the URL is shareable (spec UX)."""
    cfg = get_section(db, VulnSettings)
    now = utcnow()
    filters = _finding_filters_from_request(
        severity=severity, kev=kev, epss_min=epss_min, network_id=network_id,
        service=service, port=port, os_name=os_name, device_type=device_type,
        state=state, cve_age=cve_age, exposure_duration=exposure_duration, risk_band=risk_band,
        vendor=vendor, product=product, cve_id=cve_id, device_uuid=device_uuid,
        new_since=new_since,
    )
    total = db.scalar(_apply_filters(_count_base(), db, cfg, filters, now)) or 0
    rows = db.execute(
        _apply_filters(_rows_base(), db, cfg, filters, now)
        .order_by(*_findings_order_by(db, sort, order))
        .offset(paging.offset).limit(paging.page_size)
    ).all()
    items = [
        vuln_finding_out(dpv, port_row, device, vuln, network_name, first_seen_at)
        for dpv, port_row, device, vuln, network_name, first_seen_at in rows
    ]
    return paged(items, total, paging)


def _csv_local_tz_label() -> str:
    """Short timezone label for CSV date column headers (e.g. IDT, UTC, EST)."""
    return datetime.now().astimezone().tzname() or "local"


def _csv_columns() -> list[str]:
    """Stable headers; date columns name the local timezone Excel will see."""
    tz = _csv_local_tz_label()
    return [
        "network",
        "device_name",
        "hostname",
        "ip",
        "mac",
        "port",
        "protocol",
        "service",
        "product",
        "version",
        "cve",
        "title",
        "cvss",
        "severity",
        "kev",
        "epss",
        "state",
        f"first_seen ({tz})",
        f"last_matched ({tz})",
        "cve_link",
    ]


def _csv_local_date(ts: datetime | None) -> str:
    """Excel-friendly local wall time ``YYYY-MM-DD HH:MM:SS``; empty when unknown."""
    if ts is None:
        return ""
    local = ts.astimezone() if ts.tzinfo is not None else ts.replace(tzinfo=datetime.now().astimezone().tzinfo)
    return local.strftime("%Y-%m-%d %H:%M:%S")


def _export_row(dpv: DevicePortVuln, port_row: DevicePort, device: Device, vuln: Vulnerability,
                network_name: str | None, first_seen_at: datetime | None) -> list:
    device_name = device.hostname or device.discovery_name or device.current_ip or ""
    title = (vuln.summary or "").replace("\r\n", " ").replace("\n", " ").strip()
    cells = [
        network_name or "Unassigned",
        device_name,
        device.hostname or "",
        device.current_ip or "",
        device.mac or "",
        port_row.port,
        port_row.protocol,
        port_row.service or "",
        port_row.product or "",
        port_row.version or "",
        vuln.cve_id,
        title,
        vuln.cvss_base if vuln.cvss_base is not None else "",
        severity_bucket(vuln.cvss_base),
        "Yes" if vuln.kev else "No",
        vuln.epss if vuln.epss is not None else "",
        dpv.state,
        _csv_local_date(first_seen_at),
        _csv_local_date(dpv.matched_at),
        CVE_NVD_URL.format(cve_id=vuln.cve_id),
    ]
    return [csv_safe_cell(c) for c in cells]


def _export_filename(db: Session, filters: FindingFilters) -> str:
    """``vulns_<context>_<yyyymmdd>.csv`` with a sanitized filter slug when scoped.

    Unicode network names are preserved in the filename (paired with an ASCII
    ``Content-Disposition`` fallback via ``content_disposition_attachment``).
    """
    day = datetime.now().strftime("%Y%m%d")
    parts: list[str] = []
    if filters.network_id == NETWORK_UNASSIGNED:
        parts.append("unassigned")
    elif filters.network_id is not None:
        name = db.scalar(select(Network.name).where(Network.id == int(filters.network_id)))
        parts.append(sanitize_filename_part(name or f"net{filters.network_id}"))
    if filters.device_uuid:
        parts.append(sanitize_filename_part(f"device-{filters.device_uuid[:8]}"))
    if filters.cve_id:
        parts.append(sanitize_filename_part(normalize_cve_id(filters.cve_id)))
    if filters.kev is True:
        parts.append("kev")
    elif filters.kev is False:
        parts.append("not-kev")
    if filters.severity:
        parts.append(sanitize_filename_part(filters.severity))
    if filters.state:
        parts.append(sanitize_filename_part(filters.state))
    slug = "_".join(parts) if parts else "all"
    return f"vulns_{slug}_{day}.csv"


def _export_lines(filters: FindingFilters, now: datetime) -> Iterator[str]:
    db = SessionLocal()
    try:
        cfg = get_section(db, VulnSettings)
        buf = io.StringIO()
        # UTF-8 BOM so Excel on Windows opens Hebrew / non-ASCII titles correctly.
        buf.write("\ufeff")
        writer = csv.writer(buf)
        writer.writerow(_csv_columns())
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
    network_id: str | None = Query(None, max_length=32),
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
    cve_id: str | None = Query(None, max_length=32),
    device_uuid: str | None = Query(None, max_length=64),
    new_since: str | None = Query(None, pattern=NEW_SINCE_PATTERN),
    db: Session = Depends(get_db),
    user: User = Depends(current_user),
):
    """Same filters as GET /api/vulns, no pagination: every matching row, streamed as UTF-8 CSV (BOM)."""
    filters = _finding_filters_from_request(
        severity=severity, kev=kev, epss_min=epss_min, network_id=network_id,
        service=service, port=port, os_name=os_name, device_type=device_type,
        state=state, cve_age=cve_age, exposure_duration=exposure_duration, risk_band=risk_band,
        vendor=vendor, product=product, cve_id=cve_id, device_uuid=device_uuid,
        new_since=new_since,
    )
    filename = _export_filename(db, filters)
    return StreamingResponse(
        _export_lines(filters, utcnow()),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": content_disposition_attachment(filename)},
    )


@router.get("/{cve_id}")
def cve_detail(cve_id: str, db: Session = Depends(get_db), user: User = Depends(current_user)):
    """Metadata, visibility-filtered affected devices/services, and first-seen (the earliest
    lifecycle first_seen_at across those devices) for one CVE.

    404 only when the CVE is absent from the local cache. A known CVE with no visible
    affected devices (none matched, filtered by min_cvss_display, or on hidden devices)
    still returns metadata with an empty ``affected_devices`` list.
    """
    cve_id = normalize_cve_id(cve_id)
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
