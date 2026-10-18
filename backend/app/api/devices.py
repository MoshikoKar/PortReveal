from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import case, func, select
from sqlalchemy.orm import Session, joinedload, selectinload
from sqlalchemy.sql.elements import ColumnElement

from ..auth.deps import client_ip, current_user, require_admin
from ..core.audit import audit
from ..core.availability import AVAILABILITY_WINDOW_DAYS, availability_pct
from ..core.exposure import level as exposure_level
from ..core.mockdata import device_visible, event_visible, scan_visible
from ..core.query.compile import compile_host
from ..core.query.search import http_out, make_ctx, prepare
from ..core.query.sqlfn import ipv4_int_expr
from ..core.tagging import normalize_tag, reclassify_device
from ..db import get_db, utcnow
from ..models import (
    CRITICALITY_LEVELS,
    SCREENSHOT_CAPTURED,
    TAG_SOURCE_MANUAL,
    TAG_SOURCE_RULE,
    TAG_SOURCE_SUPPRESSED,
    VULN_STATE_DISMISSED,
    VULN_STATE_POTENTIAL,
    Device,
    DevicePort,
    DevicePortVuln,
    DeviceProfile,
    DeviceRttSample,
    DeviceTag,
    Event,
    Network,
    Scan,
    ScanHost,
    User,
    VulnJob,
    Vulnerability,
    WebCapture,
    WebPage,
)
from .common import FULL_REPLACE, Paging, device_summary, event_out, paged, port_out

router = APIRouter(prefix="/api/devices", tags=["devices"])

# Soft cap for bulk UUID selection (web capture / scans). Matches settings max_addresses ceiling.
MAX_UUIDS = 4096


def _device_filter_conds(
    db: Session,
    *,
    q: str | None,
    status: str | None,
    network_id: int | None,
    port: int | None,
    service: str | None,
) -> list:
    conds: list = [device_visible(db)]
    if q and q.strip():
        conds.append(compile_host(prepare(q), make_ctx(db)))
    if status:
        conds.append(Device.status == status)
    if network_id is not None:
        conds.append(Device.network_id == network_id)
    if port is not None:
        conds.append(Device.id.in_(select(DevicePort.device_id).where(DevicePort.is_open.is_(True),
                                                                      DevicePort.port == port)))
    if service:
        conds.append(Device.id.in_(select(DevicePort.device_id).where(DevicePort.is_open.is_(True),
                                                                      DevicePort.service == service)))
    return conds


def _ipv4_int_expr(db: Session, col) -> ColumnElement:
    """Numeric IPv4 ORDER BY key (matches netutils.ip_sort_key) for SQLite and PostgreSQL."""
    return ipv4_int_expr(db.get_bind().dialect.name, col)


def _open_port_count_expr():
    return (
        select(func.count(DevicePort.id))
        .where(DevicePort.device_id == Device.id, DevicePort.is_open.is_(True))
        .correlate(Device)
        .scalar_subquery()
    )


def _device_order_by(db: Session, sort: str, order: str) -> list:
    desc = order == "desc"
    ip_key = _ipv4_int_expr(db, Device.current_ip)

    def directed(expr, *, flip: bool = False):
        use_desc = desc ^ flip
        return expr.desc() if use_desc else expr.asc()

    if sort == "hostname":
        host = func.coalesce(func.nullif(Device.hostname, ""), "~")
        return [directed(host), directed(ip_key), directed(Device.id)]
    if sort == "last_seen":
        return [directed(Device.last_seen), directed(Device.id)]
    if sort == "first_seen":
        return [directed(Device.first_seen), directed(Device.id)]
    if sort == "open_ports":
        # Python key was (open_count, -ip); reverse flips both → IP tiebreak opposite primary.
        return [directed(_open_port_count_expr()), directed(ip_key, flip=True), directed(Device.id)]
    if sort == "status":
        return [directed(Device.status), directed(ip_key), directed(Device.id)]
    if sort == "os":
        os_key = func.coalesce(func.nullif(Device.os_name, ""), "~")
        return [directed(os_key), directed(ip_key), directed(Device.id)]
    return [directed(ip_key), directed(Device.id)]


@router.get("")
def list_devices(
    q: str | None = Query(None, max_length=1000),
    status: str | None = Query(None, pattern="^(active|unknown|not_detected)$"),
    network_id: int | None = None,
    port: int | None = Query(None, ge=1, le=65535),
    service: str | None = Query(None, max_length=100),
    sort: str = Query("ip", pattern="^(ip|hostname|last_seen|first_seen|open_ports|status|os)$"),
    order: str = Query("asc", pattern="^(asc|desc)$"),
    paging: Paging = Depends(),
    db: Session = Depends(get_db),
    user: User = Depends(current_user),
):
    conds = _device_filter_conds(db, q=q, status=status, network_id=network_id, port=port, service=service)
    total = db.scalar(select(func.count(Device.id)).where(*conds)) or 0
    devices = list(db.scalars(
        select(Device)
        .where(*conds)
        .order_by(*_device_order_by(db, sort, order))
        .offset(paging.offset)
        .limit(paging.page_size)
        .options(selectinload(Device.ports))
    ).unique().all())
    names = {n.id: n.name for n in db.scalars(select(Network)).all()}
    return paged([device_summary(d, network_name=names.get(d.network_id)) for d in devices], total, paging)


@router.get("/uuids")
def list_device_uuids(
    q: str | None = Query(None, max_length=1000),
    status: str | None = Query(None, pattern="^(active|unknown|not_detected)$"),
    network_id: int | None = None,
    port: int | None = Query(None, ge=1, le=65535),
    service: str | None = Query(None, max_length=100),
    sort: str = Query("ip", pattern="^(ip|hostname|last_seen|first_seen|open_ports|status|os)$"),
    order: str = Query("asc", pattern="^(asc|desc)$"),
    db: Session = Depends(get_db),
    user: User = Depends(current_user),
):
    """All device UUIDs matching the same filters as the list endpoint (for bulk select)."""
    conds = _device_filter_conds(db, q=q, status=status, network_id=network_id, port=port, service=service)
    # LIMIT cap+1 in SQL: never materializes more than the cap; one extra row detects overflow,
    # and the COUNT only runs then (for the error message).
    uuids = list(db.scalars(
        select(Device.uuid).where(*conds).order_by(*_device_order_by(db, sort, order)).limit(MAX_UUIDS + 1)
    ).all())
    if len(uuids) > MAX_UUIDS:
        total = db.scalar(select(func.count(Device.id)).where(*conds)) or 0
        raise HTTPException(422, f"Too many matching devices ({total}); maximum selectable is {MAX_UUIDS}")
    return {"uuids": uuids, "total": len(uuids)}


def _get(db: Session, uuid: str, *, detail: bool = False) -> Device:
    options = [selectinload(Device.ports), selectinload(Device.ips)]
    if detail:
        options = [
            selectinload(Device.ports).joinedload(DevicePort.http),
            selectinload(Device.ips),
            joinedload(Device.network),
            joinedload(Device.tags),
            joinedload(Device.profile),
        ]
    d = db.scalars(select(Device).where(Device.uuid == uuid).options(*options)).unique().one_or_none()
    if d is None:
        raise HTTPException(404, "Device not found")
    return d


def _tag_out(t: DeviceTag) -> dict:
    return {"tag": t.tag, "source": t.source, "reason": t.reason, "created_at": t.created_at}


def _profile_out(p: DeviceProfile | None) -> dict:
    return {
        "owner": p.owner if p else None, "location": p.location if p else None,
        "criticality": p.criticality if p else None, "notes": p.notes if p else None,
        "exposure_factors": (p.exposure_factors or []) if p else [],
        "risk_factors": (p.risk_factors or []) if p else [],
        "type_evidence": (p.type_evidence or []) if p else [],
        "updated_at": p.updated_at if p else None,
    }


def _latest_vuln_job_for_device(db: Session, device_id: int) -> VulnJob | None:
    """Newest job that targeted this device. JSON device_ids is scanned in Python (portable across
    SQLite/Postgres); bound the walk so a busy install cannot load the whole history."""
    # Walk newest-first in chunks until a hit (covers jobs older than a tiny recent window).
    offset, chunk = 0, 100
    while offset < 2000:
        batch = db.scalars(
            select(VulnJob).order_by(VulnJob.id.desc()).offset(offset).limit(chunk)
        ).all()
        if not batch:
            return None
        for j in batch:
            if j.device_ids and device_id in j.device_ids:
                return j
        offset += chunk
    return None


def _vuln_job_summary(j: VulnJob | None) -> dict | None:
    if j is None:
        return None
    return {"id": j.id, "status": j.status, "stage": j.stage, "finished_at": j.finished_at}


@router.get("/{uuid}")
def get_device(uuid: str, db: Session = Depends(get_db), user: User = Depends(current_user)):
    d = _get(db, uuid, detail=True)
    net = d.network
    score = d.exposure_score or 0
    now = utcnow()
    rtt_samples = db.scalars(
        select(DeviceRttSample).where(DeviceRttSample.device_id == d.id)
        .order_by(DeviceRttSample.sampled_at.desc()).limit(200)
    ).all()
    out = device_summary(d, network_name=net.name if net else None)
    out.update({
        "dns_name": d.dns_name,
        "missed_scans": d.missed_scans,
        "last_port_scan_at": d.last_port_scan_at,
        "full_scanned_at": d.full_scanned_at,
        "availability_pct": availability_pct(db, d.id, now=now),
        "availability_window_days": AVAILABILITY_WINDOW_DAYS,
        "rtt_samples": [{"rtt_ms": s.rtt_ms, "sampled_at": s.sampled_at}
                        for s in reversed(rtt_samples)],
        "vuln_job": _vuln_job_summary(_latest_vuln_job_for_device(db, d.id)),
        "ports": [{**port_out(p), "cpe": p.cpe.split() if p.cpe else [], "tunnel": p.tunnel,
                   "http": http_out(p.http)}
                  for p in sorted(d.ports, key=lambda p: (not p.is_open, p.port))],
        "ips": [{"ip": i.ip, "first_seen": i.first_seen, "last_seen": i.last_seen} for i in d.ips],
        "previous_ips": [i.ip for i in d.ips if i.ip != d.current_ip],
        "type": d.device_type,
        "type_confidence": d.type_confidence,
        "score": score,
        "score_level": exposure_level(score),
        "risk_level": exposure_level(d.risk_score or 0),
        "combined_level": exposure_level(d.combined_score or 0),
        "classified_at": d.classified_at,
        "zone": net.zone if net else None,
        "tags": [_tag_out(t) for t in d.tags],
        "profile": _profile_out(d.profile),
    })
    return out


class TagIn(BaseModel):
    tag: str = Field(min_length=1, max_length=120)


@router.post("/{uuid}/tags")
def add_tag(uuid: str, body: TagIn, request: Request, db: Session = Depends(get_db),
            user: User = Depends(require_admin)):
    d = _get(db, uuid)
    try:
        tag = normalize_tag(body.tag)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from None
    row = db.scalar(select(DeviceTag).where(DeviceTag.device_id == d.id, DeviceTag.tag == tag))
    if row is None:
        row = DeviceTag(device_id=d.id, tag=tag, source=TAG_SOURCE_MANUAL, reason=f"added by {user.username}")
        db.add(row)
    elif row.source != TAG_SOURCE_MANUAL:
        # Pin a rule or suppressed tag so it stays even when the rule stops matching.
        row.source, row.reason = TAG_SOURCE_MANUAL, f"pinned by {user.username}"
    audit(db, user.username, "device.tag_add", d.hostname or d.current_ip, {"uuid": d.uuid, "tag": tag},
          client_ip(request))
    db.flush()
    reclassify_device(db, d.id, now=utcnow())
    db.commit()
    db.refresh(row)
    return _tag_out(row)


@router.delete("/{uuid}/tags/{tag}", status_code=204)
def remove_tag(uuid: str, tag: str, request: Request, db: Session = Depends(get_db),
               user: User = Depends(require_admin)):
    d = _get(db, uuid)
    try:
        name = normalize_tag(tag)
    except ValueError:
        name = (tag or "").strip().lower()
    row = db.scalar(select(DeviceTag).where(DeviceTag.device_id == d.id, DeviceTag.tag == name))
    if row is None:
        raise HTTPException(404, "Tag not found")
    action = "device.tag_remove"
    if row.source == TAG_SOURCE_MANUAL:
        db.delete(row)
    elif row.source == TAG_SOURCE_SUPPRESSED:
        # Clear dismiss so the rule may apply again on reclassify.
        db.delete(row)
        action = "device.tag_unsuppress"
    elif row.source == TAG_SOURCE_RULE:
        row.source, row.reason = TAG_SOURCE_SUPPRESSED, f"dismissed by {user.username}"
        action = "device.tag_dismiss"
    else:
        raise HTTPException(409, f"Cannot remove tag with source {row.source}")
    audit(db, user.username, action, d.hostname or d.current_ip, {"uuid": d.uuid, "tag": name},
          client_ip(request))
    db.flush()
    reclassify_device(db, d.id, now=utcnow())
    db.commit()


class ProfileIn(BaseModel):
    owner: str | None = Field(None, max_length=150)
    location: str | None = Field(None, max_length=200)
    criticality: str | None = None
    notes: str | None = Field(None, max_length=5000)

    @field_validator("owner", "location", "notes")
    @classmethod
    def _blank(cls, v: str | None) -> str | None:
        return (v or "").strip() or None

    @field_validator("criticality")
    @classmethod
    def _criticality(cls, v: str | None) -> str | None:
        v = (v or "").strip().lower() or None
        if v is not None and v not in CRITICALITY_LEVELS:
            raise ValueError(f"criticality must be one of: {', '.join(CRITICALITY_LEVELS)}")
        return v


@router.put("/{uuid}/profile", description=FULL_REPLACE)
def update_profile(uuid: str, body: ProfileIn, request: Request, db: Session = Depends(get_db),
                   user: User = Depends(require_admin)):
    d = _get(db, uuid)
    p = db.scalar(select(DeviceProfile).where(DeviceProfile.device_id == d.id))
    if p is None:
        p = DeviceProfile(device_id=d.id)
        db.add(p)
    p.owner, p.location, p.criticality, p.notes = body.owner, body.location, body.criticality, body.notes
    audit(db, user.username, "device.profile_update", d.hostname or d.current_ip,
          {"uuid": d.uuid, **body.model_dump()}, client_ip(request))
    db.commit()
    return _profile_out(p)


TIMELINE_MAX_PER_SOURCE = 200


@router.get("/{uuid}/timeline")
def device_timeline(uuid: str, limit: int = Query(100, ge=1, le=TIMELINE_MAX_PER_SOURCE),
                    db: Session = Depends(get_db), user: User = Depends(current_user)):
    """Events, scans and web captures of one device, newest first (the UI groups them by day)."""
    d = _get(db, uuid)
    items: list[dict] = []
    for e in db.scalars(select(Event).where(Event.device_id == d.id, event_visible(db))
                        .order_by(Event.id.desc()).limit(limit)).unique():
        items.append({"kind": "event", "at": e.created_at, **event_out(e)})
    for sh, s in db.execute(
        select(ScanHost, Scan).join(Scan, Scan.id == ScanHost.scan_id)
        .where(ScanHost.device_id == d.id, scan_visible(db)).order_by(ScanHost.id.desc()).limit(limit)
    ).all():
        items.append({"kind": "scan", "at": sh.created_at, "scan_id": s.id, "scan_type": s.scan_type,
                      "scan_status": s.status, "ip": sh.ip, "status": sh.status, "open_ports": sh.open_ports})
    n_pages = func.count(WebPage.id)
    n_shots = func.sum(case((WebPage.screenshot_status == SCREENSHOT_CAPTURED, 1), else_=0))
    for cap, pages, shots in db.execute(
        select(WebCapture, n_pages, n_shots).join(WebPage, WebPage.capture_id == WebCapture.id)
        .where(WebPage.device_id == d.id).group_by(WebCapture.id).order_by(WebCapture.id.desc()).limit(limit)
    ).all():
        items.append({"kind": "web_capture", "at": cap.finished_at or cap.created_at, "capture_id": cap.id,
                      "status": cap.status, "pages": int(pages), "screenshots": int(shots or 0)})
    items.sort(key=lambda x: x["at"], reverse=True)
    return {"items": items[:limit * 3]}


@router.get("/{uuid}/events")
def device_events(uuid: str, paging: Paging = Depends(), db: Session = Depends(get_db),
                  user: User = Depends(current_user)):
    d = _get(db, uuid)
    conds = (Event.device_id == d.id, event_visible(db))
    base = select(Event).where(*conds)
    total = db.scalar(select(func.count(Event.id)).where(*conds)) or 0
    rows = db.scalars(base.order_by(Event.id.desc()).offset(paging.offset).limit(paging.page_size)).unique().all()
    return paged([event_out(e) for e in rows], total, paging)


@router.get("/{uuid}/scans")
def device_scans(uuid: str, paging: Paging = Depends(), db: Session = Depends(get_db),
                 user: User = Depends(current_user)):
    d = _get(db, uuid)
    conds = (ScanHost.device_id == d.id, scan_visible(db))
    total = db.scalar(select(func.count(ScanHost.id)).join(Scan, Scan.id == ScanHost.scan_id).where(*conds)) or 0
    rows = db.execute(
        select(ScanHost, Scan).join(Scan, Scan.id == ScanHost.scan_id).where(*conds)
        .order_by(ScanHost.id.desc()).offset(paging.offset).limit(paging.page_size)
    ).all()
    items = [{
        "scan_id": s.id, "scan_type": s.scan_type, "scan_status": s.status, "scanner_mode": s.scanner_mode,
        "created_at": sh.created_at, "ip": sh.ip, "status": sh.status, "open_ports": sh.open_ports,
    } for sh, s in rows]
    return paged(items, total, paging)


def _vuln_out(dpv: DevicePortVuln, port: DevicePort, vuln: Vulnerability) -> dict:
    return {
        "cve_id": vuln.cve_id,
        "port": port.port, "protocol": port.protocol, "service": port.service,
        "product": port.product, "version": port.version,
        "matched_cpe": dpv.matched_cpe,
        "state": dpv.state,
        "source": dpv.source,
        "cvss_base": vuln.cvss_base,
        "cvss_vector": vuln.cvss_vector,
        "severity": vuln.severity,
        "kev": vuln.kev,
        "epss": vuln.epss,
        "epss_percentile": vuln.epss_percentile,
        "summary": vuln.summary,
        "matched_at": dpv.matched_at,
    }


@router.get("/{uuid}/vulns")
def device_vulns(uuid: str, db: Session = Depends(get_db), user: User = Depends(current_user)):
    """Every CVE matched to this device's ports (confirmed, potential and dismissed)."""
    from ..settings_store import VulnSettings, get_section

    d = _get(db, uuid)
    cfg = get_section(db, VulnSettings)
    rows = db.execute(
        select(DevicePortVuln, DevicePort, Vulnerability)
        .join(DevicePort, DevicePort.id == DevicePortVuln.device_port_id)
        .join(Vulnerability, Vulnerability.cve_id == DevicePortVuln.cve_id)
        .where(DevicePort.device_id == d.id)
    ).all()
    items = []
    from ..core.vuln.score import DEFAULT_CVSS

    for dpv, port, vuln in rows:
        if not cfg.include_potential and dpv.state == VULN_STATE_POTENTIAL:
            continue
        # Consistent with scoring: missing CVSS uses DEFAULT_CVSS (not 0). KEV is never hidden by
        # the display floor — exploited-in-the-wild entries must remain visible.
        if dpv.state != VULN_STATE_DISMISSED and not vuln.kev:
            effective_cvss = vuln.cvss_base if vuln.cvss_base is not None else DEFAULT_CVSS
            if effective_cvss < cfg.min_cvss_display:
                continue
        items.append(_vuln_out(dpv, port, vuln))
    items.sort(key=lambda it: (it["state"] == VULN_STATE_DISMISSED, it["kev"] is not True,
                               -(it["cvss_base"] or 0)))
    return {"items": items}


@router.post("/{uuid}/vulns/{cve_id}/dismiss")
def dismiss_vuln(uuid: str, cve_id: str, request: Request, db: Session = Depends(get_db),
                 user: User = Depends(require_admin)):
    """Learned no: this match stays dismissed until explicitly undone, even across rematches."""
    from ..core.vuln.score import apply_risk_scores

    d = _get(db, uuid)
    rows = db.scalars(
        select(DevicePortVuln).join(DevicePort, DevicePort.id == DevicePortVuln.device_port_id)
        .where(DevicePort.device_id == d.id, DevicePortVuln.cve_id == cve_id)
    ).all()
    if not rows:
        raise HTTPException(404, "No matching vulnerability on this device")
    for row in rows:
        row.state = VULN_STATE_DISMISSED
    apply_risk_scores(db, [d.id], now=utcnow())
    audit(db, user.username, "device.vuln_dismiss", d.hostname or d.current_ip,
          {"uuid": d.uuid, "cve_id": cve_id}, client_ip(request))
    db.commit()
    return {"ok": True}


@router.delete("/{uuid}/vulns/{cve_id}/dismiss", status_code=204)
def undismiss_vuln(uuid: str, cve_id: str, request: Request, db: Session = Depends(get_db),
                   user: User = Depends(require_admin)):
    from ..core.vuln.score import apply_risk_scores

    d = _get(db, uuid)
    rows = db.scalars(
        select(DevicePortVuln).join(DevicePort, DevicePort.id == DevicePortVuln.device_port_id)
        .where(DevicePort.device_id == d.id, DevicePortVuln.cve_id == cve_id,
               DevicePortVuln.state == VULN_STATE_DISMISSED)
    ).all()
    if not rows:
        raise HTTPException(404, "No dismissed match for this device/CVE")
    for row in rows:
        row.state = VULN_STATE_POTENTIAL  # corrected to `confirmed` (if warranted) on the next match run
    apply_risk_scores(db, [d.id], now=utcnow())
    audit(db, user.username, "device.vuln_undismiss", d.hostname or d.current_ip,
          {"uuid": d.uuid, "cve_id": cve_id}, client_ip(request))
    db.commit()


@router.delete("/{uuid}", status_code=204)
def delete_device(uuid: str, request: Request, db: Session = Depends(get_db), user: User = Depends(require_admin)):
    d = _get(db, uuid)
    audit(db, user.username, "device.delete", d.hostname or d.current_ip, {"uuid": d.uuid, "ip": d.current_ip},
          client_ip(request))
    db.delete(d)
    db.commit()
