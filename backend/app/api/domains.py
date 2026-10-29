"""Domains: subdomain inventory, domain scans (own queue) and manual host lookup.

Read endpoints are open to every signed-in user; changes, scans and lookups (which send DNS
traffic) are admin only, like network scans. Every change and lookup is audit-logged.
"""
from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import String, cast, func, or_, select
from sqlalchemy.orm import Session

from ..auth.deps import client_ip, current_user, require_admin
from ..core.audit import audit
from ..core.domains.classify import records_summary
from ..core.domains.inventory import load_context
from ..core.domains.lookup import add_to_inventory, lookup_host
from ..core.domains.manager import domain_has_active_scan, domain_scan_manager, enqueue_domain_scan
from ..core.domains.runner import DEFAULT_PUBLIC_RESOLVERS, queue_port_scan
from ..core.domains.tools import tool_status
from ..core.domains.validate import DomainError, normalize_domain, normalize_resolvers, normalize_words
from ..core.manager import manager
from ..core.wordlists import KIND_SUBDOMAINS
from ..db import get_db
from ..models import (
    EXPOSURES,
    SCAN_ACTIVE_STATES,
    SCAN_COMPLETED,
    SCAN_PARTIAL,
    SCAN_QUEUED,
    SCAN_RUNNING,
    WORDLIST_MODE_CUSTOM,
    WORDLIST_MODE_LIBRARY,
    WORDLIST_MODE_NONE,
    Device,
    Domain,
    DomainScan,
    Subdomain,
    User,
    Wordlist,
)
from ..settings_store import DomainDiscoverySettings, _hhmm, get_section
from .common import FULL_REPLACE, UNPAGED_LIST, Paging, Row, like_pattern, paged

router = APIRouter(prefix="/api", tags=["domains"])


class ScheduleIn(BaseModel):
    enabled: bool = False
    time: str = Field("03:30", max_length=5)
    days: list[int] = Field(default_factory=lambda: [0, 1, 2, 3, 4, 5, 6])

    @field_validator("time")
    @classmethod
    def _time(cls, v: str) -> str:
        return _hhmm(v, "schedule time")

    @field_validator("days")
    @classmethod
    def _days(cls, v: list[int]) -> list[int]:
        if any(d < 0 or d > 6 for d in v):
            raise ValueError("days must be 0 (Monday) .. 6 (Sunday)")
        return sorted(set(v))


class DomainIn(BaseModel):
    name: str = Field(..., max_length=300)
    enabled: bool = True
    wordlist_mode: Literal["none", "library", "custom"] = WORDLIST_MODE_NONE
    wordlist_id: int | None = Field(None, ge=1)
    custom_words: list[str] = Field(default_factory=list, max_length=5000)
    passive_enabled: bool = True
    axfr_enabled: bool = False
    axfr_servers: list[str] = Field(default_factory=list, max_length=8)
    internal_resolvers: list[str] = Field(default_factory=list, max_length=8)
    public_resolvers: list[str] = Field(default_factory=lambda: list(DEFAULT_PUBLIC_RESOLVERS), max_length=8)
    schedule: ScheduleIn = Field(default_factory=ScheduleIn)
    notes: str | None = Field(None, max_length=2000)


class LookupIn(BaseModel):
    hostname: str = Field(..., max_length=300)


# --- serialization ------------------------------------------------------------------------------
def domain_scan_out(j: DomainScan, domain_name: str | None = None) -> dict:
    return {
        "id": j.id,
        "domain_id": j.domain_id,
        "domain_name": domain_name,
        "status": j.status,
        "trigger": j.trigger,
        "requested_by": j.requested_by,
        "created_at": j.created_at,
        "started_at": j.started_at,
        "finished_at": j.finished_at,
        "stage": j.stage,
        "progress": round(j.progress or 0.0, 4),
        "error": j.error,
        "notes": j.notes,
        "stats": j.stats,
        "wildcard": j.wildcard,
        "axfr": j.axfr,
        "phases": j.phases or [],
        "port_scan_id": j.port_scan_id,
    }


def _last_scan(db: Session, domain_id: int) -> DomainScan | None:
    return db.scalar(select(DomainScan).where(DomainScan.domain_id == domain_id).order_by(DomainScan.id.desc()).limit(1))


def _last_finished(db: Session, domain_id: int) -> DomainScan | None:
    return db.scalar(select(DomainScan).where(DomainScan.domain_id == domain_id,
                                              DomainScan.status.in_((SCAN_COMPLETED, SCAN_PARTIAL)))
                     .order_by(DomainScan.id.desc()).limit(1))


def domain_out(db: Session, d: Domain) -> dict:
    counts = dict(db.execute(
        select(Subdomain.exposure, func.count(Subdomain.id))
        .where(Subdomain.domain_id == d.id, Subdomain.status == "active").group_by(Subdomain.exposure)
    ).all())
    wildcard_n = db.scalar(select(func.count(Subdomain.id)).where(
        Subdomain.domain_id == d.id, Subdomain.status == "active", Subdomain.wildcard.is_(True))) or 0
    wl = db.get(Wordlist, d.wordlist_id) if d.wordlist_id else None
    last = _last_scan(db, d.id)
    finished = _last_finished(db, d.id)
    return {
        "id": d.id,
        "name": d.name,
        "enabled": d.enabled,
        "notes": d.notes,
        "wordlist_mode": d.wordlist_mode,
        "wordlist_id": d.wordlist_id,
        "wordlist_name": wl.name if wl else None,
        # Entries in the selected list vs Settings > Domain discovery > Max wordlist entries (scans use the first N).
        "wordlist_entries": (wl.entries if wl else 0) if d.wordlist_mode == WORDLIST_MODE_LIBRARY
        else len(d.custom_words or []) if d.wordlist_mode == WORDLIST_MODE_CUSTOM else 0,
        "wordlist_limit": get_section(db, DomainDiscoverySettings).max_wordlist_entries,
        "custom_words": list(d.custom_words or []),
        "passive_enabled": d.passive_enabled,
        "axfr_enabled": d.axfr_enabled,
        "axfr_servers": list(d.axfr_servers or []),
        "internal_resolvers": list(d.internal_resolvers or []),
        "public_resolvers": list(d.public_resolvers or []),
        "schedule": d.schedule or ScheduleIn().model_dump(),
        "created_at": d.created_at,
        "updated_at": d.updated_at,
        "created_by": d.created_by,
        "counts": {
            "active": sum(counts.values()),
            **{k: int(counts.get(k, 0)) for k in EXPOSURES},
            "wildcard": wildcard_n,
        },
        "wildcard": (finished.wildcard if finished else None) or {"internal": [], "public": []},
        "zone_transfer_open": [k for k, v in (((finished.axfr if finished else None) or {}).get("public") or {}).items()
                               if v.get("status") == "open"],
        "last_scan": domain_scan_out(last, d.name) if last else None,
    }


def subdomain_out(s: Subdomain, device_uuid: str | None = None) -> dict:
    records = s.records or {}
    return {
        "id": s.id,
        "domain_id": s.domain_id,
        "name": s.name,
        "exposure": s.exposure,
        "records": records,
        "records_summary": records_summary(records.get("internal"), records.get("public")),
        "ips": list(s.ips or []),
        "hosting": list(s.hosting or []),
        "sources": list(s.sources or []),
        "wildcard": s.wildcard,
        "flags": list(s.flags or []),
        "device_uuid": device_uuid,
        "status": s.status,
        "unverified": bool(s.unverified),  # the latest scan could not check it: state kept as is
        "in_progress": bool(s.in_progress),  # written by a running scan, not classified yet
        "missed_scans": s.missed_scans or 0,
        # When a scan last verified the name (None: never, e.g. only discovered by an unfinished scan).
        "last_verified_at": s.last_seen if s.last_scan_id is not None else None,
        "first_seen": s.first_seen,
        "last_seen": s.last_seen,
    }


# --- validation ---------------------------------------------------------------------------------
def _apply(db: Session, d: Domain, body: DomainIn) -> None:
    try:
        name = normalize_domain(body.name)
        words = normalize_words(body.custom_words) if body.wordlist_mode == WORDLIST_MODE_CUSTOM else []
        axfr = normalize_resolvers(body.axfr_servers, field="zone transfer servers")
        internal = normalize_resolvers(body.internal_resolvers, field="internal resolvers")
        public = normalize_resolvers(body.public_resolvers, field="public resolvers")
    except DomainError as exc:
        raise HTTPException(422, str(exc)) from exc
    taken = db.scalar(select(Domain.id).where(Domain.name == name, Domain.id != (d.id or 0)))
    if taken:
        raise HTTPException(409, f"domain {name} already exists")
    if body.wordlist_mode == WORDLIST_MODE_LIBRARY:
        w = db.get(Wordlist, body.wordlist_id) if body.wordlist_id else None
        if w is None:
            raise HTTPException(422, "select a wordlist from the library")
        if w.kind != KIND_SUBDOMAINS:
            raise HTTPException(422, f"wordlist '{w.name}' is a {w.kind} list; select a subdomains list")
    if body.wordlist_mode == WORDLIST_MODE_CUSTOM and not words:
        raise HTTPException(422, "type at least one subdomain label, or choose another wordlist option")
    d.name = name
    d.enabled = body.enabled
    d.wordlist_mode = body.wordlist_mode
    d.wordlist_id = body.wordlist_id if body.wordlist_mode == WORDLIST_MODE_LIBRARY else None
    d.custom_words = words or None
    d.passive_enabled = body.passive_enabled
    d.axfr_enabled = body.axfr_enabled
    d.axfr_servers = axfr
    d.internal_resolvers = internal
    d.public_resolvers = public
    d.schedule = body.schedule.model_dump()
    d.notes = (body.notes or "").strip() or None


def _get_domain(db: Session, domain_id: int) -> Domain:
    d = db.get(Domain, domain_id)
    if d is None:
        raise HTTPException(404, "Domain not found")
    return d


def _audit_body(body: DomainIn) -> dict:
    data = body.model_dump()
    data["custom_words"] = len(body.custom_words)
    return data


# --- static routes first (a {domain_id} route would otherwise swallow them) ----------------------
@router.get("/domains/tools")
def domain_tools(refresh: bool = False, user: User = Depends(current_user)):
    return {name: st.as_dict() for name, st in tool_status(refresh=refresh).items()}


@router.post("/domains/lookup")
def lookup(body: LookupIn, request: Request, db: Session = Depends(get_db), user: User = Depends(require_admin)):
    try:
        result = lookup_host(db, body.hostname)
    except DomainError as exc:
        raise HTTPException(422, str(exc)) from exc
    audit(db, user.username, "domain.lookup", result["hostname"],
          {"domain": result["domain"], "exposure": result["exposure"], "ips": result["ips"]}, client_ip(request))
    db.commit()
    return result


@router.post("/domains/lookup/add", status_code=201)
def lookup_add(body: LookupIn, request: Request, db: Session = Depends(get_db), user: User = Depends(require_admin)):
    try:
        result = lookup_host(db, body.hostname)
    except DomainError as exc:
        raise HTTPException(422, str(exc)) from exc
    row = add_to_inventory(db, result)
    audit(db, user.username, "domain.lookup_add", result["hostname"],
          {"domain": result["domain"], "exposure": result["exposure"], "ips": result["ips"]}, client_ip(request))
    db.commit()
    return subdomain_out(row)


@router.post("/domains/lookup/port-scan")
def lookup_port_scan(body: LookupIn, request: Request, db: Session = Depends(get_db),
                     user: User = Depends(require_admin)):
    try:
        result = lookup_host(db, body.hostname)
    except DomainError as exc:
        raise HTTPException(422, str(exc)) from exc
    if not result["ips"]:
        raise HTTPException(409, f"{result['hostname']} does not resolve; nothing to scan")
    cfg = get_section(db, DomainDiscoverySettings)
    scan_id, targets, reason = queue_port_scan(
        db, result["ips"], load_context(db, result["ips"]), cfg.port_scan_type, requested_by=user.username,
        criteria=f"Manual lookup of {result['hostname']}",
    )
    if scan_id is None:
        raise HTTPException(409, f"No port scan queued: {reason}")
    audit(db, user.username, "domain.lookup_port_scan", result["hostname"],
          {"scan_id": scan_id, "targets": targets}, client_ip(request))
    db.commit()
    manager.wake()
    return {"scan_id": scan_id, "targets": targets}


@router.get("/domain-scans/active")
def active_domain_scans(db: Session = Depends(get_db), user: User = Depends(current_user)):
    names = {d.id: d.name for d in db.scalars(select(Domain)).all()}
    rows = db.scalars(select(DomainScan).where(DomainScan.status.in_(SCAN_ACTIVE_STATES)).order_by(DomainScan.id)).all()
    return {
        "running": [domain_scan_out(j, names.get(j.domain_id)) for j in rows if j.status == SCAN_RUNNING],
        "queued": [domain_scan_out(j, names.get(j.domain_id)) for j in rows if j.status == SCAN_QUEUED],
    }


@router.get("/domain-scans/{scan_id}")
def get_domain_scan(scan_id: int, db: Session = Depends(get_db), user: User = Depends(current_user)):
    j = db.get(DomainScan, scan_id)
    if j is None:
        raise HTTPException(404, "Domain scan not found")
    d = db.get(Domain, j.domain_id)
    return domain_scan_out(j, d.name if d else None)


@router.post("/domain-scans/{scan_id}/cancel")
def cancel_domain_scan(scan_id: int, request: Request, db: Session = Depends(get_db),
                       user: User = Depends(require_admin)):
    j = db.get(DomainScan, scan_id)
    if j is None:
        raise HTTPException(404, "Domain scan not found")
    if j.status not in SCAN_ACTIVE_STATES:
        raise HTTPException(409, f"Domain scan is already {j.status}")
    db.rollback()  # the manager updates the row in its own session
    if not domain_scan_manager.cancel(scan_id):
        raise HTTPException(409, "Could not cancel the domain scan")
    audit(db, user.username, "domain.scan_cancel", f"domain scan {scan_id}", None, client_ip(request))
    db.commit()
    return {"ok": True}


# --- domains CRUD -------------------------------------------------------------------------------
@router.get("/domains", response_model=list[Row], description=UNPAGED_LIST)
def list_domains(db: Session = Depends(get_db), user: User = Depends(current_user)):
    return [domain_out(db, d) for d in db.scalars(select(Domain).order_by(Domain.name)).all()]


@router.post("/domains", status_code=201)
def create_domain(body: DomainIn, request: Request, db: Session = Depends(get_db),
                  user: User = Depends(require_admin)):
    d = Domain(created_by=user.username)
    _apply(db, d, body)
    db.add(d)
    db.flush()
    audit(db, user.username, "domain.create", d.name, _audit_body(body), client_ip(request))
    db.commit()
    return domain_out(db, d)


@router.get("/domains/{domain_id}")
def get_domain(domain_id: int, db: Session = Depends(get_db), user: User = Depends(current_user)):
    return domain_out(db, _get_domain(db, domain_id))


@router.put("/domains/{domain_id}", description=FULL_REPLACE)
def update_domain(domain_id: int, body: DomainIn, request: Request, db: Session = Depends(get_db),
                  user: User = Depends(require_admin)):
    d = _get_domain(db, domain_id)
    try:
        renamed = normalize_domain(body.name) != d.name
    except DomainError as exc:
        raise HTTPException(422, str(exc)) from exc
    if renamed and db.scalar(select(func.count(Subdomain.id)).where(Subdomain.domain_id == d.id)):
        raise HTTPException(409, "the name of a domain with inventory cannot change; add a new domain instead")
    _apply(db, d, body)
    audit(db, user.username, "domain.update", d.name, _audit_body(body), client_ip(request))
    db.commit()
    return domain_out(db, d)


@router.delete("/domains/{domain_id}", status_code=204)
def delete_domain(domain_id: int, request: Request, db: Session = Depends(get_db),
                  user: User = Depends(require_admin)):
    d = _get_domain(db, domain_id)
    if domain_has_active_scan(db, d.id):
        raise HTTPException(409, "a scan of this domain is queued or running; cancel it first")
    audit(db, user.username, "domain.delete", d.name, {"id": d.id}, client_ip(request))
    db.delete(d)
    db.commit()
    return Response(status_code=204)


@router.post("/domains/{domain_id}/scan", status_code=201)
def scan_domain(domain_id: int, request: Request, db: Session = Depends(get_db), user: User = Depends(require_admin)):
    d = _get_domain(db, domain_id)
    if domain_has_active_scan(db, d.id):
        raise HTTPException(409, f"a scan of {d.name} is already queued or running")
    job = enqueue_domain_scan(db, d, requested_by=user.username)
    audit(db, user.username, "domain.scan", d.name, {"domain_scan_id": job.id}, client_ip(request))
    db.commit()
    domain_scan_manager.wake()
    return domain_scan_out(job, d.name)


@router.get("/domains/{domain_id}/scans")
def domain_scans(domain_id: int, paging: Paging = Depends(), db: Session = Depends(get_db),
                 user: User = Depends(current_user)):
    d = _get_domain(db, domain_id)
    total = db.scalar(select(func.count(DomainScan.id)).where(DomainScan.domain_id == d.id)) or 0
    rows = db.scalars(select(DomainScan).where(DomainScan.domain_id == d.id).order_by(DomainScan.id.desc())
                      .offset(paging.offset).limit(paging.page_size)).all()
    return paged([domain_scan_out(j, d.name) for j in rows], total, paging)


_SORTS = {
    "name": Subdomain.name,
    "exposure": Subdomain.exposure,
    "first_seen": Subdomain.first_seen,
    "last_seen": Subdomain.last_seen,
    "status": Subdomain.status,
}


@router.get("/domains/{domain_id}/subdomains")
def list_subdomains(
    domain_id: int,
    q: str | None = Query(None, max_length=200),
    exposure: str | None = Query(None, pattern="^(external|internal|both|unresolved)$"),
    status: str | None = Query("active", pattern="^(active|gone|all)$"),
    source: str | None = Query(None, pattern="^(passive|wordlist|axfr|manual)$"),
    flag: str | None = Query(None, pattern="^(internal_authorized|internal_name_exposed|private_ip_public)$"),
    wildcard: bool | None = None,
    sort: str = Query("name", pattern="^-?(name|exposure|first_seen|last_seen|status)$"),
    paging: Paging = Depends(),
    db: Session = Depends(get_db),
    user: User = Depends(current_user),
):
    d = _get_domain(db, domain_id)
    conds = [Subdomain.domain_id == d.id]
    if status and status != "all":
        conds.append(Subdomain.status == status)
    if exposure:
        conds.append(Subdomain.exposure == exposure)
    if wildcard is not None:
        conds.append(Subdomain.wildcard.is_(wildcard))
    # JSON lists rendered as text: '"passive"' matches the quoted element on SQLite and PostgreSQL alike.
    if source:
        conds.append(cast(Subdomain.sources, String).like(f'%"{source}"%'))
    if flag:
        conds.append(cast(Subdomain.flags, String).like(f'%"{flag}"%'))
    if q and q.strip():
        like = like_pattern(q.strip().lower())
        conds.append(or_(Subdomain.name.like(like, escape="\\"), cast(Subdomain.ips, String).like(like, escape="\\")))
    col = _SORTS[sort.lstrip("-")]
    order = col.desc() if sort.startswith("-") else col.asc()
    total = db.scalar(select(func.count(Subdomain.id)).where(*conds)) or 0
    rows = db.scalars(select(Subdomain).where(*conds).order_by(order, Subdomain.name)
                      .offset(paging.offset).limit(paging.page_size)).all()
    dev_ids = {s.device_id for s in rows if s.device_id}
    uuids = dict(db.execute(select(Device.id, Device.uuid).where(Device.id.in_(dev_ids))).all()) if dev_ids else {}
    return paged([subdomain_out(s, uuids.get(s.device_id)) for s in rows], total, paging)
