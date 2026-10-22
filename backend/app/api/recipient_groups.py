"""CRUD for notification recipient groups (channels)."""

from __future__ import annotations

import re
from urllib.parse import urlparse

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from ..auth.deps import client_ip, require_admin
from ..core.audit import audit
from ..core.channels import daily_seed_last_digest_on, send_group_test
from ..db import get_db, utcnow
from ..models import (
    DELIVERY_DAILY,
    DELIVERY_IMMEDIATE,
    DELIVERY_MODES,
    DEST_EMAIL,
    DEST_KINDS,
    DEST_SLACK,
    DEST_TEAMS,
    DEST_WEBHOOK,
    EVENT_TYPES,
    SEVERITIES,
    Network,
    RecipientDestination,
    RecipientGroup,
    WebhookEndpoint,
)
from ..security import decrypt_secret, encrypt_secret
from .common import UNPAGED_LIST, Row

router = APIRouter(prefix="/api/recipient-groups", tags=["recipient-groups"])

_EMAIL_RE = re.compile(r"[^@\s]+@[^@\s]+")
_TIME_RE = re.compile(r"^(\d{1,2}):(\d{2})$")


class DestinationIn(BaseModel):
    id: int | None = None
    kind: str
    enabled: bool = True
    target: str | None = Field(None, max_length=255)  # email address
    webhook_id: int | None = None
    # Slack / Teams incoming webhook URL — write-only; never returned in full.
    url: str | None = Field(None, max_length=2000)


class GroupIn(BaseModel):
    name: str = Field(..., max_length=120)
    enabled: bool = True
    event_types: list[str] | None = None
    min_severity: str = "info"
    network_ids: list[int] | None = None
    delivery_mode: str = DELIVERY_DAILY
    digest_time: str | None = Field(None, max_length=5)
    max_per_hour: int = Field(20, ge=1, le=500)
    dedupe_seconds: int = Field(300, ge=0, le=86400)
    quiet_start: str | None = Field(None, max_length=5)
    quiet_end: str | None = Field(None, max_length=5)
    quiet_bypass_critical: bool = True
    destinations: list[DestinationIn] = Field(default_factory=list)


class GroupPatch(BaseModel):
    name: str | None = Field(None, max_length=120)
    enabled: bool | None = None
    event_types: list[str] | None = None
    min_severity: str | None = None
    network_ids: list[int] | None = None
    delivery_mode: str | None = None
    digest_time: str | None = Field(None, max_length=5)
    max_per_hour: int | None = Field(None, ge=1, le=500)
    dedupe_seconds: int | None = Field(None, ge=0, le=86400)
    quiet_start: str | None = Field(None, max_length=5)
    quiet_end: str | None = Field(None, max_length=5)
    quiet_bypass_critical: bool | None = None
    destinations: list[DestinationIn] | None = None


def _norm_time(value: str | None, field: str) -> str | None:
    if value is None or value.strip() == "":
        return None
    m = _TIME_RE.fullmatch(value.strip())
    if not m or int(m.group(1)) > 23 or int(m.group(2)) > 59:
        raise HTTPException(422, f"{field} must be HH:MM (24h)")
    return f"{int(m.group(1)):02d}:{m.group(2)}"


def _validate_group_fields(
    *,
    name: str,
    min_severity: str,
    delivery_mode: str,
    event_types: list[str] | None,
    digest_time: str | None,
    quiet_start: str | None,
    quiet_end: str | None,
) -> tuple[str, str, str, list[str] | None, str | None, str | None, str | None]:
    name = name.strip()
    if not name:
        raise HTTPException(422, "name is required")
    if min_severity not in SEVERITIES:
        raise HTTPException(422, f"min_severity must be one of {SEVERITIES}")
    if delivery_mode not in DELIVERY_MODES:
        raise HTTPException(422, f"delivery_mode must be one of {DELIVERY_MODES}")
    if event_types is not None:
        bad = [t for t in event_types if t not in EVENT_TYPES]
        if bad:
            raise HTTPException(422, f"unknown event types: {bad}")
    digest_time = _norm_time(digest_time, "digest_time")
    quiet_start = _norm_time(quiet_start, "quiet_start")
    quiet_end = _norm_time(quiet_end, "quiet_end")
    if delivery_mode == DELIVERY_DAILY and not digest_time:
        digest_time = "08:00"
    if delivery_mode == DELIVERY_IMMEDIATE:
        digest_time = None
    return name, min_severity, delivery_mode, event_types, digest_time, quiet_start, quiet_end


def _mask_url(url: str) -> str:
    try:
        parsed = urlparse(url)
        host = parsed.hostname or "?"
        scheme = parsed.scheme if parsed.scheme in ("http", "https") else "https"
    except Exception:
        host, scheme = "?", "https"
    return f"{scheme}://{host}/…"


def _dest_out(d: RecipientDestination) -> dict:
    data = {
        "id": d.id,
        "kind": d.kind,
        "enabled": d.enabled,
        "target": d.target if d.kind == DEST_EMAIL else None,
        "webhook_id": d.webhook_id,
        "has_url": bool(d.url_enc) if d.kind in (DEST_SLACK, DEST_TEAMS) else False,
        "url_hint": None,
    }
    if d.kind in (DEST_SLACK, DEST_TEAMS) and d.url_enc:
        try:
            data["url_hint"] = _mask_url(decrypt_secret(d.url_enc))
        except Exception:
            data["url_hint"] = "…"
    return data


def _network_names(db: Session, ids: list[int] | None) -> dict[int, str]:
    if not ids:
        return {}
    rows = db.scalars(select(Network).where(Network.id.in_(ids))).all()
    return {n.id: n.name for n in rows}


def _group_summary(g: RecipientGroup, net_names: dict[int, str] | None = None) -> str:
    """One-line card summary — omits name and delivery mode (badges cover those)."""
    sev = {
        "high": "Critical+High",
        "medium": "Medium+",
        "low": "Low+",
        "info": "All severities",
    }.get(g.min_severity or "info", (g.min_severity or "info").capitalize())
    ids = list(g.network_ids or [])
    if not ids:
        nets = "All networks"
    else:
        names = net_names or {}
        labels = [names.get(i) or f"#{i}" for i in ids]
        if len(labels) == 1:
            nets = labels[0]
        elif len(labels) == 2:
            nets = f"{labels[0]}, {labels[1]}"
        else:
            nets = f"{labels[0]}, {labels[1]} +{len(labels) - 2}"
    # Delivery mode (and daily clock) live on the badge only — avoid doubling.
    return f"{sev} · {nets}"


def _friendly_error(err: str | None) -> str | None:
    if not err:
        return None
    low = err.lower()
    if "timeout" in low or "deadline" in low:
        return "Delivery timed out"
    if "connection" in low or "connect" in low:
        return "Could not reach destination"
    if low.startswith("http "):
        return f"Destination returned an error ({err.split()[1] if len(err.split()) > 1 else 'HTTP'})"
    if "smtp" in low:
        return "Email delivery failed"
    return "Delivery failed"


def _destination_kind_labels(dests: list[dict]) -> list[str]:
    """Badge labels — email shows address or recipient count."""
    kinds: list[str] = []
    emails = [d["target"] for d in dests if d.get("kind") == DEST_EMAIL and d.get("target")]
    if len(emails) == 1:
        kinds.append(f"Email · {emails[0]}")
    elif len(emails) > 1:
        kinds.append(f"Email · {len(emails)} recipients")
    for d in dests:
        if d.get("kind") == DEST_EMAIL:
            continue
        label = {"slack": "Slack", "teams": "Teams", "webhook": "Webhook"}.get(d["kind"], d["kind"])
        if label not in kinds:
            kinds.append(label)
    return kinds


def _out(g: RecipientGroup, net_names: dict[int, str] | None = None) -> dict:
    dests = [_dest_out(d) for d in (g.destinations or [])]
    kinds = _destination_kind_labels(dests)
    return {
        "id": g.id,
        "name": g.name,
        "enabled": g.enabled,
        "is_default": g.is_default,
        "event_types": g.event_types or [],
        "min_severity": g.min_severity,
        "network_ids": g.network_ids or [],
        "delivery_mode": g.delivery_mode,
        "digest_time": g.digest_time,
        "max_per_hour": g.max_per_hour,
        "dedupe_seconds": g.dedupe_seconds,
        "quiet_start": g.quiet_start,
        "quiet_end": g.quiet_end,
        "quiet_bypass_critical": g.quiet_bypass_critical,
        "summary": _group_summary(g, net_names),
        "destination_kinds": kinds,
        "destinations": dests,
        "created_at": g.created_at,
        "updated_at": g.updated_at,
        "last_success_at": g.last_success_at,
        "last_error": g.last_error,
        "last_error_at": g.last_error_at,
        "last_error_friendly": _friendly_error(g.last_error),
    }


def _require_destinations(destinations: list[DestinationIn] | None, *, allow_empty_disabled: bool = False) -> None:
    if destinations is None:
        return
    if not destinations:
        raise HTTPException(422, "at least one destination is required")
    if not any(d.enabled for d in destinations) and not allow_empty_disabled:
        raise HTTPException(422, "at least one destination must be enabled (or disable the group)")


def _validate_network_ids(db: Session, network_ids: list[int] | None) -> list[int] | None:
    if not network_ids:
        return None
    existing = set(db.scalars(select(Network.id).where(Network.id.in_(network_ids))).all())
    missing = [i for i in network_ids if i not in existing]
    if missing:
        raise HTTPException(422, f"unknown network_ids: {missing}")
    return list(network_ids)


def _apply_destinations(db: Session, group: RecipientGroup, destinations: list[DestinationIn]) -> None:
    existing = {d.id: d for d in (group.destinations or []) if d.id is not None}
    keep: set[int] = set()
    for raw in destinations:
        kind = raw.kind
        if kind not in DEST_KINDS:
            raise HTTPException(422, f"unknown destination kind: {kind}")
        row: RecipientDestination | None = existing.get(raw.id) if raw.id else None
        if row is None:
            row = RecipientDestination(group=group, kind=kind)
            db.add(row)
        row.kind = kind
        row.enabled = raw.enabled
        row.target = None
        row.webhook_id = None
        if kind == DEST_EMAIL:
            addr = (raw.target or "").strip()
            if not addr or not _EMAIL_RE.fullmatch(addr):
                raise HTTPException(422, f"invalid email address: {raw.target!r}")
            row.target = addr
        elif kind == DEST_WEBHOOK:
            if raw.webhook_id is None or db.get(WebhookEndpoint, raw.webhook_id) is None:
                raise HTTPException(422, "webhook_id must reference an existing webhook")
            row.webhook_id = raw.webhook_id
        elif kind in (DEST_SLACK, DEST_TEAMS):
            if raw.url is not None and raw.url.strip():
                u = raw.url.strip()
                if not (u.startswith("https://") or u.startswith("http://")):
                    raise HTTPException(422, "url must start with http:// or https://")
                if not (urlparse(u).hostname or "").strip():
                    raise HTTPException(422, "url must include a host")
                row.url_enc = encrypt_secret(u)
            elif row.id is None or not row.url_enc:
                raise HTTPException(422, f"{kind} destination requires a webhook URL")
            # else: keep existing url_enc
        if row.id is not None:
            keep.add(row.id)
    for did, row in list(existing.items()):
        if did not in keep:
            db.delete(row)


@router.get("", response_model=list[Row], description=UNPAGED_LIST)
def list_groups(db: Session = Depends(get_db), user=Depends(require_admin)):
    rows = (
        db.scalars(select(RecipientGroup).options(selectinload(RecipientGroup.destinations)).order_by(RecipientGroup.id))
        .unique()
        .all()
    )
    all_net_ids = {i for g in rows for i in (g.network_ids or [])}
    names = _network_names(db, list(all_net_ids)) if all_net_ids else {}
    return [_out(g, names) for g in rows]


@router.post("", status_code=201)
def create_group(body: GroupIn, request: Request, db: Session = Depends(get_db), user=Depends(require_admin)):
    name, min_sev, mode, types, digest, qs, qe = _validate_group_fields(
        name=body.name,
        min_severity=body.min_severity,
        delivery_mode=body.delivery_mode,
        event_types=body.event_types,
        digest_time=body.digest_time,
        quiet_start=body.quiet_start,
        quiet_end=body.quiet_end,
    )
    _require_destinations(body.destinations)
    net_ids = _validate_network_ids(db, body.network_ids)
    g = RecipientGroup(
        name=name,
        enabled=body.enabled,
        is_default=False,
        event_types=types,
        min_severity=min_sev,
        network_ids=net_ids,
        delivery_mode=mode,
        digest_time=digest,
        max_per_hour=body.max_per_hour,
        dedupe_seconds=body.dedupe_seconds,
        quiet_start=qs,
        quiet_end=qe,
        quiet_bypass_critical=body.quiet_bypass_critical,
        last_digest_on=daily_seed_last_digest_on(digest) if mode == DELIVERY_DAILY else None,
        created_at=utcnow(),
        updated_at=utcnow(),
    )
    db.add(g)
    db.flush()
    _apply_destinations(db, g, body.destinations)
    audit(db, user.username, "recipient_group.create", g.name, {"id": g.id, "mode": mode}, client_ip(request))
    db.commit()
    g = db.scalar(select(RecipientGroup).where(RecipientGroup.id == g.id).options(selectinload(RecipientGroup.destinations)))
    return _out(g, _network_names(db, g.network_ids))


@router.patch("/{group_id}")
def patch_group(
    group_id: int,
    body: GroupPatch,
    request: Request,
    db: Session = Depends(get_db),
    user=Depends(require_admin),
):
    g = db.scalar(select(RecipientGroup).where(RecipientGroup.id == group_id).options(selectinload(RecipientGroup.destinations)))
    if g is None:
        raise HTTPException(404, "group not found")
    data = body.model_dump(exclude_unset=True)
    name = data.get("name", g.name)
    min_sev = data.get("min_severity", g.min_severity)
    mode = data.get("delivery_mode", g.delivery_mode)
    types = data["event_types"] if "event_types" in data else g.event_types
    digest = data["digest_time"] if "digest_time" in data else g.digest_time
    qs = data["quiet_start"] if "quiet_start" in data else g.quiet_start
    qe = data["quiet_end"] if "quiet_end" in data else g.quiet_end
    name, min_sev, mode, types, digest, qs, qe = _validate_group_fields(
        name=name,
        min_severity=min_sev,
        delivery_mode=mode,
        event_types=types,
        digest_time=digest,
        quiet_start=qs,
        quiet_end=qe,
    )
    if "destinations" in data and body.destinations is not None:
        _require_destinations(body.destinations, allow_empty_disabled=not data.get("enabled", g.enabled))
    g.name = name
    if "enabled" in data:
        g.enabled = data["enabled"]
    g.min_severity = min_sev
    g.delivery_mode = mode
    g.event_types = types
    g.digest_time = digest
    g.quiet_start = qs
    g.quiet_end = qe
    if mode == DELIVERY_DAILY and g.last_digest_on is None:
        g.last_digest_on = daily_seed_last_digest_on(digest)
    if "network_ids" in data:
        g.network_ids = _validate_network_ids(db, data["network_ids"])
    if "max_per_hour" in data:
        g.max_per_hour = data["max_per_hour"]
    if "dedupe_seconds" in data:
        g.dedupe_seconds = data["dedupe_seconds"]
    if "quiet_bypass_critical" in data:
        g.quiet_bypass_critical = data["quiet_bypass_critical"]
    if "destinations" in data and body.destinations is not None:
        _apply_destinations(db, g, body.destinations)
    g.updated_at = utcnow()
    audit(db, user.username, "recipient_group.update", g.name, {"id": g.id, "mode": mode}, client_ip(request))
    db.commit()
    g = db.scalar(select(RecipientGroup).where(RecipientGroup.id == g.id).options(selectinload(RecipientGroup.destinations)))
    return _out(g, _network_names(db, g.network_ids))


@router.delete("/{group_id}", status_code=204)
def delete_group(group_id: int, request: Request, db: Session = Depends(get_db), user=Depends(require_admin)):
    g = db.get(RecipientGroup, group_id)
    if g is None:
        raise HTTPException(404, "group not found")
    if g.is_default:
        raise HTTPException(400, "the default email digest group cannot be deleted")
    name = g.name
    db.delete(g)
    audit(db, user.username, "recipient_group.delete", name, {"id": group_id}, client_ip(request))
    db.commit()


@router.post("/{group_id}/test")
def test_group(group_id: int, request: Request, db: Session = Depends(get_db), user=Depends(require_admin)):
    g = db.get(RecipientGroup, group_id)
    if g is None:
        raise HTTPException(404, "group not found")
    name = g.name
    db.commit()  # end read txn before I/O
    try:
        result = send_group_test(group_id)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    audit(
        db,
        user.username,
        "recipient_group.test",
        name,
        {"ok": result.get("ok"), "id": group_id},
        client_ip(request),
    )
    db.commit()
    return result
