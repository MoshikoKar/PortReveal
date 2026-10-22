"""Admin CVE watchlist: subscribe to CVE IDs and alert when they appear in the environment."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..auth.deps import client_ip, current_user, require_admin
from ..core.audit import audit
from ..core.vuln.watchlist import check_watchlist_safe, entry_status, parse_cve_ids
from ..db import get_db, utcnow
from ..models import CveWatchlistEntry, User
from .common import UNPAGED_LIST, Row

router = APIRouter(prefix="/api/cve-watchlist", tags=["cve-watchlist"])


class WatchlistAddIn(BaseModel):
    """Bulk add: `cve_ids` text accepts spaces, commas, newlines, and 'and' as separators."""

    cve_ids: str = Field(..., min_length=1, max_length=8000)
    note: str | None = Field(None, max_length=1000)


class WatchlistPatchIn(BaseModel):
    note: str | None = Field(None, max_length=1000)
    enabled: bool | None = None


def _out(db: Session, entry: CveWatchlistEntry) -> dict:
    status = entry_status(db, entry)
    return {
        "id": entry.id,
        "cve_id": entry.cve_id,
        "note": entry.note,
        "created_by": entry.created_by,
        "created_at": entry.created_at,
        "enabled": entry.enabled,
        **status,
    }


@router.get("", response_model=list[Row], description=UNPAGED_LIST)
def list_watchlist(db: Session = Depends(get_db), user: User = Depends(current_user)):
    rows = db.scalars(select(CveWatchlistEntry).order_by(CveWatchlistEntry.cve_id)).all()
    return [_out(db, e) for e in rows]


@router.post("", status_code=201)
def add_watchlist(body: WatchlistAddIn, request: Request, db: Session = Depends(get_db),
                  user: User = Depends(require_admin)):
    try:
        cve_ids = parse_cve_ids(body.cve_ids)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    note = (body.note or "").strip() or None
    existing = {
        e.cve_id: e
        for e in db.scalars(select(CveWatchlistEntry).where(CveWatchlistEntry.cve_id.in_(cve_ids))).all()
    }
    created: list[CveWatchlistEntry] = []
    for cve_id in cve_ids:
        if cve_id in existing:
            continue
        entry = CveWatchlistEntry(
            cve_id=cve_id, note=note, created_by=user.username, created_at=utcnow(), enabled=True,
        )
        db.add(entry)
        created.append(entry)
    db.flush()
    # Immediate check: if the CVE is already present, alert right away (no silent baseline).
    if created:
        check_watchlist_safe(db, cve_ids=[e.cve_id for e in created], now=utcnow())
    audit(
        db, user.username, "cve_watchlist.add",
        ",".join(e.cve_id for e in created) or None,
        {"requested": cve_ids, "created": [e.cve_id for e in created], "skipped": sorted(existing)},
        client_ip(request),
    )
    db.commit()
    # Return all requested entries (created + already present) in request order.
    by_id = {e.cve_id: e for e in db.scalars(
        select(CveWatchlistEntry).where(CveWatchlistEntry.cve_id.in_(cve_ids))
    ).all()}
    return [_out(db, by_id[c]) for c in cve_ids if c in by_id]


@router.patch("/{entry_id}")
def patch_watchlist(entry_id: int, body: WatchlistPatchIn, request: Request,
                    db: Session = Depends(get_db), user: User = Depends(require_admin)):
    entry = db.get(CveWatchlistEntry, entry_id)
    if entry is None:
        raise HTTPException(404, "Watchlist entry not found")
    if body.note is not None:
        entry.note = body.note.strip() or None
    was_enabled = entry.enabled
    if body.enabled is not None:
        entry.enabled = body.enabled
    db.flush()
    if body.enabled is True and not was_enabled:
        check_watchlist_safe(db, cve_ids=[entry.cve_id], now=utcnow())
    audit(db, user.username, "cve_watchlist.update", entry.cve_id,
          body.model_dump(exclude_none=True), client_ip(request))
    db.commit()
    return _out(db, entry)


@router.delete("/{entry_id}", status_code=204)
def delete_watchlist(entry_id: int, request: Request, db: Session = Depends(get_db),
                     user: User = Depends(require_admin)):
    entry = db.get(CveWatchlistEntry, entry_id)
    if entry is None:
        raise HTTPException(404, "Watchlist entry not found")
    audit(db, user.username, "cve_watchlist.delete", entry.cve_id, None, client_ip(request))
    db.delete(entry)
    db.commit()
