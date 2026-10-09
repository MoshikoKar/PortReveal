"""Saved-search evaluation: watches alert on new matches, policies flag every new violating device.

The first evaluation of a search records its current matches silently (its baseline). A broken
query is stored in `last_error` and never interrupts the scan or capture that triggered the run.
"""
from __future__ import annotations

import logging

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db import utcnow
from ..models import (
    EV_POLICY_VIOLATION,
    EV_WATCH_MATCH,
    EVENT_SEVERITY,
    SEARCH_KIND_POLICY,
    Device,
    Event,
    SavedSearch,
    SavedSearchHit,
)
from .compare import device_label
from .query.compile import compile_host
from .query.search import make_ctx, prepare

log = logging.getLogger(__name__)

MAX_ERROR_LEN = 500


def _matching_ids(db: Session, query: str) -> set[int]:
    # Not filtered by device_visible: toggling the simulated-data switch must not re-alert every hit.
    return set(db.scalars(select(Device.id).where(compile_host(prepare(query), make_ctx(db)))).all())


def evaluate(db: Session, search: SavedSearch, *, scan_id: int | None = None) -> list[Event]:
    now = utcnow()
    ids = _matching_ids(db, search.query)
    hits = {h.device_id: h for h in db.scalars(select(SavedSearchHit).where(SavedSearchHit.search_id == search.id))}
    new_ids = sorted(ids - hits.keys())
    events: list[Event] = []
    if search.initialized and new_ids:
        etype = EV_POLICY_VIOLATION if search.kind == SEARCH_KIND_POLICY else EV_WATCH_MATCH
        what = "violates policy" if etype == EV_POLICY_VIOLATION else "matches watch"
        for d in db.scalars(select(Device).where(Device.id.in_(new_ids)).order_by(Device.id)):
            ev = Event(created_at=now, scan_id=scan_id, device=d, event_type=etype, severity=EVENT_SEVERITY[etype],
                       ip=d.current_ip, new_value=search.name,
                       message=f"{device_label(d)} {what} '{search.name}' ({search.query})", notify=search.alert)
            db.add(ev)
            events.append(ev)
    for dev_id in new_ids:
        db.add(SavedSearchHit(search_id=search.id, device_id=dev_id, first_matched_at=now))
    for dev_id, hit in hits.items():
        if dev_id not in ids:
            db.delete(hit)
    search.initialized = True
    search.last_count = len(ids)
    search.last_run_at = now
    search.last_error = None
    return events


def evaluate_all(db: Session, *, scan_id: int | None = None) -> int:
    """Evaluate every saved search; returns the number of alert events created."""
    created = 0
    for search_id in db.scalars(select(SavedSearch.id).order_by(SavedSearch.id)).all():
        search = db.get(SavedSearch, search_id)
        try:
            with db.begin_nested():
                created += len(evaluate(db, search, scan_id=scan_id))
        except Exception as exc:
            log.warning("saved search %s (%s) failed: %s", search_id, search.name, exc)
            db.expire(search)
            search.last_error = str(exc)[:MAX_ERROR_LEN]
            search.last_run_at = utcnow()
    db.flush()
    return created
