"""Saved-search evaluation: watches alert on new matches, policies flag every new violating device.

The first evaluation of a search records its current matches silently (its baseline). A broken
query is stored in `last_error` and never interrupts the scan or capture that triggered the run.

Evaluation diffs matches against stored hits in SQL and walks new matches in id chunks, so even
a query matching the whole inventory (`*`) never materializes the full matching id set.
"""
from __future__ import annotations

import logging

from sqlalchemy import delete, exists, func, insert, select
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
# New matches handled per round trip (hits inserted, alert events created, then flushed).
CHUNK = 1000


def evaluate(db: Session, search: SavedSearch, *, scan_id: int | None = None) -> int:
    """Re-run one saved search; returns the number of alert events created."""
    now = utcnow()
    # Not filtered by device_visible: toggling the simulated-data switch must not re-alert every hit.
    cond = compile_host(prepare(search.query), make_ctx(db))
    # Hits of devices that no longer match are dropped, so they alert again if they come back.
    db.execute(
        delete(SavedSearchHit)
        .where(SavedSearchHit.search_id == search.id, SavedSearchHit.device_id.not_in(select(Device.id).where(cond)))
        .execution_options(synchronize_session=False)
    )
    already_hit = exists().where(SavedSearchHit.search_id == search.id, SavedSearchHit.device_id == Device.id)
    alert = search.initialized  # the first run records the baseline silently
    etype = EV_POLICY_VIOLATION if search.kind == SEARCH_KIND_POLICY else EV_WATCH_MATCH
    what = "violates policy" if etype == EV_POLICY_VIOLATION else "matches watch"
    created = 0
    last_id = 0
    while True:
        new = select(Device).where(cond, ~already_hit, Device.id > last_id).order_by(Device.id).limit(CHUNK)
        if alert:
            devices = db.scalars(new).all()
            ids = [d.id for d in devices]
        else:
            ids = db.scalars(new.with_only_columns(Device.id)).all()
        if not ids:
            break
        db.execute(insert(SavedSearchHit), [
            {"search_id": search.id, "device_id": dev_id, "first_matched_at": now} for dev_id in ids
        ])
        if alert:
            for d in devices:
                db.add(Event(created_at=now, scan_id=scan_id, device=d, event_type=etype,
                             severity=EVENT_SEVERITY[etype], ip=d.current_ip, new_value=search.name,
                             message=f"{device_label(d)} {what} '{search.name}' ({search.query})",
                             notify=search.alert))
            created += len(devices)
            db.flush()
        last_id = ids[-1]
        if len(ids) < CHUNK:
            break
    search.initialized = True
    search.last_count = db.scalar(select(func.count()).select_from(Device).where(cond)) or 0
    search.last_run_at = now
    search.last_error = None
    return created


def evaluate_all(db: Session, *, scan_id: int | None = None) -> int:
    """Evaluate every saved search; returns the number of alert events created."""
    created = 0
    searches = db.scalars(select(SavedSearch).order_by(SavedSearch.id)).all()
    for search in searches:
        search_id, search_name = search.id, search.name
        try:
            with db.begin_nested():
                created += evaluate(db, search, scan_id=scan_id)
        except Exception as exc:
            log.warning("saved search %s (%s) failed: %s", search_id, search_name, exc)
            db.expire(search)
            search.last_error = str(exc)[:MAX_ERROR_LEN]
            search.last_run_at = utcnow()
    db.flush()
    return created
