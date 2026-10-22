"""Saved-search evaluation: watches alert on new matches, policies flag every new violating device,
and monitors alert when a matching host itself changes.

The first evaluation of a search records its current matches silently (its baseline). A broken
query is stored in `last_error` and never interrupts the scan or capture that triggered the run.

Evaluation diffs matches against stored hits in SQL and walks new matches in id chunks, so even
a query matching the whole inventory (`*`) never materializes the full matching id set.
"""

from __future__ import annotations

import logging

from sqlalchemy import String, cast, delete, exists, func, insert, select
from sqlalchemy.orm import Session, aliased

from ..db import utcnow
from ..models import (
    EV_BANNER_CHANGED,
    EV_DEVICE_DISAPPEARED,
    EV_DEVICE_REAPPEARED,
    EV_IP_CHANGED,
    EV_MONITOR_CHANGE,
    EV_OS_CHANGED,
    EV_POLICY_VIOLATION,
    EV_PORT_CLOSED,
    EV_PORT_OPENED,
    EV_SERVICE_CHANGED,
    EV_SERVICE_DETECTED,
    EV_VERSION_CHANGED,
    EV_WATCH_MATCH,
    EVENT_SEVERITY,
    SEARCH_KIND_MONITOR,
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

# Inventory changes a monitor reports; tags and saved-search events are excluded to avoid recursion.
MONITOR_CHANGE_TYPES = (
    EV_PORT_OPENED,
    EV_PORT_CLOSED,
    EV_SERVICE_DETECTED,
    EV_SERVICE_CHANGED,
    EV_VERSION_CHANGED,
    EV_OS_CHANGED,
    EV_BANNER_CHANGED,
    EV_IP_CHANGED,
    EV_DEVICE_DISAPPEARED,
    EV_DEVICE_REAPPEARED,
)


def evaluate(db: Session, search: SavedSearch, *, scan_id: int | None = None) -> list[int]:
    """Re-run one saved search; returns ids of alert events created."""
    now = utcnow()
    # Not filtered by device_visible: toggling the simulated-data switch must not re-alert every hit.
    cond = compile_host(prepare(search.query), make_ctx(db))
    if search.kind == SEARCH_KIND_MONITOR:
        return _evaluate_monitor(db, search, cond, now, scan_id=scan_id)
    return _evaluate_new_matches(db, search, cond, now, scan_id=scan_id)


def _drop_stale_hits(db: Session, search: SavedSearch, cond) -> None:
    db.execute(
        delete(SavedSearchHit)
        .where(SavedSearchHit.search_id == search.id, SavedSearchHit.device_id.not_in(select(Device.id).where(cond)))
        .execution_options(synchronize_session=False)
    )


def _insert_new_hits(db: Session, search: SavedSearch, cond, now) -> list[int]:
    """Insert hit rows for devices that newly match. Returns their device ids (chunked internally)."""
    already_hit = exists().where(SavedSearchHit.search_id == search.id, SavedSearchHit.device_id == Device.id)
    ids_all: list[int] = []
    last_id = 0
    while True:
        ids = db.scalars(select(Device.id).where(cond, ~already_hit, Device.id > last_id).order_by(Device.id).limit(CHUNK)).all()
        if not ids:
            break
        db.execute(
            insert(SavedSearchHit), [{"search_id": search.id, "device_id": dev_id, "first_matched_at": now} for dev_id in ids]
        )
        ids_all.extend(ids)
        last_id = ids[-1]
        if len(ids) < CHUNK:
            break
    return ids_all


def _finish(db: Session, search: SavedSearch, cond, now) -> None:
    search.initialized = True
    search.last_count = db.scalar(select(func.count()).select_from(Device).where(cond)) or 0
    search.last_run_at = now
    search.last_error = None


def _evaluate_new_matches(db: Session, search: SavedSearch, cond, now, *, scan_id: int | None) -> list[int]:
    """Watch/policy: alert when a host newly matches after the silent baseline."""
    _drop_stale_hits(db, search, cond)
    already_hit = exists().where(SavedSearchHit.search_id == search.id, SavedSearchHit.device_id == Device.id)
    alert = search.initialized  # the first run records the baseline silently
    etype = EV_POLICY_VIOLATION if search.kind == SEARCH_KIND_POLICY else EV_WATCH_MATCH
    what = "violates policy" if etype == EV_POLICY_VIOLATION else "matches watch"
    event_ids: list[int] = []
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
        db.execute(
            insert(SavedSearchHit), [{"search_id": search.id, "device_id": dev_id, "first_matched_at": now} for dev_id in ids]
        )
        if alert:
            created_rows: list[Event] = []
            for d in devices:
                ev = Event(
                    created_at=now,
                    scan_id=scan_id,
                    device=d,
                    event_type=etype,
                    severity=EVENT_SEVERITY[etype],
                    ip=d.current_ip,
                    new_value=search.name,
                    message=f"{device_label(d)} {what} '{search.name}' ({search.query})",
                    notify=search.alert,
                )
                db.add(ev)
                created_rows.append(ev)
            db.flush()
            event_ids.extend(ev.id for ev in created_rows if ev.id is not None)
        last_id = ids[-1]
        if len(ids) < CHUNK:
            break
    _finish(db, search, cond, now)
    return event_ids


def _evaluate_monitor(db: Session, search: SavedSearch, cond, now, *, scan_id: int | None) -> list[int]:
    """Monitor: silent hit sync, then alert on inventory changes to currently matching hosts."""
    prev_run = search.last_run_at
    was_initialized = search.initialized
    _drop_stale_hits(db, search, cond)
    _insert_new_hits(db, search, cond, now)
    event_ids: list[int] = []
    if was_initialized:
        event_ids = _emit_monitor_changes(db, search, cond, now, scan_id=scan_id, prev_run=prev_run)
    _finish(db, search, cond, now)
    return event_ids


def _emit_monitor_changes(db: Session, search: SavedSearch, cond, now, *, scan_id: int | None, prev_run) -> list[int]:
    q = select(Event).where(
        Event.device_id.in_(select(Device.id).where(cond)),
        Event.event_type.in_(MONITOR_CHANGE_TYPES),
    )
    if scan_id is not None:
        q = q.where(Event.scan_id == scan_id)
    elif prev_run is not None:
        q = q.where(Event.created_at > prev_run)
    else:
        return []
    prior = aliased(Event)
    already = exists().where(
        prior.event_type == EV_MONITOR_CHANGE,
        prior.new_value == search.name,
        prior.old_value == cast(Event.id, String),
    )
    event_ids: list[int] = []
    last_id = 0
    while True:
        rows = db.scalars(q.where(~already, Event.id > last_id).order_by(Event.id).limit(CHUNK)).unique().all()
        if not rows:
            break
        created_rows: list[Event] = []
        for src in rows:
            d = src.device
            label = device_label(d) if d is not None else (src.ip or "unknown")
            ev = Event(
                created_at=now,
                scan_id=scan_id if scan_id is not None else src.scan_id,
                device=d,
                event_type=EV_MONITOR_CHANGE,
                severity=EVENT_SEVERITY[EV_MONITOR_CHANGE],
                ip=src.ip,
                protocol=src.protocol,
                port=src.port,
                new_value=search.name,
                old_value=str(src.id),
                message=f"{label} change watched by '{search.name}': {src.message}",
                notify=search.alert,
            )
            db.add(ev)
            created_rows.append(ev)
        db.flush()
        event_ids.extend(ev.id for ev in created_rows if ev.id is not None)
        last_id = rows[-1].id
        if len(rows) < CHUNK:
            break
    return event_ids


def evaluate_all(db: Session, *, scan_id: int | None = None) -> list[int]:
    """Evaluate every saved search; returns ids of alert events created."""
    event_ids: list[int] = []
    searches = db.scalars(select(SavedSearch).order_by(SavedSearch.id)).all()
    for search in searches:
        search_id, search_name = search.id, search.name
        try:
            with db.begin_nested():
                event_ids.extend(evaluate(db, search, scan_id=scan_id))
        except Exception as exc:
            log.warning("saved search %s (%s) failed: %s", search_id, search_name, exc)
            db.expire(search)
            search.last_error = str(exc)[:MAX_ERROR_LEN]
            search.last_run_at = utcnow()
    db.flush()
    return event_ids
