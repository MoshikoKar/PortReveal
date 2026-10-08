"""Retention cleanup (default 365 days) - runs daily from the scheduler."""
from __future__ import annotations

import logging
import shutil
import time
from datetime import datetime, timedelta

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from ..config import get_settings
from ..db import utcnow
from ..models import (
    DEVICE_ACTIVE,
    SCAN_ACTIVE_STATES,
    WEB_CAPTURE_ACTIVE_STATES,
    AuditLog,
    Device,
    Event,
    Scan,
    ScanHost,
    Snapshot,
    UserSession,
    WebCapture,
)
from .web_storage import cleanup_capture_dirs, delete_capture_files

log = logging.getLogger(__name__)


def run_retention(db: Session, days: int, raw_days: int = 7, now: datetime | None = None) -> dict[str, int]:
    """DB deletes, commit, then filesystem cleanup (no transaction held open during rmtree)."""
    counts, stale_uuids = purge_expired(db, days, now)
    db.commit()
    counts.update(cleanup_files(stale_uuids, live_capture_uuids(db), raw_days))
    log.info("Retention cleanup (%s days): %s", days, counts)
    return counts


def purge_expired(db: Session, days: int, now: datetime | None = None) -> tuple[dict[str, int], list[str]]:
    """Delete expired rows (not committed). Returns counts and the uuids of deleted web captures,
    whose files the caller removes with cleanup_files() once the deletes are committed."""
    now = now or utcnow()
    cutoff = now - timedelta(days=days)
    counts: dict[str, int] = {}

    def _del(name: str, stmt) -> None:
        counts[name] = db.execute(stmt.execution_options(synchronize_session=False)).rowcount or 0

    _del("events", delete(Event).where(Event.created_at < cutoff))
    _del("scan_hosts", delete(ScanHost).where(ScanHost.created_at < cutoff))
    _del("snapshots", delete(Snapshot).where(Snapshot.snapshot_date < cutoff.date()))
    _del("scans", delete(Scan).where(Scan.created_at < cutoff, Scan.status.not_in(SCAN_ACTIVE_STATES)))
    _del("audit_log", delete(AuditLog).where(AuditLog.created_at < cutoff))
    # Devices not seen for the whole retention period are forgotten (ports/IPs/events cascade)
    _del("devices", delete(Device).where(Device.last_seen < cutoff, Device.status != DEVICE_ACTIVE))
    _del("sessions", delete(UserSession).where(UserSession.expires_at < now))

    # Web captures past retention (never delete active jobs); cascade deletes web_pages
    stale = list(
        db.scalars(
            select(WebCapture).where(
                WebCapture.created_at < cutoff,
                WebCapture.status.not_in(WEB_CAPTURE_ACTIVE_STATES),
            )
        ).all()
    )
    stale_uuids = [cap.uuid for cap in stale]
    for cap in stale:
        db.delete(cap)
    counts["web_captures"] = len(stale)
    db.flush()
    return counts, stale_uuids


def live_capture_uuids(db: Session) -> set[str]:
    return set(db.scalars(select(WebCapture.uuid)).all())


def cleanup_files(stale_uuids: list[str], keep_uuids: set[str], raw_days: int) -> dict[str, int]:
    """Filesystem half of retention; call after the DB deletes are committed."""
    for uuid in stale_uuids:
        delete_capture_files(uuid)
    return {
        "web_capture_orphan_dirs": cleanup_capture_dirs(keep_uuids),
        "raw_dirs": cleanup_raw(raw_days),
    }


def cleanup_raw(raw_days: int) -> int:
    raw_root = get_settings().data_path / "raw"
    if not raw_root.is_dir():
        return 0
    limit = time.time() - raw_days * 86400
    removed = 0
    for d in raw_root.iterdir():
        try:
            if d.is_dir() and d.stat().st_mtime < limit:
                shutil.rmtree(d, ignore_errors=True)
                removed += 1
        except OSError:
            pass
    return removed
