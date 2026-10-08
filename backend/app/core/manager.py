"""Scan queue: one scan executes at a time (parallelism happens inside a scan).

Queued scans are rows in the `scans` table, so the queue survives restarts.
Scans that were running when the process stopped are marked failed on startup
(their partial results were never applied).
"""
from __future__ import annotations

import logging
import threading

from sqlalchemy import select

from ..db import session_scope, utcnow
from ..models import (
    SCAN_ACTIVE_STATES,
    SCAN_CANCELLED,
    SCAN_FAILED,
    SCAN_QUEUED,
    SCAN_RUNNING,
    Network,
    Scan,
)
from ..netutils import AddressSet
from ..scanner.types import ScanContext
from .runner import run_scan

log = logging.getLogger(__name__)


def create_scan(db, scan_type: str, *, trigger: str = "manual", network: Network | None = None,
                targets: AddressSet | None = None, requested_by: str | None = None,
                criteria: str | None = None, ignore_version_cache: bool = False) -> Scan:
    scan = Scan(
        scan_type=scan_type,
        trigger=trigger,
        status=SCAN_QUEUED,
        network_id=network.id if network else None,
        targets=None if network else ",".join(targets.to_cidrs()) if targets else None,
        target_count=len(AddressSet.from_specs(network.cidr)) if network else len(targets or AddressSet()),
        criteria=criteria,
        requested_by=requested_by,
        ignore_version_cache=ignore_version_cache,
    )
    db.add(scan)
    db.flush()
    return scan


def network_has_active_scan(db, network_id: int, scan_type: str | None = None) -> bool:
    q = select(Scan.id).where(Scan.network_id == network_id, Scan.status.in_(SCAN_ACTIVE_STATES))
    if scan_type:
        q = q.where(Scan.scan_type == scan_type)
    return db.scalar(q.limit(1)) is not None


class ScanManager:
    def __init__(self) -> None:
        self._wake = threading.Event()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._lock = threading.Lock()
        self._current: tuple[int, ScanContext] | None = None

    @property
    def current_scan_id(self) -> int | None:
        cur = self._current
        return cur[0] if cur else None

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def start(self) -> None:
        if self.running:
            return
        self.recover_interrupted()
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, name="scan-worker", daemon=True)
        self._thread.start()
        log.info("scan worker started")

    def stop(self) -> None:
        self._stop.set()
        self._wake.set()
        with self._lock:
            if self._current:
                self._current[1].cancel()
        if self._thread:
            self._thread.join(timeout=10)

    def wake(self) -> None:
        self._wake.set()

    def cancel(self, scan_id: int) -> bool:
        with self._lock:
            if self._current and self._current[0] == scan_id:
                self._current[1].cancel()
                return True
        with session_scope() as db:
            scan = db.get(Scan, scan_id)
            if scan is not None and scan.status == SCAN_QUEUED:
                scan.status = SCAN_CANCELLED
                scan.finished_at = utcnow()
                scan.notes = "Cancelled before it started."
                return True
        return False

    @staticmethod
    def recover_interrupted() -> None:
        with session_scope() as db:
            for scan in db.scalars(select(Scan).where(Scan.status == SCAN_RUNNING)).all():
                scan.status = SCAN_FAILED
                scan.finished_at = utcnow()
                scan.stage = None
                scan.error = "Interrupted by an application restart"
                scan.notes = "Scan was interrupted. The previous known state was preserved."
                log.warning("scan %s marked failed: interrupted by restart", scan.id)

    def _next_queued(self) -> int | None:
        with session_scope() as db:
            return db.scalar(select(Scan.id).where(Scan.status == SCAN_QUEUED).order_by(Scan.id).limit(1))

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                scan_id = self._next_queued()
            except Exception:
                log.exception("scan worker: database error")
                scan_id = None
            if scan_id is None:
                self._wake.wait(5)
                self._wake.clear()
                continue
            ctx = ScanContext(scan_id)
            with self._lock:
                self._current = (scan_id, ctx)
            try:
                run_scan(scan_id, ctx)
            except Exception:
                log.exception("scan worker: unexpected error in scan %s", scan_id)
            finally:
                with self._lock:
                    self._current = None


manager = ScanManager()
