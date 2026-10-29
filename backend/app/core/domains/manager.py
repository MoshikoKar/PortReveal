"""Domain-scan queue: its own job type, table and worker threads (never the nmap scan worker).

Up to `domain_discovery.concurrency` jobs run at once (default 1). Network scans have priority: no
domain job starts while a network scan is queued or running (a job already running keeps going; its
DNS traffic is rate-limited). Queued jobs survive a restart; running ones are marked failed then.
"""
from __future__ import annotations

import logging
import threading
from datetime import datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from ...db import session_scope, utcnow
from ...models import (
    SCAN_ACTIVE_STATES,
    SCAN_CANCELLED,
    SCAN_FAILED,
    SCAN_QUEUED,
    SCAN_RUNNING,
    TRIGGER_MANUAL,
    TRIGGER_SCHEDULED,
    Domain,
    DomainScan,
    Scan,
)
from ...scanner.types import ScanContext
from ...settings_store import DomainDiscoverySettings, get_section
from .runner import release_in_progress, run_domain_scan

log = logging.getLogger(__name__)


def domain_has_active_scan(db: Session, domain_id: int) -> bool:
    q = select(DomainScan.id).where(DomainScan.domain_id == domain_id, DomainScan.status.in_(SCAN_ACTIVE_STATES))
    return db.scalar(q.limit(1)) is not None


def enqueue_domain_scan(db: Session, domain: Domain, *, trigger: str = TRIGGER_MANUAL,
                        requested_by: str | None = None) -> DomainScan:
    job = DomainScan(domain_id=domain.id, status=SCAN_QUEUED, trigger=trigger, requested_by=requested_by,
                     created_at=utcnow(), progress=0.0)
    db.add(job)
    db.flush()
    return job


def enqueue_scheduled_domain_scans(db: Session, now: datetime, catch_up: timedelta = timedelta(hours=6)) -> list[int]:
    """Per-domain schedule ({"enabled", "time", "days"}, server-local time), checked on every scheduler
    tick. A slot missed while the app was down runs within `catch_up`; one run per domain per day."""
    today = now.date().isoformat()
    ids: list[int] = []
    for d in db.scalars(select(Domain).where(Domain.enabled.is_(True)).order_by(Domain.id)).all():
        sch = d.schedule or {}
        if not sch.get("enabled") or now.weekday() not in (sch.get("days") or []) or d.last_scheduled_on == today:
            continue
        try:
            hh, mm = (int(x) for x in str(sch.get("time") or "").split(":"))
            due = now.replace(hour=hh, minute=mm, second=0, microsecond=0)
        except ValueError:
            continue
        if not due <= now < due + catch_up:
            continue
        d.last_scheduled_on = today
        if domain_has_active_scan(db, d.id):
            log.info("scheduled domain scan of %s skipped: one is already queued/running", d.name)
            continue
        ids.append(enqueue_domain_scan(db, d, trigger=TRIGGER_SCHEDULED, requested_by="scheduler").id)
    return ids


class DomainScanManager:
    def __init__(self) -> None:
        self._wake = threading.Event()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._lock = threading.Lock()
        self._running: dict[int, tuple[ScanContext, threading.Thread]] = {}

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    @property
    def current_ids(self) -> list[int]:
        with self._lock:
            return sorted(self._running)

    def start(self) -> None:
        if self.running:
            return
        self.recover_interrupted()
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, name="domain-scan-dispatcher", daemon=True)
        self._thread.start()
        log.info("domain scan worker started")

    def stop(self) -> None:
        self._stop.set()
        self._wake.set()
        with self._lock:
            running = list(self._running.values())
        for ctx, _ in running:
            ctx.cancel()
        for _, t in running:
            t.join(timeout=10)
        if self._thread:
            self._thread.join(timeout=10)

    def wake(self) -> None:
        self._wake.set()

    def cancel(self, scan_id: int) -> bool:
        with self._lock:
            cur = self._running.get(scan_id)
        if cur is not None:
            cur[0].cancel()
            return True
        with session_scope() as db:
            job = db.get(DomainScan, scan_id)
            if job is not None and job.status == SCAN_QUEUED:
                job.status = SCAN_CANCELLED
                job.finished_at = utcnow()
                job.notes = "Cancelled before it started."
                return True
        return False

    @staticmethod
    def recover_interrupted() -> None:
        with session_scope() as db:
            interrupted = db.scalars(select(DomainScan).where(DomainScan.status == SCAN_RUNNING)).all()
            for job in interrupted:
                job.status = SCAN_FAILED
                job.finished_at = utcnow()
                job.stage = None
                job.error = "Interrupted by an application restart"
                job.notes = "The previous inventory was kept."
                job.phases = [{**p, "status": "failed", "reason": "interrupted by an application restart"}
                              if p.get("status") == "running" else p for p in (job.phases or [])]
                log.warning("domain scan %s marked failed: interrupted by restart", job.id)
            stale = [(j.domain_id, j.started_at) for j in interrupted]
        for domain_id, started_at in stale:
            release_in_progress(domain_id, started_at)

    @staticmethod
    def network_scan_busy(db: Session) -> bool:
        return db.scalar(select(Scan.id).where(Scan.status.in_(SCAN_ACTIVE_STATES)).limit(1)) is not None

    def next_job(self) -> int | None:
        """Next queued job when a slot is free and no network scan is active; else None."""
        with session_scope() as db:
            limit = get_section(db, DomainDiscoverySettings).concurrency
            with self._lock:
                busy = set(self._running)
            if len(busy) >= limit or self.network_scan_busy(db):
                return None
            q = select(DomainScan.id).where(DomainScan.status == SCAN_QUEUED)
            if busy:
                q = q.where(DomainScan.id.not_in(busy))
            # One job per domain at a time: skip domains that already have a running job.
            running_domains = select(DomainScan.domain_id).where(DomainScan.status == SCAN_RUNNING)
            q = q.where(DomainScan.domain_id.not_in(running_domains))
            return db.scalar(q.order_by(DomainScan.id).limit(1))

    def _run(self, scan_id: int, ctx: ScanContext) -> None:
        try:
            run_domain_scan(scan_id, ctx)
        except Exception:
            log.exception("domain scan worker: unexpected error in job %s", scan_id)
        finally:
            with self._lock:
                self._running.pop(scan_id, None)
            self._wake.set()

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                scan_id = self.next_job()
            except Exception:
                log.exception("domain scan worker: database error")
                scan_id = None
            if scan_id is None:
                self._wake.wait(5)
                self._wake.clear()
                continue
            ctx = ScanContext(scan_id)
            t = threading.Thread(target=self._run, args=(scan_id, ctx), name=f"domain-scan-{scan_id}", daemon=True)
            with self._lock:
                self._running[scan_id] = (ctx, t)
            t.start()


domain_scan_manager = DomainScanManager()
