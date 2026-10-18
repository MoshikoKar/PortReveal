"""Durable background vulnerability-check queue (spec section 8). Mirrors core/manager.py and
core/web_capture/manager.py: one job active at a time, survives a restart through the row in the
database, yields to the nmap scan worker so it never competes with a real scan for the network.
"""
from __future__ import annotations

import logging
import threading

from sqlalchemy import case, select
from sqlalchemy.orm import Session

from ...db import session_scope, utcnow
from ...models import (
    SCAN_ACTIVE_STATES,
    VULN_JOB_CANCELLED,
    VULN_JOB_FAILED,
    VULN_JOB_QUEUED,
    VULN_JOB_RUNNING,
    VULN_JOB_TRIGGER_MANUAL,
    Scan,
    VulnJob,
)
from ...scanner.types import ScanContext
from .runner import run_vuln_job

log = logging.getLogger(__name__)


def enqueue_vuln_job(db: Session, *, trigger: str, scan_id: int | None = None,
                     device_ids: list[int] | None = None, network_id: int | None = None,
                     requested_by: str | None = None) -> VulnJob:
    """Queue a vulnerability-check job. Merges into an already-queued job on the same devices
    instead of creating a duplicate (spec 8.2): a scan that keeps re-triggering the same hosts, or
    a manual click while an after_scan job for the same hosts is still waiting, both just extend it.
    """
    wanted = set(device_ids or [])
    if wanted:
        existing = db.scalars(
            select(VulnJob).where(VulnJob.status == VULN_JOB_QUEUED, VulnJob.network_id.is_(None))
        ).all()
        for job in existing:
            have = set(job.device_ids or [])
            if have and (have & wanted):
                job.device_ids = sorted(have | wanted)
                if scan_id is not None:
                    job.scan_id = scan_id
                if trigger == VULN_JOB_TRIGGER_MANUAL:
                    job.trigger = VULN_JOB_TRIGGER_MANUAL  # manual jobs run before after_scan ones
                db.flush()
                return job
    job = VulnJob(
        status=VULN_JOB_QUEUED, trigger=trigger, scan_id=scan_id, network_id=network_id,
        device_ids=sorted(wanted) if wanted else None, requested_by=requested_by, created_at=utcnow(),
    )
    db.add(job)
    db.flush()
    return job


class VulnJobManager:
    def __init__(self) -> None:
        self._wake = threading.Event()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._lock = threading.Lock()
        self._current: tuple[int, ScanContext] | None = None

    @property
    def current_job_id(self) -> int | None:
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
        self._thread = threading.Thread(target=self._loop, name="vuln-job-worker", daemon=True)
        self._thread.start()
        log.info("vulnerability job worker started")

    def stop(self) -> None:
        self._stop.set()
        self._wake.set()
        with self._lock:
            if self._current:
                self._current[1].cancel()
        if self._thread:
            self._thread.join(timeout=15)

    def wake(self) -> None:
        self._wake.set()

    def cancel(self, job_id: int) -> bool:
        with self._lock:
            if self._current and self._current[0] == job_id:
                self._current[1].cancel()
                return True
        with session_scope() as db:
            job = db.get(VulnJob, job_id)
            if job is not None and job.status == VULN_JOB_QUEUED:
                job.status = VULN_JOB_CANCELLED
                job.finished_at = utcnow()
                job.notes = "Cancelled before it started."
                return True
        return False

    @staticmethod
    def recover_interrupted() -> None:
        with session_scope() as db:
            for job in db.scalars(select(VulnJob).where(VulnJob.status == VULN_JOB_RUNNING)).all():
                job.status = VULN_JOB_FAILED
                job.finished_at = utcnow()
                job.stage = None
                job.error = "Interrupted by an application restart"
                log.warning("vuln job %s marked failed: interrupted by restart", job.id)

    @staticmethod
    def _scan_busy() -> bool:
        with session_scope() as db:
            return db.scalar(select(Scan.id).where(Scan.status.in_(SCAN_ACTIVE_STATES)).limit(1)) is not None

    @staticmethod
    def _next_queued() -> int | None:
        with session_scope() as db:
            # Manual jobs before after_scan jobs (spec 8.2 priority), then FIFO.
            priority = case((VulnJob.trigger == VULN_JOB_TRIGGER_MANUAL, 0), else_=1)
            return db.scalar(
                select(VulnJob.id).where(VulnJob.status == VULN_JOB_QUEUED)
                .order_by(priority, VulnJob.id).limit(1)
            )

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                if self._scan_busy():
                    # Nmap scans have priority over the vuln pipeline (never compete for the network).
                    self._wake.wait(3)
                    self._wake.clear()
                    continue
                job_id = self._next_queued()
            except Exception:
                log.exception("vuln job worker: database error")
                job_id = None
            if job_id is None:
                self._wake.wait(5)
                self._wake.clear()
                continue
            ctx = ScanContext(job_id)
            with self._lock:
                self._current = (job_id, ctx)
            try:
                run_vuln_job(job_id, ctx)
            except Exception:
                log.exception("vuln job worker: unexpected error in job %s", job_id)
            finally:
                with self._lock:
                    self._current = None


vuln_job_manager = VulnJobManager()
