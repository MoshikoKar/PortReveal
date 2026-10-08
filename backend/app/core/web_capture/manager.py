"""Durable Web Capture queue. Yields to the Nmap scan worker when scans are active."""
from __future__ import annotations

import logging
import threading

from sqlalchemy import select

from ...db import session_scope, utcnow
from ...models import (
    SCAN_ACTIVE_STATES,
    WEB_CAPTURE_CANCELLED,
    WEB_CAPTURE_FAILED,
    WEB_CAPTURE_QUEUED,
    WEB_CAPTURE_RUNNING,
    Scan,
    WebCapture,
)
from .runner import CaptureContext, run_web_capture

log = logging.getLogger(__name__)


class WebCaptureManager:
    def __init__(self) -> None:
        self._wake = threading.Event()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._lock = threading.Lock()
        self._current: tuple[int, CaptureContext] | None = None

    @property
    def current_capture_id(self) -> int | None:
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
        self._thread = threading.Thread(target=self._loop, name="web-capture-worker", daemon=True)
        self._thread.start()
        log.info("web capture worker started")

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

    def cancel(self, capture_id: int) -> bool:
        with self._lock:
            if self._current and self._current[0] == capture_id:
                self._current[1].cancel()
                return True
        with session_scope() as db:
            job = db.get(WebCapture, capture_id)
            if job is not None and job.status == WEB_CAPTURE_QUEUED:
                job.status = WEB_CAPTURE_CANCELLED
                job.finished_at = utcnow()
                job.notes = "Cancelled before it started."
                return True
        return False

    @staticmethod
    def recover_interrupted() -> None:
        with session_scope() as db:
            for job in db.scalars(select(WebCapture).where(WebCapture.status == WEB_CAPTURE_RUNNING)).all():
                job.status = WEB_CAPTURE_FAILED
                job.finished_at = utcnow()
                job.stage = None
                job.error = "Interrupted by an application restart"
                job.notes = (job.notes or "") + ("\n" if job.notes else "") + "Capture was interrupted."
                log.warning("web capture %s marked failed: interrupted by restart", job.id)

    def _scan_busy(self) -> bool:
        with session_scope() as db:
            return db.scalar(select(Scan.id).where(Scan.status.in_(SCAN_ACTIVE_STATES)).limit(1)) is not None

    def _next_queued(self) -> int | None:
        with session_scope() as db:
            return db.scalar(
                select(WebCapture.id).where(WebCapture.status == WEB_CAPTURE_QUEUED).order_by(WebCapture.id).limit(1)
            )

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                if self._scan_busy():
                    # Nmap has priority — wait and re-check
                    self._wake.wait(3)
                    self._wake.clear()
                    continue
                capture_id = self._next_queued()
            except Exception:
                log.exception("web capture worker: database error")
                capture_id = None
            if capture_id is None:
                self._wake.wait(5)
                self._wake.clear()
                continue
            ctx = CaptureContext(capture_id)
            with self._lock:
                self._current = (capture_id, ctx)
            try:
                run_web_capture(capture_id, ctx)
            except Exception:
                log.exception("web capture worker: unexpected error in capture %s", capture_id)
            finally:
                with self._lock:
                    self._current = None


web_capture_manager = WebCaptureManager()
