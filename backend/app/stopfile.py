"""Graceful stop request by file, for hosts without a usable stop signal (Windows `run.ps1 -Stop`).

Windows cannot deliver Ctrl+C / SIGTERM to a process in another (hidden) console, so
`scripts/run.ps1` sets NETWORK_FINDER_STOP_FILE and creates that file to ask for a stop. The
watcher then raises SIGINT inside this process; uvicorn treats it like Ctrl+C and runs the normal
shutdown (scheduler, scan worker and web-capture worker stop before the process exits).
"""
from __future__ import annotations

import logging
import os
import signal
import threading
from pathlib import Path

log = logging.getLogger(__name__)
ENV_VAR = "NETWORK_FINDER_STOP_FILE"
POLL_SECONDS = 1.0


class StopFileWatcher:
    def __init__(self, path: Path, poll_seconds: float = POLL_SECONDS):
        self.path = path
        self.poll_seconds = poll_seconds
        self._done = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        self.path.unlink(missing_ok=True)  # a stale request from an earlier run must not stop this one
        self._thread = threading.Thread(target=self._run, name="stop-file-watcher", daemon=True)
        self._thread.start()
        log.info("graceful stop file: %s", self.path)

    def stop(self) -> None:
        self._done.set()

    def _run(self) -> None:
        while not self._done.wait(self.poll_seconds):
            if self.path.exists():
                self.path.unlink(missing_ok=True)
                log.warning("stop requested via %s; shutting down gracefully", self.path)
                signal.raise_signal(signal.SIGINT)
                return


def watcher_from_env() -> StopFileWatcher | None:
    raw = (os.environ.get(ENV_VAR) or "").strip()
    return StopFileWatcher(Path(raw)) if raw else None
