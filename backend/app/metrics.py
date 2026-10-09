"""In-process counters, exported in Prometheus text format by GET /api/metrics.

Counters (HTTP requests, finished scans) live in this process and reset on restart, as
Prometheus counters may. Gauges (queue depth, devices by status) are read from the database at
scrape time. No client library: the exposition format is a few lines of text.
"""
from __future__ import annotations

import threading
import time
from collections import Counter

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from . import __version__
from .models import (
    DEVICE_STATUSES,
    SCAN_QUEUED,
    SCAN_RUNNING,
    WEB_CAPTURE_QUEUED,
    WEB_CAPTURE_RUNNING,
    Device,
    Scan,
    WebCapture,
)

STARTED = time.time()

_lock = threading.Lock()
_http_requests: Counter[tuple[str, str]] = Counter()  # (method, status code)
_http_seconds = [0.0, 0]  # sum, count
_scans: Counter[tuple[str, str]] = Counter()  # (scan type, final status)
_scan_seconds: dict[str, list[float]] = {}  # scan type -> [sum, count]


def observe_request(method: str, status: int, seconds: float) -> None:
    with _lock:
        _http_requests[(method, str(status))] += 1
        _http_seconds[0] += seconds
        _http_seconds[1] += 1


def observe_scan(scan_type: str, status: str, seconds: float) -> None:
    with _lock:
        _scans[(scan_type, status)] += 1
        acc = _scan_seconds.setdefault(scan_type, [0.0, 0])
        acc[0] += seconds
        acc[1] += 1


def reset() -> None:
    """Forget all counters (tests)."""
    with _lock:
        _http_requests.clear()
        _http_seconds[:] = [0.0, 0]
        _scans.clear()
        _scan_seconds.clear()


def _labels(**labels: str) -> str:
    if not labels:
        return ""
    body = ",".join(f'{k}="{str(v).replace(chr(92), chr(92) * 2).replace(chr(34), chr(92) + chr(34))}"'
                    for k, v in labels.items())
    return "{" + body + "}"


class _Out:
    def __init__(self) -> None:
        self.lines: list[str] = []

    def metric(self, name: str, kind: str, help_text: str, samples: list[tuple[dict, float]]) -> None:
        self.lines += [f"# HELP {name} {help_text}", f"# TYPE {name} {kind}"]
        self.lines += [f"{name}{_labels(**labels)} {value:g}" for labels, value in samples]

    def text(self) -> str:
        return "\n".join(self.lines) + "\n"


def render(db: Session) -> str:
    with _lock:
        http = sorted(_http_requests.items())
        http_sum, http_count = _http_seconds
        scans = sorted(_scans.items())
        scan_seconds = {k: tuple(v) for k, v in sorted(_scan_seconds.items())}

    scan_queue = dict(db.execute(
        select(Scan.status, func.count()).where(Scan.status.in_((SCAN_QUEUED, SCAN_RUNNING))).group_by(Scan.status)
    ).tuples().all())
    capture_queue = dict(db.execute(
        select(WebCapture.status, func.count())
        .where(WebCapture.status.in_((WEB_CAPTURE_QUEUED, WEB_CAPTURE_RUNNING))).group_by(WebCapture.status)
    ).tuples().all())
    devices = dict(db.execute(select(Device.status, func.count()).group_by(Device.status)).tuples().all())

    out = _Out()
    out.metric("nf_build_info", "gauge", "Application version.", [({"version": __version__}, 1)])
    out.metric("nf_uptime_seconds", "gauge", "Seconds since this process started.", [({}, time.time() - STARTED)])
    out.metric("nf_http_requests_total", "counter", "API requests by method and status code.",
               [({"method": m, "status": s}, n) for (m, s), n in http])
    out.metric("nf_http_request_duration_seconds", "summary", "API request latency (to the first response byte).", [])
    out.lines += [f"nf_http_request_duration_seconds_sum {http_sum:g}", f"nf_http_request_duration_seconds_count {http_count}"]
    out.metric("nf_scans_finished_total", "counter", "Scans finished by this process, by type and final status.",
               [({"type": t, "status": s}, n) for (t, s), n in scans])
    out.metric("nf_scan_duration_seconds", "summary", "Wall-clock duration of finished scans, by type.", [])
    for t, (total, count) in scan_seconds.items():
        out.lines += [f"nf_scan_duration_seconds_sum{_labels(type=t)} {total:g}",
                      f"nf_scan_duration_seconds_count{_labels(type=t)} {count}"]
    out.metric("nf_scan_queue", "gauge", "Scans waiting or running.",
               [({"state": st}, scan_queue.get(st, 0)) for st in (SCAN_QUEUED, SCAN_RUNNING)])
    out.metric("nf_web_capture_queue", "gauge", "Web capture jobs waiting or running.",
               [({"state": st}, capture_queue.get(st, 0)) for st in (WEB_CAPTURE_QUEUED, WEB_CAPTURE_RUNNING)])
    out.metric("nf_devices", "gauge", "Known devices by status.",
               [({"status": st}, devices.get(st, 0)) for st in DEVICE_STATUSES])
    return out.text()
