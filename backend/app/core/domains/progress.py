"""Per-phase progress of a running domain scan, written to `domain_scans.phases` in batches.

Phases run in a fixed order; each records status (pending / running / done / skipped / failed),
start / finish time, processed / total, names found, DNS queries and a reason (skip / failure).
The overall percent is weighted by phase work (wordlist phases by candidate count, resolution by
name count) and never moves backwards. Writes happen at most every `interval` seconds (or when a
phase changes state), never per query.
"""
from __future__ import annotations

import time
from collections.abc import Callable

from ...db import session_scope, utcnow
from ...models import SCAN_RUNNING, DomainScan

PHASES = (
    ("passive", "Passive (subfinder)"),
    ("wordlist_internal", "Wordlist (dnsx internal)"),
    ("wordlist_public", "Wordlist (dnsx public)"),
    ("axfr", "Zone transfer (authorized)"),
    ("public_axfr", "Public AXFR check"),
    ("resolve", "Resolve & classify"),
    ("diff", "Diff & events"),
    ("port_scan", "Port-scan queueing"),
)
PENDING = "pending"
RUNNING = "running"
DONE = "done"
SKIPPED = "skipped"
FAILED = "failed"
FINISHED = (DONE, SKIPPED, FAILED)

# Relative cost per unit of work (≈ DNS queries): dnsx asks A/AAAA/CNAME per candidate, resolution
# asks A/AAAA on two views per name. Phases without a natural count get a fixed weight.
_UNIT_COST = {"wordlist_internal": 3, "wordlist_public": 3, "resolve": 4}
_FIXED_COST = {"passive": 300, "axfr": 60, "public_axfr": 60, "diff": 30, "port_scan": 10}
# Queries per processed unit when a phase does not count real queries (dnsx runs out of process).
QUERIES_PER_CANDIDATE = 3


class Progress:
    def __init__(self, scan_id: int | None, *, interval: float = 2.0, write: bool = True,
                 clock: Callable[[], float] = time.monotonic, estimates: dict[str, int] | None = None):
        self.scan_id = scan_id
        self.interval = interval
        self.write = write
        self.clock = clock
        self.percent = 0.0
        self._last_flush = float("-inf")
        self._t0: dict[str, float] = {}
        self.phases: list[dict] = [
            {"key": k, "label": label, "status": PENDING, "started_at": None, "finished_at": None,
             "processed": 0, "total": (estimates or {}).get(k), "found": 0, "queries": 0, "unit": None,
             "reason": None, "duration_s": None, "rate": None, "eta_s": None}
            for k, label in PHASES
        ]

    # --- state ------------------------------------------------------------------------------------
    def get(self, key: str) -> dict:
        return next(p for p in self.phases if p["key"] == key)

    @property
    def current(self) -> dict | None:
        return next((p for p in self.phases if p["status"] == RUNNING), None)

    def start(self, key: str, *, total: int | None = None, unit: str | None = None) -> None:
        p = self.get(key)
        p.update(status=RUNNING, started_at=utcnow().isoformat(), processed=0, unit=unit)
        if total is not None:
            p["total"] = total
        self._t0[key] = self.clock()
        self.flush(force=True)

    def update(self, key: str, *, processed: int | None = None, found: int | None = None, total: int | None = None,
               queries: int | None = None, force: bool = False) -> None:
        p = self.get(key)
        if total is not None:
            p["total"] = total
        if processed is not None:
            p["processed"] = max(p["processed"], processed)
        if found is not None:
            p["found"] = found
        if queries is not None:
            p["queries"] = queries
        self.flush(force=force)

    def finish(self, key: str, status: str = DONE, reason: str | None = None) -> None:
        p = self.get(key)
        if p["status"] in FINISHED:
            return
        if status == DONE and p["total"] is not None:
            p["processed"] = max(p["processed"], p["total"])
        p.update(status=status, reason=reason, finished_at=utcnow().isoformat())
        t0 = self._t0.get(key)
        p["duration_s"] = round(self.clock() - t0, 1) if t0 is not None else 0.0
        p["eta_s"] = 0 if status == DONE else None
        self.flush(force=True)

    def skip(self, key: str, reason: str) -> None:
        p = self.get(key)
        if p["status"] == PENDING:
            p.update(status=SKIPPED, reason=reason)
            self.flush(force=True)

    def stop_all(self, reason: str) -> None:
        """Cancel / crash: the running phase fails, the rest are skipped (nothing still 'running')."""
        for p in self.phases:
            if p["status"] == RUNNING:
                self.finish(p["key"], FAILED, reason)
            elif p["status"] == PENDING:
                p.update(status=SKIPPED, reason=reason)
        self.flush(force=True)

    # --- derived ----------------------------------------------------------------------------------
    def _weight(self, p: dict) -> float:
        if p["key"] in _UNIT_COST:
            return float(_UNIT_COST[p["key"]] * max(1, p["total"] or 1))
        return float(_FIXED_COST.get(p["key"], 10))

    def compute_percent(self) -> float:
        total = done = 0.0
        for p in self.phases:
            w = self._weight(p)
            total += w
            if p["status"] in FINISHED:
                done += w
            elif p["status"] == RUNNING and p["total"]:
                done += w * min(1.0, p["processed"] / p["total"])
        raw = done / total if total else 0.0
        if any(p["status"] in (PENDING, RUNNING) for p in self.phases):
            raw = min(raw, 0.99)
        self.percent = round(max(self.percent, raw), 4)  # never backwards
        return self.percent

    def _rates(self) -> None:
        now = self.clock()
        for p in self.phases:
            if p["status"] != RUNNING or p["key"] not in self._t0:
                continue
            elapsed = max(1e-6, now - self._t0[p["key"]])
            p["duration_s"] = round(elapsed, 1)
            p["rate"] = round(p["queries"] / elapsed, 1) if p["queries"] else None
            if p["total"] and p["processed"]:
                remaining = max(0, p["total"] - p["processed"])
                p["eta_s"] = round(remaining / (p["processed"] / elapsed))
            else:
                p["eta_s"] = None

    def snapshot(self) -> list[dict]:
        self._rates()
        return [dict(p) for p in self.phases]

    def due(self) -> bool:
        return self.clock() - self._last_flush >= self.interval

    def flush(self, force: bool = False) -> bool:
        """Write phases + percent + current stage when forced or the interval has passed."""
        if not force and not self.due():
            return False
        self._last_flush = self.clock()
        pct = self.compute_percent()
        phases = self.snapshot()
        if not self.write or self.scan_id is None:
            return True
        cur = self.current
        with session_scope() as db:
            job = db.get(DomainScan, self.scan_id)
            if job is not None and job.status == SCAN_RUNNING:
                job.phases = phases
                job.progress = max(job.progress or 0.0, pct)
                job.stage = cur["label"] if cur else job.stage
        return True
