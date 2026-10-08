"""Daily scheduler (in-process thread, no external dependency).

The schedule is re-read from the database on every tick, so changes in the UI
apply immediately without restarting. Times are server-local (set TZ in Docker).
"""
from __future__ import annotations

import logging
import threading
from datetime import datetime, timedelta

from sqlalchemy import func, select

from ..db import session_scope, utcnow
from ..models import SCAN_DISCOVERY, SCAN_STANDARD, Network, Scan
from ..settings_store import RetentionSettings, ScanSettings, ScheduleSettings, get_section, get_value, set_value
from .manager import create_scan, manager, network_has_active_scan
from .retention import run_retention

log = logging.getLogger(__name__)

STATE_KEY = "scheduler_state"
CATCH_UP_WINDOW = timedelta(hours=6)  # run a missed schedule if the app was down briefly
RETENTION_TIME = (3, 15)
TICK_SECONDS = 20
# A network without a baseline gets another standard scan this long after its last one started,
# so a failed/partial first scan is retried without waiting for someone to notice.
BASELINE_RETRY_AFTER = timedelta(hours=12)
NEW_NETWORK_GRACE = timedelta(hours=1)  # leave time for the admin to start the first scan themselves


def _due_today(cfg: ScheduleSettings, now: datetime) -> datetime:
    hh, mm = (int(x) for x in cfg.time.split(":"))
    return now.replace(hour=hh, minute=mm, second=0, microsecond=0)


def next_run(cfg: ScheduleSettings, now: datetime | None = None, last_run_date: str | None = None) -> datetime | None:
    if not cfg.enabled or not cfg.days:
        return None
    now = now or datetime.now().astimezone()
    for offset in range(0, 8):
        day = now + timedelta(days=offset)
        due = _due_today(cfg, day)
        if due.weekday() not in cfg.days:
            continue
        if offset == 0 and (due < now - timedelta(minutes=1) or last_run_date == now.date().isoformat()):
            continue
        return due
    return None


def _enqueue_network_scans(db, net: Network, *, discovery_before: bool) -> list[int]:
    """Queue discovery (optional) then standard for one network. Discovery is queued first so
    the serial scan worker registers new hosts before the longer service scan."""
    ids: list[int] = []
    if discovery_before:
        disc = create_scan(db, SCAN_DISCOVERY, trigger="scheduled", network=net, requested_by="scheduler")
        ids.append(disc.id)
    scan = create_scan(db, SCAN_STANDARD, trigger="scheduled", network=net, requested_by="scheduler")
    ids.append(scan.id)
    return ids


def enqueue_scheduled_scans(db, cfg: ScheduleSettings | None = None) -> list[int]:
    cfg = cfg or get_section(db, ScheduleSettings)
    ids = []
    for net in db.scalars(select(Network).where(Network.enabled.is_(True)).order_by(Network.id)).all():
        if network_has_active_scan(db, net.id):
            log.info("scheduled scan for %s skipped: a scan is already queued/running", net.name)
            continue
        ids.extend(_enqueue_network_scans(db, net, discovery_before=cfg.discovery_before_standard))
    return ids


def enqueue_baseline_retries(db, now_utc: datetime | None = None,
                             cfg: ScheduleSettings | None = None) -> list[int]:
    now_utc = now_utc or utcnow()
    cfg = cfg or get_section(db, ScheduleSettings)
    ids = []
    for net in db.scalars(select(Network).where(Network.enabled.is_(True), Network.baseline_scan_id.is_(None))
                          .order_by(Network.id)).all():
        if net.created_at and net.created_at > now_utc - NEW_NETWORK_GRACE:
            continue
        if network_has_active_scan(db, net.id):
            continue
        last = db.scalar(select(func.max(Scan.created_at))
                         .where(Scan.network_id == net.id, Scan.scan_type == SCAN_STANDARD))
        if last is not None and last > now_utc - BASELINE_RETRY_AFTER:
            continue
        queued = _enqueue_network_scans(db, net, discovery_before=cfg.discovery_before_standard)
        log.info("network %s has no baseline yet: queued scans %s", net.name, queued)
        ids.extend(queued)
    return ids


def tick(now: datetime | None = None) -> None:
    now = now or datetime.now().astimezone()
    today = now.date().isoformat()
    queued: list[int] = []
    with session_scope() as db:
        state = dict(get_value(db, STATE_KEY, {}) or {})
        cfg = get_section(db, ScheduleSettings)
        changed = False

        if "initialized" not in state:
            # First start: never "catch up" a schedule that passed before installation
            state = {"initialized": today, "last_scan_date": today if now >= _due_today(cfg, now) else None,
                     "last_retention_date": None}
            changed = True
        elif cfg.enabled and now.weekday() in cfg.days and state.get("last_scan_date") != today:
            due = _due_today(cfg, now)
            if due <= now < due + CATCH_UP_WINDOW:
                queued = enqueue_scheduled_scans(db, cfg)
                state["last_scan_date"] = today
                changed = True
                log.info("scheduled scan triggered (%s): queued scans %s", cfg.time, queued)
        if cfg.enabled and "initialized" in state:
            queued += enqueue_baseline_retries(db, cfg=cfg)

        rt = now.replace(hour=RETENTION_TIME[0], minute=RETENTION_TIME[1], second=0, microsecond=0)
        if now >= rt and state.get("last_retention_date") != today:
            ret = get_section(db, RetentionSettings)
            run_retention(db, ret.days, get_section(db, ScanSettings).raw_retention_days)
            state["last_retention_date"] = today
            changed = True

        if changed:
            set_value(db, STATE_KEY, state)
    if queued:
        manager.wake()


def last_scheduled_date() -> str | None:
    with session_scope() as db:
        return (get_value(db, STATE_KEY, {}) or {}).get("last_scan_date")


class Scheduler:
    def __init__(self) -> None:
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def start(self) -> None:
        if self.running:
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, name="scheduler", daemon=True)
        self._thread.start()
        log.info("scheduler started")

    def stop(self) -> None:
        self._stop.set()

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                tick()
            except Exception:
                log.exception("scheduler tick failed")
            self._stop.wait(TICK_SECONDS)


scheduler = Scheduler()
