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
from ..models import (
    SCAN_ACTIVE_STATES,
    SCAN_DISCOVERY,
    SCAN_STANDARD,
    TRIGGER_PRESENCE,
    TRIGGER_SCHEDULED,
    Network,
    Scan,
)
from ..settings_store import (
    GeoSettings,
    NotificationSettings,
    PresenceSettings,
    RetentionSettings,
    ScanSettings,
    ScheduleSettings,
    VulnSettings,
    get_section,
    get_value,
    set_value,
)
from .geo_sync import sync_due as geo_sync_due
from .geo_sync import sync_running as geo_sync_running
from .geo_sync import trigger_background_sync as trigger_geo_sync
from .manager import create_scan, manager, network_has_active_scan
from .notify import send_daily_digest
from .presence import evaluate_absence, presence_scan_active
from .retention import cleanup_files, live_capture_uuids, purge_expired
from .vuln.sync import sync_due, sync_running, trigger_background_sync

log = logging.getLogger(__name__)

STATE_KEY = "scheduler_state"
CATCH_UP_WINDOW = timedelta(hours=6)  # run a missed schedule if the app was down briefly
PRESENCE_CATCH_UP_WINDOW = timedelta(hours=1)  # a stale presence slot is skipped, not run hours late
RETENTION_TIME = (3, 15)
TICK_SECONDS = 20
# A network without a baseline gets another standard scan this long after its last one started,
# so a failed/partial first scan is retried without waiting for someone to notice.
BASELINE_RETRY_AFTER = timedelta(hours=12)
NEW_NETWORK_GRACE = timedelta(hours=1)  # leave time for the admin to start the first scan themselves


def _at(now: datetime, hhmm: str) -> datetime:
    hh, mm = (int(x) for x in hhmm.split(":"))
    return now.replace(hour=hh, minute=mm, second=0, microsecond=0)


def _due_today(cfg: ScheduleSettings, now: datetime) -> datetime:
    return _at(now, cfg.time)


def next_presence_run(cfg: PresenceSettings, now: datetime | None = None, done_today: list[str] | None = None) -> datetime | None:
    if not cfg.enabled or not cfg.days or not cfg.times:
        return None
    now = now or datetime.now().astimezone()
    done_today = done_today or []
    for offset in range(0, 8):
        day = now + timedelta(days=offset)
        if day.weekday() not in cfg.days:
            continue
        for slot in cfg.times:
            due = _at(day, slot)
            if offset == 0 and (due < now - timedelta(minutes=1) or slot in done_today):
                continue
            return due
    return None


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
        disc = create_scan(db, SCAN_DISCOVERY, trigger=TRIGGER_SCHEDULED, network=net, requested_by="scheduler")
        ids.append(disc.id)
    scan = create_scan(db, SCAN_STANDARD, trigger=TRIGGER_SCHEDULED, network=net, requested_by="scheduler")
    ids.append(scan.id)
    return ids


def any_scan_active(db) -> bool:
    return db.scalar(select(Scan.id).where(Scan.status.in_(SCAN_ACTIVE_STATES)).limit(1)) is not None


def enqueue_presence_scans(db) -> list[int]:
    """Queue one discovery-only presence scan per enabled network (no port stage, no web capture)."""
    ids = []
    for net in db.scalars(select(Network).where(Network.enabled.is_(True)).order_by(Network.id)).all():
        if network_has_active_scan(db, net.id):
            log.info("presence scan for %s skipped: a scan is already queued/running", net.name)
            continue
        ids.append(create_scan(db, SCAN_DISCOVERY, trigger=TRIGGER_PRESENCE, network=net, requested_by="scheduler").id)
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


def enqueue_baseline_retries(db, now_utc: datetime | None = None, cfg: ScheduleSettings | None = None) -> list[int]:
    now_utc = now_utc or utcnow()
    cfg = cfg or get_section(db, ScheduleSettings)
    ids = []
    for net in db.scalars(
        select(Network).where(Network.enabled.is_(True), Network.baseline_scan_id.is_(None)).order_by(Network.id)
    ).all():
        if net.created_at and net.created_at > now_utc - NEW_NETWORK_GRACE:
            continue
        if network_has_active_scan(db, net.id):
            continue
        last = db.scalar(select(func.max(Scan.created_at)).where(Scan.network_id == net.id, Scan.scan_type == SCAN_STANDARD))
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
    send_digest = False
    retention_files: tuple[int, int] | None = None
    ret_counts: dict[str, int] = {}
    stale_captures: list[str] = []
    webhook_ids: list[int] = []
    with session_scope() as db:
        state = dict(get_value(db, STATE_KEY, {}) or {})
        cfg = get_section(db, ScheduleSettings)
        pcfg = get_section(db, PresenceSettings)
        changed = False

        if "initialized" not in state:
            # First start: never "catch up" a schedule that passed before installation
            state = {
                "initialized": today,
                "last_scan_date": today if now >= _due_today(cfg, now) else None,
                "last_retention_date": None,
                "presence_date": today,
                "presence_slots": [t for t in pcfg.times if now >= _at(now, t)],
            }
            changed = True
        elif cfg.enabled and now.weekday() in cfg.days and state.get("last_scan_date") != today:
            due = _due_today(cfg, now)
            if due <= now < due + CATCH_UP_WINDOW and any_scan_active(db):
                if state.get("deferred_scan_date") != today:
                    state["deferred_scan_date"] = today
                    changed = True
                    log.info("scheduled scan deferred: another scan is still queued/running")
            elif due <= now < due + CATCH_UP_WINDOW:
                queued = enqueue_scheduled_scans(db, cfg)
                state["last_scan_date"] = today
                changed = True
                log.info("scheduled scan triggered (%s): queued scans %s", cfg.time, queued)
        if cfg.enabled and "initialized" in state:
            queued += enqueue_baseline_retries(db, cfg=cfg)

        if pcfg.enabled and now.weekday() in pcfg.days:
            slots = list(state.get("presence_slots") or []) if state.get("presence_date") == today else []
            for slot in pcfg.times:
                due = _at(now, slot)
                if slot not in slots and due <= now < due + PRESENCE_CATCH_UP_WINDOW:
                    ids = enqueue_presence_scans(db)
                    queued += ids
                    slots.append(slot)
                    log.info("presence scan triggered (%s): queued scans %s", slot, ids)
            if state.get("presence_date") != today or slots != state.get("presence_slots"):
                state["presence_date"], state["presence_slots"] = today, slots
                changed = True
            last_due = _at(now, pcfg.times[-1])
            last_settled = pcfg.times[-1] in slots or now >= last_due + PRESENCE_CATCH_UP_WINDOW
            if state.get("last_absence_eval_date") != today and now >= last_due and last_settled and not presence_scan_active(db):
                webhook_ids = evaluate_absence(db, pcfg, now.date(), utcnow())
                state["last_absence_eval_date"] = today
                changed = True

        rt = now.replace(hour=RETENTION_TIME[0], minute=RETENTION_TIME[1], second=0, microsecond=0)
        if now >= rt and state.get("last_retention_date") != today:
            ret = get_section(db, RetentionSettings)
            ret_counts, stale_captures = purge_expired(db, ret.days, rtt_days=ret.rtt_sample_days)
            retention_files = (ret.days, get_section(db, ScanSettings).raw_retention_days)
            state["last_retention_date"] = today
            changed = True

        vuln_cfg = get_section(db, VulnSettings)
        if sync_due(db, vuln_cfg, now=now) and not sync_running():
            log.info("vulnerability feed sync is due: starting in the background")
            trigger_background_sync(vuln_cfg)

        geo_cfg = get_section(db, GeoSettings)
        if geo_sync_due(db, geo_cfg, now=now) and not geo_sync_running():
            log.info("geo feed sync is due: starting in the background")
            trigger_geo_sync(geo_cfg)

        notify_cfg = get_section(db, NotificationSettings)
        if notify_cfg.enabled and state.get("last_notification_date") != today:
            hh, mm = (int(x) for x in notify_cfg.digest_time.split(":"))
            due = now.replace(hour=hh, minute=mm, second=0, microsecond=0)
            if now >= due:
                # Claim the day before SMTP so overlapping ticks cannot double-send.
                state["last_notification_date"] = today
                changed = True
                send_digest = True

        if changed:
            set_value(db, STATE_KEY, state)
    if webhook_ids:
        try:
            from .webhooks import deliver_event_ids

            deliver_event_ids(webhook_ids)
        except Exception:
            log.exception("presence absence webhook delivery failed")
    if retention_files is not None:
        # Deletes are committed above; capture-dir/raw-XML cleanup runs without holding the tick's session.
        ret_days, raw_days = retention_files
        with session_scope() as db:
            keep = live_capture_uuids(db)
        ret_counts.update(cleanup_files(stale_captures, keep, raw_days))
        log.info("Retention cleanup (%s days): %s", ret_days, ret_counts)
    if send_digest:
        result = send_daily_digest()
        log.info("daily notification digest: %s", result)
        if result == "failed":
            with session_scope() as db:
                state = dict(get_value(db, STATE_KEY, {}) or {})
                if state.get("last_notification_date") == today:
                    state["last_notification_date"] = None
                    set_value(db, STATE_KEY, state)
    if queued:
        manager.wake()


def last_scheduled_date() -> str | None:
    with session_scope() as db:
        return (get_value(db, STATE_KEY, {}) or {}).get("last_scan_date")


def presence_slots_done_today() -> list[str]:
    today = datetime.now().astimezone().date().isoformat()
    with session_scope() as db:
        state = get_value(db, STATE_KEY, {}) or {}
        return list(state.get("presence_slots") or []) if state.get("presence_date") == today else []


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
