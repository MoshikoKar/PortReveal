"""Daytime presence scans and correlated absence (night + presence) before disappear/reappear email."""
from __future__ import annotations

from datetime import date, datetime, time, timedelta

from sqlalchemy import func, select

from app.core.presence import evaluate_absence
from app.core.scheduler import STATE_KEY, tick
from app.models import (
    DEVICE_NOT_DETECTED,
    SCAN_COMPLETED,
    SCAN_PARTIAL,
    TRIGGER_PRESENCE,
    TRIGGER_SCHEDULED,
    Event,
    Scan,
)
from app.settings_store import PresenceSettings, ScheduleSettings, get_value, put_section

from .helpers import ScriptedScanner, device_by_ip, events, host, make_network, port, scan

MAC_A = "00:11:22:33:66:01"
MAC_B = "00:11:22:33:66:02"
CFG = PresenceSettings()


def hosts_ab():
    return [host("10.0.0.1", [port(22, "ssh")], mac=MAC_A, hostname="srv-a.corp"),
            host("10.0.0.2", [port(3389, "ms-wbt-server")], mac=MAC_B, hostname="laptop-b.corp")]


def noon(day: date) -> datetime:
    return datetime.combine(day, time(12, 0)).astimezone()


def simulate_day(db, net_id: int, day: date, *, night: str | None = SCAN_COMPLETED,
                 presence: list[str] | None = None, seen_ips: tuple[str, ...] = ("10.0.0.1",)) -> None:
    """Record that day's scheduled scans (as finished rows) and which devices they saw."""
    presence = [SCAN_COMPLETED, SCAN_COMPLETED] if presence is None else presence
    if night is not None:
        db.add(Scan(scan_type="standard", trigger=TRIGGER_SCHEDULED, status=night, network_id=net_id,
                    created_at=noon(day) - timedelta(hours=10)))
    for i, status in enumerate(presence):
        db.add(Scan(scan_type="discovery", trigger=TRIGGER_PRESENCE, status=status, network_id=net_id,
                    created_at=noon(day) + timedelta(hours=i)))
    for ip in seen_ips:
        device_by_ip(db, ip).last_seen = noon(day)
    db.commit()


def setup_absent_b(db):
    net = make_network(db)
    scan(ScriptedScanner(hosts_ab()), network_id=net.id)  # baseline (today)
    start = datetime.now().astimezone().date() - timedelta(days=20)
    device_by_ip(db, "10.0.0.2").last_seen = noon(start - timedelta(days=1))
    db.commit()
    return net, start


def notify_events(db, etype: str) -> list[Event]:
    return [e for e in events(db) if e.event_type == etype and e.notify]


def test_streak_counts_only_days_missed_by_night_and_presence_then_alerts(db):
    net, start = setup_absent_b(db)
    for i in range(4):
        simulate_day(db, net.id, start + timedelta(days=i))
        evaluate_absence(db, CFG, start + timedelta(days=i), noon(start + timedelta(days=i)))
        db.commit()
        assert device_by_ip(db, "10.0.0.2").absence_days == i + 1
    assert notify_events(db, "device_disappeared") == []
    assert device_by_ip(db, "10.0.0.1").absence_days == 0  # seen every day

    day5 = start + timedelta(days=4)
    simulate_day(db, net.id, day5)
    evaluate_absence(db, CFG, day5, noon(day5))
    db.commit()
    b = device_by_ip(db, "10.0.0.2")
    assert b.absence_days == 5 and b.absence_alerted and b.status == DEVICE_NOT_DETECTED
    alerts = notify_events(db, "device_disappeared")
    assert len(alerts) == 1 and "5 days" in alerts[0].message

    evaluate_absence(db, CFG, day5, noon(day5))  # idempotent per day
    db.commit()
    assert device_by_ip(db, "10.0.0.2").absence_days == 5
    assert len(notify_events(db, "device_disappeared")) == 1

    s = scan(ScriptedScanner(hosts_ab()), network_id=net.id)  # back in the office
    evs = [e for e in events(db, s.id) if e.event_type == "device_reappeared"]
    assert len(evs) == 1 and evs[0].notify is True
    b = device_by_ip(db, "10.0.0.2")
    assert b.absence_days == 0 and not b.absence_alerted


def test_sighting_mid_streak_resets_without_email(db):
    net, start = setup_absent_b(db)
    for i in range(3):
        simulate_day(db, net.id, start + timedelta(days=i))
        evaluate_absence(db, CFG, start + timedelta(days=i), noon(start + timedelta(days=i)))
        db.commit()
    assert device_by_ip(db, "10.0.0.2").absence_days == 3

    s = scan(ScriptedScanner(hosts_ab()), scan_type="discovery", network_id=net.id)  # seen at a presence pass
    assert [e for e in events(db, s.id) if e.event_type == "device_reappeared"] == []
    assert device_by_ip(db, "10.0.0.2").absence_days == 0

    future = datetime.now().astimezone().date() + timedelta(days=1)
    for i in range(4):
        simulate_day(db, net.id, future + timedelta(days=i))
        evaluate_absence(db, CFG, future + timedelta(days=i), noon(future + timedelta(days=i)))
        db.commit()
    assert device_by_ip(db, "10.0.0.2").absence_days == 4  # counter started again
    assert notify_events(db, "device_disappeared") == []


def test_days_without_both_scan_kinds_never_count(db):
    net, start = setup_absent_b(db)
    simulate_day(db, net.id, start, presence=[])  # no presence schedule (e.g. Saturday)
    simulate_day(db, net.id, start + timedelta(days=1), night=None)  # night scan did not run
    simulate_day(db, net.id, start + timedelta(days=2), night=SCAN_PARTIAL)
    simulate_day(db, net.id, start + timedelta(days=3), presence=[SCAN_COMPLETED, SCAN_PARTIAL])
    for i in range(4):
        evaluate_absence(db, CFG, start + timedelta(days=i), noon(start + timedelta(days=i)))
        db.commit()
    assert device_by_ip(db, "10.0.0.2").absence_days == 0


def test_per_scan_disappearance_is_quiet_while_presence_enabled(db):
    net = make_network(db)
    scan(ScriptedScanner(hosts_ab()), network_id=net.id)
    only_a = hosts_ab()[:1]
    scan(ScriptedScanner(only_a), network_id=net.id)
    s = scan(ScriptedScanner(only_a), network_id=net.id)
    evs = events(db, s.id)
    assert [e.event_type for e in evs] == ["device_disappeared"] and evs[0].notify is False
    s = scan(ScriptedScanner(hosts_ab()), network_id=net.id)
    evs = events(db, s.id)
    assert [e.event_type for e in evs] == ["device_reappeared"] and evs[0].notify is False


def test_per_scan_disappearance_emails_when_presence_disabled(db):
    put_section(db, PresenceSettings(enabled=False))
    db.commit()
    net = make_network(db)
    scan(ScriptedScanner(hosts_ab()), network_id=net.id)
    only_a = hosts_ab()[:1]
    scan(ScriptedScanner(only_a), network_id=net.id)
    s = scan(ScriptedScanner(only_a), network_id=net.id)
    assert [(e.event_type, e.notify) for e in events(db, s.id)] == [("device_disappeared", True)]
    s = scan(ScriptedScanner(hosts_ab()), network_id=net.id)
    assert [(e.event_type, e.notify) for e in events(db, s.id)] == [("device_reappeared", True)]


def test_presence_scans_run_sunday_to_friday_and_absence_evaluated_after_last_slot(db):
    put_section(db, ScheduleSettings(enabled=True, time="02:00", days=[0, 1, 2, 3, 4, 5, 6]))
    db.commit()
    make_network(db)
    saturday = datetime(2026, 10, 10, 9, 0).astimezone()
    assert saturday.weekday() == 5
    tick(saturday)  # initializes state
    tick(saturday.replace(hour=10, minute=1))
    tick(saturday.replace(hour=15, minute=1))
    assert db.scalar(select(func.count(Scan.id)).where(Scan.trigger == TRIGGER_PRESENCE)) == 0

    sunday = saturday + timedelta(days=1)
    tick(sunday.replace(hour=2, minute=1))
    db.query(Scan).update({Scan.status: SCAN_COMPLETED})  # night scans finished
    db.commit()
    tick(sunday.replace(hour=10, minute=1))
    tick(sunday.replace(hour=10, minute=5))  # same slot: no duplicate
    presence = db.scalars(select(Scan).where(Scan.trigger == TRIGGER_PRESENCE)).all()
    assert [(s.scan_type, s.status) for s in presence] == [("discovery", "queued")]

    db.query(Scan).update({Scan.status: SCAN_COMPLETED})
    db.commit()
    tick(sunday.replace(hour=15, minute=1))  # queues the last slot; evaluation waits for it
    db.expire_all()
    assert (get_value(db, STATE_KEY, {}) or {}).get("last_absence_eval_date") is None
    db.query(Scan).update({Scan.status: SCAN_COMPLETED})
    db.commit()
    tick(sunday.replace(hour=15, minute=30))
    db.expire_all()
    assert (get_value(db, STATE_KEY, {}) or {}).get("last_absence_eval_date") == sunday.date().isoformat()
    assert db.scalar(select(func.count(Scan.id)).where(Scan.trigger == TRIGGER_PRESENCE)) == 2
