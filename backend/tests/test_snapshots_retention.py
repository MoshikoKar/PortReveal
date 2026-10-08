from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select

from app.core.notify import format_digest, format_event, notify_events
from app.core.retention import run_retention
from app.core.scheduler import enqueue_scheduled_scans, next_run, tick
from app.core.snapshots import load_snapshot
from app.models import AuditLog, Device, Event, Scan, Snapshot
from app.security import encrypt_secret
from app.settings_store import NotificationSettings, ScheduleSettings, put_section

from .helpers import ScriptedScanner, events, host, make_network, port, scan


def test_snapshot_created_after_successful_scan_and_replaced_same_day(db):
    net = make_network(db)
    hosts = [host("10.0.0.1", [port(22, "ssh", "OpenSSH")], mac="00:00:00:00:00:01")]
    s1 = scan(ScriptedScanner(hosts), network_id=net.id)
    snaps = db.scalars(select(Snapshot)).all()
    assert len(snaps) == 1 and snaps[0].scan_id == s1.id
    data = load_snapshot(snaps[0])
    assert data["devices"][0][1] == "10.0.0.1" and data["devices"][0][5][0][0] == 22
    assert snaps[0].hosts_active == 1 and snaps[0].open_ports == 1
    assert len(snaps[0].data) < 1000  # compact

    s2 = scan(ScriptedScanner(hosts), network_id=net.id)
    db.expire_all()
    snaps = db.scalars(select(Snapshot)).all()
    assert len(snaps) == 1 and snaps[0].scan_id == s2.id  # one per network per day


def test_no_snapshot_for_failed_or_discovery_scans(db):
    net = make_network(db)
    scan(ScriptedScanner([], fail_all=True), network_id=net.id)
    scan(ScriptedScanner([host("10.0.0.1")]), scan_type="discovery", network_id=net.id)
    assert db.scalar(select(func.count(Snapshot.id))) == 0


def test_retention_cleanup(db):
    net = make_network(db)
    hosts = [host("10.0.0.1", [port(22, "ssh")], mac="00:00:00:00:00:01"),
             host("10.0.0.2", [port(80, "http")], mac="00:00:00:00:00:02")]
    scan(ScriptedScanner(hosts), network_id=net.id)
    scan(ScriptedScanner(hosts + [host("10.0.0.3", [], mac="00:00:00:00:00:03")]), network_id=net.id)
    db.add(AuditLog(action="test", created_at=datetime.now(timezone.utc) - timedelta(days=400)))
    db.commit()
    # Age everything: pretend the last activity was 400 days ago, device .2 gone since then
    old = datetime.now(timezone.utc) - timedelta(days=400)
    for e in db.scalars(select(Event)).unique():
        e.created_at = old
    for s in db.scalars(select(Scan)):
        s.created_at = old
    for snap in db.scalars(select(Snapshot)):
        snap.snapshot_date = old.date()
    d2 = db.scalar(select(Device).where(Device.current_ip == "10.0.0.2"))
    d2.status, d2.last_seen = "not_detected", old
    db.commit()

    counts = run_retention(db, days=365)
    db.commit()
    assert counts["events"] >= 1 and counts["snapshots"] == 1 and counts["scans"] == 2
    assert counts["audit_log"] == 1 and counts["devices"] == 1
    assert db.scalar(select(func.count(Event.id))) == 0
    assert {d.current_ip for d in db.scalars(select(Device))} == {"10.0.0.1", "10.0.0.3"}


def test_email_format_is_concise(db):
    net = make_network(db, cidr="10.20.15.0/24")
    scan(ScriptedScanner([host("10.20.15.22", [port(22, "ssh")], hostname="server01")]), network_id=net.id)
    s = scan(ScriptedScanner([host("10.20.15.22", [port(22, "ssh"), port(8080, "http")], hostname="server01")]),
             network_id=net.id)
    ev = events(db, s.id)[0]
    subject, body = format_event(ev)
    assert subject == "[Network Monitor] New port detected"
    assert "Device: server01" in body and "IP: 10.20.15.22" in body and "Port: TCP/8080" in body
    assert "Service: http" in body and "Detected: " in body
    assert len(body.splitlines()) <= 7
    subject, body = format_digest([ev] * 60)
    assert "60 network changes" in subject and "... and 10 more" in body


def test_notifications_sent_once_per_event(db, monkeypatch):
    sent = []

    class FakeSMTP:
        def __init__(self, host, port, timeout=None):
            sent.append(("connect", host, port))

        def ehlo_or_helo_if_needed(self):
            pass

        def send_message(self, msg):
            sent.append(("send", msg["Subject"], msg["To"]))

        def quit(self):
            pass

    monkeypatch.setattr("app.core.notify.smtplib.SMTP", FakeSMTP)
    put_section(db, NotificationSettings(enabled=True, smtp_host="relay.local", recipients=["a@x.local", "b@x.local"],
                                         password_enc=encrypt_secret("")))
    db.commit()
    net = make_network(db)
    scan(ScriptedScanner([host("10.0.0.1", [port(22, "ssh")])]), network_id=net.id)
    assert not [s for s in sent if s[0] == "send"]  # baseline: nothing
    s = scan(ScriptedScanner([host("10.0.0.1", [port(22, "ssh"), port(9000, "http")])]), network_id=net.id)
    sends = [x for x in sent if x[0] == "send"]
    assert sends == [("send", "[Network Monitor] New port detected", "a@x.local, b@x.local")]
    assert events(db, s.id)[0].notified_at is not None
    assert notify_events([e.id for e in events(db, s.id)]) == 0  # never re-sent
    scan(ScriptedScanner([host("10.0.0.1", [port(22, "ssh"), port(9000, "http")])]), network_id=net.id)
    assert len([x for x in sent if x[0] == "send"]) == 1  # unchanged state, no new email


def test_schedule_next_run_and_tick(db):
    cfg = ScheduleSettings(enabled=True, time="02:00", days=[0, 1, 2, 3, 4, 5, 6])
    now = datetime(2026, 10, 5, 1, 0).astimezone()
    assert next_run(cfg, now).hour == 2 and next_run(cfg, now).date() == now.date()
    later = now.replace(hour=3)
    assert next_run(cfg, later).date() == (later + timedelta(days=1)).date()
    assert next_run(ScheduleSettings(enabled=False), now) is None

    make_network(db)
    put_section(db, cfg)
    db.commit()
    tick(now)  # first tick initializes state without catching up
    tick(now.replace(hour=2, minute=1))
    assert db.scalar(select(func.count(Scan.id))) == 1
    tick(now.replace(hour=2, minute=5))  # same day: no duplicate
    assert db.scalar(select(func.count(Scan.id))) == 1
    assert enqueue_scheduled_scans(db) == []  # already queued for that network
