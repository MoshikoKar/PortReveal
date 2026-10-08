from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select

from app.core.notify import format_daily_digest, send_daily_digest
from app.core.retention import run_retention
from app.core.scheduler import enqueue_baseline_retries, enqueue_scheduled_scans, next_run, tick
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


def test_email_format_is_categorized_html(db):
    net = make_network(db, cidr="10.20.15.0/24")
    scan(ScriptedScanner([host("10.20.15.22", [port(22, "ssh")], hostname="server01")]), network_id=net.id)
    s = scan(ScriptedScanner([host("10.20.15.22", [port(22, "ssh"), port(8080, "http")], hostname="server01")]),
             network_id=net.id)
    ev = events(db, s.id)[0]
    subject, plain, html_body = format_daily_digest([ev], {net.id: net.name})
    assert "Daily summary" in subject and "1 change" in subject
    assert "Ports" in plain and "server01" in plain and "10.20.15.22" in plain
    assert "TCP/8080" in plain and "http" in plain
    assert "<table" in html_body and "New port detected" in html_body
    assert "Ports" in html_body and "server01" in html_body
    subject60, plain60, html60 = format_daily_digest([ev] * 60, {net.id: net.name})
    assert "60 changes" in subject60 and "Ports (60)" in plain60
    assert "<table" in html60


def test_notifications_sent_once_as_daily_digest(db, monkeypatch):
    sent = []

    class FakeSMTP:
        def __init__(self, host, port, timeout=None):
            sent.append(("connect", host, port))

        def ehlo_or_helo_if_needed(self):
            pass

        def send_message(self, msg):
            html_part = None
            for part in msg.iter_parts():
                if part.get_content_type() == "text/html":
                    html_part = part.get_content()
            sent.append(("send", msg["Subject"], msg["To"], bool(html_part)))

        def quit(self):
            pass

    monkeypatch.setattr("app.core.notify.smtplib.SMTP", FakeSMTP)
    put_section(db, NotificationSettings(enabled=True, smtp_host="relay.local", recipients=["a@x.local", "b@x.local"],
                                         password_enc=encrypt_secret(""), digest_time="08:00"))
    db.commit()
    net = make_network(db)
    scan(ScriptedScanner([host("10.0.0.1", [port(22, "ssh")])]), network_id=net.id)
    assert not [s for s in sent if s[0] == "send"]  # baseline: nothing; scans never email immediately
    s = scan(ScriptedScanner([host("10.0.0.1", [port(22, "ssh"), port(9000, "http")])]), network_id=net.id)
    assert events(db, s.id)[0].notified_at is None
    assert not [x for x in sent if x[0] == "send"]

    assert send_daily_digest() == "sent"
    sends = [x for x in sent if x[0] == "send"]
    assert len(sends) == 1
    assert "Daily summary" in sends[0][1] and sends[0][2] == "a@x.local, b@x.local" and sends[0][3] is True
    db.expire_all()
    assert events(db, s.id)[0].notified_at is not None
    assert send_daily_digest() == "empty"  # never re-sent
    scan(ScriptedScanner([host("10.0.0.1", [port(22, "ssh"), port(9000, "http")])]), network_id=net.id)
    assert send_daily_digest() == "empty"  # unchanged state, no pending events
    assert len([x for x in sent if x[0] == "send"]) == 1


def test_schedule_next_run_and_tick(db):
    cfg = ScheduleSettings(enabled=True, time="02:00", days=[0, 1, 2, 3, 4, 5, 6],
                           discovery_before_standard=True)
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
    scans = list(db.scalars(select(Scan).order_by(Scan.id)).all())
    assert [(s.scan_type, s.trigger) for s in scans] == [("discovery", "scheduled"), ("standard", "scheduled")]
    tick(now.replace(hour=2, minute=5))  # same day: no duplicate
    assert db.scalar(select(func.count(Scan.id))) == 2
    assert enqueue_scheduled_scans(db) == []  # already queued for that network


def test_schedule_skips_discovery_when_disabled(db):
    cfg = ScheduleSettings(enabled=True, time="02:00", days=[0, 1, 2, 3, 4, 5, 6],
                           discovery_before_standard=False)
    put_section(db, cfg)
    make_network(db)
    db.commit()
    ids = enqueue_scheduled_scans(db, cfg)
    assert len(ids) == 1
    assert db.get(Scan, ids[0]).scan_type == "standard"


def test_network_without_baseline_is_rescanned_until_baseline_exists(db):
    net = make_network(db)
    now = datetime.now(timezone.utc)
    net.created_at = now - timedelta(minutes=10)
    db.commit()
    assert enqueue_baseline_retries(db, now) == []  # brand-new network: give the admin time to scan it

    net.created_at = now - timedelta(days=2)
    db.commit()
    first = enqueue_baseline_retries(db, now)
    assert len(first) == 2  # discovery then standard
    assert [db.get(Scan, i).scan_type for i in first] == ["discovery", "standard"]
    assert enqueue_baseline_retries(db, now) == []  # already queued: never stack a second one

    for sid in first:
        db.get(Scan, sid).status = "completed" if db.get(Scan, sid).scan_type == "discovery" else "partial"
    db.commit()
    assert enqueue_baseline_retries(db, now + timedelta(hours=1)) == []  # too soon after the last attempt
    assert len(enqueue_baseline_retries(db, now + timedelta(hours=13))) == 2

    db.query(Scan).update({Scan.status: "completed"})
    s = db.get(Scan, first[-1])
    net.baseline_scan_id, net.baseline_at = s.id, now
    db.commit()
    assert enqueue_baseline_retries(db, now + timedelta(days=5)) == []  # baseline done: no more retries
