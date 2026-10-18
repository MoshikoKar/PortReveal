"""IP assignment heuristic (spec 7), RTT samples and continuous-uptime (spec 6)."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from app.core.availability import availability_pct
from app.core.ip_assignment import compute as compute_ip_assignment
from app.core.retention import purge_expired
from app.models import Device, DeviceRttSample
from app.settings_store import RetentionSettings, get_section

from .helpers import ScriptedScanner, device_by_ip, host, make_network, port, scan

T = datetime(2026, 1, 20, tzinfo=timezone.utc)


def _dev(hostname: str | None = None, current_ip: str = "10.0.0.5") -> Device:
    return Device(current_ip=current_ip, hostname=hostname)


def test_ip_assignment_new_device_is_unknown():
    assert compute_ip_assignment(_dev(), [], T) == "unknown"
    # one address, but barely any history yet
    recent = [("10.0.0.5", T - timedelta(hours=1), T)]
    assert compute_ip_assignment(_dev(), recent, T) == "unknown"


def test_ip_assignment_single_stable_ip_is_static():
    rows = [("10.0.0.5", T - timedelta(days=30), T)]
    assert compute_ip_assignment(_dev(), rows, T) == "static"


def test_ip_assignment_multiple_recent_ips_is_dynamic():
    rows = [
        ("10.0.0.5", T - timedelta(days=40), T - timedelta(days=10)),
        ("10.0.0.6", T - timedelta(days=5), T),
    ]
    assert compute_ip_assignment(_dev(), rows, T) == "dynamic"


def test_ip_assignment_old_single_ip_outside_dynamic_window_stays_static():
    # Two addresses total, but the older one fell out of the dynamic-detection window:
    # the device has held its current address alone for a long time now → static.
    rows = [
        ("10.0.0.4", T - timedelta(days=200), T - timedelta(days=100)),
        ("10.0.0.5", T - timedelta(days=60), T),
    ]
    assert compute_ip_assignment(_dev(), rows, T) == "static"
    generic = _dev(hostname="10-0-0-5.dhcp.corp")
    assert compute_ip_assignment(generic, rows, T) == "dynamic"


def test_rtt_sample_written_and_last_rtt_ms_set(db):
    net = make_network(db)
    scan(ScriptedScanner([host("10.0.0.1", [port(22, "ssh")], mac="00:11:22:33:44:01", rtt_ms=1.5)]),
         network_id=net.id)
    d = device_by_ip(db, "10.0.0.1")
    assert d.last_rtt_ms == 1.5
    samples = db.query(DeviceRttSample).filter_by(device_id=d.id).all()
    assert len(samples) == 1 and samples[0].rtt_ms == 1.5

    scan(ScriptedScanner([host("10.0.0.1", [port(22, "ssh")], mac="00:11:22:33:44:01", rtt_ms=3.0)]),
         network_id=net.id)
    d = device_by_ip(db, "10.0.0.1")
    assert d.last_rtt_ms == 3.0
    assert db.query(DeviceRttSample).filter_by(device_id=d.id).count() == 2


def test_rtt_missing_this_scan_keeps_last_known_value(db):
    net = make_network(db)
    scan(ScriptedScanner([host("10.0.0.1", [port(22, "ssh")], mac="00:11:22:33:44:01", rtt_ms=2.0)]),
         network_id=net.id)
    scan(ScriptedScanner([host("10.0.0.1", [port(22, "ssh")], mac="00:11:22:33:44:01")]), network_id=net.id)
    d = device_by_ip(db, "10.0.0.1")
    assert d.last_rtt_ms == 2.0  # unchanged: this scan had no srtt
    assert db.query(DeviceRttSample).filter_by(device_id=d.id).count() == 1


def test_continuous_since_set_on_discovery_and_reset_on_reappear(db):
    net = make_network(db)
    scan(ScriptedScanner([host("10.0.0.1", [port(22, "ssh")], mac="00:11:22:33:44:01")]), network_id=net.id)
    d = device_by_ip(db, "10.0.0.1")
    assert d.continuous_since is not None
    first_streak = d.continuous_since

    # Force "not detected" directly (disappearance mechanics are covered elsewhere).
    with db.begin_nested():
        d.status = "not_detected"
        d.missed_scans = 5
    db.commit()

    scan(ScriptedScanner([host("10.0.0.1", [port(22, "ssh")], mac="00:11:22:33:44:01")]), network_id=net.id)
    d = device_by_ip(db, "10.0.0.1")
    assert d.status == "active"
    assert d.continuous_since is not None and d.continuous_since > first_streak


def test_rtt_sample_retention_uses_its_own_window(db):
    net = make_network(db)
    scan(ScriptedScanner([host("10.0.0.1", [port(22, "ssh")], mac="00:11:22:33:44:01", rtt_ms=1.0)]),
         network_id=net.id)
    d = device_by_ip(db, "10.0.0.1")
    old = db.query(DeviceRttSample).filter_by(device_id=d.id).one()
    old.sampled_at = T - timedelta(days=200)
    db.commit()

    cfg = get_section(db, RetentionSettings)
    assert cfg.rtt_sample_days == 90
    counts, _ = purge_expired(db, cfg.days, now=T, rtt_days=cfg.rtt_sample_days)
    db.commit()
    assert counts["device_rtt_samples"] == 1
    assert db.query(DeviceRttSample).filter_by(device_id=d.id).count() == 0


def test_availability_pct_from_scan_hosts(db):
    net = make_network(db)
    scan(ScriptedScanner([host("10.0.0.1", [port(22, "ssh")], mac="00:11:22:33:44:01")]), network_id=net.id)
    d = device_by_ip(db, "10.0.0.1")
    assert availability_pct(db, d.id, now=d.last_seen) == 100.0


def test_availability_pct_counts_missed_network_scans(db):
    net = make_network(db)
    scan(ScriptedScanner([host("10.0.0.1", [port(22, "ssh")], mac="00:11:22:33:44:01")]), network_id=net.id)
    # Second network scan does not see the device → missed scan must lower availability.
    scan(ScriptedScanner([host("10.0.0.2", [port(22, "ssh")], mac="00:11:22:33:44:02")]), network_id=net.id)
    d = device_by_ip(db, "10.0.0.1")
    pct = availability_pct(db, d.id, now=d.last_seen + timedelta(minutes=1))
    assert pct == 50.0


def test_availability_pct_none_without_history(db):
    net = make_network(db)
    scan(ScriptedScanner([host("10.0.0.1", [port(22, "ssh")], mac="00:11:22:33:44:01")]), network_id=net.id)
    d = device_by_ip(db, "10.0.0.1")
    assert availability_pct(db, d.id, now=d.last_seen + timedelta(days=365)) is None
