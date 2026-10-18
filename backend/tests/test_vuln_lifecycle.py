"""core/vuln/lifecycle.py: first-seen/resolved tracking in vuln_finding_lifecycle."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from app.core.vuln.lifecycle import (
    RESOLUTION_DEVICE_REMOVED,
    RESOLUTION_NO_LONGER_MATCHED,
    sync_finding_lifecycle,
)
from app.models import VULN_STATE_CONFIRMED, VULN_STATE_DISMISSED, DevicePortVuln, Vulnerability, VulnFindingLifecycle

from .helpers import ScriptedScanner, device_by_ip, host, make_network, port, scan

T0 = datetime(2026, 1, 1, tzinfo=timezone.utc)
T1 = T0 + timedelta(days=7)
T2 = T0 + timedelta(days=14)


def _seed_device_with_finding(db, ip="10.0.0.1"):
    net = make_network(db)
    scan(ScriptedScanner([host(ip, [port(22, "ssh", "OpenSSH", "7.4")], mac="00:11:22:33:44:01")]), network_id=net.id)
    d = device_by_ip(db, ip)
    p = next(pp for pp in d.ports if pp.port == 22)
    db.add(Vulnerability(cve_id="CVE-2024-0001", cvss_base=7.5))
    db.flush()
    db.add(DevicePortVuln(device_port_id=p.id, cve_id="CVE-2024-0001", state=VULN_STATE_CONFIRMED, matched_at=T0))
    db.commit()
    return d, p


def test_new_finding_creates_lifecycle_row(db):
    d, p = _seed_device_with_finding(db)
    stats = sync_finding_lifecycle(db, now=T0)
    db.commit()
    assert stats == {"new": 1, "resolved": 0, "reopened": 0}
    row = db.query(VulnFindingLifecycle).one()
    assert row.device_uuid == d.uuid and row.port == 22 and row.cve_id == "CVE-2024-0001"
    assert row.first_seen_at == T0 and row.last_seen_at == T0
    assert row.resolved_at is None and row.dismissed_at is None


def test_still_matching_bumps_last_seen_not_first_seen(db):
    _seed_device_with_finding(db)
    sync_finding_lifecycle(db, now=T0)
    db.commit()
    stats = sync_finding_lifecycle(db, now=T1)
    db.commit()
    assert stats == {"new": 0, "resolved": 0, "reopened": 0}
    row = db.query(VulnFindingLifecycle).one()
    assert row.first_seen_at == T0 and row.last_seen_at == T1


def test_no_longer_matching_resolves(db):
    d, p = _seed_device_with_finding(db)
    sync_finding_lifecycle(db, now=T0)
    db.commit()
    db.query(DevicePortVuln).filter_by(device_port_id=p.id).delete()
    db.commit()
    stats = sync_finding_lifecycle(db, now=T1)
    db.commit()
    assert stats == {"new": 0, "resolved": 1, "reopened": 0}
    row = db.query(VulnFindingLifecycle).one()
    assert row.resolved_at == T1 and row.resolution == RESOLUTION_NO_LONGER_MATCHED


def test_device_removed_sets_device_removed_resolution(db):
    d, p = _seed_device_with_finding(db)
    sync_finding_lifecycle(db, now=T0)
    db.commit()
    db.delete(d)
    db.commit()
    stats = sync_finding_lifecycle(db, now=T1)
    db.commit()
    assert stats == {"new": 0, "resolved": 1, "reopened": 0}
    row = db.query(VulnFindingLifecycle).one()
    assert row.resolution == RESOLUTION_DEVICE_REMOVED


def test_resolved_finding_reappearing_reopens(db):
    d, p = _seed_device_with_finding(db)
    sync_finding_lifecycle(db, now=T0)
    db.commit()
    db.query(DevicePortVuln).filter_by(device_port_id=p.id).delete()
    db.commit()
    sync_finding_lifecycle(db, now=T1)
    db.commit()
    row = db.query(VulnFindingLifecycle).one()
    assert row.resolved_at is not None

    db.add(DevicePortVuln(device_port_id=p.id, cve_id="CVE-2024-0001", state=VULN_STATE_CONFIRMED, matched_at=T2))
    db.commit()
    stats = sync_finding_lifecycle(db, now=T2)
    db.commit()
    assert stats == {"new": 0, "resolved": 0, "reopened": 1}
    row = db.query(VulnFindingLifecycle).one()
    assert row.resolved_at is None and row.resolution is None
    assert row.first_seen_at == T0  # original first-seen date preserved across a reopen


def test_dismiss_and_undismiss_set_and_clear_dismissed_at(db):
    d, p = _seed_device_with_finding(db)
    sync_finding_lifecycle(db, now=T0)
    db.commit()

    row = db.query(DevicePortVuln).filter_by(device_port_id=p.id).one()
    row.state = VULN_STATE_DISMISSED
    db.commit()
    sync_finding_lifecycle(db, now=T1)
    db.commit()
    lc = db.query(VulnFindingLifecycle).one()
    assert lc.dismissed_at == T1 and lc.resolved_at is None

    row.state = VULN_STATE_CONFIRMED
    db.commit()
    sync_finding_lifecycle(db, now=T2)
    db.commit()
    lc = db.query(VulnFindingLifecycle).one()
    assert lc.dismissed_at is None
