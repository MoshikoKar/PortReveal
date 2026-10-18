"""core/vuln/summary.py: the computed dict backing the vulnerabilities dashboard."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from app.core.mockdata import set_mock_hidden
from app.core.vuln.summary import (
    get_vuln_summary,
    invalidate_vuln_summary_cache,
    refresh_vuln_summary,
    write_daily_snapshot,
)
from app.db import utcnow
from app.models import (
    VULN_STATE_CONFIRMED,
    VULN_STATE_DISMISSED,
    VULN_STATE_POTENTIAL,
    DevicePortVuln,
    Network,
    VulnDailySnapshot,
    Vulnerability,
)
from app.settings_store import VulnSettings, put_section

from .helpers import ScriptedScanner, device_by_ip, host, make_network, port, scan

T = datetime(2026, 1, 20, tzinfo=timezone.utc)


def _seed(db):
    """Two devices, each with one matched CVE: critical+KEV+high-EPSS on device A (confirmed),
    medium+no-KEV+low-EPSS on device B (potential)."""
    net = make_network(db)
    scan(ScriptedScanner([
        host("10.0.0.1", [port(22, "ssh", "OpenSSH", "7.4")], mac="00:11:22:33:44:01"),
        host("10.0.0.2", [port(80, "http", "nginx", "1.18")], mac="00:11:22:33:44:02"),
    ]), network_id=net.id)
    da = device_by_ip(db, "10.0.0.1")
    db_ = device_by_ip(db, "10.0.0.2")
    pa = next(p for p in da.ports if p.port == 22)
    pb = next(p for p in db_.ports if p.port == 80)
    db.add(Vulnerability(cve_id="CVE-2024-CRIT", cvss_base=9.8, kev=True, epss=0.9))
    db.add(Vulnerability(cve_id="CVE-2024-MED", cvss_base=5.0, kev=False, epss=0.01))
    db.flush()
    db.add(DevicePortVuln(device_port_id=pa.id, cve_id="CVE-2024-CRIT", state=VULN_STATE_CONFIRMED, matched_at=T))
    db.add(DevicePortVuln(device_port_id=pb.id, cve_id="CVE-2024-MED", state=VULN_STATE_POTENTIAL, matched_at=T))
    db.commit()
    return net, da, db_


def test_refresh_vuln_summary_counts_severity_kev_epss(db):
    _seed(db)
    put_section(db, VulnSettings(enabled=True, epss_high_threshold=0.1))
    db.commit()
    summary = refresh_vuln_summary(db, now=T)
    assert summary["severity_counts"]["critical"] == 1
    assert summary["severity_counts"]["medium"] == 1
    assert summary["kev_count"] == 1
    assert summary["epss_high_count"] == 1  # only CVE-2024-CRIT (epss 0.9) clears the 0.1 threshold
    assert summary["confirmed_count"] == 1
    assert summary["potential_count"] == 1
    assert summary["epss_threshold"] == 0.1


def test_dismissed_findings_excluded_from_counts(db):
    _seed(db)
    row = db.query(DevicePortVuln).filter_by(cve_id="CVE-2024-CRIT").one()
    row.state = VULN_STATE_DISMISSED
    db.commit()
    summary = refresh_vuln_summary(db, now=T)
    assert summary["severity_counts"]["critical"] == 0
    assert summary["kev_count"] == 0


def test_mock_devices_excluded_when_hidden(db):
    """Every device from the ScriptedScanner helper is mock-only (scanner_mode='mock'); hiding
    mock data must zero out their findings."""
    _seed(db)
    summary = refresh_vuln_summary(db, now=T)
    assert summary["severity_counts"]["critical"] == 1

    set_mock_hidden(db, True)
    db.commit()
    summary = refresh_vuln_summary(db, now=T)
    assert summary["severity_counts"]["critical"] == 0
    assert summary["severity_counts"]["medium"] == 0


def test_archived_network_devices_excluded(db):
    net, da, db_ = _seed(db)
    summary = refresh_vuln_summary(db, now=T)
    assert summary["severity_counts"]["critical"] == 1

    n = db.get(Network, net.id)
    n.archived_at = utcnow()
    db.commit()
    summary = refresh_vuln_summary(db, now=T)
    assert summary["severity_counts"]["critical"] == 0
    assert summary["severity_counts"]["medium"] == 0


def test_get_vuln_summary_caches_until_invalidated(db):
    _seed(db)
    first = get_vuln_summary(db, now=T)
    assert first["severity_counts"]["critical"] == 1

    row = db.query(DevicePortVuln).filter_by(cve_id="CVE-2024-CRIT").one()
    row.state = VULN_STATE_DISMISSED
    db.commit()
    cached = get_vuln_summary(db, now=T)
    assert cached["severity_counts"]["critical"] == 1  # stale cache, not yet invalidated

    invalidate_vuln_summary_cache()
    fresh = get_vuln_summary(db, now=T)
    assert fresh["severity_counts"]["critical"] == 0


def test_write_daily_snapshot_is_idempotent_same_day(db):
    _seed(db)
    write_daily_snapshot(db, T)
    db.commit()
    assert db.query(VulnDailySnapshot).filter_by(network_id=None).count() == 1
    global_row = db.query(VulnDailySnapshot).filter_by(network_id=None).one()
    assert global_row.critical == 1 and global_row.medium == 1

    write_daily_snapshot(db, T + timedelta(hours=2))
    db.commit()
    assert db.query(VulnDailySnapshot).filter_by(network_id=None).count() == 1  # same local day: upsert, not insert


def test_write_daily_snapshot_purges_rows_older_than_a_year(db):
    net, _da, _db_ = _seed(db)
    old = VulnDailySnapshot(network_id=None, snapshot_date=(T - timedelta(days=400)).date())
    db.add(old)
    db.commit()
    write_daily_snapshot(db, T)
    db.commit()
    assert db.query(VulnDailySnapshot).filter_by(snapshot_date=(T - timedelta(days=400)).date()).count() == 0
