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


def test_severity_by_network_matrix(db):
    net = make_network(db)
    scan(ScriptedScanner([host("10.0.0.1", [port(22, "ssh", "OpenSSH", "7.4")], mac="00:11:22:33:44:01")]),
         network_id=net.id)
    net2 = make_network(db, cidr="10.0.1.0/24", name="Second Net")
    scan(ScriptedScanner([host("10.0.1.1", [port(80, "http", "nginx", "1.18")], mac="00:11:22:33:44:02")]),
         network_id=net2.id)
    da = device_by_ip(db, "10.0.0.1")
    db_ = device_by_ip(db, "10.0.1.1")
    pa = next(p for p in da.ports if p.port == 22)
    pb = next(p for p in db_.ports if p.port == 80)
    db.add(Vulnerability(cve_id="CVE-2024-CRIT", cvss_base=9.8))
    db.add(Vulnerability(cve_id="CVE-2024-MED", cvss_base=5.0))
    db.flush()
    db.add(DevicePortVuln(device_port_id=pa.id, cve_id="CVE-2024-CRIT", state=VULN_STATE_CONFIRMED, matched_at=T))
    db.add(DevicePortVuln(device_port_id=pb.id, cve_id="CVE-2024-MED", state=VULN_STATE_CONFIRMED, matched_at=T))
    db.commit()

    summary = refresh_vuln_summary(db, now=T)
    matrix = {row["network"]: row for row in summary["severity_by_network"]}
    assert matrix["Test Net"]["critical"] == 1 and matrix["Test Net"]["medium"] == 0
    assert matrix["Test Net"]["network_id"] == net.id
    assert matrix["Second Net"]["medium"] == 1 and matrix["Second Net"]["critical"] == 0

    network_facet = {b["key"]: b for b in summary["facets"]["network"]}
    assert network_facet[net.id]["label"] == "Test Net" and network_facet[net.id]["count"] == 1
    assert network_facet[net2.id]["label"] == "Second Net" and network_facet[net2.id]["count"] == 1


def test_snapshot_trend_full_resolution_within_90_days(db):
    _seed(db)
    for days_ago in (5, 10):
        write_daily_snapshot(db, T - timedelta(days=days_ago))
    write_daily_snapshot(db, T)
    db.commit()

    trend = refresh_vuln_summary(db, now=T)["snapshot_trend"]
    dates = {p["date"] for p in trend}
    assert len(dates) == 3  # one point per day, no decimation


def test_snapshot_trend_decimates_to_weekly_beyond_90_days(db):
    _seed(db)
    for days_ago in range(95, 110):  # 16 consecutive days, all older than the 90-day cutoff
        write_daily_snapshot(db, T - timedelta(days=days_ago))
    db.commit()

    trend = refresh_vuln_summary(db, now=T)["snapshot_trend"]
    assert 1 <= len(trend) <= 3  # 16 days span at most 3 ISO weeks, collapsed to one point each


def test_new_since_last_scan_lists_findings_matched_after_scan(db):
    _seed(db)
    from app.models import Scan
    for s in db.query(Scan).all():
        s.finished_at = T - timedelta(hours=1)
    db.commit()
    summary = refresh_vuln_summary(db, now=T)
    cves = {row["cve_id"] for row in summary["new_since_last_scan"]}
    assert cves == {"CVE-2024-CRIT", "CVE-2024-MED"}
    assert all(row["device_uuid"] and row["device_ip"] for row in summary["new_since_last_scan"])


def test_new_since_last_db_update_uses_newest_enabled_feed_sync(db):
    _seed(db)
    from app.models import VulnFeedState
    db.add(VulnFeedState(source="nvd", last_synced_at=T - timedelta(hours=2)))
    db.add(VulnFeedState(source="kev", last_synced_at=T - timedelta(minutes=30)))
    db.add(VulnFeedState(source="epss", last_synced_at=T - timedelta(hours=1)))
    db.commit()
    summary = refresh_vuln_summary(db, now=T)
    # newest enabled sync is kev at T-30m; findings matched_at=T are after that
    assert {row["cve_id"] for row in summary["new_since_last_db_update"]} == {"CVE-2024-CRIT", "CVE-2024-MED"}


def test_write_daily_snapshot_purges_rows_older_than_a_year(db):
    net, _da, _db_ = _seed(db)
    old = VulnDailySnapshot(network_id=None, snapshot_date=(T - timedelta(days=400)).date())
    db.add(old)
    db.commit()
    write_daily_snapshot(db, T)
    db.commit()
    assert db.query(VulnDailySnapshot).filter_by(snapshot_date=(T - timedelta(days=400)).date()).count() == 0
