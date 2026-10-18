"""CVSS -> severity bucket helper, and round-trips for the two new vuln-dashboard tables."""
from __future__ import annotations

from datetime import date, datetime, timezone

from sqlalchemy import func, select

from app.core.vuln.buckets import severity_bucket, severity_bucket_expr
from app.models import VulnDailySnapshot, Vulnerability, VulnFindingLifecycle

from .helpers import make_network

T = datetime(2026, 1, 20, tzinfo=timezone.utc)


# --- severity_bucket: boundary values --------------------------------------------------------
def test_severity_bucket_boundaries():
    assert severity_bucket(9.0) == "critical"
    assert severity_bucket(8.9) == "high"
    assert severity_bucket(7.0) == "high"
    assert severity_bucket(6.9) == "medium"
    assert severity_bucket(4.0) == "medium"
    assert severity_bucket(3.9) == "low"
    assert severity_bucket(0.0) == "low"


def test_severity_bucket_none_is_unknown_not_guessed_medium():
    """Display severity comes from CVSS bands only; missing score is unscored, not DEFAULT_CVSS."""
    assert severity_bucket(None) == "unknown"


# --- severity_bucket_expr: same buckets, computed in SQL -------------------------------------
def test_severity_bucket_expr_matches_python_helper(db):
    rows = [
        ("CVE-2026-0001", 9.8),
        ("CVE-2026-0002", 7.2),
        ("CVE-2026-0003", 5.5),
        ("CVE-2026-0004", 1.0),
        ("CVE-2026-0005", None),
    ]
    for cve_id, cvss in rows:
        db.add(Vulnerability(cve_id=cve_id, cvss_base=cvss))
    db.commit()

    counts = dict(db.execute(
        select(severity_bucket_expr(Vulnerability.cvss_base), func.count())
        .where(Vulnerability.cve_id.in_([r[0] for r in rows]))
        .group_by(severity_bucket_expr(Vulnerability.cvss_base))
    ).all())

    expected: dict[str, int] = {}
    for _cve_id, cvss in rows:
        bucket = severity_bucket(cvss)
        expected[bucket] = expected.get(bucket, 0) + 1
    assert counts == expected


# --- VulnDailySnapshot: round trip ------------------------------------------------------------
def test_vuln_daily_snapshot_round_trip(db):
    net = make_network(db)
    snap = VulnDailySnapshot(
        snapshot_date=date(2026, 1, 20), network_id=net.id, critical=1, high=2, medium=3, low=4,
        kev_count=1, confirmed_count=5, potential_count=5, avg_risk_score=42.5, avg_combined_score=55.0,
    )
    db.add(snap)
    db.commit()

    loaded = db.scalar(select(VulnDailySnapshot).where(VulnDailySnapshot.network_id == net.id))
    assert loaded is not None
    assert loaded.snapshot_date == date(2026, 1, 20)
    assert (loaded.critical, loaded.high, loaded.medium, loaded.low) == (1, 2, 3, 4)
    assert loaded.kev_count == 1
    assert loaded.avg_risk_score == 42.5
    assert loaded.created_at is not None


def test_vuln_daily_snapshot_global_row_has_no_network(db):
    snap = VulnDailySnapshot(snapshot_date=date(2026, 1, 20), network_id=None, critical=0)
    db.add(snap)
    db.commit()
    loaded = db.scalar(select(VulnDailySnapshot).where(VulnDailySnapshot.id == snap.id))
    assert loaded.network_id is None


# --- VulnFindingLifecycle: round trip ---------------------------------------------------------
def test_vuln_finding_lifecycle_round_trip(db):
    net = make_network(db)
    row = VulnFindingLifecycle(
        device_uuid="11111111-1111-1111-1111-111111111111", port=22, protocol="tcp",
        cve_id="CVE-2026-0001", network_id=net.id, first_seen_at=T, last_seen_at=T,
    )
    db.add(row)
    db.commit()

    loaded = db.scalar(select(VulnFindingLifecycle).where(VulnFindingLifecycle.cve_id == "CVE-2026-0001"))
    assert loaded is not None
    assert (loaded.device_uuid, loaded.port, loaded.protocol) == (row.device_uuid, 22, "tcp")
    assert loaded.resolved_at is None
    assert loaded.resolution is None
    assert loaded.dismissed_at is None


def test_vuln_finding_lifecycle_survives_device_removal():
    """Identity fields are plain values, not cascading FKs: a row must be insertable (and later
    readable) for a device uuid that no longer has a live `devices` row at all."""
    from app.db import session_scope

    with session_scope() as db:
        db.add(VulnFindingLifecycle(
            device_uuid="22222222-2222-2222-2222-222222222222", port=443, protocol="tcp",
            cve_id="CVE-2026-0002", network_id=None, first_seen_at=T, last_seen_at=T,
            resolved_at=T, resolution="device_removed",
        ))

    with session_scope() as db:
        loaded = db.scalar(
            select(VulnFindingLifecycle).where(VulnFindingLifecycle.cve_id == "CVE-2026-0002")
        )
        assert loaded.resolution == "device_removed"
        assert loaded.resolved_at is not None
