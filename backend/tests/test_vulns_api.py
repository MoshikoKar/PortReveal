"""GET /api/vulns (filterable finding list) and GET /api/vulns/{cve_id} (CVE detail)."""
from __future__ import annotations

from datetime import timedelta

import pytest
from fastapi.testclient import TestClient

from app.api.auth import limiter
from app.core.vuln.lifecycle import sync_finding_lifecycle
from app.core.vuln.score import RISK_HIGH_THRESHOLD, RISK_MEDIUM_THRESHOLD
from app.db import utcnow
from app.main import app
from app.models import (
    VULN_STATE_CONFIRMED,
    VULN_STATE_DISMISSED,
    VULN_STATE_POTENTIAL,
    DevicePortVuln,
    VulnCpeMatch,
    Vulnerability,
)
from app.settings_store import VulnSettings, put_section

from .helpers import ScriptedScanner, device_by_ip, host, make_network, port, scan


@pytest.fixture
def client(db_env):
    limiter.reset()
    with TestClient(app) as c:
        yield c


def csrf(c: TestClient) -> dict:
    return {"X-CSRF-Token": c.cookies.get("nf_csrf", "")}


@pytest.fixture
def admin(db, client):
    assert client.post("/api/setup/admin", json={"username": "admin", "password": "correct-horse-1"}).status_code == 200
    return client


def _uuid(c: TestClient, ip: str) -> str:
    return c.get("/api/search", params={"q": f"ip:{ip}"}).json()["items"][0]["uuid"]


def _seed_two_devices(db):
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
    db.add(DevicePortVuln(device_port_id=pa.id, cve_id="CVE-2024-CRIT", state=VULN_STATE_CONFIRMED, matched_at=utcnow()))
    db.add(DevicePortVuln(device_port_id=pb.id, cve_id="CVE-2024-MED", state=VULN_STATE_POTENTIAL, matched_at=utcnow()))
    db.commit()
    sync_finding_lifecycle(db, now=utcnow())
    db.commit()
    return net, da, db_


def test_list_vulns_no_filter_returns_open_findings(admin, db):
    _seed_two_devices(db)
    r = admin.get("/api/vulns")
    assert r.status_code == 200
    body = r.json()
    assert body["total"] == 2
    cve_ids = {it["cve_id"] for it in body["items"]}
    assert cve_ids == {"CVE-2024-CRIT", "CVE-2024-MED"}


def test_list_vulns_filters_by_severity_kev_epss(admin, db):
    _seed_two_devices(db)
    assert admin.get("/api/vulns", params={"severity": "critical"}).json()["total"] == 1
    assert admin.get("/api/vulns", params={"kev": "true"}).json()["total"] == 1
    assert admin.get("/api/vulns", params={"epss_min": 0.5}).json()["total"] == 1
    assert admin.get("/api/vulns", params={"epss_min": 0.5}).json()["items"][0]["cve_id"] == "CVE-2024-CRIT"


def test_list_vulns_filters_by_network_service_port_os_device_type(admin, db):
    net, da, _db = _seed_two_devices(db)
    assert admin.get("/api/vulns", params={"network_id": net.id}).json()["total"] == 2
    assert admin.get("/api/vulns", params={"network_id": net.id + 999}).json()["total"] == 0
    assert admin.get("/api/vulns", params={"service": "ssh"}).json()["total"] == 1
    assert admin.get("/api/vulns", params={"port": 80}).json()["total"] == 1


def test_list_vulns_filters_unassigned_network(admin, db):
    """Facet key network_id=unassigned must round-trip (devices with no network)."""
    _seed_two_devices(db)
    orphan = device_by_ip(db, "10.0.0.2")
    orphan.network_id = None
    db.commit()
    body = admin.get("/api/vulns", params={"network_id": "unassigned"}).json()
    assert body["total"] == 1 and body["items"][0]["cve_id"] == "CVE-2024-MED"
    assert admin.get("/api/vulns", params={"network_id": "not-a-network"}).status_code == 422


def test_list_vulns_filters_by_cve_id_and_device_uuid(admin, db):
    _net, da, _db = _seed_two_devices(db)
    by_cve = admin.get("/api/vulns", params={"cve_id": "cve-2024-crit"}).json()
    assert by_cve["total"] == 1 and by_cve["items"][0]["cve_id"] == "CVE-2024-CRIT"
    by_device = admin.get("/api/vulns", params={"device_uuid": da.uuid}).json()
    assert by_device["total"] == 1 and by_device["items"][0]["device_uuid"] == da.uuid


def test_list_vulns_filters_new_since_scan_and_db(admin, db):
    """new_since=scan|db matches the dashboard 'New since …' lists (first_seen/matched_at cutoff)."""
    from app.models import VulnFeedState, VulnFindingLifecycle

    _seed_two_devices(db)
    now = utcnow()
    # Seed ran a completed scan before inserting findings → they count as new since that scan.
    assert admin.get("/api/vulns", params={"new_since": "scan"}).json()["total"] == 2

    db.add(VulnFeedState(source="nvd", last_synced_at=now - timedelta(hours=1), record_count=1,
                         mirror_complete=True))
    db.commit()
    assert admin.get("/api/vulns", params={"new_since": "db"}).json()["total"] == 2

    # Age matched_at / lifecycle first_seen earlier than the cutoffs → none are "new".
    for row in db.query(DevicePortVuln).all():
        row.matched_at = now - timedelta(days=3)
    for row in db.query(VulnFindingLifecycle).all():
        row.first_seen_at = now - timedelta(days=3)
    db.commit()
    assert admin.get("/api/vulns", params={"new_since": "scan"}).json()["total"] == 0
    assert admin.get("/api/vulns", params={"new_since": "db"}).json()["total"] == 0


def test_list_vulns_state_filter_and_dismissed_excluded_by_default(admin, db):
    _seed_two_devices(db)
    row = db.query(DevicePortVuln).filter_by(cve_id="CVE-2024-CRIT").one()
    row.state = VULN_STATE_DISMISSED
    db.commit()

    body = admin.get("/api/vulns").json()
    assert body["total"] == 1 and body["items"][0]["cve_id"] == "CVE-2024-MED"

    dismissed = admin.get("/api/vulns", params={"state": "dismissed"}).json()
    assert dismissed["total"] == 1 and dismissed["items"][0]["cve_id"] == "CVE-2024-CRIT"


def test_list_vulns_pagination(admin, db):
    _seed_two_devices(db)
    page1 = admin.get("/api/vulns", params={"page": 1, "page_size": 1}).json()
    page2 = admin.get("/api/vulns", params={"page": 2, "page_size": 1}).json()
    assert page1["total"] == 2 and len(page1["items"]) == 1
    assert len(page2["items"]) == 1
    assert page1["items"][0]["cve_id"] != page2["items"][0]["cve_id"]


def test_list_vulns_exposure_duration_and_cve_age_buckets(admin, db):
    _seed_two_devices(db)
    assert admin.get("/api/vulns", params={"exposure_duration": "under_30d"}).json()["total"] == 2
    assert admin.get("/api/vulns", params={"exposure_duration": "over_365d"}).json()["total"] == 0
    assert admin.get("/api/vulns", params={"cve_age": "unknown"}).json()["total"] == 2  # no published_at seeded


def test_list_vulns_filters_by_risk_band_using_combined_score_thresholds(admin, db):
    """risk_band uses the same combined-score cut points as the summary's high-risk device card."""
    _net, da, db_ = _seed_two_devices(db)
    da.combined_score = RISK_HIGH_THRESHOLD
    db_.combined_score = RISK_MEDIUM_THRESHOLD
    db.commit()

    high = admin.get("/api/vulns", params={"risk_band": "high"}).json()
    assert high["total"] == 1 and high["items"][0]["cve_id"] == "CVE-2024-CRIT"
    medium = admin.get("/api/vulns", params={"risk_band": "medium"}).json()
    assert medium["total"] == 1 and medium["items"][0]["cve_id"] == "CVE-2024-MED"
    assert admin.get("/api/vulns", params={"risk_band": "low"}).json()["total"] == 0

    # Boundary: just below high is medium; just below medium is low.
    da.combined_score = RISK_HIGH_THRESHOLD - 1
    db_.combined_score = RISK_MEDIUM_THRESHOLD - 1
    db.commit()
    assert admin.get("/api/vulns", params={"risk_band": "high"}).json()["total"] == 0
    assert admin.get("/api/vulns", params={"risk_band": "medium"}).json()["total"] == 1
    assert admin.get("/api/vulns", params={"risk_band": "low"}).json()["total"] == 1


def test_export_vulns_respects_risk_band(admin, db):
    _net, da, db_ = _seed_two_devices(db)
    da.combined_score = RISK_HIGH_THRESHOLD
    db_.combined_score = 0
    db.commit()
    r = admin.get("/api/vulns/export", params={"risk_band": "high"})
    body = r.text
    assert "CVE-2024-CRIT" in body and "CVE-2024-MED" not in body


def test_list_vulns_filters_by_vendor_and_product(admin, db):
    """vendor/product match the summary facet keys via vuln_cpe_match.vendor_product."""
    _seed_two_devices(db)
    crit = db.query(DevicePortVuln).filter_by(cve_id="CVE-2024-CRIT").one()
    med = db.query(DevicePortVuln).filter_by(cve_id="CVE-2024-MED").one()
    crit.matched_cpe = "cpe:2.3:a:openbsd:openssh:7.4:*:*:*:*:*:*:*"
    med.matched_cpe = "cpe:2.3:a:f5:nginx:1.18:*:*:*:*:*:*:*"
    db.add(VulnCpeMatch(cve_id="CVE-2024-CRIT", cpe23=crit.matched_cpe, vendor_product="openbsd:openssh"))
    db.add(VulnCpeMatch(cve_id="CVE-2024-MED", cpe23=med.matched_cpe, vendor_product="f5:nginx"))
    db.commit()

    both = admin.get("/api/vulns", params={"vendor": "openbsd", "product": "openssh"}).json()
    assert both["total"] == 1 and both["items"][0]["cve_id"] == "CVE-2024-CRIT"
    vendor_only = admin.get("/api/vulns", params={"vendor": "f5"}).json()
    assert vendor_only["total"] == 1 and vendor_only["items"][0]["cve_id"] == "CVE-2024-MED"
    product_only = admin.get("/api/vulns", params={"product": "openssh"}).json()
    assert product_only["total"] == 1 and product_only["items"][0]["cve_id"] == "CVE-2024-CRIT"

    # Clear CPE match so the finding falls into the facet's "unknown" bucket.
    med.matched_cpe = None
    db.commit()
    unknown = admin.get("/api/vulns", params={"vendor": "unknown"}).json()
    assert unknown["total"] == 1 and unknown["items"][0]["cve_id"] == "CVE-2024-MED"


def test_export_vulns_respects_vendor_product(admin, db):
    _seed_two_devices(db)
    crit = db.query(DevicePortVuln).filter_by(cve_id="CVE-2024-CRIT").one()
    crit.matched_cpe = "cpe:2.3:a:openbsd:openssh:7.4:*:*:*:*:*:*:*"
    db.add(VulnCpeMatch(cve_id="CVE-2024-CRIT", cpe23=crit.matched_cpe, vendor_product="openbsd:openssh"))
    db.commit()
    r = admin.get("/api/vulns/export", params={"vendor": "openbsd", "product": "openssh"})
    assert "CVE-2024-CRIT" in r.text and "CVE-2024-MED" not in r.text


def test_list_vulns_respects_min_cvss_display_like_device_endpoint(admin, db):
    """Parity: /api/vulns and the per-device list must agree on what's visible under the floor."""
    _seed_two_devices(db)
    put_section(db, VulnSettings(enabled=True, min_cvss_display=6.0))
    db.commit()

    body = admin.get("/api/vulns").json()
    assert body["total"] == 1 and body["items"][0]["cve_id"] == "CVE-2024-CRIT"  # KEV never hidden

    uuid_a = _uuid(admin, "10.0.0.1")
    uuid_b = _uuid(admin, "10.0.0.2")
    device_items_a = admin.get(f"/api/devices/{uuid_a}/vulns").json()["items"]
    device_items_b = admin.get(f"/api/devices/{uuid_b}/vulns").json()["items"]
    assert {it["cve_id"] for it in device_items_a} == {"CVE-2024-CRIT"}
    assert {it["cve_id"] for it in device_items_b} == set()  # below floor, not KEV


def test_cve_detail_returns_metadata_and_affected_devices(admin, db):
    _seed_two_devices(db)
    r = admin.get("/api/vulns/CVE-2024-CRIT")
    assert r.status_code == 200
    body = r.json()
    assert body["cve_id"] == "CVE-2024-CRIT" and body["kev"] is True
    assert body["severity"] == "critical"
    assert len(body["affected_devices"]) == 1
    assert body["affected_devices"][0]["device_ip"] == "10.0.0.1"
    assert body["first_seen_at"] is not None


def test_cve_detail_404_for_unknown_cve(admin):
    assert admin.get("/api/vulns/CVE-NOPE-0000").status_code == 404


def test_cve_detail_returns_empty_devices_when_invisible_under_min_cvss_display(admin, db):
    """CVE is in the cache but every finding is below the display floor → metadata, no devices."""
    _seed_two_devices(db)
    put_section(db, VulnSettings(enabled=True, min_cvss_display=6.0))
    db.commit()
    r = admin.get("/api/vulns/CVE-2024-MED")
    assert r.status_code == 200
    body = r.json()
    assert body["cve_id"] == "CVE-2024-MED" and body["affected_devices"] == []
    assert body["first_seen_at"] is None


def test_cve_detail_returns_empty_devices_when_cve_in_cache_but_unmatched(admin, db):
    db.add(Vulnerability(cve_id="CVE-2024-6387", summary="regreSSHion", cvss_base=8.1, kev=False))
    db.commit()
    r = admin.get("/api/vulns/CVE-2024-6387")
    assert r.status_code == 200
    body = r.json()
    assert body["cve_id"] == "CVE-2024-6387" and body["cvss_base"] == 8.1
    assert body["affected_devices"] == [] and body["first_seen_at"] is None


def test_cve_detail_unscored_when_cvss_missing(admin, db):
    """No CVSS in cache → severity unknown (not a guessed medium from DEFAULT_CVSS)."""
    db.add(Vulnerability(cve_id="CVE-2014-0160", summary="Heartbleed", cvss_base=None, kev=False))
    db.commit()
    body = admin.get("/api/vulns/CVE-2014-0160").json()
    assert body["cvss_base"] is None and body["severity"] == "unknown"


def test_cve_detail_is_case_insensitive(admin, db):
    db.add(Vulnerability(cve_id="CVE-2025-24813", summary="Tomcat", cvss_base=9.8, kev=False))
    db.commit()
    lower = admin.get("/api/vulns/cve-2025-24813")
    upper = admin.get("/api/vulns/CVE-2025-24813")
    assert lower.status_code == 200 and upper.status_code == 200
    assert lower.json()["cve_id"] == upper.json()["cve_id"] == "CVE-2025-24813"


def test_cve_detail_first_seen_uses_min_lifecycle_first_seen(admin, db):
    _seed_two_devices(db)
    d = device_by_ip(db, "10.0.0.1")
    p = next(pp for pp in d.ports if pp.port == 22)
    db.add(DevicePortVuln(device_port_id=p.id, cve_id="CVE-2024-MED", state=VULN_STATE_CONFIRMED, matched_at=utcnow()))
    db.commit()
    later = utcnow() + timedelta(days=5)
    sync_finding_lifecycle(db, now=later)
    db.commit()

    body = admin.get("/api/vulns/CVE-2024-MED").json()
    assert len(body["affected_devices"]) == 2
    first_seen_values = {dv["first_seen_at"] for dv in body["affected_devices"]}
    assert len(first_seen_values) == 2  # one from the original seed, one from the later sync
    assert body["first_seen_at"] == min(first_seen_values)


# --- CSV export --------------------------------------------------------------------------------------
def test_export_vulns_streams_header_and_rows(admin, db):
    _seed_two_devices(db)
    r = admin.get("/api/vulns/export")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/csv")
    assert "attachment" in r.headers["content-disposition"]
    lines = r.text.strip().splitlines()
    header = lines[0].split(",")
    assert header == ["cve_id", "device_ip", "device_hostname", "network", "port", "protocol", "service",
                      "cvss_base", "severity", "kev", "epss", "state", "first_seen", "matched_at"]
    assert len(lines) == 3  # header + 2 findings
    body = "\n".join(lines)
    assert "CVE-2024-CRIT" in body and "CVE-2024-MED" in body


def test_export_vulns_respects_filters(admin, db):
    _seed_two_devices(db)
    r = admin.get("/api/vulns/export", params={"severity": "critical"})
    lines = r.text.strip().splitlines()
    assert len(lines) == 2  # header + 1 finding
    assert "CVE-2024-CRIT" in lines[1] and "CVE-2024-MED" not in lines[1]


def test_export_vulns_no_rows_still_returns_header_only(admin, db):
    _seed_two_devices(db)
    r = admin.get("/api/vulns/export", params={"network_id": 999999})
    lines = r.text.strip().splitlines()
    assert len(lines) == 1
