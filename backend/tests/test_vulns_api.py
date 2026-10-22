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
    scan(
        ScriptedScanner(
            [
                host("10.0.0.1", [port(22, "ssh", "OpenSSH", "7.4")], mac="00:11:22:33:44:01"),
                host("10.0.0.2", [port(80, "http", "nginx", "1.18")], mac="00:11:22:33:44:02"),
            ]
        ),
        network_id=net.id,
    )
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

    db.add(VulnFeedState(source="nvd", last_synced_at=now - timedelta(hours=1), record_count=1, mirror_complete=True))
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


def test_list_vulns_sort_and_order(admin, db):
    _seed_two_devices(db)

    def order(**params) -> list[str]:
        r = admin.get("/api/vulns", params=params)
        assert r.status_code == 200
        return [it["cve_id"] for it in r.json()["items"]]

    # Default triage order: KEV first, then highest CVSS.
    assert order() == ["CVE-2024-CRIT", "CVE-2024-MED"]
    assert order(sort="cvss", order="asc") == ["CVE-2024-MED", "CVE-2024-CRIT"]
    assert order(sort="cvss", order="desc") == ["CVE-2024-CRIT", "CVE-2024-MED"]
    # Device sorts by numeric IP (10.0.0.1 has CRIT, 10.0.0.2 has MED).
    assert order(sort="device", order="desc") == ["CVE-2024-MED", "CVE-2024-CRIT"]
    assert order(sort="port", order="asc") == ["CVE-2024-CRIT", "CVE-2024-MED"]  # 22 before 80
    assert order(sort="state", order="asc") == ["CVE-2024-CRIT", "CVE-2024-MED"]  # confirmed < potential
    for key in ("cve", "network", "first_seen"):
        assert sorted(order(sort=key)) == ["CVE-2024-CRIT", "CVE-2024-MED"]
    assert admin.get("/api/vulns", params={"sort": "bogus"}).status_code == 422
    assert admin.get("/api/vulns", params={"order": "sideways"}).status_code == 422


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


def test_list_vulns_q_matches_cve_device_product_port_and_summary(admin, db):
    """Free-text q matches CVE id, IP/hostname, product, port, and summary (case-insensitive)."""
    _net, da, _db = _seed_two_devices(db)
    da.hostname = "edge-gw"
    med = db.query(Vulnerability).filter_by(cve_id="CVE-2024-MED").one()
    med.summary = "nginx buffer overflow in HTTP parser"
    pb = next(p for p in _db.ports if p.port == 80)
    pb.product = "nginx"
    db.commit()

    by_cve = admin.get("/api/vulns", params={"q": "2024-med"}).json()
    assert by_cve["total"] == 1 and by_cve["items"][0]["cve_id"] == "CVE-2024-MED"
    assert "hidden_reasons" in by_cve["items"][0]
    assert by_cve["hidden_total"] == 0 and by_cve["total_matches"] == 1

    by_ip = admin.get("/api/vulns", params={"q": "10.0.0.1"}).json()
    assert by_ip["total"] == 1 and by_ip["items"][0]["cve_id"] == "CVE-2024-CRIT"

    by_host = admin.get("/api/vulns", params={"q": "EDGE-GW"}).json()
    assert by_host["total"] == 1 and by_host["items"][0]["device_hostname"] == "edge-gw"

    by_product = admin.get("/api/vulns", params={"q": "nginx"}).json()
    assert by_product["total"] == 1 and by_product["items"][0]["cve_id"] == "CVE-2024-MED"

    by_port = admin.get("/api/vulns", params={"q": "22"}).json()
    assert by_port["total"] == 1 and by_port["items"][0]["port"] == 22

    by_port_prefix = admin.get("/api/vulns", params={"q": "port:80"}).json()
    assert by_port_prefix["total"] == 1 and by_port_prefix["items"][0]["port"] == 80

    by_summary = admin.get("/api/vulns", params={"q": "buffer overflow"}).json()
    assert by_summary["total"] == 1 and by_summary["items"][0]["cve_id"] == "CVE-2024-MED"

    # Empty / whitespace q must not lift the floor or attach hidden_reasons.
    no_q = admin.get("/api/vulns", params={"q": "   "}).json()
    assert no_q["total"] == 2
    assert all("hidden_reasons" not in it for it in no_q["items"])
    assert "hidden_total" not in no_q


def test_list_vulns_q_digit_port_is_exact_not_substring(admin, db):
    """Pure-digit q must not match port 122 via LIKE '%22%'; only exact port (and other fields)."""
    from app.models import DevicePort

    _seed_two_devices(db)
    # Attach a second port 122 on the MED device so a naive port LIKE would over-match "22".
    db_ = device_by_ip(db, "10.0.0.2")
    db.add(DevicePort(device_id=db_.id, port=122, protocol="tcp", is_open=True, service="custom"))
    db.flush()
    db.refresh(db_)
    p122 = next(p for p in db_.ports if p.port == 122)
    db.add(
        DevicePortVuln(
            device_port_id=p122.id,
            cve_id="CVE-2024-MED",
            state=VULN_STATE_POTENTIAL,
            matched_at=utcnow(),
        )
    )
    db.commit()

    body = admin.get("/api/vulns", params={"q": "22"}).json()
    assert body["total"] == 1 and body["items"][0]["port"] == 22
    assert admin.get("/api/vulns", params={"q": "port:122"}).json()["total"] == 1
    assert admin.get("/api/vulns", params={"q": "port:122"}).json()["items"][0]["port"] == 122


def test_list_vulns_q_includes_below_floor_with_hidden_reason(admin, db):
    _seed_two_devices(db)
    put_section(db, VulnSettings(enabled=True, min_cvss_display=6.0))
    db.commit()

    assert admin.get("/api/vulns").json()["total"] == 1  # MED hidden by floor

    body = admin.get("/api/vulns", params={"q": "CVE-2024-MED"}).json()
    assert body["total"] == 1
    item = body["items"][0]
    assert item["cve_id"] == "CVE-2024-MED"
    assert item["hidden_reasons"] == ["Below CVSS floor"]
    assert body["hidden_total"] == 1 and body["total_matches"] == 1


def test_list_vulns_q_includes_dismissed_with_hidden_reason(admin, db):
    _seed_two_devices(db)
    row = db.query(DevicePortVuln).filter_by(cve_id="CVE-2024-CRIT").one()
    row.state = VULN_STATE_DISMISSED
    db.commit()

    assert admin.get("/api/vulns").json()["total"] == 1  # CRIT dismissed

    body = admin.get("/api/vulns", params={"q": "CRIT"}).json()
    assert body["total"] == 1
    item = body["items"][0]
    assert item["cve_id"] == "CVE-2024-CRIT"
    assert item["hidden_reasons"] == ["Dismissed"]


def test_list_vulns_q_includes_potential_when_include_potential_off(admin, db):
    _seed_two_devices(db)
    put_section(db, VulnSettings(enabled=True, include_potential=False, min_cvss_display=0.0))
    db.commit()

    assert admin.get("/api/vulns").json()["total"] == 1  # MED is potential
    assert admin.get("/api/vulns").json()["items"][0]["cve_id"] == "CVE-2024-CRIT"

    body = admin.get("/api/vulns", params={"q": "MED"}).json()
    assert body["total"] == 1
    item = body["items"][0]
    assert item["cve_id"] == "CVE-2024-MED"
    assert item["hidden_reasons"] == ["Potential (hidden)"]


def test_list_vulns_q_with_state_filter_still_narrows(admin, db):
    """Explicit state= continues to apply on top of search (floor bypass only when state unset)."""
    _seed_two_devices(db)
    row = db.query(DevicePortVuln).filter_by(cve_id="CVE-2024-CRIT").one()
    row.state = VULN_STATE_DISMISSED
    db.commit()

    dismissed = admin.get("/api/vulns", params={"q": "2024", "state": "dismissed"}).json()
    assert dismissed["total"] == 1 and dismissed["items"][0]["cve_id"] == "CVE-2024-CRIT"

    confirmed = admin.get("/api/vulns", params={"q": "2024", "state": "confirmed"}).json()
    assert confirmed["total"] == 0

    potential = admin.get("/api/vulns", params={"q": "2024", "state": "potential"}).json()
    assert potential["total"] == 1 and potential["items"][0]["cve_id"] == "CVE-2024-MED"


def test_list_vulns_q_only_hidden_filters_to_normally_hidden(admin, db):
    _seed_two_devices(db)
    put_section(db, VulnSettings(enabled=True, min_cvss_display=6.0))
    db.commit()

    all_q = admin.get("/api/vulns", params={"q": "2024"}).json()
    assert all_q["total"] == 2 and all_q["hidden_total"] == 1 and all_q["total_matches"] == 2

    hidden_only = admin.get("/api/vulns", params={"q": "2024", "only_hidden": "true"}).json()
    assert hidden_only["total"] == 1
    assert hidden_only["items"][0]["cve_id"] == "CVE-2024-MED"
    assert hidden_only["hidden_total"] == 1 and hidden_only["total_matches"] == 2


def test_list_vulns_q_still_respects_facet_filters(admin, db):
    """Search lifts the display floor but severity/network/etc. facets still narrow results."""
    _seed_two_devices(db)
    put_section(db, VulnSettings(enabled=True, min_cvss_display=6.0))
    db.commit()

    # q alone would find MED; severity=critical must exclude it.
    body = admin.get("/api/vulns", params={"q": "2024", "severity": "critical"}).json()
    assert body["total"] == 1 and body["items"][0]["cve_id"] == "CVE-2024-CRIT"


def test_export_vulns_respects_q_including_below_floor(admin, db):
    _seed_two_devices(db)
    put_section(db, VulnSettings(enabled=True, min_cvss_display=6.0))
    db.commit()

    default = admin.get("/api/vulns/export").text
    assert "CVE-2024-CRIT" in default and "CVE-2024-MED" not in default

    searched = admin.get("/api/vulns/export", params={"q": "MED"}).text
    assert "CVE-2024-MED" in searched
    # Semicolon-joined hidden_reasons when q is set; empty for normally-visible rows.
    med_line = next(line for line in searched.strip().splitlines() if "CVE-2024-MED" in line)
    assert med_line.endswith("Below CVSS floor") or ";Below CVSS floor" in med_line or med_line.endswith(",Below CVSS floor")


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
CSV_HEADER_PREFIX = [
    "network",
    "device_name",
    "hostname",
    "ip",
    "mac",
    "port",
    "protocol",
    "service",
    "product",
    "version",
    "cve",
    "title",
    "cvss",
    "severity",
    "kev",
    "epss",
    "state",
]


def _csv_lines(text: str) -> list[str]:
    """Strip UTF-8 BOM then split rows."""
    return text.lstrip("\ufeff").strip().splitlines()


def _assert_csv_header(header: list[str]) -> None:
    """Date columns name the local timezone; everything before them is stable."""
    assert header[:17] == CSV_HEADER_PREFIX
    assert header[17].startswith("first_seen (") and header[17].endswith(")")
    assert header[18].startswith("last_matched (") and header[18].endswith(")")
    assert header[19] == "cve_link"


def test_export_vulns_streams_header_and_rows(admin, db):
    _seed_two_devices(db)
    r = admin.get("/api/vulns/export")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/csv")
    assert "attachment" in r.headers["content-disposition"]
    assert r.content.startswith(b"\xef\xbb\xbf")  # UTF-8 BOM for Excel
    lines = _csv_lines(r.text)
    header = lines[0].split(",")
    _assert_csv_header(header)
    assert "hidden_reasons" not in header  # only appended when q is set
    assert len(lines) == 3  # header + 2 findings
    body = "\n".join(lines)
    assert "CVE-2024-CRIT" in body and "CVE-2024-MED" in body
    assert "Yes" in body and "No" in body
    assert "nvd.nist.gov/vuln/detail/CVE-2024-CRIT" in body


def test_export_vulns_hidden_reasons_column_with_q(admin, db):
    """With ``q``, rich CSV gains a trailing hidden_reasons column (search includes hidden rows)."""
    import csv
    import io

    _seed_two_devices(db)
    put_section(db, VulnSettings(enabled=True, min_cvss_display=6.0, include_potential=False))
    row = db.query(DevicePortVuln).filter_by(cve_id="CVE-2024-CRIT").one()
    row.state = VULN_STATE_DISMISSED
    db.commit()

    r = admin.get("/api/vulns/export", params={"q": "2024"})
    rows = list(csv.reader(io.StringIO(r.text.lstrip("\ufeff"))))
    header, *data = rows
    assert header[-1] == "hidden_reasons"
    _assert_csv_header(header[:-1])
    by_cve = {row[header.index("cve")]: row for row in data}
    assert "Dismissed" in by_cve["CVE-2024-CRIT"][header.index("hidden_reasons")]
    # MED is potential + below floor → semicolon-joined reasons.
    med_reasons = by_cve["CVE-2024-MED"][header.index("hidden_reasons")]
    assert "Potential (hidden)" in med_reasons
    assert "Below CVSS floor" in med_reasons
    assert ";" in med_reasons


def test_export_vulns_respects_filters(admin, db):
    _seed_two_devices(db)
    r = admin.get("/api/vulns/export", params={"severity": "critical"})
    lines = _csv_lines(r.text)
    assert len(lines) == 2  # header + 1 finding
    assert "CVE-2024-CRIT" in lines[1] and "CVE-2024-MED" not in lines[1]


def test_export_vulns_respects_network_device_cve_kev(admin, db):
    net, da, _db = _seed_two_devices(db)
    by_net = _csv_lines(admin.get("/api/vulns/export", params={"network_id": net.id}).text)
    assert len(by_net) == 3
    assert "vulns_" in admin.get("/api/vulns/export", params={"network_id": net.id}).headers["content-disposition"]
    assert "test-net" in admin.get("/api/vulns/export", params={"network_id": net.id}).headers["content-disposition"].lower()

    by_device = _csv_lines(admin.get("/api/vulns/export", params={"device_uuid": da.uuid}).text)
    assert len(by_device) == 2 and "CVE-2024-CRIT" in by_device[1]

    by_cve = _csv_lines(admin.get("/api/vulns/export", params={"cve_id": "CVE-2024-MED"}).text)
    assert len(by_cve) == 2 and "CVE-2024-MED" in by_cve[1]

    kev_yes = _csv_lines(admin.get("/api/vulns/export", params={"kev": "true"}).text)
    assert len(kev_yes) == 2 and "CVE-2024-CRIT" in kev_yes[1]
    kev_no = _csv_lines(admin.get("/api/vulns/export", params={"kev": "false"}).text)
    assert len(kev_no) == 2 and "CVE-2024-MED" in kev_no[1]


def test_export_vulns_no_rows_still_returns_header_only(admin, db):
    _seed_two_devices(db)
    r = admin.get("/api/vulns/export", params={"network_id": 999999})
    lines = _csv_lines(r.text)
    assert len(lines) == 1
    _assert_csv_header(lines[0].split(","))


def test_export_vulns_hebrew_network_name_content_disposition(admin, db):
    """Non-ASCII network names must not 500: ASCII filename= + RFC 5987 filename*."""
    from urllib.parse import unquote

    # Generic Hebrew placeholder network name (not a real org/site).
    net = make_network(db, cidr="10.30.0.0/24", name="רשת-בדיקה")
    scan(ScriptedScanner([host("10.30.0.1", [port(22, "ssh", "OpenSSH", "7.4")], mac="00:11:22:33:44:30")]), network_id=net.id)
    d = device_by_ip(db, "10.30.0.1")
    p = next(pp for pp in d.ports if pp.port == 22)
    db.add(Vulnerability(cve_id="CVE-2024-HEB", cvss_base=9.8, kev=True, summary="hebrew net"))
    db.flush()
    db.add(DevicePortVuln(device_port_id=p.id, cve_id="CVE-2024-HEB", state=VULN_STATE_CONFIRMED, matched_at=utcnow()))
    db.commit()

    r = admin.get("/api/vulns/export", params={"network_id": net.id})
    assert r.status_code == 200
    cd = r.headers["content-disposition"]
    # Starlette encodes headers as latin-1; this must not raise.
    cd.encode("latin-1")
    assert 'filename="' in cd
    assert "filename*=UTF-8''" in cd
    # UTF-8 form keeps the Hebrew slug; ASCII fallback stays latin-1-safe and drops empty segments.
    assert "רשת" in unquote(cd) or "%D7%A8" in cd
    assert "vulns_" in cd
    assert "vulns_-_" not in cd
    ascii_name = cd.split("filename=")[1].split(";")[0].strip().strip('"')
    assert ascii_name.startswith("vulns_") and ascii_name.endswith(".csv")
    assert "_-_" not in ascii_name
    assert "CVE-2024-HEB" in r.text


def test_export_vulns_csv_injection_prefix(admin, db):
    """Hostname / title / product cells starting with =+-@ get a leading apostrophe."""
    net = make_network(db, cidr="10.40.0.0/24", name="Inj Net")
    scan(
        ScriptedScanner(
            [
                host(
                    "10.40.0.1", [port(22, "ssh", "=EvilProduct", "1.0")], hostname="=cmd|' /C calc'!A0", mac="00:11:22:33:44:40"
                ),
            ]
        ),
        network_id=net.id,
    )
    d = device_by_ip(db, "10.40.0.1")
    d.hostname = "=cmd|' /C calc'!A0"
    p = next(pp for pp in d.ports if pp.port == 22)
    p.product = "+1+1"
    db.add(
        Vulnerability(
            cve_id="CVE-2024-INJ",
            cvss_base=5.0,
            kev=False,
            summary="@SUM(A1:A10) formula title",
        )
    )
    db.flush()
    db.add(DevicePortVuln(device_port_id=p.id, cve_id="CVE-2024-INJ", state=VULN_STATE_CONFIRMED, matched_at=utcnow()))
    db.commit()

    import csv
    import io

    r = admin.get("/api/vulns/export", params={"cve_id": "CVE-2024-INJ"})
    assert r.status_code == 200
    rows = list(csv.reader(io.StringIO(r.text.lstrip("\ufeff"))))
    assert len(rows) == 2
    header, data = rows
    hostname = data[header.index("hostname")]
    product = data[header.index("product")]
    title = data[header.index("title")]
    assert hostname.startswith("'=")
    assert product.startswith("'+")
    assert title.startswith("'@")


def test_export_vulns_unassigned_network_label(admin, db):
    _seed_two_devices(db)
    orphan = device_by_ip(db, "10.0.0.2")
    orphan.network_id = None
    db.commit()

    import csv
    import io

    r = admin.get("/api/vulns/export", params={"network_id": "unassigned"})
    rows = list(csv.reader(io.StringIO(r.text.lstrip("\ufeff"))))
    assert len(rows) == 2
    assert rows[1][rows[0].index("network")] == "Unassigned"
    assert "CVE-2024-MED" in rows[1]


def test_vulns_routes_accept_q_and_network_together(admin, db):
    """List, summary, and CSV all compose ``q`` with ``network_id`` (and other facets)."""
    import csv
    import io

    net, _da, other = _seed_two_devices(db)
    net_b = make_network(db, cidr="10.1.0.0/24", name="other-net")
    other.network_id = net_b.id
    put_section(db, VulnSettings(enabled=True, min_cvss_display=6.0, include_potential=False))
    db.commit()

    # q alone lifts the floor → both CVEs; network scopes to CRIT's device only.
    alone = admin.get("/api/vulns", params={"q": "2024"}).json()
    assert alone["total"] == 2
    listed = admin.get("/api/vulns", params={"q": "2024", "network_id": net.id}).json()
    assert listed["total"] == 1
    assert listed["items"][0]["cve_id"] == "CVE-2024-CRIT"

    # kev + network + q still compose.
    kev = admin.get(
        "/api/vulns",
        params={
            "q": "2024",
            "network_id": net.id,
            "kev": "true",
        },
    ).json()
    assert kev["total"] == 1 and kev["items"][0]["kev"] is True

    summary = admin.get("/api/vulns/summary", params={"q": "2024", "network_id": net.id}).json()
    assert summary["findings_total"] == 1
    assert summary["severity_counts"]["critical"] == 1

    exported = admin.get("/api/vulns/export", params={"q": "2024", "network_id": net.id})
    rows = list(csv.reader(io.StringIO(exported.text.lstrip("\ufeff"))))
    assert rows[0][-1] == "hidden_reasons"
    assert len(rows) == 2
    assert "CVE-2024-CRIT" in rows[1]
    assert "CVE-2024-MED" not in exported.text
    cd = exported.headers["content-disposition"]
    assert "vulns_" in cd and "search" in cd


def test_export_filename_preserves_underscores_in_ascii_fallback(admin, db):
    """ASCII ``filename=`` keeps underscores (``vulns_network-a_YYYYMMDD`` style), not hyphens-only."""
    from app.core.vuln.filters import content_disposition_attachment, sanitize_filename_part

    assert "_" in sanitize_filename_part("network_a")
    assert sanitize_filename_part("network_a", ascii_only=True) == "network_a"
    # Spaces/dots become hyphens; underscores stay.
    assert sanitize_filename_part("My_Net Work", ascii_only=True) == "my_net-work"
    cd = content_disposition_attachment("vulns_network_a_20261022.csv")
    assert 'filename="vulns_network_a_20261022.csv"' in cd
    assert "filename*=UTF-8''vulns_network_a_20261022.csv" in cd


def test_export_filename_ascii_drops_empty_slug_parts_for_hebrew_network(admin, db):
    """Hebrew network slug → ASCII fallback drops empty/dash segments (not ``vulns_-_YYYYMMDD``)."""
    from urllib.parse import unquote

    from app.core.vuln.filters import content_disposition_attachment

    cd = content_disposition_attachment("vulns_רשת-בדיקה_20261022.csv")
    assert 'filename="vulns_20261022.csv"' in cd
    assert "vulns_-_" not in cd
    assert "רשת" in unquote(cd) or "%D7%A8" in cd

    net = make_network(db, cidr="10.30.0.0/24", name="רשת-בדיקה")
    scan(
        ScriptedScanner([host("10.30.0.2", [port(22, "ssh", "OpenSSH", "7.4")], mac="00:11:22:33:44:31")]),
        network_id=net.id,
    )
    d = device_by_ip(db, "10.30.0.2")
    p = next(pp for pp in d.ports if pp.port == 22)
    db.add(Vulnerability(cve_id="CVE-2024-HEB2", cvss_base=9.8, kev=True, summary="hebrew net 2"))
    db.flush()
    db.add(DevicePortVuln(device_port_id=p.id, cve_id="CVE-2024-HEB2", state=VULN_STATE_CONFIRMED, matched_at=utcnow()))
    db.commit()

    r = admin.get("/api/vulns/export", params={"network_id": net.id})
    assert r.status_code == 200
    ascii_name = r.headers["content-disposition"].split("filename=")[1].split(";")[0].strip().strip('"')
    assert ascii_name.startswith("vulns_")
    assert "_-_" not in ascii_name
    assert ascii_name.endswith(".csv")


# --- HTML report export ------------------------------------------------------------------------------


def test_export_vulns_html_self_contained_with_counts(admin, db):
    """HTML report is offline (no CDN), includes summary counts and both seeded findings."""
    _seed_two_devices(db)
    r = admin.get("/api/vulns/export/html")
    assert r.status_code == 200
    assert "text/html" in r.headers["content-type"]
    cd = r.headers["content-disposition"]
    assert "attachment" in cd and ".html" in cd
    assert 'filename="' in cd and "filename*=UTF-8''" in cd
    body = r.text
    assert "<!DOCTYPE html>" in body
    assert "PortReveal vulnerability report" in body
    assert "cdn." not in body.lower()
    assert "http://cdn" not in body.lower() and "https://cdn" not in body.lower()
    assert 'src="http' not in body.lower()  # no external script/img
    assert "CVE-2024-CRIT" in body and "CVE-2024-MED" in body
    # Summary cards: 2 findings, 1 KEV, 2 devices (in JSON payload and card markup).
    assert ">2</div>" in body or "findings_total" in body or 'class="value">2</div>' in body
    assert "window.__REPORT_DATA__=" in body
    assert body.count("CVE-2024-CRIT") >= 1
    assert "Filters:" in body
    assert "All networks (no filters)" in body


def test_export_vulns_html_respects_filters_and_search_line(admin, db):
    net, _da, _db = _seed_two_devices(db)
    r = admin.get("/api/vulns/export/html", params={"severity": "critical"})
    assert r.status_code == 200
    assert "CVE-2024-CRIT" in r.text
    assert "CVE-2024-MED" not in r.text
    assert "severity: Critical" in r.text

    r2 = admin.get(
        "/api/vulns/export/html",
        params={"q": "2024", "network_id": net.id, "only_hidden": "false"},
    )
    assert "Includes hidden" in r2.text
    assert "network:" in r2.text
    assert "Search: &quot;2024&quot;" in r2.text or 'Search: "2024"' in r2.text


def test_export_vulns_html_escapes_xss_in_hostname_and_title(admin, db):
    """Untrusted hostname / summary must not break out of HTML or the JSON payload."""
    net = make_network(db, cidr="10.50.0.0/24", name="Xss Lab")
    scan(
        ScriptedScanner(
            [host("10.50.0.1", [port(22, "ssh", "OpenSSH", "7.4")], hostname="safe", mac="00:11:22:33:44:50")]
        ),
        network_id=net.id,
    )
    d = device_by_ip(db, "10.50.0.1")
    d.hostname = '<img src=x onerror=alert(1)>evil'
    p = next(pp for pp in d.ports if pp.port == 22)
    db.add(
        Vulnerability(
            cve_id="CVE-2024-XSS",
            cvss_base=7.5,
            kev=False,
            summary='</script><script>alert("xss")</script>',
        )
    )
    db.flush()
    db.add(DevicePortVuln(device_port_id=p.id, cve_id="CVE-2024-XSS", state=VULN_STATE_CONFIRMED, matched_at=utcnow()))
    db.commit()

    r = admin.get("/api/vulns/export/html", params={"cve_id": "CVE-2024-XSS"})
    assert r.status_code == 200
    body = r.text
    assert "<img src=x onerror=" not in body
    assert "</script><script>" not in body
    # Escaped forms present in JSON (\u003c) or HTML entities.
    assert "\\u003c" in body or "&lt;" in body
    assert "CVE-2024-XSS" in body
    assert "alert" in body  # payload text may remain as escaped data
    # Must not contain an executable script tag from the payload (only our two report scripts).
    assert body.count("<script>") == 2


def test_export_vulns_html_hebrew_filename_content_disposition(admin, db):
    from urllib.parse import unquote

    net = make_network(db, cidr="10.31.0.0/24", name="רשת-בדיקה")
    scan(ScriptedScanner([host("10.31.0.1", [port(22, "ssh", "OpenSSH", "7.4")], mac="00:11:22:33:44:32")]), network_id=net.id)
    d = device_by_ip(db, "10.31.0.1")
    p = next(pp for pp in d.ports if pp.port == 22)
    db.add(Vulnerability(cve_id="CVE-2024-HEB3", cvss_base=9.8, kev=True, summary="html heb"))
    db.flush()
    db.add(DevicePortVuln(device_port_id=p.id, cve_id="CVE-2024-HEB3", state=VULN_STATE_CONFIRMED, matched_at=utcnow()))
    db.commit()

    r = admin.get("/api/vulns/export/html", params={"network_id": net.id})
    assert r.status_code == 200
    cd = r.headers["content-disposition"]
    cd.encode("latin-1")
    assert ".html" in cd
    assert "רשת" in unquote(cd) or "%D7%A8" in cd
    ascii_name = cd.split("filename=")[1].split(";")[0].strip().strip('"')
    assert ascii_name.endswith(".html")
    assert "_-_" not in ascii_name
