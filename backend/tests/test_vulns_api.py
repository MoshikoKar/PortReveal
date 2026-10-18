"""GET /api/vulns (filterable finding list) and GET /api/vulns/{cve_id} (CVE detail)."""
from __future__ import annotations

from datetime import timedelta

import pytest
from fastapi.testclient import TestClient

from app.api.auth import limiter
from app.core.vuln.lifecycle import sync_finding_lifecycle
from app.db import utcnow
from app.main import app
from app.models import VULN_STATE_CONFIRMED, VULN_STATE_DISMISSED, VULN_STATE_POTENTIAL, DevicePortVuln, Vulnerability
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


def test_cve_detail_404_when_invisible_under_min_cvss_display(admin, db):
    _seed_two_devices(db)
    put_section(db, VulnSettings(enabled=True, min_cvss_display=6.0))
    db.commit()
    assert admin.get("/api/vulns/CVE-2024-MED").status_code == 404  # below floor, not KEV


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
