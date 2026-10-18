"""HTTP API for vulnerability settings, device vuln list/dismiss, and the vulnerabilities report."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.api.auth import limiter
from app.core.vuln.match import sync_port_matches
from app.db import session_scope
from app.main import app
from app.models import VULN_STATE_CONFIRMED, Device, DevicePort, Vulnerability, VulnCpeMatch

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
    net = make_network(db)
    scan(ScriptedScanner([host("10.0.0.1", [port(22, "ssh", "OpenSSH", "7.4")], mac="00:11:22:33:44:01")]),
         network_id=net.id)
    assert client.post("/api/setup/admin", json={"username": "admin", "password": "correct-horse-1"}).status_code == 200
    client.net_id = net.id
    return client


def _uuid(c: TestClient, ip: str) -> str:
    return c.get("/api/search", params={"q": f"ip:{ip}"}).json()["items"][0]["uuid"]


def test_vuln_settings_default_off_and_roundtrip(admin):
    r = admin.get("/api/settings/vuln")
    assert r.status_code == 200
    body = r.json()
    assert body["enabled"] is False
    assert set(body["sources"]) == {"nvd", "kev", "epss"}
    assert body["nvd_api_key_set"] is False

    r = admin.put("/api/settings/vuln", json={
        "enabled": True, "sources": ["nvd"], "sync_interval_hours": 48, "sync_time": "05:30",
        "offline_mode": True, "nvd_api_key": "secret-key", "include_potential": False,
        "min_cvss_display": 4.0, "scripts_enabled": False,
    }, headers=csrf(admin))
    assert r.status_code == 200
    body = r.json()
    assert body["enabled"] is True and body["sources"] == ["nvd"] and body["offline_mode"] is True
    assert body["nvd_api_key_set"] is True and "nvd_api_key" not in body

    # The key stays set when omitted on a later save.
    r = admin.put("/api/settings/vuln", json={
        "enabled": True, "sources": ["nvd"], "sync_interval_hours": 48, "sync_time": "05:30",
        "offline_mode": True, "include_potential": False, "min_cvss_display": 4.0, "scripts_enabled": False,
    }, headers=csrf(admin))
    assert r.json()["nvd_api_key_set"] is True


def test_vuln_settings_rejects_unknown_source(admin):
    r = admin.put("/api/settings/vuln", json={
        "enabled": False, "sources": ["vulners"], "sync_interval_hours": 168, "sync_time": "04:00",
        "offline_mode": False, "include_potential": True, "min_cvss_display": 0.0, "scripts_enabled": True,
    }, headers=csrf(admin))
    assert r.status_code == 422


def test_sync_now_requires_enabled_and_online(admin):
    r = admin.post("/api/settings/vuln/sync", headers=csrf(admin))
    assert r.status_code == 409  # disabled by default

    admin.put("/api/settings/vuln", json={
        "enabled": True, "sources": ["nvd"], "sync_interval_hours": 168, "sync_time": "04:00",
        "offline_mode": True, "include_potential": True, "min_cvss_display": 0.0, "scripts_enabled": True,
    }, headers=csrf(admin))
    r = admin.post("/api/settings/vuln/sync", headers=csrf(admin))
    assert r.status_code == 409  # offline mode


def test_viewer_cannot_change_vuln_settings(client, db):
    make_network(db)
    assert client.post("/api/setup/admin", json={"username": "owner", "password": "correct-horse-1"}).status_code == 200
    assert client.post("/api/users", json={"username": "viewer1", "password": "correct-horse-1", "role": "viewer"},
                       headers=csrf(client)).status_code == 201
    client.post("/api/auth/logout", headers=csrf(client))
    assert client.post("/api/auth/login", json={"username": "viewer1", "password": "correct-horse-1"}).status_code == 200
    assert client.get("/api/settings/vuln").status_code == 403
    assert client.put("/api/settings/vuln", json={}, headers=csrf(client)).status_code == 403


def test_device_vulns_list_dismiss_and_undismiss(admin, db):
    uuid = _uuid(admin, "10.0.0.1")
    d = device_by_ip(db, "10.0.0.1")
    p = next(pp for pp in d.ports if pp.port == 22)
    db.add(Vulnerability(cve_id="CVE-2024-0001", cvss_base=7.5))
    db.flush()
    db.add(VulnCpeMatch(cve_id="CVE-2024-0001", cpe23="cpe:2.3:a:openbsd:openssh:7.4:*:*:*:*:*:*:*",
                        vendor_product="openbsd:openssh"))
    db.commit()
    p.cpe = "cpe:/a:openbsd:openssh:7.4"
    db.commit()
    from app.db import utcnow
    sync_port_matches(db, [db.get(DevicePort, p.id)], now=utcnow())
    db.commit()

    r = admin.get(f"/api/devices/{uuid}/vulns")
    assert r.status_code == 200
    items = r.json()["items"]
    assert len(items) == 1 and items[0]["cve_id"] == "CVE-2024-0001"
    assert items[0]["state"] == VULN_STATE_CONFIRMED

    r = admin.post(f"/api/devices/{uuid}/vulns/CVE-2024-0001/dismiss", headers=csrf(admin))
    assert r.status_code == 200
    items = admin.get(f"/api/devices/{uuid}/vulns").json()["items"]
    assert items[0]["state"] == "dismissed"

    r = admin.delete(f"/api/devices/{uuid}/vulns/CVE-2024-0001/dismiss", headers=csrf(admin))
    assert r.status_code == 204
    items = admin.get(f"/api/devices/{uuid}/vulns").json()["items"]
    assert items[0]["state"] != "dismissed"

    assert admin.post(f"/api/devices/{uuid}/vulns/CVE-NOPE/dismiss", headers=csrf(admin)).status_code == 404


def test_vulnerabilities_report(admin, db):
    uuid = _uuid(admin, "10.0.0.1")
    d = device_by_ip(db, "10.0.0.1")
    d.risk_score, d.combined_score = 85, 90
    from app.db import utcnow
    d.risk_scored_at = utcnow()
    db.add(Vulnerability(cve_id="CVE-2024-0002", cvss_base=9.0, kev=True))
    db.flush()
    p = next(pp for pp in d.ports if pp.port == 22)
    from app.models import DevicePortVuln
    db.add(DevicePortVuln(device_port_id=p.id, cve_id="CVE-2024-0002", state=VULN_STATE_CONFIRMED, matched_at=utcnow()))
    db.commit()

    r = admin.get("/api/reports/vulnerabilities")
    assert r.status_code == 200
    body = r.json()
    assert body["top_devices"][0]["uuid"] == uuid
    assert body["top_devices"][0]["risk"] == 85 and body["top_devices"][0]["combined"] == 90
    assert body["top_cves"][0]["cve_id"] == "CVE-2024-0002"
    assert body["top_cves"][0]["kev"] is True and body["top_cves"][0]["device_count"] == 1
