"""GET /api/vulns/summary: the one read endpoint backing the vulnerabilities dashboard."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.api.auth import limiter
from app.core.mockdata import set_mock_hidden
from app.core.vuln.summary import invalidate_vuln_summary_cache
from app.db import utcnow
from app.main import app
from app.models import VULN_STATE_CONFIRMED, DevicePortVuln, Vulnerability
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


def test_summary_empty_state_is_zeroed_not_an_error(admin):
    invalidate_vuln_summary_cache()
    r = admin.get("/api/vulns/summary")
    assert r.status_code == 200
    body = r.json()
    assert body["severity_counts"] == {"critical": 0, "high": 0, "medium": 0, "low": 0, "unknown": 0}
    assert body["kev_count"] == 0 and body["epss_high_count"] == 0
    assert body["confirmed_count"] == 0 and body["potential_count"] == 0
    assert body["top_devices"] == [] and body["top_cves"] == []
    assert body["new_since_last_scan"] == [] and body["new_since_last_db_update"] == []
    assert body["severity_by_network"] == [] and body["snapshot_trend"] == []
    assert len(body["weekly"]) == 12


def test_summary_reflects_seeded_findings_and_echoes_settings(admin, db):
    net = make_network(db)
    scan(ScriptedScanner([host("10.0.0.1", [port(22, "ssh", "OpenSSH", "7.4")], mac="00:11:22:33:44:01")]),
         network_id=net.id)
    d = device_by_ip(db, "10.0.0.1")
    p = next(pp for pp in d.ports if pp.port == 22)
    db.add(Vulnerability(cve_id="CVE-2024-0001", cvss_base=9.8, kev=True, epss=0.95))
    db.flush()
    db.add(DevicePortVuln(device_port_id=p.id, cve_id="CVE-2024-0001", state=VULN_STATE_CONFIRMED, matched_at=utcnow()))
    put_section(db, VulnSettings(enabled=True, epss_high_threshold=0.2))
    db.commit()
    invalidate_vuln_summary_cache()

    r = admin.get("/api/vulns/summary")
    assert r.status_code == 200
    body = r.json()
    assert body["severity_counts"]["critical"] == 1
    assert body["kev_count"] == 1
    assert body["epss_high_count"] == 1
    assert body["epss_threshold"] == 0.2
    assert body["feed"]["stale_threshold_hours"] == VulnSettings().sync_interval_hours * 2


def test_summary_excludes_mock_devices_when_hidden(admin, db):
    net = make_network(db)
    scan(ScriptedScanner([host("10.0.0.1", [port(22, "ssh", "OpenSSH", "7.4")], mac="00:11:22:33:44:01")]),
         network_id=net.id)
    d = device_by_ip(db, "10.0.0.1")
    p = next(pp for pp in d.ports if pp.port == 22)
    db.add(Vulnerability(cve_id="CVE-2024-0001", cvss_base=9.8))
    db.flush()
    db.add(DevicePortVuln(device_port_id=p.id, cve_id="CVE-2024-0001", state=VULN_STATE_CONFIRMED, matched_at=utcnow()))
    db.commit()
    invalidate_vuln_summary_cache()
    assert admin.get("/api/vulns/summary").json()["severity_counts"]["critical"] == 1

    set_mock_hidden(db, True)
    db.commit()
    invalidate_vuln_summary_cache()
    assert admin.get("/api/vulns/summary").json()["severity_counts"]["critical"] == 0


def test_summary_cold_cache_self_populates(admin):
    invalidate_vuln_summary_cache()
    r = admin.get("/api/vulns/summary")
    assert r.status_code == 200
    assert r.json()["generated_at"] is not None


def test_viewer_can_read_summary(db, client):
    make_network(db)
    assert client.post("/api/setup/admin", json={"username": "owner", "password": "correct-horse-1"}).status_code == 200
    assert client.post("/api/users", json={"username": "viewer1", "password": "correct-horse-1", "role": "viewer"},
                       headers=csrf(client)).status_code == 201
    client.post("/api/auth/logout", headers=csrf(client))
    assert client.post("/api/auth/login", json={"username": "viewer1", "password": "correct-horse-1"}).status_code == 200
    assert client.get("/api/vulns/summary").status_code == 200
