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
    assert body["findings_total"] == 0
    assert body["snapshot_trend_note"] is None
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


def test_dismiss_and_undismiss_invalidate_summary_cache(admin, db):
    """Both dismiss and undo must refresh /api/vulns/summary immediately (not wait for TTL)."""
    net = make_network(db)
    scan(ScriptedScanner([host("10.0.0.1", [port(22, "ssh", "OpenSSH", "7.4")], mac="00:11:22:33:44:01")]),
         network_id=net.id)
    d = device_by_ip(db, "10.0.0.1")
    p = next(pp for pp in d.ports if pp.port == 22)
    db.add(Vulnerability(cve_id="CVE-2024-CACHE", cvss_base=9.8, kev=True))
    db.flush()
    db.add(DevicePortVuln(device_port_id=p.id, cve_id="CVE-2024-CACHE", state=VULN_STATE_CONFIRMED,
                          matched_at=utcnow()))
    put_section(db, VulnSettings(enabled=True))
    db.commit()
    invalidate_vuln_summary_cache()

    before = admin.get("/api/vulns/summary").json()
    assert before["severity_counts"]["critical"] == 1
    generated_at = before["generated_at"]

    assert admin.post(f"/api/devices/{d.uuid}/vulns/CVE-2024-CACHE/dismiss",
                      headers=csrf(admin)).status_code == 200
    after_dismiss = admin.get("/api/vulns/summary").json()
    assert after_dismiss["severity_counts"]["critical"] == 0
    assert after_dismiss["generated_at"] != generated_at

    assert admin.delete(f"/api/devices/{d.uuid}/vulns/CVE-2024-CACHE/dismiss",
                        headers=csrf(admin)).status_code == 204
    after_undo = admin.get("/api/vulns/summary").json()
    assert after_undo["severity_counts"]["critical"] == 1
    assert after_undo["generated_at"] != after_dismiss["generated_at"]


def test_viewer_can_read_summary(db, client):
    make_network(db)
    assert client.post("/api/setup/admin", json={"username": "owner", "password": "correct-horse-1"}).status_code == 200
    assert client.post("/api/users", json={"username": "viewer1", "password": "correct-horse-1", "role": "viewer"},
                       headers=csrf(client)).status_code == 201
    client.post("/api/auth/logout", headers=csrf(client))
    assert client.post("/api/auth/login", json={"username": "viewer1", "password": "correct-horse-1"}).status_code == 200
    assert client.get("/api/vulns/summary").status_code == 200


def _seed_two_networks(db):
    """Two placeholder networks with one finding each (critical KEV vs medium)."""
    from app.core.vuln.lifecycle import sync_finding_lifecycle

    net_a = make_network(db, cidr="10.10.0.0/24", name="Lab Alpha")
    net_b = make_network(db, cidr="10.20.0.0/24", name="Lab Beta")
    scan(ScriptedScanner([host("10.10.0.1", [port(22, "ssh", "OpenSSH", "7.4")], mac="00:11:22:33:44:11")]),
         network_id=net_a.id)
    scan(ScriptedScanner([host("10.20.0.1", [port(80, "http", "nginx", "1.18")], mac="00:11:22:33:44:22")]),
         network_id=net_b.id)
    da = device_by_ip(db, "10.10.0.1")
    db_ = device_by_ip(db, "10.20.0.1")
    pa = next(p for p in da.ports if p.port == 22)
    pb = next(p for p in db_.ports if p.port == 80)
    db.add(Vulnerability(cve_id="CVE-2024-ALPHA", cvss_base=9.8, kev=True, epss=0.9))
    db.add(Vulnerability(cve_id="CVE-2024-BETA", cvss_base=5.0, kev=False, epss=0.01))
    db.flush()
    db.add(DevicePortVuln(device_port_id=pa.id, cve_id="CVE-2024-ALPHA", state=VULN_STATE_CONFIRMED, matched_at=utcnow()))
    db.add(DevicePortVuln(device_port_id=pb.id, cve_id="CVE-2024-BETA", state=VULN_STATE_CONFIRMED, matched_at=utcnow()))
    db.commit()
    sync_finding_lifecycle(db, now=utcnow())
    db.commit()
    return net_a, net_b, da, db_


def test_summary_respects_network_device_cve_kev_filters(admin, db):
    net_a, net_b, da, _db = _seed_two_networks(db)
    invalidate_vuln_summary_cache()

    all_body = admin.get("/api/vulns/summary").json()
    assert all_body["severity_counts"]["critical"] == 1
    assert all_body["severity_counts"]["medium"] == 1
    assert all_body["kev_count"] == 1

    by_a = admin.get("/api/vulns/summary", params={"network_id": net_a.id}).json()
    assert by_a["severity_counts"]["critical"] == 1
    assert by_a["severity_counts"]["medium"] == 0
    assert by_a["kev_count"] == 1
    assert len(by_a["severity_by_network"]) == 1
    assert by_a["severity_by_network"][0]["network_id"] == net_a.id

    by_b = admin.get("/api/vulns/summary", params={"network_id": net_b.id}).json()
    assert by_b["severity_counts"]["critical"] == 0
    assert by_b["severity_counts"]["medium"] == 1
    assert by_b["kev_count"] == 0

    by_device = admin.get("/api/vulns/summary", params={"device_uuid": da.uuid}).json()
    assert by_device["severity_counts"]["critical"] == 1
    assert by_device["severity_counts"]["medium"] == 0

    by_cve = admin.get("/api/vulns/summary", params={"cve_id": "CVE-2024-BETA"}).json()
    assert by_cve["severity_counts"]["medium"] == 1
    assert by_cve["kev_count"] == 0

    kev_yes = admin.get("/api/vulns/summary", params={"kev": "true"}).json()
    assert kev_yes["kev_count"] == 1 and kev_yes["severity_counts"]["critical"] == 1
    kev_no = admin.get("/api/vulns/summary", params={"kev": "false"}).json()
    assert kev_no["kev_count"] == 0 and kev_no["severity_counts"]["medium"] == 1

    # Filtered responses must not poison the unfiltered cache.
    again = admin.get("/api/vulns/summary").json()
    assert again["severity_counts"]["critical"] == 1
    assert again["severity_counts"]["medium"] == 1


def _sev_total(body: dict) -> int:
    return sum(body["severity_counts"].values())


def test_summary_findings_total_matches_list_for_filter_combos(admin, db):
    """Parity: summary findings_total (== severity sum) equals GET /api/vulns total per filter."""
    net_a, net_b, da, _db = _seed_two_networks(db)
    invalidate_vuln_summary_cache()

    combos = [
        {},
        {"network_id": net_a.id},
        {"network_id": net_b.id},
        {"device_uuid": da.uuid},
        {"cve_id": "CVE-2024-BETA"},
        {"kev": "true"},
        {"kev": "false"},
        {"severity": "critical"},
        {"severity": "medium"},
        {"network_id": net_a.id, "kev": "true"},
        {"network_id": net_b.id, "severity": "medium"},
    ]
    for params in combos:
        summary = admin.get("/api/vulns/summary", params=params).json()
        listing = admin.get("/api/vulns", params=params).json()
        assert summary["findings_total"] == listing["total"], params
        assert _sev_total(summary) == listing["total"], params


def test_summary_weekly_respects_kev_and_snapshot_note_when_partial(admin, db):
    net_a, _net_b, _da, _db = _seed_two_networks(db)
    invalidate_vuln_summary_cache()

    kev = admin.get("/api/vulns/summary", params={"kev": "true"}).json()
    assert kev["findings_total"] == 1
    assert sum(w["new"] for w in kev["weekly"]) == 1
    assert kev["snapshot_trend_note"] is not None
    assert "kev" in kev["snapshot_trend_note"]

    # Network-only filter can reshape snapshots; no partial-filter note.
    by_net = admin.get("/api/vulns/summary", params={"network_id": net_a.id}).json()
    assert by_net["snapshot_trend_note"] is None
    assert by_net["findings_total"] == 1

    # High-risk devices among matching findings (filtered path).
    assert "high" in kev["risk_device_levels"]
    assert sum(kev["risk_device_levels"].values()) == 1
