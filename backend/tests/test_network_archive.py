"""Removing a network archives it: findings stay linked but are hidden unless asked for."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.api.auth import limiter
from app.core.scheduler import enqueue_scheduled_scans
from app.main import app
from app.models import WEB_CAPTURE_COMPLETED, AuditLog, Device, Network, Scan, WebCapture, WebPage

from .helpers import ScriptedScanner, host, make_network, port, scan


@pytest.fixture
def client(db_env):
    limiter.reset()
    with TestClient(app) as c:
        yield c


def csrf(c: TestClient) -> dict:
    return {"X-CSRF-Token": c.cookies.get("nf_csrf", "")}


@pytest.fixture
def admin(db, client):
    kept = make_network(db, "10.0.1.0/24", "Kept")
    gone = make_network(db, "10.0.2.0/24", "Gone")
    scan(ScriptedScanner([host("10.0.1.5", [port(22, "ssh")], mac="00:11:22:33:44:05")]), network_id=kept.id)
    scan(ScriptedScanner([host("10.0.2.7", [port(80, "http")], mac="00:11:22:33:44:07")]), network_id=gone.id)
    assert client.post("/api/setup/admin", json={"username": "admin", "password": "correct-horse-1"}).status_code == 200
    client.kept_id, client.gone_id = kept.id, gone.id
    return client


def _ips(c: TestClient, **params) -> set[str]:
    return {d["current_ip"] for d in c.get("/api/devices", params=params).json()["items"]}


def test_archive_hides_findings_but_keeps_them(admin, db):
    assert _ips(admin) == {"10.0.1.5", "10.0.2.7"}
    assert admin.delete(f"/api/networks/{admin.gone_id}", headers=csrf(admin)).status_code == 204

    db.expire_all()
    net = db.get(Network, admin.gone_id)
    assert net is not None and net.archived_at is not None and net.enabled is False
    assert db.query(Device).filter_by(current_ip="10.0.2.7").one().network_id == admin.gone_id

    assert _ips(admin) == {"10.0.1.5"}
    assert _ips(admin, include_archived="true") == {"10.0.1.5", "10.0.2.7"}
    assert _ips(admin, network_id=admin.gone_id) == {"10.0.2.7"}
    assert {n["name"] for n in admin.get("/api/networks").json()} == {"Kept"}
    listed = {n["name"]: n for n in admin.get("/api/networks", params={"include_archived": "true"}).json()}
    assert listed["Gone"]["archived_at"] is not None and listed["Gone"]["device_count"] == 1
    assert {n["name"] for n in admin.get("/api/dashboard").json()["networks"]} == {"Kept"}
    recent = admin.get("/api/dashboard").json()["recent_events"]
    assert all(e.get("ip") != "10.0.2.7" for e in recent)
    assert db.query(AuditLog).filter_by(action="network.archive", target="Gone").count() == 1


def test_archived_network_cannot_be_scanned_or_edited(admin, db):
    admin.delete(f"/api/networks/{admin.gone_id}", headers=csrf(admin))
    r = admin.post("/api/scans", json={"scan_type": "standard", "network_ids": [admin.gone_id]}, headers=csrf(admin))
    assert r.status_code == 409
    body = {"name": "Gone", "cidr": "10.0.2.0/24", "enabled": True}
    assert admin.put(f"/api/networks/{admin.gone_id}", json=body, headers=csrf(admin)).status_code == 404
    assert admin.delete(f"/api/networks/{admin.gone_id}", headers=csrf(admin)).status_code == 404
    r = admin.post("/api/networks", json=body, headers=csrf(admin))
    assert r.status_code == 409 and "archived" in r.json()["detail"]
    db.expire_all()
    ids = enqueue_scheduled_scans(db)
    db.commit()
    assert ids and {db.get(Scan, i).network_id for i in ids} == {admin.kept_id}


def test_restore_brings_findings_back(admin):
    admin.delete(f"/api/networks/{admin.gone_id}", headers=csrf(admin))
    r = admin.post(f"/api/networks/{admin.gone_id}/restore", headers=csrf(admin))
    assert r.status_code == 200 and r.json()["archived_at"] is None
    assert _ips(admin) == {"10.0.1.5", "10.0.2.7"}
    assert admin.post(f"/api/networks/{admin.gone_id}/restore", headers=csrf(admin)).status_code == 409


def test_devices_outside_any_network_stay_visible(admin):
    scan(ScriptedScanner([host("192.168.50.9", [port(443, "https")])]), targets="192.168.50.9")
    admin.delete(f"/api/networks/{admin.gone_id}", headers=csrf(admin))
    assert _ips(admin) == {"10.0.1.5", "192.168.50.9"}


def test_migration_recovers_hard_deleted_networks_as_archived(tmp_path):
    """Upgrading turns old `network.delete` audit entries into archived networks and re-links
    the devices that were orphaned by the hard delete (ad-hoc devices outside it stay unlinked)."""
    import sqlalchemy as sa
    from alembic import command

    from app.migrate import alembic_config

    url = f"sqlite:///{(tmp_path / 'm.db').as_posix()}"
    cfg = alembic_config(url)
    command.upgrade(cfg, "0019")
    engine = sa.create_engine(url)
    with engine.begin() as conn:
        conn.execute(sa.text(
            "INSERT INTO audit_log (created_at, username, action, target, details) VALUES "
            "('2026-10-17 10:00:00', 'admin', 'network.delete', 'Old Lab', '{\"cidr\": \"10.9.0.0/24\"}')"))
        for i, ip in enumerate(("10.9.0.4", "172.16.0.8")):
            conn.execute(sa.text(
                "INSERT INTO devices (uuid, current_ip, status, first_seen, last_seen, missed_scans, port_scan_failed) "
                "VALUES (:u, :ip, 'active', '2026-10-01', '2026-10-01', 0, 0)"), {"u": f"uuid-{i}", "ip": ip})
    command.upgrade(cfg, "head")
    with engine.connect() as conn:
        net = conn.execute(sa.text("SELECT id, enabled, archived_at FROM networks WHERE name = 'Old Lab'")).one()
        links = dict(conn.execute(sa.text("SELECT current_ip, network_id FROM devices")).all())
    engine.dispose()
    assert net.archived_at is not None and not net.enabled
    assert links == {"10.9.0.4": net.id, "172.16.0.8": None}


def test_new_sightings_do_not_join_an_archived_network(admin, db):
    admin.delete(f"/api/networks/{admin.gone_id}", headers=csrf(admin))
    scan(ScriptedScanner([host("10.0.2.99", [port(22, "ssh")])]), targets="10.0.2.99")
    db.expire_all()
    orphan = db.query(Device).filter_by(current_ip="10.0.2.99").one()
    assert orphan.network_id is None
    # Still in the revoked CIDR: hidden from default inventory, same as the archived network's devices.
    assert _ips(admin) == {"10.0.1.5"}
    assert "10.0.2.99" in _ips(admin, include_archived="true")


def _add_capture(db, ip: str) -> WebCapture:
    dev = db.query(Device).filter_by(current_ip=ip).one()
    cap = WebCapture(status=WEB_CAPTURE_COMPLETED, targets=ip)
    db.add(cap)
    db.flush()
    db.add(WebPage(
        capture_id=cap.id, device_id=dev.id, ip=ip, port=80, scheme="http",
        host_used=ip, kind="home", url=f"http://{ip}/", final_url=f"http://{ip}/",
        http_status=200, title=ip, screenshot_status="skipped",
    ))
    db.commit()
    return cap


def test_archive_hides_web_captures_and_hosts(admin, db):
    kept_cap = _add_capture(db, "10.0.1.5")
    gone_cap = _add_capture(db, "10.0.2.7")
    assert {h["ip"] for h in admin.get("/api/web-hosts").json()["hosts"]} == {"10.0.1.5", "10.0.2.7"}
    assert {c["id"] for c in admin.get("/api/web-captures").json()["items"]} == {kept_cap.id, gone_cap.id}

    assert admin.delete(f"/api/networks/{admin.gone_id}", headers=csrf(admin)).status_code == 204

    assert {h["ip"] for h in admin.get("/api/web-hosts").json()["hosts"]} == {"10.0.1.5"}
    assert {c["id"] for c in admin.get("/api/web-captures").json()["items"]} == {kept_cap.id}
    shown = admin.get("/api/web-hosts", params={"include_archived": "true"}).json()["hosts"]
    assert {h["ip"] for h in shown} == {"10.0.1.5", "10.0.2.7"}
    jobs = admin.get("/api/web-captures", params={"include_archived": "true"}).json()["items"]
    assert {c["id"] for c in jobs} == {kept_cap.id, gone_cap.id}
