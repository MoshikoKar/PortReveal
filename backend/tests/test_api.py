"""API: setup wizard, authentication, CSRF, roles, scans, settings."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.api.auth import limiter
from app.core.runner import run_scan
from app.main import app


@pytest.fixture
def client(db_env):
    limiter.reset()
    with TestClient(app) as c:
        yield c


def csrf(c: TestClient) -> dict:
    return {"X-CSRF-Token": c.cookies.get("nf_csrf", "")}


def setup_admin(c: TestClient, username="admin", password="correct-horse-1"):
    r = c.post("/api/setup/admin", json={"username": username, "password": password})
    assert r.status_code == 200, r.text
    return r.json()


def test_health_is_public(client):
    r = client.get("/api/health")
    assert r.status_code == 200 and r.json()["database"] == "ok"


def test_first_run_wizard_and_login(client):
    assert client.get("/api/setup/status").json()["needs_admin"] is True
    setup_admin(client)
    assert client.get("/api/setup/status").json()["needs_admin"] is False
    assert client.post("/api/setup/admin", json={"username": "other", "password": "another-pass-1"}).status_code == 409
    assert client.get("/api/auth/me").json()["user"]["role"] == "admin"
    assert client.post("/api/setup/complete", headers=csrf(client)).status_code == 200

    client.post("/api/auth/logout", headers=csrf(client))
    assert client.get("/api/auth/me").status_code == 401
    assert client.post("/api/auth/login", json={"username": "admin", "password": "wrong"}).status_code == 401
    r = client.post("/api/auth/login", json={"username": "ADMIN", "password": "correct-horse-1"})
    assert r.status_code == 200 and r.json()["csrf_token"]


def test_session_cookie_flags(client):
    setup_admin(client)
    r = client.post("/api/auth/login", json={"username": "admin", "password": "correct-horse-1"})
    cookie = [h for h in r.headers.get_list("set-cookie") if h.startswith("nf_session=")][0].lower()
    assert "httponly" in cookie and "samesite=lax" in cookie


def test_csrf_required_for_state_changes(client):
    setup_admin(client)
    body = {"name": "Office", "cidr": "10.10.0.0/16"}
    assert client.post("/api/networks", json=body).status_code == 403
    assert client.post("/api/networks", json=body, headers={"X-CSRF-Token": "bogus"}).status_code == 403
    assert client.post("/api/networks", json=body, headers=csrf(client)).status_code == 200


def test_login_rate_limit(client):
    setup_admin(client)
    for _ in range(10):
        client.post("/api/auth/login", json={"username": "admin", "password": "bad"})
    r = client.post("/api/auth/login", json={"username": "admin", "password": "correct-horse-1"})
    assert r.status_code == 429


def test_login_requires_json(client):
    setup_admin(client)
    r = client.post("/api/auth/login", data={"username": "admin", "password": "correct-horse-1"})
    assert r.status_code == 415


def test_viewer_is_read_only(client):
    setup_admin(client)
    r = client.post("/api/users", json={"username": "viewer1", "password": "viewer-pass-1", "role": "viewer"},
                    headers=csrf(client))
    assert r.status_code == 200
    client.post("/api/auth/logout", headers=csrf(client))
    client.post("/api/auth/login", json={"username": "viewer1", "password": "viewer-pass-1"})
    assert client.get("/api/dashboard").status_code == 200
    assert client.get("/api/devices").status_code == 200
    assert client.post("/api/scans", json={"scan_type": "standard", "targets": "10.0.0.1"},
                       headers=csrf(client)).status_code == 403
    assert client.get("/api/settings/notifications").status_code == 403
    assert client.post("/api/networks", json={"name": "x", "cidr": "10.0.0.0/24"}, headers=csrf(client)).status_code == 403


def test_last_local_admin_cannot_be_removed(client):
    me = setup_admin(client)["user"]
    assert client.patch(f"/api/users/{me['id']}", json={"role": "viewer"}, headers=csrf(client)).status_code == 409
    assert client.delete(f"/api/users/{me['id']}", headers=csrf(client)).status_code == 409


def test_network_and_exclusion_validation(client):
    setup_admin(client)
    h = csrf(client)
    assert client.post("/api/networks", json={"name": "Huge", "cidr": "10.0.0.0/8"}, headers=h).status_code == 422
    assert client.post("/api/networks", json={"name": "Bad", "cidr": "10.0.0.0/24; rm -rf"}, headers=h).status_code == 422
    r = client.post("/api/exclusions", json={"value": "10.0.0.5\n10.0.0.10-20, 10.0.1.0/30", "description": "printers"},
                    headers=h)
    assert r.status_code == 200 and r.json()["address_count"] == 1 + 11 + 4
    assert client.post("/api/exclusions", json={"value": "10.0.0.999"}, headers=h).status_code == 422


def test_scan_flow_through_api(client):
    setup_admin(client)
    h = csrf(client)
    net = client.post("/api/networks", json={"name": "Mock Lab", "cidr": "10.99.0.0/24"}, headers=h).json()
    r = client.post("/api/scans", json={"scan_type": "standard", "network_ids": [net["id"]]}, headers=h)
    assert r.status_code == 200, r.text
    scan_id = r.json()["scans"][0]["id"]
    # duplicate request while queued is refused
    assert client.post("/api/scans", json={"scan_type": "standard", "network_ids": [net["id"]]},
                       headers=h).status_code == 409
    assert run_scan(scan_id) == "completed"  # background worker disabled in tests

    s = client.get(f"/api/scans/{scan_id}").json()
    assert s["status"] == "completed" and s["is_baseline"] and s["scanner_mode"] == "mock"
    dash = client.get("/api/dashboard").json()
    assert dash["devices"]["active"] == 15 and dash["open_ports_total"] > 0
    assert dash["last_7d"]["changes"] == 0

    devs = client.get("/api/devices", params={"q": "5432"}).json()
    assert devs["total"] == 1 and devs["items"][0]["hostname"].startswith("srv-db01")
    assert client.get("/api/devices", params={"q": "nginx"}).json()["total"] >= 1
    uuid = devs["items"][0]["uuid"]
    detail = client.get(f"/api/devices/{uuid}").json()
    assert {p["port"] for p in detail["ports"]} == {22, 5432}
    assert client.get(f"/api/devices/{uuid}/scans").json()["total"] == 1

    by_port = client.get("/api/devices", params={"port": 80}).json()
    uuids = client.get("/api/devices/uuids", params={"port": 80}).json()
    assert uuids["total"] == by_port["total"] > 0
    assert set(uuids["uuids"]) >= {d["uuid"] for d in by_port["items"]}
    assert len(uuids["uuids"]) == uuids["total"]

    r = client.post("/api/scans", json={"scan_type": "full", "device_uuids": [uuid]}, headers=h)
    assert r.status_code == 200
    assert client.post("/api/scans", json={"scan_type": "full", "targets": "10.0.0.1; reboot"},
                       headers=h).status_code == 422
    snaps = client.get("/api/snapshots").json()
    assert snaps["total"] == 1
    assert client.get(f"/api/snapshots/{snaps['items'][0]['id']}").json()["network"]["name"] == "Mock Lab"
    audit = client.get("/api/audit").json()
    assert any(a["action"] == "scan.full_port" for a in audit["items"])


def test_secrets_are_write_only(client):
    setup_admin(client)
    h = csrf(client)
    body = {"enabled": False, "smtp_host": "relay", "smtp_port": 25, "security": "none", "username": "u",
            "password": "s3cret", "sender": "nm@corp", "recipients": ["it@corp"], "event_types": ["port_opened"],
            "digest_time": "08:00"}
    r = client.put("/api/settings/notifications", json=body, headers=h)
    assert r.status_code == 200 and "s3cret" not in r.text and r.json()["password_set"] is True
    body.pop("password")
    r = client.put("/api/settings/notifications", json=body, headers=h)
    assert r.json()["password_set"] is True  # omitted password keeps the stored one
    r = client.put("/api/settings/ldap", json={"enabled": False, "server_uri": "ldap://dc01.corp",
                                               "bind_password": "pw"}, headers=h)
    assert r.status_code == 200 and "pw\"" not in r.text and r.json()["bind_password_set"] is True


def test_schedule_update_applies_without_restart(client):
    setup_admin(client)
    r = client.put("/api/settings/schedule",
                   json={"enabled": True, "time": "23:59", "days": [0, 1, 2, 3, 4, 5, 6],
                         "discovery_before_standard": True},
                   headers=csrf(client))
    assert r.status_code == 200 and r.json()["next_run"]
    sched = client.get("/api/system/status").json()["scans"]["schedule"]
    assert sched["time"] == "23:59" and sched["discovery_before_standard"] is True
    assert client.put("/api/settings/schedule", json={"time": "25:00"}, headers=csrf(client)).status_code == 422


def test_system_status_reports_dev_info(client):
    setup_admin(client)
    st = client.get("/api/system/status").json()
    assert st["database"]["type"] == "sqlite" and st["database"]["ok"]
    assert st["scanner"]["mock_active"] is True and st["app"]["dev_mode"] is True


def test_mock_data_can_be_hidden(client):
    setup_admin(client)
    h = csrf(client)
    net = client.post("/api/networks", json={"name": "Mock Lab", "cidr": "10.99.0.0/24"}, headers=h).json()
    scan_id = client.post("/api/scans", json={"scan_type": "standard", "network_ids": [net["id"]]},
                          headers=h).json()["scans"][0]["id"]
    assert run_scan(scan_id) == "completed"
    state = client.get("/api/mock-data").json()
    assert state == {"hidden": False, "scans": 1, "devices": 15, "events": 0}

    r = client.put("/api/mock-data", json={"hidden": True}, headers=h)
    assert r.status_code == 200 and r.json()["hidden"] and r.json()["devices"] == 15  # nothing deleted
    assert client.get("/api/system/status").json()["app"]["mock_data_hidden"] is True
    dash = client.get("/api/dashboard").json()
    assert dash["devices"]["total"] == 0 and dash["open_ports_total"] == 0 and not dash["top_ports"]
    assert dash["scans"]["last_completed"] is None
    assert client.get("/api/devices").json()["total"] == 0
    assert client.get("/api/scans").json()["total"] == 0
    assert client.get("/api/snapshots").json()["total"] == 0
    assert client.get("/api/networks").json()[0]["device_count"] == 0

    client.put("/api/mock-data", json={"hidden": False}, headers=h)
    assert client.get("/api/devices").json()["total"] == 15
    assert client.get("/api/scans").json()["total"] == 1
