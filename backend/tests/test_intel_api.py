"""API for inventory intelligence: tags, profile, timeline, saved searches, reports, tokens, dashboard."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import event as sa_event

from app.api.auth import limiter
from app.api.devices import get_device
from app.main import app

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
    net = make_network(db)
    scan(ScriptedScanner([
        host("10.0.0.1", [port(3389, "ms-wbt-server"), port(80, "http")], mac="02:00:00:00:00:01", hostname="ws1"),
        host("10.0.0.2", [port(22, "ssh")], mac="02:00:00:00:00:02"),
    ]), network_id=net.id)
    r = client.post("/api/setup/admin", json={"username": "admin", "password": "correct-horse-1"})
    assert r.status_code == 200
    client.net_id = net.id
    return client


def _uuid(c: TestClient, ip: str) -> str:
    return c.get("/api/search", params={"q": f"ip:{ip}"}).json()["items"][0]["uuid"]


def _viewer(c: TestClient) -> TestClient:
    c.post("/api/users", json={"username": "viewer1", "password": "viewer-pass-1", "role": "viewer"},
           headers=csrf(c))
    v = TestClient(app)
    assert v.post("/api/auth/login", json={"username": "viewer1", "password": "viewer-pass-1"}).status_code == 200
    return v


def test_device_detail_tags_and_profile(admin):
    uuid = _uuid(admin, "10.0.0.1")
    d = admin.get(f"/api/devices/{uuid}").json()
    assert d["type"] == "web-server" and d["score"] == 35 and d["score_level"] == "medium"
    assert {t["tag"] for t in d["tags"]} == {"remote-access", "web-server"}
    assert {f["factor"] for f in d["profile"]["exposure_factors"]} == {"rdp", "new_host"}
    assert all("http" in p and "cpe" in p for p in d["ports"])

    r = admin.post(f"/api/devices/{uuid}/tags", json={"tag": "PCI Zone"}, headers=csrf(admin))
    assert r.status_code == 200 and r.json()["tag"] == "pci-zone" and r.json()["source"] == "manual"
    assert admin.post(f"/api/devices/{uuid}/tags", json={"tag": "!!"}, headers=csrf(admin)).status_code == 422
    # Dismiss a rule tag: stays off search and type recomputes without it.
    assert admin.delete(f"/api/devices/{uuid}/tags/web-server", headers=csrf(admin)).status_code == 200
    d = admin.get(f"/api/devices/{uuid}").json()
    assert any(t["tag"] == "web-server" and t["source"] == "suppressed" for t in d["tags"])
    assert d["type"] is None  # remote-access has no type; web-server was the only type rule
    assert admin.get("/api/search", params={"q": "tag:web-server"}).json()["total"] == 0
    # Clear dismiss → rule tag returns.
    assert admin.delete(f"/api/devices/{uuid}/tags/web-server", headers=csrf(admin)).status_code == 200
    d = admin.get(f"/api/devices/{uuid}").json()
    assert any(t["tag"] == "web-server" and t["source"] == "rule" for t in d["tags"])
    assert d["type"] == "web-server"
    assert admin.get("/api/search", params={"q": "tag:pci-zone"}).json()["total"] == 1
    assert admin.delete(f"/api/devices/{uuid}/tags/pci-zone", headers=csrf(admin)).status_code == 200

    body = {"owner": " alice ", "location": "rack 4", "criticality": "high", "notes": ""}
    r = admin.put(f"/api/devices/{uuid}/profile", json=body, headers=csrf(admin))
    assert r.status_code == 200 and r.json()["owner"] == "alice" and r.json()["notes"] is None
    assert admin.put(f"/api/devices/{uuid}/profile", json={"criticality": "extreme"},
                     headers=csrf(admin)).status_code == 422
    assert admin.get("/api/search", params={"q": "owner:alice criticality:high"}).json()["total"] == 1

    items = admin.get(f"/api/devices/{uuid}/timeline").json()["items"]
    assert [i["kind"] for i in items] == ["scan"]

    viewer = _viewer(admin)
    assert viewer.post(f"/api/devices/{uuid}/tags", json={"tag": "x"},
                       headers={"X-CSRF-Token": viewer.cookies.get("nf_csrf", "")}).status_code == 403


def test_device_detail_eager_loads_related_data_in_three_queries(admin, db):
    uuid = _uuid(admin, "10.0.0.1")
    db.expunge_all()
    selects: list[str] = []

    def record_select(_conn, _cursor, statement, _parameters, _context, _executemany):
        if statement.lstrip().upper().startswith("SELECT"):
            selects.append(statement)

    bind = db.get_bind()
    sa_event.listen(bind, "before_cursor_execute", record_select)
    try:
        detail = get_device(uuid, db=db, user=None)
    finally:
        sa_event.remove(bind, "before_cursor_execute", record_select)

    assert len(selects) == 3
    assert detail["tags"] and detail["profile"]["exposure_factors"]
    assert all("http" in port_data for port_data in detail["ports"])


def test_saved_searches_crud_and_ownership(admin):
    r = admin.post("/api/saved-searches", json={"name": "RDP", "query": "port:3389"}, headers=csrf(admin))
    assert r.status_code == 200
    s = r.json()
    assert s["initialized"] and s["last_count"] == 1 and s["kind"] == "watch" and s["can_edit"]
    bad = admin.post("/api/saved-searches", json={"name": "x", "query": "nosuch:1"}, headers=csrf(admin))
    assert bad.status_code == 400 and bad.json()["pos"] == 0
    r = admin.put(f"/api/saved-searches/{s['id']}", json={"name": "SSH", "query": "port:22", "kind": "policy"},
                  headers=csrf(admin))
    assert r.json()["last_count"] == 1 and r.json()["kind"] == "policy"

    viewer = _viewer(admin)
    vh = {"X-CSRF-Token": viewer.cookies.get("nf_csrf", "")}
    mine = viewer.post("/api/saved-searches", json={"name": "Mine", "query": "port:80"}, headers=vh).json()
    listed = {x["name"]: x["can_edit"] for x in viewer.get("/api/saved-searches").json()}
    assert listed == {"SSH": False, "Mine": True}
    assert viewer.delete(f"/api/saved-searches/{s['id']}", headers=vh).status_code == 403
    assert viewer.delete(f"/api/saved-searches/{mine['id']}", headers=vh).status_code == 200
    assert admin.delete(f"/api/saved-searches/{s['id']}", headers=csrf(admin)).status_code == 200


def test_reports_dashboard_and_zone(admin):
    exp = admin.get("/api/reports/exposure").json()
    assert exp["levels"] == {"high": 0, "medium": 1, "low": 1}
    assert sum(b["count"] for b in exp["distribution"]) == 2 and exp["top"][0]["ip"] == "10.0.0.1"
    assert admin.get("/api/reports/rare-services").json()["items"] == []  # network under 5 hosts
    assert admin.get("/api/reports/version-skew").status_code == 200
    subnets = admin.get("/api/reports/subnets").json()["items"]
    assert subnets == [{"subnet": "10.0.0.0/24", "hosts": 2, "active": 2, "max_score": 35, "avg_score": 22.5,
                        "query": "net:10.0.0.0/24"}]

    dash = admin.get("/api/dashboard").json()
    assert dash["exposure"]["medium"] == 1 and dash["exposure"]["top"][0]["score"] == 35
    assert {t["type"] for t in dash["device_types"]} == {"web-server"}
    assert dash["new_hosts_7d"] == 2 and dash["watch_alerts"]["last_7d"] == 0

    body = {"name": "Test Net", "cidr": "10.0.0.0/24", "zone": "users"}
    r = admin.put(f"/api/networks/{admin.net_id}", json=body, headers=csrf(admin))
    assert r.status_code == 200 and r.json()["zone"] == "users"
    assert admin.get(f"/api/devices/{_uuid(admin, '10.0.0.1')}").json()["score"] == 48  # RDP x1.5
    body["zone"] = "moon"
    assert admin.put(f"/api/networks/{admin.net_id}", json=body, headers=csrf(admin)).status_code == 422


def test_api_tokens_are_read_only_and_revocable(admin):
    r = admin.post("/api/tokens", json={"name": "script", "expires_days": 30}, headers=csrf(admin))
    assert r.status_code == 200
    secret = r.json()["token"]
    assert secret.startswith("nf_") and r.json()["prefix"] == secret[:12]
    assert "token" not in admin.get("/api/tokens").json()[0]

    bearer = TestClient(app)
    auth = {"Authorization": f"Bearer {secret}"}
    assert bearer.get("/api/search/count", params={"q": "port:22"}, headers=auth).json()["hosts"] == 1
    assert bearer.get("/api/auth/me", headers=auth).json()["csrf_token"] is None
    assert bearer.post("/api/saved-searches", json={"name": "x", "query": "port:1"}, headers=auth).status_code == 403
    assert bearer.get("/api/tokens", headers=auth).status_code == 401  # tokens cannot manage tokens
    assert bearer.get("/api/dashboard", headers={"Authorization": "Bearer nf_wrong"}).status_code == 401
    assert admin.get("/api/tokens").json()[0]["last_used_at"] is not None

    token_id = r.json()["id"]
    assert admin.delete(f"/api/tokens/{token_id}", headers=csrf(admin)).status_code == 200
    assert bearer.get("/api/dashboard", headers=auth).status_code == 401
