"""API contract conventions: status codes (201/204), versioned alias, canonical paths, pagination bounds."""
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
        assert c.post("/api/setup/admin", json={"username": "admin", "password": "correct-horse-1"}).status_code == 200
        yield c


def csrf(c: TestClient) -> dict:
    return {"X-CSRF-Token": c.cookies.get("nf_csrf", "")}


@pytest.fixture
def scanned(client):
    """A completed mock scan of the mock lab network: (client, scan id)."""
    net = client.post("/api/networks", json={"name": "Mock Lab", "cidr": "10.99.0.0/24"}, headers=csrf(client)).json()
    scan_id = client.post("/api/scans", json={"scan_type": "standard", "network_ids": [net["id"]]},
                          headers=csrf(client)).json()["scans"][0]["id"]
    assert run_scan(scan_id) == "completed"
    return client, scan_id


@pytest.mark.parametrize("path,body", [
    ("/api/networks", {"name": "Office", "cidr": "10.10.0.0/24"}),
    ("/api/exclusions", {"value": "10.10.0.5"}),
    ("/api/users", {"username": "viewer1", "password": "viewer-pass-1", "role": "viewer"}),
    ("/api/webhooks", {"name": "hook", "url": "https://hooks.example.test/nf"}),
    ("/api/saved-searches", {"name": "SSH", "query": "port:22"}),
    ("/api/tokens", {"name": "script"}),
])
def test_creates_answer_201_and_deletes_204_without_body(client, path, body):
    r = client.post(path, json=body, headers=csrf(client))
    assert r.status_code == 201, r.text
    r = client.delete(f"{path}/{r.json()['id']}", headers=csrf(client))
    assert r.status_code == 204 and r.content == b""


def test_versioned_prefix_is_an_alias_of_api(client):
    assert client.get("/api/v1/live").json()["status"] == "ok"
    me = client.get("/api/v1/auth/me")
    assert me.status_code == 200 and me.json()["user"]["username"] == "admin"
    r = client.post("/api/v1/networks", json={"name": "Office", "cidr": "10.10.0.0/24"}, headers=csrf(client))
    assert r.status_code == 201
    assert [n["name"] for n in client.get("/api/networks").json()] == ["Office"]
    assert client.get("/api/v1/nosuch").status_code == 404
    assert client.get("/api/v10/live").status_code == 404  # only the exact v1 prefix is rewritten


def test_openapi_documents_versioning_and_conventions(client):
    spec = client.get("/api/openapi.json").json()
    assert "/api/v1" in spec["info"]["description"] and "PATCH" in spec["info"]["description"]
    paths = spec["paths"]
    assert "/api/hosts/{ip}" in paths and "/api/host/{ip}" in paths
    assert "deprecated" in paths["/api/hosts/{ip}"]["get"]["description"]
    assert paths["/api/networks"]["post"]["responses"].keys() >= {"201"}
    assert paths["/api/networks/{network_id}"]["delete"]["responses"].keys() >= {"204"}


def test_scan_detail_no_longer_embeds_events(scanned):
    client, scan_id = scanned
    detail = client.get(f"/api/scans/{scan_id}").json()
    assert "events" not in detail and detail["status"] == "completed"
    r = client.get(f"/api/scans/{scan_id}/events", params={"page_size": 2})
    assert r.status_code == 200
    body = r.json()
    assert body.keys() == {"items", "total", "page", "page_size"}
    assert body["page_size"] == 2 and len(body["items"]) <= 2 and body["total"] == detail["events_count"]
    assert all(e["scan_id"] == scan_id for e in body["items"])
    assert client.get("/api/scans/99999/events").status_code == 404
    assert client.get(f"/api/scans/{scan_id}/events", params={"page_size": 501}).status_code == 422


def test_host_document_canonical_and_alias_paths_match(scanned):
    client, _ = scanned
    ip = client.get("/api/devices", params={"page_size": 1}).json()["items"][0]["current_ip"]
    canonical = client.get(f"/api/hosts/{ip}")
    alias = client.get(f"/api/host/{ip}")
    assert canonical.status_code == alias.status_code == 200
    assert canonical.json() == alias.json()
    assert canonical.json()["data"] == canonical.json()["ports"]  # deprecated alias still served
    assert client.get("/api/hosts/192.0.2.250").status_code == 404


def test_web_hosts_are_paged(client):
    r = client.get("/api/web-hosts", params={"kind": "web", "page": 2, "page_size": 10})
    assert r.status_code == 200
    assert r.json() == {"hosts": [], "total": 0, "page": 2, "page_size": 10}
    assert client.get("/api/web-hosts", params={"page_size": 501}).status_code == 422


def test_search_uses_shared_paging_with_lower_ceiling(client):
    r = client.get("/api/search", params={"q": ""})
    assert r.status_code == 200 and r.json()["page"] == 1 and r.json()["page_size"] == 25
    assert client.get("/api/search", params={"page_size": 100}).status_code == 200
    assert client.get("/api/search", params={"page_size": 101}).status_code == 422
    assert client.get("/api/search", params={"page": 0}).status_code == 422


def test_web_capture_settings_live_under_settings_router(client):
    from app.api import settings as settings_api
    from app.api import web_captures

    paths = {r.path for r in settings_api.router.routes}
    assert "/api/settings/web-capture" in paths
    assert not any(r.path.startswith("/api/settings") for r in web_captures.router.routes)

    cfg = client.get("/api/settings/web-capture").json()
    cfg["max_addresses"] = 64
    r = client.put("/api/settings/web-capture", json=cfg, headers=csrf(client))
    assert r.status_code == 200 and r.json()["max_addresses"] == 64
    assert client.get("/api/settings/web-capture").json()["max_addresses"] == 64
