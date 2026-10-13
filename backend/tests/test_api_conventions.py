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


# --- error envelope (API13-H3) -------------------------------------------------------------------------------
def test_errors_share_one_envelope_with_a_machine_readable_code(client):
    r = client.get("/api/scans/99999")
    assert r.status_code == 404
    assert r.json() == {"code": "not_found", "message": "Scan not found", "detail": "Scan not found"}

    r = client.get("/api/definitely/not/a/route")
    assert r.status_code == 404 and r.json()["code"] == "not_found"

    r = client.post("/api/networks", json={"name": "Office", "cidr": "10.10.0.0/24"})  # no CSRF header
    assert r.status_code == 403 and r.json()["code"] == "forbidden" and isinstance(r.json()["message"], str)

    r = client.post("/api/networks", json={"name": "", "cidr": "10.10.0.0/24"}, headers=csrf(client))
    body = r.json()
    assert r.status_code == 422 and body["code"] == "validation_error"
    assert body["message"].startswith("name: ")
    assert isinstance(body["detail"], list) and body["detail"][0]["loc"] == ["body", "name"]  # legacy shape kept
    assert body["details"][0].keys() == {"loc", "msg", "type"}

    r = client.post("/api/scans", json={"scan_type": "standard", "targets": "10.0.0.1; reboot"}, headers=csrf(client))
    assert r.status_code == 422 and r.json()["code"] in ("invalid_target", "validation_error")

    r = client.get("/api/search", params={"q": "nosuch:1"})
    assert r.status_code == 400 and r.json()["code"] == "invalid_query" and r.json()["pos"] == 0


def test_api_error_carries_a_specific_code_and_headers():
    from app.api.errors import ApiError, code_for

    exc = ApiError(502, "Sending failed", "smtp_send_failed", headers={"Retry-After": "5"})
    assert (exc.status_code, exc.detail, exc.code, exc.headers) == (502, "Sending failed", "smtp_send_failed",
                                                                    {"Retry-After": "5"})
    assert ApiError(409, "x").code == "conflict"
    assert code_for(418) == "client_error" and code_for(599) == "server_error"


# --- cancel semantics (API13-H2) -----------------------------------------------------------------------------
def test_scan_cancel_failure_is_409_not_200(client, monkeypatch):
    from app.api import scans as scans_api

    net = client.post("/api/networks", json={"name": "Lab", "cidr": "10.99.0.0/24"}, headers=csrf(client)).json()
    scan_id = client.post("/api/scans", json={"scan_type": "standard", "network_ids": [net["id"]]},
                          headers=csrf(client)).json()["scans"][0]["id"]

    monkeypatch.setattr(scans_api.manager, "cancel", lambda _id: False)
    r = client.post(f"/api/scans/{scan_id}/cancel", headers=csrf(client))
    assert r.status_code == 409 and r.json()["code"] == "conflict"
    assert client.get(f"/api/scans/{scan_id}").json()["status"] == "queued"
    assert not client.get("/api/audit", params={"q": "scan.cancel"}).json()["items"]

    monkeypatch.undo()
    r = client.post(f"/api/scans/{scan_id}/cancel", headers=csrf(client))
    assert r.status_code == 200 and r.json() == {"ok": True}
    assert client.get(f"/api/scans/{scan_id}").json()["status"] == "cancelled"
    r = client.post(f"/api/scans/{scan_id}/cancel", headers=csrf(client))
    assert r.status_code == 409 and r.json()["message"] == "Scan is already cancelled"


# --- list contracts in OpenAPI (API13-H4) ----------------------------------------------------------------------
def test_openapi_documents_unpaged_admin_lists_and_custom_envelopes(client):
    paths = client.get("/api/openapi.json").json()["paths"]
    for path in ("/api/users", "/api/networks", "/api/exclusions", "/api/tokens", "/api/webhooks",
                 "/api/saved-searches"):
        get = paths[path]["get"]
        assert "plain JSON array" in get["description"], path
        assert get["responses"]["200"]["content"]["application/json"]["schema"]["type"] == "array", path

    def ref(path, method):
        return paths[path][method]["responses"]["200"]["content"]["application/json"]["schema"]["$ref"]

    assert ref("/api/web-hosts", "get").endswith("/WebHostsPage")
    assert ref("/api/scans", "post").endswith("/ScansStarted")
    assert ref("/api/web-captures", "post").endswith("/CaptureStarted")
    assert ref("/api/exposed-ports", "get").endswith("/ExposedPorts")


def test_documented_envelopes_match_the_bodies(scanned):
    client, _ = scanned
    assert isinstance(client.get("/api/networks").json(), list)
    ports = client.get("/api/exposed-ports", params={"limit": 1}).json()
    assert ports.keys() == {"ports", "total", "truncated"} and len(ports["ports"]) <= 1
    started = client.post("/api/scans", json={"scan_type": "discovery", "targets": "10.99.0.7"},
                          headers=csrf(client)).json()
    assert started.keys() == {"scans"} and started["scans"][0]["targets"]
    capture = client.post("/api/web-captures", json={"targets": "10.99.0.5"}, headers=csrf(client)).json()
    assert capture.keys() == {"capture"} and capture["capture"]["id"]
