"""Search API: status codes, error positions, facet round-trip, bulk ids and export."""
from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient

from app.api.auth import limiter
from app.main import app
from app.models import DeviceTag

from .helpers import ScriptedScanner, device_by_ip, host, make_network, port, scan


@pytest.fixture
def client(db_env):
    limiter.reset()
    with TestClient(app) as c:
        yield c


def setup_admin(c: TestClient):
    r = c.post("/api/setup/admin", json={"username": "admin", "password": "correct-horse-1"})
    assert r.status_code == 200, r.text


@pytest.fixture
def seeded(db, client):
    net = make_network(db)
    scan(ScriptedScanner([
        host("10.0.0.10", [port(22, "ssh", "OpenSSH", "8.9p1"), port(443, "https", "nginx", "1.24.0")],
             mac="02:00:00:00:00:10", hostname="web01"),
        host("10.0.0.11", [port(443, "https", "Apache httpd", "2.4.57")], mac="02:00:00:00:00:11",
             hostname="web02"),
        host("10.0.0.12", [port(3389, "ms-wbt-server")], mac="02:00:00:00:00:12", hostname="ws01"),
    ]), network_id=net.id)
    db.add(DeviceTag(device_id=device_by_ip(db, "10.0.0.11").id, tag="lab"))
    db.commit()
    setup_admin(client)
    return client


def test_search_requires_login(client):
    assert client.get("/api/search", params={"q": "port:22"}).status_code == 401


def test_search_hosts_and_services(seeded):
    r = seeded.get("/api/search", params={"q": "port:443", "sort": "ip"})
    assert r.status_code == 200
    body = r.json()
    assert body["total"] == 2 and body["page"] == 1 and body["page_size"] == 25
    assert [h["ip"] for h in body["items"]] == ["10.0.0.10", "10.0.0.11"]
    assert [s["port"] for s in body["items"][0]["services"]] == [443]
    r = seeded.get("/api/search", params={"q": "product:nginx", "view": "services"})
    assert r.json()["total"] == 1 and r.json()["items"][0]["host"]["ip"] == "10.0.0.10"
    assert seeded.get("/api/search", params={"page_size": 101}).status_code == 422
    assert seeded.get("/api/search", params={"sort": "bogus"}).status_code == 422


def test_query_error_reports_position(seeded):
    r = seeded.get("/api/search", params={"q": "port:22 nosuch:1"})
    assert r.status_code == 400
    assert r.json() == {"code": "invalid_query", "message": "unknown field 'nosuch'",
                        "detail": "unknown field 'nosuch'", "pos": 8}
    r = seeded.get("/api/search/count", params={"q": 'title:"open'})
    assert r.status_code == 400 and isinstance(r.json()["pos"], int)
    assert seeded.get("/api/search/facets", params={"facets": "nosuch"}).status_code == 400


def test_facet_term_round_trip(seeded):
    r = seeded.get("/api/search/facets", params={"q": "port:443", "facets": "product,tag,port"})
    assert r.status_code == 200
    out = r.json()
    assert out["port"] == [{"value": "443/tcp", "count": 2, "term": "port:443"}]
    apache = next(f for f in out["product"] if f["value"] == "Apache httpd")
    r = seeded.get("/api/search", params={"q": f"port:443 {apache['term']}"})
    assert [h["ip"] for h in r.json()["items"]] == ["10.0.0.11"]
    lab = next(f for f in out["tag"] if f["value"] == "lab")
    r = seeded.get("/api/search", params={"q": f"port:443 -{lab['term']}"})
    assert [h["ip"] for h in r.json()["items"]] == ["10.0.0.10"]


def test_count_fields_and_uuids(seeded, monkeypatch):
    assert seeded.get("/api/search/count", params={"q": "port:443"}).json() == {"hosts": 2, "services": 2}
    fields = seeded.get("/api/search/fields").json()
    assert {"port", "product", "http.title", "tag"} <= {f["name"] for f in fields}
    r = seeded.get("/api/search/uuids", params={"q": "port:443"})
    assert r.status_code == 200 and r.json()["total"] == 2
    monkeypatch.setattr("app.api.search.MAX_UUIDS", 1)
    assert seeded.get("/api/search/uuids", params={"q": "port:443"}).status_code == 422


def test_export_csv_and_ndjson(seeded):
    r = seeded.get("/api/search/export", params={"q": "port:443", "format": "csv"})
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/csv")
    lines = r.text.strip().splitlines()
    assert lines[0].startswith("ip,hostname") and len(lines) == 3
    assert "22/tcp OpenSSH 8.9p1; 443/tcp nginx 1.24.0" in r.text
    r = seeded.get("/api/search/export", params={"q": "tag:lab", "format": "ndjson"})
    rows = [json.loads(line) for line in r.text.strip().splitlines()]
    assert [x["ip"] for x in rows] == ["10.0.0.11"] and "lab" in rows[0]["tags"]
    assert seeded.get("/api/search/export", params={"q": "nosuch:1"}).status_code == 400


def test_point_in_time_search(seeded):
    from datetime import date

    r = seeded.get("/api/search", params={"q": "port:22", "at": date.today().isoformat()})
    assert r.status_code == 200
    assert [h["ip"] for h in r.json()["items"]] == ["10.0.0.10"]
    r = seeded.get("/api/search", params={"q": "http.title:x", "at": date.today().isoformat()})
    assert r.status_code == 400
