"""Login-protected web apps, TLS scheme choice, and screenshots whose files are gone."""
from __future__ import annotations

import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select

from app.api.web_captures import web_page_out
from app.core.web_capture.classify import auth_challenge_scheme, unusable_page_reason
from app.core.web_capture.inventory import find_web_endpoints, guess_scheme
from app.core.web_capture.probe import classify_probe, probe_url
from app.core.web_storage import resolve_screenshot
from app.main import app
from app.models import WEB_CAPTURE_COMPLETED, WEB_PAGE_HOME, WEB_PAGE_LOGIN, Device, WebCapture, WebPage
from app.scanner.types import PortObservation
from app.settings_store import WebCaptureSettings, put_section
from tests.helpers import ScriptedScanner, host, make_network, port, scan
from tests.test_api import csrf, setup_admin


@pytest.fixture
def client(db_env):
    from app.api.auth import limiter

    limiter.reset()
    with TestClient(app) as c:
        yield c


def test_auth_challenge_is_a_login_not_an_error_page():
    assert auth_challenge_scheme(401, {"www-authenticate": 'Digest realm="ManagementRealm", qop="auth"'}) == "Digest"
    assert auth_challenge_scheme(407, {"proxy-authenticate": "NTLM"}) == "NTLM"
    assert auth_challenge_scheme(200, {"www-authenticate": "Basic"}) is None
    assert auth_challenge_scheme(401, {}) is None
    assert unusable_page_reason(401, "401 Unauthorized") == "error page (HTTP 401)"
    assert unusable_page_reason(401, "401 Unauthorized", auth_scheme="Basic") is None
    assert unusable_page_reason(403, "Forbidden", auth_scheme="Basic") == "error page (HTTP 403)"


def test_probe_records_auth_scheme_and_classifies_login():
    def handler(_req: httpx.Request) -> httpx.Response:
        return httpx.Response(401, headers={"WWW-Authenticate": 'Basic realm=""', "Content-Type": "text/html"},
                              text="<html><title>401 Unauthorized</title>Authorization required!</html>")

    with httpx.Client(transport=httpx.MockTransport(handler)) as http:
        pr = probe_url(http, "http://192.0.2.5/", allowed_hosts={"192.0.2.5"}, allowed_ips={"192.0.2.5"},
                       max_bytes=10_000, verify_tls=False)
    assert (pr.http_status, pr.auth_scheme) == (401, "Basic")
    assert classify_probe(pr, WEB_PAGE_HOME) == WEB_PAGE_LOGIN


def test_capture_scheme_follows_nmap_tls_flag():
    assert guess_scheme("http", 9993, "ssl") == "https"
    assert guess_scheme("http", 3000, "ssl") == "https"
    assert guess_scheme("http", 8080) == "http"
    assert guess_scheme("rtsp", 8443, "ssl") == "rtsps"


def test_inventory_endpoint_uses_tls_tunnel(db):
    net = make_network(db, "10.0.0.0/24", name="TlsWeb")
    tls_http = PortObservation(port=9993, service="http", tunnel="ssl", method="verified", confidence=9,
                               product="WildFly management console (HAL)")
    scan(ScriptedScanner([host("10.0.0.61", [tls_http])]), network_id=net.id)
    endpoints, _ = find_web_endpoints(db, {"10.0.0.61"}, max_endpoints=10)
    assert [(e.port, e.scheme) for e in endpoints] == [(9993, "https")]


def test_stored_auth_page_is_usable_login(db):
    page = WebPage(capture_id=1, ip="10.0.0.62", port=80, scheme="http", host_used="10.0.0.62", kind=WEB_PAGE_LOGIN,
                   url="http://10.0.0.62/", http_status=401, title="401 Unauthorized", auth_scheme="Basic",
                   capture_error="error page (HTTP 401)", screenshot_status="skipped")
    out = web_page_out(page)
    assert out["error_reason"] is None
    assert out["auth_scheme"] == "Basic"


def test_missing_screenshot_file_is_not_offered(db, client):
    setup_admin(client)
    put_section(db, WebCaptureSettings(enabled=True, force_mock=True))
    db.commit()
    net = make_network(db, "10.0.0.0/24", name="ShotNet")
    scan(ScriptedScanner([host("10.0.0.63", [port(80, "http")])]), network_id=net.id)
    r = client.post("/api/web-captures", json={"targets": "10.0.0.63"}, headers=csrf(client))
    assert r.status_code == 200
    cap_id = r.json()["capture"]["id"]
    shots = [p for p in client.get(f"/api/web-captures/{cap_id}").json()["pages"] if p["has_screenshot"]]
    assert shots
    page = db.get(WebPage, shots[0]["id"])
    resolve_screenshot(page.screenshot_relpath).unlink()

    again = {p["id"]: p for p in client.get(f"/api/web-captures/{cap_id}").json()["pages"]}
    assert again[page.id]["has_screenshot"] is False
    assert client.get(f"/api/web-pages/{page.id}/screenshot").status_code == 404


def _finished_capture_with_page(db, ip: str, port_no: int, **page_fields) -> None:
    job = db.scalar(select(WebCapture))
    job.status = WEB_CAPTURE_COMPLETED
    dev = db.scalar(select(Device).where(Device.current_ip == ip))
    port_id = next(p.id for p in dev.ports if p.port == port_no)
    fields = dict(scheme="http", screenshot_status="captured")
    fields.update(page_fields)
    db.add(WebPage(capture_id=job.id, device_id=dev.id, device_port_id=port_id, ip=ip, port=port_no,
                   host_used=ip, kind="home", url=f"{fields['scheme']}://{ip}:{port_no}/", **fields))
    db.commit()


def _auto_settings(db) -> None:
    put_section(db, WebCaptureSettings(enabled=True, auto_after_scan=True, auto_only_new_or_changed=True,
                                       force_mock=True))
    db.commit()


def test_auto_capture_redoes_host_whose_screenshot_file_is_gone(db):
    _auto_settings(db)
    net = make_network(db, "10.0.0.0/24", name="GoneShot")
    hosts = [host("10.0.0.64", [port(80, "http")])]
    scan(ScriptedScanner(hosts), network_id=net.id)
    _finished_capture_with_page(db, "10.0.0.64", 80,
                                screenshot_relpath="00000000-0000-4000-8000-000000000000/"
                                                   "00000000-0000-4000-8000-000000000001.webp")
    scan(ScriptedScanner(hosts), network_id=net.id)
    assert db.scalar(select(func.count(WebCapture.id))) == 2


def test_auto_capture_redoes_port_reidentified_with_other_scheme(db):
    """Old page was taken as an RTSP stream; the port is now known to be HTTP."""
    _auto_settings(db)
    net = make_network(db, "10.0.0.0/24", name="Relabel")
    hosts = [host("10.0.0.65", [port(8088, "http")])]
    scan(ScriptedScanner(hosts), network_id=net.id)
    _finished_capture_with_page(db, "10.0.0.65", 8088, scheme="rtsp", screenshot_status="skipped")
    scan(ScriptedScanner(hosts), network_id=net.id)
    assert db.scalar(select(func.count(WebCapture.id))) == 2
