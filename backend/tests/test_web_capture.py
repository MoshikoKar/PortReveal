"""Web Capture: classification, API, auth, limits, retention."""
from __future__ import annotations

from datetime import timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select

from app.core.retention import run_retention
from app.core.web_capture.classify import (
    BLANK_PAGE_REASON,
    blank_page_reason,
    candidate_paths_for_endpoint,
    default_page_reason,
    error_page_reason,
    is_same_target,
    redirect_is_external,
    unusable_page_reason,
)
from app.core.web_capture.inventory import (
    COMMON_WEB_PORTS,
    find_web_endpoints,
    is_probable_web_port,
    is_rtsp_service,
    is_web_service,
)
from app.core.web_capture.mock import mock_probe_endpoint, mock_rtsp_endpoint
from app.core.web_capture.screenshot import meta_refresh_target
from app.core.web_storage import captures_root
from app.db import utcnow
from app.main import app
from app.models import WEB_CAPTURE_COMPLETED, WEB_PAGE_STREAM, Device, Exclusion, WebCapture, WebPage
from app.scanner.known_ports import TRUENAS_APPS_TCP_PORTS
from app.settings_store import WebCaptureSettings, put_section
from tests.helpers import ScriptedScanner, host, make_network, port, scan
from tests.test_api import csrf, setup_admin


@pytest.fixture
def client(db_env):
    from app.api.auth import limiter

    limiter.reset()
    with TestClient(app) as c:
        yield c


def _seed_web_host(db, ip: str, *, net_name: str, svc="https", p=443):
    net = make_network(db, "10.0.0.0/24", name=net_name)
    scan(ScriptedScanner([host(ip, [port(p, svc)])]), network_id=net.id)
    return db.scalar(select(Device).where(Device.current_ip == ip))


def test_external_redirect_not_same_target():
    allowed = {"10.0.0.1"}
    assert redirect_is_external(
        "https://10.0.0.1/",
        "https://login.microsoftonline.com/x",
        allowed,
        allowed,
    )
    assert is_same_target("http://10.0.0.1/", "https://10.0.0.1/", allowed, allowed)


def test_service_detection_priority():
    assert is_web_service("http")
    assert is_web_service("ssl/http")
    assert is_web_service("https")
    assert is_web_service("webdav")
    assert not is_web_service("ssh")
    assert is_rtsp_service("rtsp")
    assert is_rtsp_service("ssl/rtsp")
    assert not is_web_service("rtsp")
    assert not is_rtsp_service("http")


def test_probable_web_port_truenas_unknown_and_catalog():
    catalog = next(p for p in TRUENAS_APPS_TCP_PORTS if p >= 30000 and p not in COMMON_WEB_PORTS)
    assert is_probable_web_port("unknown", catalog, truenas=True)
    assert is_probable_web_port(None, catalog, truenas=True)
    assert is_probable_web_port("webdav", 20720, truenas=False)
    assert is_probable_web_port("unknown", 20720, truenas=True)
    assert not is_probable_web_port("unknown", catalog, truenas=False)
    assert not is_probable_web_port("postgresql", catalog, truenas=True)
    assert not is_probable_web_port("unknown", 5440, truenas=True)


def test_inventory_truenas_unknown_catalog_ports(db):
    """TrueNAS hosts: catalog / unknown high ports are web-capture candidates."""
    make_network(db, "10.0.0.0/24", name="TnWeb")
    catalog = next(p for p in TRUENAS_APPS_TCP_PORTS if p >= 30000 and p not in COMMON_WEB_PORTS)
    scan(
        ScriptedScanner([
            host(
                "10.0.0.50",
                [
                    port(80, "http"),
                    port(catalog, "unknown"),
                    port(20720, "webdav"),
                    port(5432, "postgresql"),
                ],
                hostname="truenas.lab",
            ),
        ]),
        scan_type="full",
        targets="10.0.0.50",
    )
    endpoints, _ = find_web_endpoints(db, {"10.0.0.50"}, max_endpoints=20)
    ports = {e.port for e in endpoints}
    assert {80, catalog, 20720} <= ports
    assert 5432 not in ports


def test_inventory_rtsp_on_nonstandard_port(db):
    """Service label wins: RTSP on 8443 must not be treated as HTTPS."""
    net = make_network(db, "10.0.0.0/24", name="RtspAlt")
    scan(ScriptedScanner([host("10.0.0.44", [port(8443, "rtsp")])]), network_id=net.id)
    endpoints, _ = find_web_endpoints(db, {"10.0.0.44"}, max_endpoints=10)
    assert len(endpoints) == 1
    assert endpoints[0].port == 8443
    assert endpoints[0].scheme == "rtsp"


def test_inventory_classic_rtsp_port(db):
    net = make_network(db, "10.0.0.0/24", name="RtspClassic")
    scan(ScriptedScanner([host("10.0.0.45", [port(554, "rtsp")])]), network_id=net.id)
    endpoints, _ = find_web_endpoints(db, {"10.0.0.45"}, max_endpoints=10)
    assert any(e.port == 554 and e.scheme == "rtsp" for e in endpoints)


def test_mock_rtsp_capture_and_can_live(db, client):
    setup_admin(client)
    net = make_network(db, "10.0.0.0/24", name="CamNet")
    scan(ScriptedScanner([host("10.0.0.46", [port(8443, "rtsp")])]), network_id=net.id)
    r = client.post("/api/web-captures", json={"targets": "10.0.0.46"}, headers=csrf(client))
    assert r.status_code == 200
    cap = client.get(f"/api/web-captures/{r.json()['capture']['id']}").json()
    streams = [p for p in cap["pages"] if p["scheme"] == "rtsp"]
    assert streams
    assert streams[0]["kind"] == WEB_PAGE_STREAM
    assert streams[0]["can_live"] is True
    assert streams[0]["has_screenshot"] is True
    assert streams[0]["error_reason"] is None
    # Live proxy is disabled in mock mode
    live = client.get(f"/api/web-pages/{streams[0]['id']}/live")
    assert live.status_code == 409


def test_mock_rtsp_endpoint_shape():
    ep = mock_rtsp_endpoint("rtsp", "10.0.0.7", 8443)
    assert ep.pages[0].kind == WEB_PAGE_STREAM
    assert "8443" in ep.pages[0].url


def test_looks_like_rtsp_rejects_http_json_400(monkeypatch):
    """Keycloak-like ports answer RTSP probes with RTSP/1.0 400 + JSON - not a camera."""
    from app.core.web_capture import rtsp as rtsp_mod

    class FakeSock:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def settimeout(self, t):
            pass

        def sendall(self, data):
            pass

        def recv(self, n):
            return (
                b"RTSP/1.0 400 Bad Request\r\n"
                b"content-type: application/json; charset=utf-8\r\n"
                b"content-length: 20\r\n\r\n"
                b'{"details":"x"}'
            )

    monkeypatch.setattr(rtsp_mod.socket, "create_connection", lambda *a, **k: FakeSock())
    ok, reason = rtsp_mod.looks_like_rtsp("rtsp://10.0.0.1:9000/")
    assert ok is False
    assert "HTTP" in reason or "not" in reason.lower()


def test_mock_scenario_external_sso():
    ep = mock_probe_endpoint("https", "10.0.0.5", 8443, "10.0.0.5")
    assert ep.pages
    assert ep.pages[0].external_redirect is True
    assert ep.pages[0].redirect_target and "microsoftonline" in ep.pages[0].redirect_target


def test_mock_scenario_tls_unverified():
    ep = mock_probe_endpoint("https", "10.0.0.4", 443, "10.0.0.4")
    assert ep.pages
    assert ep.pages[0].tls_verified is False


def test_arbitrary_url_rejected(client):
    setup_admin(client)
    r = client.post(
        "/api/web-captures",
        json={"targets": "https://evil.example.com/"},
        headers=csrf(client),
    )
    assert r.status_code == 422


def test_viewer_cannot_start_or_delete(client, db):
    setup_admin(client)
    dev = _seed_web_host(db, "10.0.0.11", net_name="VNet")
    r = client.post("/api/web-captures", json={"device_uuids": [dev.uuid]}, headers=csrf(client))
    assert r.status_code == 200
    cap_id = r.json()["capture"]["id"]
    client.post(
        "/api/users",
        json={"username": "viewer1", "password": "viewer-pass-1", "role": "viewer"},
        headers=csrf(client),
    )
    client.post("/api/auth/logout", headers=csrf(client))
    client.post("/api/auth/login", json={"username": "viewer1", "password": "viewer-pass-1"})
    assert client.post("/api/web-captures", json={"targets": "10.0.0.1"}, headers=csrf(client)).status_code == 403
    assert client.delete(f"/api/web-captures/{cap_id}", headers=csrf(client)).status_code == 403
    assert client.post(f"/api/web-captures/{cap_id}/cancel", headers=csrf(client)).status_code == 403


def test_mock_capture_creates_pages(db, client):
    setup_admin(client)
    dev = _seed_web_host(db, "10.0.0.10", net_name="MockNet", svc="https", p=443)
    assert dev is not None
    r = client.post("/api/web-captures", json={"device_uuids": [dev.uuid]}, headers=csrf(client))
    assert r.status_code == 200, r.text
    cap = r.json()["capture"]
    assert cap["status"] in ("completed", "partial")
    assert cap["pages_captured"] >= 1
    detail = client.get(f"/api/web-captures/{cap['id']}").json()
    assert detail["pages"]
    assert any(p.get("title") for p in detail["pages"])
    # Dedup: unique final URLs among pages
    finals = [p.get("final_url") or p["url"] for p in detail["pages"]]
    assert len(finals) == len(set(finals))


def test_excluded_target_skipped(db, client):
    setup_admin(client)
    db.add(Exclusion(value="10.0.0.50", enabled=True))
    db.commit()
    _seed_web_host(db, "10.0.0.50", net_name="ExNet", svc="http", p=80)
    r = client.post("/api/web-captures", json={"targets": "10.0.0.50"}, headers=csrf(client))
    assert r.status_code == 200
    notes = r.json()["capture"].get("notes") or ""
    assert "exclusion" in notes.lower() or r.json()["capture"]["pages_captured"] == 0


def test_address_limit_enforced(db, client):
    setup_admin(client)
    put_section(db, WebCaptureSettings(max_addresses=2))
    db.commit()
    r = client.post("/api/web-captures", json={"targets": "10.0.0.0/30"}, headers=csrf(client))
    assert r.status_code == 422


def test_delete_removes_screenshot_files(db, client):
    setup_admin(client)
    _seed_web_host(db, "10.0.0.8", net_name="DelNet")
    r = client.post("/api/web-captures", json={"targets": "10.0.0.8"}, headers=csrf(client))
    assert r.status_code == 200, r.text
    cap_id = r.json()["capture"]["id"]
    cap = db.get(WebCapture, cap_id)
    assert cap is not None
    cap_uuid = cap.uuid
    cap_dir = captures_root() / cap_uuid
    assert client.delete(f"/api/web-captures/{cap_id}", headers=csrf(client)).status_code == 204
    db.expire_all()
    assert db.get(WebCapture, cap_id) is None
    assert not cap_dir.exists()


def test_viewer_can_fetch_screenshot_when_present(db, client):
    setup_admin(client)
    _seed_web_host(db, "10.0.0.7", net_name="ViewNet", svc="http", p=80)
    r = client.post("/api/web-captures", json={"targets": "10.0.0.7"}, headers=csrf(client))
    assert r.status_code == 200
    cap = client.get(f"/api/web-captures/{r.json()['capture']['id']}").json()
    page = next((p for p in cap["pages"] if p.get("has_screenshot")), None)
    client.post(
        "/api/users",
        json={"username": "v2", "password": "viewer-pass-2", "role": "viewer"},
        headers=csrf(client),
    )
    if not page:
        pytest.skip("no screenshot in mock run")
    client.post("/api/auth/logout", headers=csrf(client))
    client.post("/api/auth/login", json={"username": "v2", "password": "viewer-pass-2"})
    assert client.get(f"/api/web-pages/{page['id']}/screenshot").status_code == 200


def test_missing_screenshot_404(client):
    setup_admin(client)
    assert client.get("/api/web-pages/999999/screenshot").status_code == 404


def test_feature_disabled_blocks_new_jobs(db, client):
    setup_admin(client)
    put_section(db, WebCaptureSettings(enabled=False))
    db.commit()
    r = client.post("/api/web-captures", json={"targets": "10.0.0.1"}, headers=csrf(client))
    assert r.status_code == 409


def test_no_web_endpoints_note(db, client):
    setup_admin(client)
    net = make_network(db, "10.0.0.0/24", name="SshOnly")
    scan(ScriptedScanner([host("10.0.0.9", [port(22, "ssh")])]), network_id=net.id)
    r = client.post("/api/web-captures", json={"targets": "10.0.0.9"}, headers=csrf(client))
    assert r.status_code == 200
    notes = (r.json()["capture"].get("notes") or "").lower()
    assert "no known web" in notes or "no known web or rtsp" in notes or r.json()["capture"]["pages_captured"] == 0


def test_inventory_finds_uncommon_http_port(db):
    net = make_network(db, "10.0.0.0/24", name="OddPort")
    scan(ScriptedScanner([host("10.0.0.12", [port(5601, "http")])]), network_id=net.id)
    endpoints, _ = find_web_endpoints(db, {"10.0.0.12"}, max_endpoints=10)
    assert any(e.port == 5601 for e in endpoints)


def test_retention_removes_captures(db, client):
    setup_admin(client)
    _seed_web_host(db, "10.0.0.6", net_name="RetNet")
    r = client.post("/api/web-captures", json={"targets": "10.0.0.6"}, headers=csrf(client))
    cap_id = r.json()["capture"]["id"]
    cap = db.get(WebCapture, cap_id)
    cap_uuid = cap.uuid
    cap.status = WEB_CAPTURE_COMPLETED
    cap.created_at = utcnow() - timedelta(days=400)
    db.commit()
    run_retention(db, days=30, raw_days=7)
    db.commit()
    db.expire_all()
    assert db.get(WebCapture, cap_id) is None
    assert not (captures_root() / cap_uuid).exists()


def test_scheduler_retention_removes_capture_files(db, client):
    from datetime import datetime

    from app.core.scheduler import tick

    setup_admin(client)
    _seed_web_host(db, "10.0.0.7", net_name="SchedRetNet")
    r = client.post("/api/web-captures", json={"targets": "10.0.0.7"}, headers=csrf(client))
    cap_id = r.json()["capture"]["id"]
    cap = db.get(WebCapture, cap_id)
    cap_uuid = cap.uuid
    cap.status = WEB_CAPTURE_COMPLETED
    cap.created_at = utcnow() - timedelta(days=400)
    db.commit()
    assert (captures_root() / cap_uuid).is_dir()
    orphan = captures_root() / "00000000-0000-4000-8000-000000000000"
    orphan.mkdir()
    tick(datetime(2026, 10, 5, 4, 0).astimezone())  # past 03:15: deletes rows, commits, then cleans files
    db.expire_all()
    assert db.get(WebCapture, cap_id) is None
    assert not (captures_root() / cap_uuid).exists() and not orphan.exists()


def test_http_probes_run_in_parallel_in_endpoint_order(db, client, monkeypatch):
    import threading
    import time

    from app.core.web_capture import runner

    setup_admin(client)
    net = make_network(db, "10.0.0.0/24", name="ParNet")
    ips = [f"10.0.0.{i}" for i in range(20, 26)]
    scan(ScriptedScanner([host(ip, [port(80, "http")]) for ip in ips]), network_id=net.id)
    uuids = [d.uuid for d in db.scalars(select(Device).where(Device.current_ip.in_(ips))).all()]
    lock = threading.Lock()
    state = {"active": 0, "peak": 0}
    real_probe = runner.mock_probe_endpoint

    def slow_probe(*args, **kwargs):
        with lock:
            state["active"] += 1
            state["peak"] = max(state["peak"], state["active"])
        time.sleep(0.05)
        with lock:
            state["active"] -= 1
        return real_probe(*args, **kwargs)

    monkeypatch.setattr(runner, "mock_probe_endpoint", slow_probe)

    def run(concurrency: int):
        state["peak"] = 0
        put_section(db, WebCaptureSettings(http_concurrency=concurrency, auto_after_scan=False))
        db.commit()
        r = client.post("/api/web-captures", json={"device_uuids": uuids}, headers=csrf(client))
        assert r.status_code == 200, r.text
        pages = db.scalars(select(WebPage).where(WebPage.capture_id == r.json()["capture"]["id"])
                           .order_by(WebPage.id)).all()
        return state["peak"], [(p.ip, p.port, p.url, p.title) for p in pages]

    peak_seq, pages_seq = run(1)
    peak_par, pages_par = run(4)
    assert peak_seq == 1 and 1 < peak_par <= 4
    assert len({p[0] for p in pages_seq}) == len(ips)
    assert pages_par == pages_seq  # parallel probing keeps the sequential page order


@pytest.mark.parametrize("status,title,is_error", [
    (200, "Example Portal: Welcome", False),
    (200, "ESXi Login", False),
    (200, "Errors dashboard", False),
    (302, None, False),
    (404, "404 - File or directory not found.", True),
    (503, None, True),
    (401, None, True),
    (None, None, True),
    (200, "Service Unavailable", True),
    (200, "Not Found", True),
    (200, "404 - Page missing", True),
])
def test_error_page_reason(status, title, is_error):
    assert (error_page_reason(status, title) is not None) is is_error


def test_soft_404_body_even_with_hal_title():
    # WildFly/Undertow: HTTP 200, misleading <title>, body is just "404 - Not Found"
    html = "<html><head><title>HAL Management Console</title></head><body>404 - Not Found</body></html>"
    assert error_page_reason(200, "HAL Management Console", html) == "error page (soft 404)"
    assert unusable_page_reason(200, "HAL Management Console", html) == "error page (soft 404)"


def test_soft_404_plain_text_body():
    assert error_page_reason(200, None, body_text="404 - Not Found") == "error page (soft 404)"
    assert unusable_page_reason(200, None, body_text="404 - Not Found") == "error page (soft 404)"


def test_real_hal_console_not_flagged_as_soft_404():
    html = (
        "<html><head><title>HAL Management Console</title></head>"
        "<body><div id=\"hal-root\">Loading management console…</div></body></html>"
    )
    assert unusable_page_reason(200, "HAL Management Console", html) is None


@pytest.mark.parametrize("title,server", [
    ("IIS Windows Server", "IIS"),
    ("Internet Information Services", "IIS"),
    ("Welcome to nginx!", "nginx"),
    ("Apache2 Ubuntu Default Page: It works", "Apache"),
    ("Apache Tomcat/9.0.52", "Tomcat"),
    ("Apache Tomcat (TomEE)/9.0.35 (8.0.2)", "Tomcat"),
    ("Test Page for the HTTP Server on Red Hat Enterprise Linux", "Red Hat"),
    ("Welcome to JBoss EAP 8", "JBoss"),
])
def test_default_server_pages_detected(title, server):
    assert unusable_page_reason(200, title) == f"default server page ({server})"


def test_jboss_welcome_body_detected():
    html = (
        "<html><head><title>Something</title></head><body>"
        "<h1>Welcome to JBoss EAP 8</h1>"
        "<p>Your Red Hat JBoss Enterprise Application Platform is running.</p>"
        "</body></html>"
    )
    assert unusable_page_reason(200, "Something", html) == "default server page (JBoss)"


def test_tomcat_welcome_body_detected():
    html = (
        "<html><head><title>Welcome</title><link rel=\"stylesheet\" href=\"tomcat.css\"></head>"
        "<body><div id=\"wrapper\">"
        "<h1>If you're seeing this, you've successfully installed Tomcat. Congratulations!</h1>"
        "</div></body></html>"
    )
    assert unusable_page_reason(200, "Welcome", html) == "default server page (Tomcat)"


def test_soft_not_found_body_is_unusable():
    assert unusable_page_reason(200, None, body_text="Not Found") == "error page (soft 404)"


def test_stored_title_rematch_without_html():
    """Existing captures keep only title/status - new rules must apply without re-capture."""
    assert unusable_page_reason(200, "Apache Tomcat (TomEE)/9.0.35 (8.0.2)") == "default server page (Tomcat)"
    assert unusable_page_reason(200, "Not Found") is not None
    assert unusable_page_reason(200, "Test Page for the HTTP Server on Red Hat Enterprise Linux") == (
        "default server page (Red Hat)"
    )


@pytest.mark.parametrize("title", ["My Real App", "VMware ESXi", "Acme Portal", "Login", "HAL Management Console"])
def test_real_pages_not_flagged_as_default(title):
    assert unusable_page_reason(200, title) is None


@pytest.mark.parametrize("status", [301, 302, 303, 307, 308])
def test_unresolved_redirect_is_unusable(status):
    # A page left at a 3xx status (destination could not be loaded) is not a screenshot-worthy page.
    assert unusable_page_reason(status, None) == "redirect"


def test_no_response_is_unusable():
    assert unusable_page_reason(None, None) is not None


def test_default_page_from_body_without_title():
    assert default_page_reason(None, "<html><body><h1>It works!</h1></body></html>")


def test_discovery_adds_app_paths_on_top_of_budget():
    base = "http://10.0.0.1/"
    normal = candidate_paths_for_endpoint(base, None, set(), set(), 10, discovery=0)
    extended = candidate_paths_for_endpoint(base, None, set(), set(), 10, discovery=5)
    assert len(extended) == len(normal) + 5
    added = {u for u, _ in extended} - {u for u, _ in normal}
    assert all(u.startswith(base) for u in added)


def test_login_paths_include_admin_variants():
    base = "http://10.0.0.1/"
    # Budget must cover / + LOGIN_PATHS + REGISTER_PATHS (admin paths are always probed).
    out = candidate_paths_for_endpoint(base, None, set(), set(), 40, discovery=0)
    urls = {u for u, _ in out}
    assert "http://10.0.0.1/admin" in urls
    assert "http://10.0.0.1/admin/login" in urls
    kinds = {u: k for u, k in out}
    assert kinds["http://10.0.0.1/admin"] == "login"
    assert kinds["http://10.0.0.1/admin/login"] == "login"


def test_discovery_uses_custom_wordlist():
    base = "http://10.0.0.1/"
    out = candidate_paths_for_endpoint(base, None, set(), set(), 3, discovery=2, app_paths=("/zzz/", "/qqq/"))
    urls = {u for u, _ in out}
    assert "http://10.0.0.1/zzz/" in urls and "http://10.0.0.1/qqq/" in urls


def test_wordlist_loads_normalises_and_dedupes(tmp_path):
    from app.core.web_capture import wordlist

    wordlist._cache.clear()
    f = tmp_path / "paths.txt"
    f.write_text("# comment\nadmin\n/admin\n/app/\n\nhttp://evil/\n../etc\nok path\n", encoding="utf-8")
    out = wordlist.load_wordlist(str(f))
    assert out == ("/admin", "/app/")  # bare+rooted deduped; url/traversal/space rejected


def test_wordlist_missing_file_falls_back_to_builtin():
    from app.core.web_capture import wordlist
    from app.core.web_capture.classify import APP_PATHS

    assert wordlist.load_wordlist("/no/such/file.txt") == ()
    assert wordlist.discovery_paths("/no/such/file.txt") == APP_PATHS


def test_screenshot_served_inline(db, client):
    setup_admin(client)
    _seed_web_host(db, "10.0.0.13", net_name="InlineNet", svc="http", p=80)
    r = client.post("/api/web-captures", json={"targets": "10.0.0.13"}, headers=csrf(client))
    cap = client.get(f"/api/web-captures/{r.json()['capture']['id']}").json()
    page = next((p for p in cap["pages"] if p.get("has_screenshot")), None)
    if not page:
        pytest.skip("no screenshot in mock run")
    res = client.get(f"/api/web-pages/{page['id']}/screenshot")
    assert res.headers["content-disposition"].startswith("inline")


def test_web_hosts_and_device_capture_history(db, client):
    setup_admin(client)
    dev = _seed_web_host(db, "10.0.0.14", net_name="HostNet", svc="https", p=443)
    first = client.post("/api/web-captures", json={"device_uuids": [dev.uuid]}, headers=csrf(client)).json()
    second = client.post("/api/web-captures", json={"device_uuids": [dev.uuid]}, headers=csrf(client)).json()
    first_id, second_id = first["capture"]["id"], second["capture"]["id"]

    hosts = client.get("/api/web-hosts").json()["hosts"]
    h = next(h for h in hosts if h["device_uuid"] == dev.uuid)
    assert h["capture_id"] == second_id
    assert h["ports"] == [443]
    assert h["hero"]["device_uuid"] == dev.uuid

    latest = client.get(f"/api/devices/{dev.uuid}/web-interfaces").json()
    assert latest["capture_id"] == second_id
    assert [c["id"] for c in latest["captures"]] == [second_id, first_id]
    assert all(p["capture_id"] == second_id for p in latest["pages"])

    older = client.get(f"/api/devices/{dev.uuid}/web-interfaces", params={"capture_id": first_id}).json()
    assert older["capture_id"] == first_id and older["pages"]
    assert client.get(f"/api/devices/{dev.uuid}/web-interfaces", params={"capture_id": 999999}).status_code == 404


@pytest.mark.parametrize("html", [
    "",
    "<html><head></head><body></body></html>",
    "<html><head><title>Device</title></head><body>  <div></div> </body></html>",
])
def test_blank_pages_are_unusable(html):
    assert unusable_page_reason(200, None, html) == BLANK_PAGE_REASON


@pytest.mark.parametrize("html", [
    '<html><body><div id="app"></div><script src="/app.js"></script></body></html>',
    '<html><head><meta http-equiv="refresh" content="2; url=/ui/"></head><body></body></html>',
    "<html><frameset><frame src=/top></frameset></html>",
    "<html><body>Welcome</body></html>",
])
def test_pages_that_can_render_are_not_blank(html):
    assert blank_page_reason(html) is None


def test_unknown_content_is_not_blank():
    # html=None means "not HTML / not kept" (e.g. the API re-checking a stored page)
    assert unusable_page_reason(200, None) is None
    assert unusable_page_reason(200, None, body_text='{"ok": true}') is None


@pytest.mark.parametrize("content,expected", [
    ("2; url=/ui/index.html", "http://10.0.0.1/ui/index.html"),
    ("0;URL='login.htm'", "http://10.0.0.1/app/login.htm"),
    ("5", None),
    (None, None),
])
def test_meta_refresh_target(content, expected):
    assert meta_refresh_target(content, "http://10.0.0.1/app/") == expected


def test_web_hosts_lists_every_usable_service(db, client):
    setup_admin(client)
    dev = _seed_web_host(db, "10.0.0.15", net_name="SvcNet", svc="http", p=80)
    cap = WebCapture(status=WEB_CAPTURE_COMPLETED, targets="10.0.0.15")
    db.add(cap)
    db.flush()

    def page(port, scheme, *, url=None, final=None, status=200, title=None, kind="home", shot=True, err=None):
        base = f"{scheme}://10.0.0.15:{port}/"
        db.add(WebPage(
            capture_id=cap.id, device_id=dev.id, ip="10.0.0.15", port=port, scheme=scheme,
            host_used="10.0.0.15", kind=kind, url=url or base, final_url=final or url or base,
            http_status=status, title=title, screenshot_status="captured" if shot else "skipped",
            screenshot_relpath=f"{cap.uuid}/x.webp" if shot else None, capture_error=err,
        ))

    page(80, "http", final="https://10.0.0.15:443/", title="Portal")  # lands on the 443 page
    page(443, "https", title="Portal")
    page(8080, "http", title="Build server")
    page(8080, "http", url="http://10.0.0.15:8080/login", title="Sign in", kind="login")
    page(8000, "http", status=404, title="Not Found", shot=False)
    page(9000, "http", shot=False, err=BLANK_PAGE_REASON)
    db.commit()

    h = next(h for h in client.get("/api/web-hosts").json()["hosts"] if h["device_uuid"] == dev.uuid)
    svcs = {s["port"]: s for s in h["services"]}
    assert set(svcs) == {443, 8080}
    assert svcs[443]["ports"] == [80, 443]
    assert svcs[8080]["page_count"] == 2 and svcs[8080]["has_login"]


def test_web_hosts_separates_remote_desktops(db, client):
    setup_admin(client)
    dev = _seed_web_host(db, "10.0.0.16", net_name="DeskNet", svc="http", p=80)
    cap = WebCapture(status=WEB_CAPTURE_COMPLETED, targets="10.0.0.16")
    db.add(cap)
    db.flush()
    db.add(WebPage(
        capture_id=cap.id, device_id=dev.id, ip="10.0.0.16", port=80, scheme="http",
        host_used="10.0.0.16", kind="home", url="http://10.0.0.16/", final_url="http://10.0.0.16/",
        http_status=200, title="Portal", screenshot_status="captured",
        screenshot_relpath=f"{cap.uuid}/http.webp",
    ))
    db.add(WebPage(
        capture_id=cap.id, device_id=dev.id, ip="10.0.0.16", port=3389, scheme="rdp",
        host_used="10.0.0.16", kind="stream", url="rdp://10.0.0.16:3389", final_url="rdp://10.0.0.16:3389",
        http_status=None, title="RDP desktop", screenshot_status="skipped",
        capture_error="freerdp unavailable",
    ))
    db.add(WebPage(
        capture_id=cap.id, device_id=dev.id, ip="10.0.0.16", port=5900, scheme="vnc",
        host_used="10.0.0.16", kind="stream", url="vnc://10.0.0.16:5900", final_url="vnc://10.0.0.16:5900",
        http_status=None, title="VNC desktop", screenshot_status="skipped",
        capture_error="vnc tools unavailable",
    ))
    db.commit()

    web = next(h for h in client.get("/api/web-hosts", params={"kind": "web"}).json()["hosts"]
               if h["device_uuid"] == dev.uuid)
    assert {s["port"] for s in web["services"]} == {80}
    assert all(s["scheme"] == "http" for s in web["services"])

    remote = next(h for h in client.get("/api/web-hosts", params={"kind": "remote"}).json()["hosts"]
                  if h["device_uuid"] == dev.uuid)
    assert {s["port"] for s in remote["services"]} == {3389, 5900}
    assert {s["scheme"] for s in remote["services"]} == {"rdp", "vnc"}
    rdp_page = next(s["page"] for s in remote["services"] if s["scheme"] == "rdp")
    assert rdp_page["can_live"] is False
    assert rdp_page["error_reason"] is None


def test_auto_web_capture_after_scan_for_new_web_host(db):
    put_section(db, WebCaptureSettings(enabled=True, auto_after_scan=True, auto_only_new_or_changed=True,
                                       force_mock=True))
    db.commit()
    net = make_network(db, "10.0.0.0/24", name="AutoCap")
    s = scan(ScriptedScanner([host("10.0.0.50", [port(443, "https")])]), network_id=net.id)
    assert s.status == "completed"
    jobs = list(db.scalars(select(WebCapture).order_by(WebCapture.id)).all())
    assert len(jobs) == 1
    assert jobs[0].requested_by == "auto-scan"
    assert "10.0.0.50" in jobs[0].targets


def test_auto_web_capture_skips_when_disabled(db):
    put_section(db, WebCaptureSettings(enabled=True, auto_after_scan=False, force_mock=True))
    db.commit()
    net = make_network(db, "10.0.0.0/24", name="NoAuto")
    scan(ScriptedScanner([host("10.0.0.51", [port(80, "http")])]), network_id=net.id)
    assert db.scalar(select(func.count(WebCapture.id))) == 0


def test_auto_web_capture_skips_unchanged_hosts(db):
    put_section(db, WebCaptureSettings(enabled=True, auto_after_scan=True, auto_only_new_or_changed=True,
                                       force_mock=True))
    db.commit()
    net = make_network(db, "10.0.0.0/24", name="StableWeb")
    hosts = [host("10.0.0.52", [port(443, "https")])]
    scan(ScriptedScanner(hosts), network_id=net.id)
    assert db.scalar(select(func.count(WebCapture.id))) == 1
    # Simulate a finished capture so the endpoint is no longer "never captured"
    job = db.scalar(select(WebCapture))
    job.status = WEB_CAPTURE_COMPLETED
    dev = db.scalar(select(Device).where(Device.current_ip == "10.0.0.52"))
    port_id = next(p.id for p in dev.ports if p.port == 443)
    db.add(WebPage(
        capture_id=job.id, device_id=dev.id, device_port_id=port_id, ip="10.0.0.52", port=443,
        scheme="https", host_used="10.0.0.52", kind="home", url="https://10.0.0.52/",
        screenshot_status="captured",
    ))
    db.commit()
    scan(ScriptedScanner(hosts), network_id=net.id)
    assert db.scalar(select(func.count(WebCapture.id))) == 1  # unchanged inventory: no second job


def test_grab_rdp_frame_tries_tls_first_for_logon_screen(monkeypatch, tmp_path):
    """Shodan-style: /sec:tls + empty creds can yield a pre-auth logon bitmap."""
    from io import BytesIO
    from pathlib import Path

    from PIL import Image

    from app.core.web_capture import rdp as rdp_mod

    calls: list[list[str]] = []

    def fake_run(exe: str, args: list[str], *, timeout: float):
        calls.append(list(args))
        shot = next(a for a in args if a.startswith("/screenshot:"))
        path = Path(shot.split(":", 1)[1])
        buf = BytesIO()
        Image.new("RGB", (64, 48), (30, 40, 50)).save(buf, format="BMP")
        path.write_bytes(buf.getvalue())
        return 0, ""

    monkeypatch.setattr(rdp_mod, "_freerdp_bin", lambda: "wfreerdp")
    monkeypatch.setattr(rdp_mod, "_run_freerdp", fake_run)
    shot = rdp_mod.grab_rdp_frame("10.0.0.205", 3389)
    assert shot.status == "captured"
    assert shot.data
    assert calls and "/sec:tls" in calls[0]


def test_grab_rdp_frame_nla_required_is_skipped_auth(monkeypatch):
    from app.core.web_capture import rdp as rdp_mod

    def fake_run(exe: str, args: list[str], *, timeout: float):
        return 1, "ERRCONNECT_AUTHENTICATION_FAILED nla credssp"

    monkeypatch.setattr(rdp_mod, "_freerdp_bin", lambda: "wfreerdp")
    monkeypatch.setattr(rdp_mod, "_run_freerdp", fake_run)
    shot = rdp_mod.grab_rdp_frame("10.0.0.205", 3389)
    assert shot.status == "skipped"
    assert shot.auth_required is True
    assert shot.error == "skipped_auth"


def test_inventory_remote_capture_scope(db, client):
    """Remote-page Recapture: inventory=true queues RDP/VNC-only stills."""
    from app.models import Network

    setup_admin(client)
    put_section(db, WebCaptureSettings(enabled=True, force_mock=True))
    db.commit()
    net = make_network(db, "10.0.0.0/24", name="RemoteInv")
    scan(
        ScriptedScanner([
            host("10.0.0.40", [port(3389, "ms-wbt-server"), port(443, "https")]),
            host("10.0.0.41", [port(5900, "vnc")]),
        ]),
        network_id=net.id,
    )
    assert db.scalar(select(Network).where(Network.name == "RemoteInv")) is not None

    r = client.post(
        "/api/web-captures",
        json={"inventory": True, "scope": "remote"},
        headers=csrf(client),
    )
    assert r.status_code == 200, r.text
    cap = r.json()["capture"]
    assert cap["scope"] == "remote"
    assert cap["status"] in ("completed", "partial")
    detail = client.get(f"/api/web-captures/{cap['id']}").json()
    schemes = {p["scheme"] for p in detail["pages"]}
    assert schemes <= {"rdp", "vnc"}
    assert "https" not in schemes
    assert "rdp" in schemes and "vnc" in schemes
