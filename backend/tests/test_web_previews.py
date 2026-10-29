"""Web gallery API: server-side paging and filters, grid thumbnails with cache headers, and capture
limits (failed / slow sites become "unavailable" cards; probes run on a bounded pool)."""
from __future__ import annotations

import threading
import time
import uuid as _uuid
from io import BytesIO

import httpx
import pytest
from fastapi.testclient import TestClient
from PIL import Image
from sqlalchemy import select

from app.core.web_capture import runner
from app.core.web_capture.classify import UNAVAILABLE_PREFIX
from app.core.web_storage import THUMB_WIDTH, captures_root, screenshot_relpath, write_screenshot
from app.db import utcnow
from app.main import app
from app.models import DEVICE_ACTIVE, WEB_CAPTURE_COMPLETED, Device, WebCapture, WebPage
from app.settings_store import WebCaptureSettings, put_section
from tests.helpers import ScriptedScanner, host, make_network, port, scan
from tests.test_api import csrf, setup_admin


@pytest.fixture
def client(db_env):
    from app.api.auth import limiter

    limiter.reset()
    with TestClient(app) as c:
        yield c


def _png(width: int = 1280, height: int = 720) -> bytes:
    out = BytesIO()
    Image.new("RGB", (width, height), (40, 90, 160)).save(out, format="PNG")
    return out.getvalue()


SHOT = _png()


def _device(db, ip: str, network_id: int, hostname: str | None = None) -> Device:
    d = Device(uuid=str(_uuid.uuid4()), current_ip=ip, hostname=hostname, network_id=network_id,
               status=DEVICE_ACTIVE, first_seen=utcnow(), last_seen=utcnow())
    db.add(d)
    db.flush()
    return d


def _page(db, cap: WebCapture, dev: Device, *, scheme="https", port_n=443, status="ok", title="Portal"):
    """status: ok = real page with a screenshot file; no_preview = real page, screenshot timed out;
    error = 404 page."""
    page_uuid = str(_uuid.uuid4())
    url = f"{scheme}://{dev.current_ip}:{port_n}/"
    row = WebPage(uuid=page_uuid, capture_id=cap.id, device_id=dev.id, ip=dev.current_ip, port=port_n,
                  scheme=scheme, host_used=dev.current_ip, kind="home", url=url, final_url=url,
                  http_status=404 if status == "error" else 200, title="Not Found" if status == "error" else title,
                  screenshot_status="skipped")
    if status == "ok":
        row.screenshot_relpath = write_screenshot(cap.uuid, page_uuid, SHOT)
        row.screenshot_status = "captured"
    elif status == "no_preview":
        row.screenshot_status = "failed"
        row.capture_error = "Timeout 15000ms exceeded"
    db.add(row)
    db.flush()
    return row


def _capture(db) -> WebCapture:
    cap = WebCapture(status=WEB_CAPTURE_COMPLETED, targets="10.0.0.0/24")
    db.add(cap)
    db.flush()
    return cap


def _keys(r) -> set[str]:
    assert r.status_code == 200, r.text
    return {c["ip"] for c in r.json()["items"]}


def test_previews_are_paged_36_by_default(db, client):
    setup_admin(client)
    net = make_network(db, "10.0.0.0/24", name="Test Network A")
    cap = _capture(db)
    for i in range(40):
        _page(db, cap, _device(db, f"10.0.0.{10 + i}", net.id), status="error")  # no files needed
    db.commit()

    first = client.get("/api/web-previews").json()
    assert first["total"] == 40 and first["page_size"] == 36 and len(first["items"]) == 36
    second = client.get("/api/web-previews", params={"page": 2}).json()
    assert len(second["items"]) == 4
    assert not {c["key"] for c in first["items"]} & {c["key"] for c in second["items"]}
    assert client.get("/api/web-previews", params={"page_size": 201}).status_code == 422


def test_preview_filters(db, client):
    setup_admin(client)
    net_a = make_network(db, "10.0.0.0/24", name="Test Network A")
    net_b = make_network(db, "10.0.1.0/24", name="Test Network B")
    cap = _capture(db)
    _page(db, cap, _device(db, "10.0.0.10", net_a.id, "host-a.example.test"), title="Alpha console")
    _page(db, cap, _device(db, "10.0.0.11", net_a.id, "host-b.example.test"), scheme="http", port_n=8080,
          status="no_preview", title="Build server")
    _page(db, cap, _device(db, "10.0.1.12", net_b.id), scheme="http", port_n=80, status="error")
    db.commit()

    everything = client.get("/api/web-previews").json()
    assert [c["status"] for c in everything["items"]] == ["ok", "no_preview", "error"]  # previews first
    assert everything["counts"] == {"ok": 1, "no_preview": 1, "error": 1}
    assert _keys(client.get("/api/web-previews", params={"network_id": net_a.id})) == {"10.0.0.10", "10.0.0.11"}
    assert _keys(client.get("/api/web-previews", params={"port": 8080})) == {"10.0.0.11"}
    assert _keys(client.get("/api/web-previews", params={"scheme": "https"})) == {"10.0.0.10"}
    assert _keys(client.get("/api/web-previews", params={"scheme": "http"})) == {"10.0.0.11", "10.0.1.12"}
    assert _keys(client.get("/api/web-previews", params={"status": "ok"})) == {"10.0.0.10"}
    assert _keys(client.get("/api/web-previews", params={"status": "no_preview"})) == {"10.0.0.11"}
    assert _keys(client.get("/api/web-previews", params={"status": "error"})) == {"10.0.1.12"}
    assert _keys(client.get("/api/web-previews", params={"q": "ALPHA"})) == {"10.0.0.10"}  # title
    assert _keys(client.get("/api/web-previews", params={"q": "host-b"})) == {"10.0.0.11"}  # hostname
    assert _keys(client.get("/api/web-previews", params={"q": "10.0.1.12"})) == {"10.0.1.12"}  # IP
    # Status counts follow the other filters
    counts = client.get("/api/web-previews", params={"network_id": net_a.id, "status": "ok"}).json()["counts"]
    assert counts == {"ok": 1, "no_preview": 1, "error": 0}
    assert client.get("/api/web-previews", params={"scheme": "ftp"}).status_code == 422


def test_thumbnail_is_small_webp_with_cache_headers(db, client):
    setup_admin(client)
    net = make_network(db, "10.0.0.0/24", name="Test Network A")
    cap = _capture(db)
    page = _page(db, cap, _device(db, "10.0.0.10", net.id, "host-a.example.test"))
    db.commit()

    r = client.get(f"/api/web-pages/{page.id}/thumbnail")
    assert r.status_code == 200
    assert r.headers["content-type"] == "image/webp"
    assert "max-age" in r.headers["cache-control"]
    etag = r.headers["etag"]
    with Image.open(BytesIO(r.content)) as img:
        assert img.format == "WEBP" and img.width == THUMB_WIDTH
    assert client.get(f"/api/web-pages/{page.id}/thumbnail", headers={"If-None-Match": etag}).status_code == 304

    full = client.get(f"/api/web-pages/{page.id}/screenshot")
    assert full.status_code == 200 and full.headers["etag"] != etag
    assert len(full.content) > len(r.content)
    assert client.get(f"/api/web-pages/{page.id}/screenshot",
                      headers={"If-None-Match": full.headers["etag"]}).status_code == 304


def test_thumbnail_built_once_for_older_screenshots(db, client):
    setup_admin(client)
    net = make_network(db, "10.0.0.0/24", name="Test Network A")
    cap = _capture(db)
    page = _page(db, cap, _device(db, "10.0.0.10", net.id), status="error")
    # A screenshot written before thumbnails existed: full image only.
    rel = screenshot_relpath(cap.uuid, page.uuid)
    (captures_root() / cap.uuid).mkdir(parents=True, exist_ok=True)
    (captures_root() / rel).write_bytes(SHOT)
    page.screenshot_relpath, page.screenshot_status = rel, "captured"
    db.commit()
    thumb_file = captures_root() / cap.uuid / f"{page.uuid}.thumb.webp"
    assert not thumb_file.exists()

    assert client.get(f"/api/web-pages/{page.id}/thumbnail").status_code == 200
    assert thumb_file.is_file()
    assert client.get("/api/web-pages/999999/thumbnail").status_code == 404


def test_timed_out_site_becomes_unavailable_card(db, client, monkeypatch):
    setup_admin(client)
    put_section(db, WebCaptureSettings(auto_after_scan=False))
    db.commit()
    net = make_network(db, "10.0.0.0/24", name="Test Network A")
    scan(ScriptedScanner([host("10.0.0.30", [port(80, "http")]), host("10.0.0.31", [port(80, "http")])]),
         network_id=net.id)
    real_probe = runner.mock_probe_endpoint

    def probe(scheme, host_used, port_n, ip):
        if ip == "10.0.0.30":
            raise httpx.ReadTimeout("")
        return real_probe(scheme, host_used, port_n, ip)

    monkeypatch.setattr(runner, "mock_probe_endpoint", probe)
    uuids = [d.uuid for d in db.scalars(select(Device).where(Device.network_id == net.id)).all()]
    r = client.post("/api/web-captures", json={"device_uuids": uuids}, headers=csrf(client))
    assert r.status_code == 200, r.text
    assert r.json()["capture"]["status"] in ("completed", "partial")  # the slow site did not block the job

    cards = {c["ip"]: c for c in client.get("/api/web-previews").json()["items"]}
    slow = cards["10.0.0.30"]
    assert slow["status"] == "error"
    assert slow["page"]["capture_error"] == UNAVAILABLE_PREFIX + "ReadTimeout"
    assert slow["page"]["http_status"] is None
    assert "10.0.0.31" in cards and cards["10.0.0.31"]["status"] != "error"


def test_unavailable_endpoint_is_retried_after_the_next_scan(db, client, monkeypatch):
    from app.core.web_capture.auto import _candidate_ips

    setup_admin(client)
    put_section(db, WebCaptureSettings(auto_after_scan=False))
    db.commit()
    net = make_network(db, "10.0.0.0/24", name="Test Network A")
    scanner = ScriptedScanner([host("10.0.0.30", [port(80, "http")])])
    scan(scanner, network_id=net.id)

    def probe(*_args):
        raise httpx.ConnectTimeout("")

    monkeypatch.setattr(runner, "mock_probe_endpoint", probe)
    dev = db.scalar(select(Device).where(Device.current_ip == "10.0.0.30"))
    assert client.post("/api/web-captures", json={"device_uuids": [dev.uuid]}, headers=csrf(client)).status_code == 200
    rescan = scan(scanner, network_id=net.id)  # nothing changed on the host
    cfg = WebCaptureSettings(auto_only_new_or_changed=True)
    db.expire_all()
    assert "10.0.0.30" in _candidate_ips(db, rescan, cfg, baseline_created=False)


def test_probe_concurrency_is_bounded_by_default(db, client, monkeypatch):
    setup_admin(client)
    put_section(db, WebCaptureSettings(auto_after_scan=False))
    db.commit()
    limit = WebCaptureSettings().http_concurrency
    net = make_network(db, "10.0.0.0/24", name="Test Network A")
    ips = [f"10.0.0.{i}" for i in range(40, 52)]
    scan(ScriptedScanner([host(ip, [port(80, "http")]) for ip in ips]), network_id=net.id)
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
    uuids = [d.uuid for d in db.scalars(select(Device).where(Device.current_ip.in_(ips))).all()]
    assert client.post("/api/web-captures", json={"device_uuids": uuids}, headers=csrf(client)).status_code == 200
    assert 1 < state["peak"] <= limit


def test_screenshot_paths_stay_inside_the_captures_dir(db_env, tmp_path):
    from app.core.web_storage import resolve_screenshot

    cap, page = str(_uuid.uuid4()), str(_uuid.uuid4())
    write_screenshot(cap, page, SHOT)
    assert resolve_screenshot(f"{cap}/{page}.webp") is not None
    for bad in (f"../{cap}/{page}.webp", f"{cap}/../{page}.webp", f"/{cap}/{page}.webp", f"{cap}/{page}.png",
                f"{cap}/x.webp", f"{cap}/{page}.thumb.webp"):
        assert resolve_screenshot(bad) is None, bad
    outside = tmp_path / "outside.webp"
    outside.write_bytes(SHOT)
    linked_page, linked_cap = str(_uuid.uuid4()), str(_uuid.uuid4())
    try:
        (captures_root() / cap / f"{linked_page}.webp").symlink_to(outside)
        (captures_root() / linked_cap).symlink_to(tmp_path, target_is_directory=True)
    except OSError:
        pytest.skip("creating symlinks needs extra rights on this system")
    (tmp_path / f"{page}.webp").write_bytes(SHOT)
    assert resolve_screenshot(f"{cap}/{linked_page}.webp") is None
    assert resolve_screenshot(f"{linked_cap}/{page}.webp") is None
