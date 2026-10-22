"""End-to-end smoke test: the built UI served by the real app, driven in headless Chromium.

Covers sign-in -> dashboard -> devices list against a uvicorn subprocess (development mode, mock
scanner, throwaway SQLite database). Marked `e2e` and excluded from the default `npm test`; run it
with `npm run test:e2e`, which builds the frontend first. Skips when frontend/dist or Playwright's
Chromium is missing.
"""
from __future__ import annotations

import os
import re
import socket
import subprocess
import sys
import time
import urllib.request
from collections.abc import Iterator
from pathlib import Path

import pytest

pytestmark = pytest.mark.e2e

BACKEND = Path(__file__).resolve().parents[1]
DIST = BACKEND.parent / "frontend" / "dist"
PASSWORD = "e2e-smoke-pass-1"
START_TIMEOUT_S = 60


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _wait_healthy(base: str, proc: subprocess.Popen) -> None:
    deadline = time.monotonic() + START_TIMEOUT_S
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            raise RuntimeError(f"app exited during startup (code {proc.returncode})")
        try:
            with urllib.request.urlopen(f"{base}/api/health", timeout=2) as r:
                if r.status == 200:
                    return
        except OSError:
            time.sleep(0.3)
    raise RuntimeError(f"app not healthy after {START_TIMEOUT_S}s")


@pytest.fixture(scope="module")
def live_app_env(tmp_path_factory) -> Iterator[dict]:
    if not (DIST / "index.html").is_file():
        pytest.skip("frontend/dist is missing; run `npm run build` (npm run test:e2e does)")
    work = tmp_path_factory.mktemp("e2e")
    port = _free_port()
    db_url = f"sqlite:///{(work / 'e2e.db').as_posix()}"
    env = {
        **os.environ,
        "APP_ENV": "development",
        "DEV_SEED": "true",  # admin user, demo network, setup completed, one mock scan queued
        "DEV_ADMIN_USERNAME": "admin",
        "DEV_ADMIN_PASSWORD": PASSWORD,
        "SCANNER_MODE": "mock",
        "MOCK_SCAN_DELAY": "0",
        "BACKGROUND_JOBS": "true",
        "DATABASE_URL": db_url,
        "DATA_DIR": str(work / "data"),
        "FRONTEND_DIST": str(DIST),
        "LOG_LEVEL": "WARNING",
    }
    env.pop("PORTREVEAL_STOP_FILE", None)
    env.pop("NETWORK_FINDER_STOP_FILE", None)
    log = (work / "app.log").open("wb")
    proc = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "app.main:app", "--host", "127.0.0.1", "--port", str(port)],
        cwd=BACKEND, env=env, stdout=log, stderr=subprocess.STDOUT,
    )
    base = f"http://127.0.0.1:{port}"
    try:
        _wait_healthy(base, proc)
        yield {"base": base, "db_url": db_url}
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=15)
        except subprocess.TimeoutExpired:
            proc.kill()
        log.close()


@pytest.fixture(scope="module")
def live_app(live_app_env) -> str:
    return live_app_env["base"]


@pytest.fixture(scope="module")
def browser():
    sync_api = pytest.importorskip("playwright.sync_api")
    with sync_api.sync_playwright() as p:
        try:
            b = p.chromium.launch(headless=True)
        except Exception as exc:  # browser binary not installed for this user
            pytest.skip(f"Playwright Chromium unavailable ({exc.__class__.__name__}); "
                        "run: python -m playwright install chromium")
        yield b
        b.close()


def _sign_in(page, live_app: str) -> None:
    page.goto(live_app)
    page.get_by_label("Username").fill("admin")
    page.get_by_label("Password").fill(PASSWORD)
    page.get_by_role("button", name="Sign in").click()


def _seed_vuln_networks(db_url: str) -> tuple[str, str]:
    """Insert two placeholder networks with one finding each into the live e2e DB.

    Returns the display names (Lab Alpha / Lab Beta) for UI assertions.
    """
    from sqlalchemy import create_engine, select
    from sqlalchemy.orm import Session

    from app.core.vuln.lifecycle import sync_finding_lifecycle
    from app.db import utcnow
    from app.models import (
        VULN_STATE_CONFIRMED,
        Device,
        DevicePort,
        DevicePortVuln,
        Network,
        Vulnerability,
    )

    name_a, name_b = "Lab Alpha", "Lab Beta"
    engine = create_engine(db_url, connect_args={"check_same_thread": False})
    with Session(engine) as db:
        # Reuse Mock Lab devices from DEV_SEED when present; otherwise create lean stubs.
        net_a = db.scalar(select(Network).where(Network.name == name_a))
        if net_a is None:
            net_a = Network(name=name_a, cidr="10.10.0.0/24", description="E2E placeholder")
            db.add(net_a)
            db.flush()
        net_b = db.scalar(select(Network).where(Network.name == name_b))
        if net_b is None:
            net_b = Network(name=name_b, cidr="10.20.0.0/24", description="E2E placeholder")
            db.add(net_b)
            db.flush()

        def ensure_device(ip: str, network_id: int, mac: str, port_n: int, service: str) -> DevicePort:
            d = db.scalar(select(Device).where(Device.current_ip == ip))
            if d is None:
                import uuid as _uuid

                from app.models import DEVICE_ACTIVE
                d = Device(
                    uuid=str(_uuid.uuid4()),
                    current_ip=ip,
                    mac=mac,
                    network_id=network_id,
                    status=DEVICE_ACTIVE,
                    first_seen=utcnow(),
                    last_seen=utcnow(),
                )
                db.add(d)
                db.flush()
            else:
                d.network_id = network_id
            p = next((pp for pp in d.ports if pp.port == port_n), None)
            if p is None:
                p = DevicePort(
                    device_id=d.id, port=port_n, protocol="tcp", service=service,
                    is_open=True, first_seen=utcnow(), last_seen=utcnow(),
                )
                db.add(p)
                db.flush()
            return p

        pa = ensure_device("10.10.0.1", net_a.id, "00:11:22:33:10:01", 22, "ssh")
        pb = ensure_device("10.20.0.1", net_b.id, "00:11:22:33:20:01", 80, "http")
        if db.get(Vulnerability, "CVE-2024-ALPHA") is None:
            db.add(Vulnerability(cve_id="CVE-2024-ALPHA", cvss_base=9.8, kev=True, epss=0.9,
                                 summary="E2E critical placeholder"))
        if db.get(Vulnerability, "CVE-2024-BETA") is None:
            db.add(Vulnerability(cve_id="CVE-2024-BETA", cvss_base=5.0, kev=False, epss=0.01,
                                 summary="E2E medium placeholder"))
        db.flush()
        if not db.scalar(select(DevicePortVuln).where(
            DevicePortVuln.device_port_id == pa.id, DevicePortVuln.cve_id == "CVE-2024-ALPHA",
        )):
            db.add(DevicePortVuln(device_port_id=pa.id, cve_id="CVE-2024-ALPHA",
                                  state=VULN_STATE_CONFIRMED, matched_at=utcnow()))
        if not db.scalar(select(DevicePortVuln).where(
            DevicePortVuln.device_port_id == pb.id, DevicePortVuln.cve_id == "CVE-2024-BETA",
        )):
            db.add(DevicePortVuln(device_port_id=pb.id, cve_id="CVE-2024-BETA",
                                  state=VULN_STATE_CONFIRMED, matched_at=utcnow()))
        db.commit()
        sync_finding_lifecycle(db, now=utcnow())
        db.commit()
    engine.dispose()
    return name_a, name_b


def test_sign_in_dashboard_and_devices_list(live_app, browser):
    from playwright.sync_api import expect

    page = browser.new_page()
    errors: list[str] = []
    page.on("pageerror", lambda exc: errors.append(str(exc)))
    try:
        _sign_in(page, live_app)

        expect(page.get_by_role("heading", name="Network overview")).to_be_visible(timeout=15_000)

        page.get_by_role("link", name="Devices", exact=True).click()
        expect(page).to_have_url(f"{live_app}/devices")
        expect(page.get_by_role("heading", name="Devices", exact=True)).to_be_visible()
        # The seeded mock scan runs in the background; its hosts (10.99.0.0/24) fill the list.
        expect(page.locator("tbody tr").filter(has_text="10.99.0.").first).to_be_visible(timeout=30_000)
        expect(page.locator("a.active", has_text="Devices")).to_have_attribute("aria-current", "page")
    finally:
        page.close()
    assert errors == []


def test_dashboard_layout_resize_save_and_reload(live_app, browser):
    """Customize → resize a card → Save → reload → layout still applied."""
    from playwright.sync_api import expect

    # 1600px so the grid content width stays at the lg breakpoint (≥1200); 1400 leaves
    # ~1118px of grid and saves into layouts.md after breakpointFor landed.
    page = browser.new_page(viewport={"width": 1600, "height": 900})
    errors: list[str] = []
    page.on("pageerror", lambda exc: errors.append(str(exc)))
    try:
        _sign_in(page, live_app)
        expect(page.get_by_role("heading", name="Network overview")).to_be_visible(timeout=15_000)
        expect(page.locator(".dashboard-rgl")).to_be_visible(timeout=15_000)

        page.get_by_role("button", name="Customize layout").click()
        expect(page.get_by_role("button", name="Done")).to_be_visible()

        card = page.locator('[data-grid-id="recent_changes"]')
        expect(card).to_be_visible()
        handle = card.locator(".react-resizable-handle-se")
        expect(handle).to_be_visible()
        # Edit bar / tall cards can push the SE handle below the viewport; mouse.drag needs
        # on-screen coordinates even when Playwright still considers the handle "visible".
        handle.scroll_into_view_if_needed()
        box = handle.bounding_box()
        assert box is not None
        page.mouse.move(box["x"] + box["width"] / 2, box["y"] + box["height"] / 2)
        page.mouse.down()
        # Grow height and width past the default (w=14, h=26).
        page.mouse.move(box["x"] + 180, box["y"] + 220, steps=12)
        page.mouse.up()

        # Dirty tracking: Save appears only after a real resize.
        expect(page.get_by_role("button", name="Save layout")).to_be_visible(timeout=5_000)
        page.get_by_role("button", name="Save layout").click()
        expect(page.get_by_text("Layout saved", exact=True)).to_be_visible(timeout=10_000)

        prefs = page.evaluate(
            """async () => {
              const r = await fetch('/api/auth/me', { credentials: 'same-origin' });
              const body = await r.json();
              return body.user && body.user.preferences;
            }"""
        )
        assert prefs and prefs.get("dashboard"), prefs
        recent = next(it for it in prefs["dashboard"]["layouts"]["lg"] if it["i"] == "recent_changes")
        assert recent["h"] > 26 or recent["w"] > 14, recent

        page.reload()
        expect(page.get_by_role("heading", name="Network overview")).to_be_visible(timeout=15_000)
        prefs2 = page.evaluate(
            """async () => {
              const r = await fetch('/api/auth/me', { credentials: 'same-origin' });
              const body = await r.json();
              return body.user && body.user.preferences;
            }"""
        )
        recent2 = next(it for it in prefs2["dashboard"]["layouts"]["lg"] if it["i"] == "recent_changes")
        assert recent2 == recent
    finally:
        page.close()
    assert errors == []


def test_vulnerabilities_network_facet_export_and_print(live_app_env, browser):
    """Click a network facet row → filter; CSV only that network; print view shows filter summary."""
    from playwright.sync_api import expect

    from app.core.vuln.summary import invalidate_vuln_summary_cache

    name_a, name_b = _seed_vuln_networks(live_app_env["db_url"])
    # Test-process cache clear is a no-op for the uvicorn worker; dismiss/undo below busts it.
    invalidate_vuln_summary_cache()
    base = live_app_env["base"]

    page = browser.new_page()
    errors: list[str] = []
    page.on("pageerror", lambda exc: errors.append(str(exc)))
    try:
        _sign_in(page, base)
        expect(page.get_by_role("heading", name="Network overview")).to_be_visible(timeout=15_000)

        # Invalidate the app-process summary cache so seeded findings appear in facets.
        page.evaluate(
            """async () => {
              const list = await fetch('/api/vulns?cve_id=CVE-2024-ALPHA', { credentials: 'same-origin' })
                .then((r) => r.json());
              if (!list.items || !list.items.length) return;
              const d = list.items[0];
              const m = document.cookie.match(/(?:^|;\\s*)nf_csrf=([^;]+)/);
              const csrf = m ? decodeURIComponent(m[1]) : '';
              const hdr = { 'X-CSRF-Token': csrf, 'Content-Type': 'application/json' };
              await fetch(`/api/devices/${d.device_uuid}/vulns/${encodeURIComponent(d.cve_id)}/dismiss`,
                { method: 'POST', credentials: 'same-origin', headers: hdr, body: '{}' });
              await fetch(`/api/devices/${d.device_uuid}/vulns/${encodeURIComponent(d.cve_id)}/dismiss`,
                { method: 'DELETE', credentials: 'same-origin', headers: { 'X-CSRF-Token': csrf } });
            }"""
        )

        page.get_by_role("link", name="Vulnerabilities", exact=True).click()
        expect(page.get_by_role("heading", name="Vulnerabilities", exact=True)).to_be_visible(timeout=15_000)

        facet_btn = page.locator(".bar-row", has_text=name_a).first
        expect(facet_btn).to_be_visible(timeout=30_000)
        facet_btn.click()
        expect(page).to_have_url(re.compile(r"network_id="), timeout=10_000)
        expect(page.get_by_role("button", name=re.compile(rf"network:\s*{re.escape(name_a)}"))).to_be_visible(
            timeout=10_000
        )

        # Export CSV for the active network filter; verify only Lab Alpha rows.
        with page.expect_download() as dl_info:
            page.get_by_role("button", name="Export CSV").click()
        download = dl_info.value
        path = download.path()
        assert path is not None
        raw = Path(path).read_bytes()
        assert raw.startswith(b"\xef\xbb\xbf")
        text = raw.decode("utf-8-sig")
        assert "CVE-2024-ALPHA" in text
        assert "CVE-2024-BETA" not in text
        assert name_a in text or "10.10.0.1" in text
        assert name_b not in text

        # Print report: load findings into the print-only block and assert filter summary.
        page.evaluate("() => { window.__pr_print_calls = 0; window.print = () => { window.__pr_print_calls++; }; }")
        page.get_by_role("button", name="Print / PDF report").click()
        page.wait_for_function("() => window.__pr_print_calls > 0", timeout=15_000)
        report = page.locator(".vuln-print-report")
        # Force print stylesheet visibility for assertion without an actual print dialog.
        page.add_style_tag(content=".vuln-print-report { display: block !important; }")
        expect(report.locator(".vuln-print-filters")).to_contain_text(f"network: {name_a}", timeout=10_000)
        expect(report.get_by_role("heading", name="PortReveal vulnerability report")).to_be_visible()
    finally:
        page.close()
    assert errors == []
