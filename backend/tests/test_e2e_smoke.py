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
def live_app(tmp_path_factory) -> Iterator[dict]:
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
        cwd=BACKEND,
        env=env,
        stdout=log,
        stderr=subprocess.STDOUT,
    )
    base = f"http://127.0.0.1:{port}"
    try:
        _wait_healthy(base, proc)
        yield {"base": base, "database_url": db_url}
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=15)
        except subprocess.TimeoutExpired:
            proc.kill()
        log.close()


@pytest.fixture(scope="module")
def browser():
    sync_api = pytest.importorskip("playwright.sync_api")
    with sync_api.sync_playwright() as p:
        try:
            b = p.chromium.launch(headless=True)
        except Exception as exc:  # browser binary not installed for this user
            pytest.skip(f"Playwright Chromium unavailable ({exc.__class__.__name__}); run: python -m playwright install chromium")
        yield b
        b.close()


def _sign_in(page, base: str) -> None:
    page.goto(base)
    page.get_by_label("Username").fill("admin")
    page.get_by_label("Password").fill(PASSWORD)
    page.get_by_role("button", name="Sign in").click()


def _seed_below_floor_finding(database_url: str, cve_id: str = "CVE-2024-99901") -> None:
    """Insert a non-KEV CVSS-5.0 finding. Caller raises min_cvss_display via the live HTTP API
    (process-local settings cache is not cleared by a foreign SQLite writer)."""
    from sqlalchemy import create_engine, select
    from sqlalchemy.orm import Session

    from app.db import utcnow
    from app.models import VULN_STATE_CONFIRMED, DevicePort, DevicePortVuln, Vulnerability

    engine = create_engine(database_url)
    with Session(engine) as db:
        port_row = db.scalars(select(DevicePort).limit(1)).first()
        if port_row is None:
            raise RuntimeError("e2e seed expected at least one device port from the mock scan")
        if db.get(Vulnerability, cve_id) is None:
            db.add(
                Vulnerability(
                    cve_id=cve_id,
                    cvss_base=5.0,
                    kev=False,
                    summary="e2e below-floor finding for vulnerabilities search",
                )
            )
            db.flush()
        existing = db.scalars(
            select(DevicePortVuln).where(
                DevicePortVuln.device_port_id == port_row.id,
                DevicePortVuln.cve_id == cve_id,
            )
        ).first()
        if existing is None:
            db.add(
                DevicePortVuln(
                    device_port_id=port_row.id,
                    cve_id=cve_id,
                    state=VULN_STATE_CONFIRMED,
                    matched_at=utcnow(),
                )
            )
        db.commit()
    engine.dispose()


def _set_min_cvss_display_via_api(page, floor: float = 6.0) -> None:
    """PUT /api/settings/vuln so the running app drops its settings cache."""
    status = page.evaluate(
        """async (floor) => {
          const m = document.cookie.match(/(?:^|; )nf_csrf=([^;]*)/);
          const csrf = m ? decodeURIComponent(m[1]) : '';
          const cur = await fetch('/api/settings/vuln', { credentials: 'same-origin' }).then((r) => r.json());
          const { nvd_api_key_set, ...body } = cur;
          const r = await fetch('/api/settings/vuln', {
            method: 'PUT',
            credentials: 'same-origin',
            headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrf },
            body: JSON.stringify({ ...body, enabled: true, min_cvss_display: floor }),
          });
          return r.status;
        }""",
        floor,
    )
    assert status == 200, status


def _seed_vuln_networks(database_url: str) -> tuple[str, str]:
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
    engine = create_engine(database_url, connect_args={"check_same_thread": False})
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
                    device_id=d.id,
                    port=port_n,
                    protocol="tcp",
                    service=service,
                    is_open=True,
                    first_seen=utcnow(),
                    last_seen=utcnow(),
                )
                db.add(p)
                db.flush()
            return p

        pa = ensure_device("10.10.0.1", net_a.id, "00:11:22:33:10:01", 22, "ssh")
        pb = ensure_device("10.20.0.1", net_b.id, "00:11:22:33:20:01", 80, "http")
        if db.get(Vulnerability, "CVE-2024-ALPHA") is None:
            db.add(Vulnerability(cve_id="CVE-2024-ALPHA", cvss_base=9.8, kev=True, epss=0.9, summary="E2E critical placeholder"))
        if db.get(Vulnerability, "CVE-2024-BETA") is None:
            db.add(Vulnerability(cve_id="CVE-2024-BETA", cvss_base=5.0, kev=False, epss=0.01, summary="E2E medium placeholder"))
        db.flush()
        if not db.scalar(
            select(DevicePortVuln).where(
                DevicePortVuln.device_port_id == pa.id,
                DevicePortVuln.cve_id == "CVE-2024-ALPHA",
            )
        ):
            db.add(DevicePortVuln(device_port_id=pa.id, cve_id="CVE-2024-ALPHA", state=VULN_STATE_CONFIRMED, matched_at=utcnow()))
        if not db.scalar(
            select(DevicePortVuln).where(
                DevicePortVuln.device_port_id == pb.id,
                DevicePortVuln.cve_id == "CVE-2024-BETA",
            )
        ):
            db.add(DevicePortVuln(device_port_id=pb.id, cve_id="CVE-2024-BETA", state=VULN_STATE_CONFIRMED, matched_at=utcnow()))
        db.commit()
        sync_finding_lifecycle(db, now=utcnow())
        db.commit()
    engine.dispose()
    return name_a, name_b


def test_sign_in_dashboard_and_devices_list(live_app, browser):
    from playwright.sync_api import expect

    base = live_app["base"]
    page = browser.new_page()
    errors: list[str] = []
    page.on("pageerror", lambda exc: errors.append(str(exc)))
    try:
        _sign_in(page, base)

        expect(page.get_by_role("heading", name="Network overview")).to_be_visible(timeout=15_000)

        page.get_by_role("link", name="Devices", exact=True).click()
        expect(page).to_have_url(f"{base}/devices")
        expect(page.get_by_role("heading", name="Devices", exact=True)).to_be_visible()
        # The seeded mock scan runs in the background; its hosts (10.99.0.0/24) fill the list.
        expect(page.locator("tbody tr").filter(has_text="10.99.0.").first).to_be_visible(timeout=30_000)
        expect(page.locator("a.active", has_text="Devices")).to_have_attribute("aria-current", "page")
    finally:
        page.close()
    assert errors == []


def test_cve_watchlist_add_and_list(live_app, browser):
    """Admin can add a CVE on the watchlist page and see it listed (pending until local sync)."""
    from playwright.sync_api import expect

    base = live_app["base"]
    page = browser.new_page()
    errors: list[str] = []
    page.on("pageerror", lambda exc: errors.append(str(exc)))
    try:
        _sign_in(page, base)
        expect(page.get_by_role("heading", name="Network overview")).to_be_visible(timeout=15_000)

        page.get_by_role("link", name="Vulnerabilities", exact=True).click()
        expect(page.get_by_role("heading", name="Vulnerabilities", exact=True)).to_be_visible(timeout=15_000)
        # Sidebar and page both link here; prefer the main-content button.
        page.get_by_role("main").get_by_role("link", name="CVE Watchlist").click()
        expect(page).to_have_url(f"{base}/vulnerabilities/watchlist")
        expect(page.get_by_role("heading", name="CVE Watchlist")).to_be_visible()

        page.get_by_label("CVE IDs").fill("CVE-2026-109618")
        page.get_by_role("button", name="Add to watchlist").click()
        expect(page.get_by_text("Added 1, already watched 0.")).to_be_visible(timeout=10_000)
        expect(page.locator("tbody tr").filter(has_text="CVE-2026-109618")).to_be_visible(timeout=10_000)
        expect(page.get_by_text("Pending sync", exact=True)).to_be_visible()
    finally:
        page.close()
    assert errors == []


def test_dashboard_layout_resize_save_and_reload(live_app, browser):
    """Customize → resize a card → Save → reload → layout still applied."""
    from playwright.sync_api import expect

    base = live_app["base"]
    # 1600px so the grid content width stays at the lg breakpoint (≥1200); 1400 leaves
    # ~1118px of grid and saves into layouts.md after breakpointFor landed.
    page = browser.new_page(viewport={"width": 1600, "height": 900})
    errors: list[str] = []
    page.on("pageerror", lambda exc: errors.append(str(exc)))
    try:
        _sign_in(page, base)
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


def test_vulnerabilities_search_shows_below_floor_finding(live_app, browser):
    """Search on /vulnerabilities includes findings hidden by min_cvss_display and badges them."""
    from playwright.sync_api import expect

    base = live_app["base"]
    page = browser.new_page()
    errors: list[str] = []
    page.on("pageerror", lambda exc: errors.append(str(exc)))
    cve_id = "CVE-2024-99901"
    try:
        _sign_in(page, base)
        expect(page.get_by_role("heading", name="Network overview")).to_be_visible(timeout=15_000)

        # Wait until the mock scan has produced at least one port to attach a finding to.
        page.get_by_role("link", name="Devices", exact=True).click()
        expect(page.locator("tbody tr").filter(has_text="10.99.0.").first).to_be_visible(timeout=30_000)
        _seed_below_floor_finding(live_app["database_url"], cve_id=cve_id)
        _set_min_cvss_display_via_api(page, floor=6.0)

        page.get_by_role("link", name="Vulnerabilities", exact=True).click()
        expect(page).to_have_url(f"{base}/vulnerabilities")
        expect(page.get_by_role("heading", name="Vulnerabilities", exact=True)).to_be_visible()
        search = page.get_by_label("Search findings")
        expect(search).to_be_visible(timeout=15_000)
        findings = page.locator("#vuln-findings")

        # Default findings table must not show the below-floor row (summary cards may lag cache).
        expect(findings.get_by_role("link", name=cve_id)).to_have_count(0)

        search.fill(cve_id)
        page.wait_for_url(f"**/*q=*{cve_id}*", timeout=10_000)
        expect(findings.get_by_role("link", name=cve_id)).to_be_visible(timeout=15_000)
        expect(findings.get_by_text("Below CVSS floor", exact=True)).to_be_visible()
    finally:
        page.close()
    assert errors == []


def test_vulnerabilities_search_debounce_respects_clear_all_and_facet(live_app, browser):
    """Debounce must read the live URL: Clear all / facet within 300ms must stick after 600ms.

    Uses direct JS input/click (no Playwright auto-scroll delay) so the race is real.
    """
    from urllib.parse import parse_qs, urlparse

    from playwright.sync_api import expect

    base = live_app["base"]
    page = browser.new_page()
    errors: list[str] = []
    page.on("pageerror", lambda exc: errors.append(str(exc)))
    try:
        _sign_in(page, base)
        expect(page.get_by_role("heading", name="Network overview")).to_be_visible(timeout=15_000)

        # --- Clear all must not be undone by a pending search debounce ---
        page.goto(f"{base}/vulnerabilities?severity=high&q=openssh&only_hidden=1")
        expect(page.get_by_label("Search findings")).to_be_visible(timeout=15_000)
        # Schedule a debounce via a direct input event (no Playwright fill/scroll delay).
        page.evaluate(
            """() => {
              const input = document.querySelector('[aria-label="Search findings"]');
              const desc = Object.getOwnPropertyDescriptor(
                window.HTMLInputElement.prototype, 'value');
              desc.set.call(input, input.value + 'x');
              input.dispatchEvent(new Event('input', { bubbles: true }));
            }"""
        )
        # Let React commit qInput + schedule the 300ms timer, then Clear all before it fires.
        page.wait_for_timeout(50)
        page.evaluate(
            """() => {
              const btn = [...document.querySelectorAll('button')]
                .find((b) => b.textContent.replace(/\\s+/g, ' ').trim() === 'Clear all');
              btn.click();
            }"""
        )
        page.wait_for_timeout(600)
        qs = parse_qs(urlparse(page.url).query)
        assert "severity" not in qs, page.url
        assert "q" not in qs, page.url
        assert "only_hidden" not in qs, page.url

        # --- Facet click during debounce must keep the facet in the final URL ---
        page.goto(f"{base}/vulnerabilities")
        expect(page.get_by_label("Search findings")).to_be_visible(timeout=15_000)
        # Wait for summary KPIs (facet targets) to render.
        expect(page.get_by_text("Critical", exact=True).first).to_be_visible(timeout=15_000)
        page.evaluate(
            """() => {
              const input = document.querySelector('[aria-label="Search findings"]');
              const desc = Object.getOwnPropertyDescriptor(
                window.HTMLInputElement.prototype, 'value');
              desc.set.call(input, 'openssh');
              input.dispatchEvent(new Event('input', { bubbles: true }));
            }"""
        )
        page.wait_for_timeout(50)
        page.evaluate(
            """() => {
              const kpi = [...document.querySelectorAll('.kpi[role="button"]')]
                .find((el) => el.querySelector('.label')?.textContent.trim() === 'Critical');
              kpi.click();
            }"""
        )
        page.wait_for_timeout(600)
        qs = parse_qs(urlparse(page.url).query)
        assert qs.get("severity") == ["critical"], page.url
        assert qs.get("q") == ["openssh"], page.url
    finally:
        page.close()
    assert errors == []


def test_vulnerabilities_network_facet_export_and_print(live_app, browser):
    """Click a network facet row → filter; CSV only that network; print view shows filter summary."""
    from playwright.sync_api import expect

    from app.core.vuln.summary import invalidate_vuln_summary_cache

    name_a, name_b = _seed_vuln_networks(live_app["database_url"])
    # Test-process cache clear is a no-op for the uvicorn worker; dismiss/undo below busts it.
    invalidate_vuln_summary_cache()
    base = live_app["base"]

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
        expect(page.get_by_role("button", name=re.compile(rf"network:\s*{re.escape(name_a)}"))).to_be_visible(timeout=10_000)

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

        # Print report: must wait for filtered summary + findings before window.print().
        def install_print_mock() -> None:
            page.evaluate(
                """() => {
                  window.__pr_print_calls = 0;
                  window.__pr_print_had_summary = false;
                  window.__pr_print_had_findings = false;
                  window.print = () => {
                    const report = document.querySelector('.vuln-print-report');
                    const kpis = report && report.querySelector('.vuln-print-kpis');
                    const rows = report && report.querySelectorAll('.vuln-print-table tbody tr');
                    window.__pr_print_had_summary = !!(kpis && kpis.textContent && /Findings/i.test(kpis.textContent));
                    window.__pr_print_had_findings = !!(rows && rows.length > 0);
                    window.__pr_print_calls++;
                  };
                }"""
            )

        install_print_mock()
        page.get_by_role("button", name="Print / PDF report").click()
        page.wait_for_function("() => window.__pr_print_calls > 0", timeout=15_000)
        assert page.evaluate("() => window.__pr_print_had_summary") is True
        assert page.evaluate("() => window.__pr_print_had_findings") is True
        report = page.locator(".vuln-print-report")
        # Force print stylesheet visibility for assertion without an actual print dialog.
        page.add_style_tag(content=".vuln-print-report { display: block !important; }")
        expect(report.locator(".vuln-print-filters")).to_contain_text(f"network: {name_a}", timeout=10_000)
        expect(report.get_by_role("heading", name="PortReveal vulnerability report")).to_be_visible()

        # Deep-link ?print=1 also waits for summary + findings (Report for this … entry points).
        # add_init_script must be a bare script body (not an unused () => {} expression).
        net_id = re.search(r"network_id=(\d+)", page.url)
        assert net_id is not None
        page.add_init_script(
            """
            window.__pr_print_calls = 0;
            window.__pr_print_had_summary = false;
            window.__pr_print_had_findings = false;
            window.print = () => {
              const report = document.querySelector('.vuln-print-report');
              const kpis = report && report.querySelector('.vuln-print-kpis');
              const rows = report && report.querySelectorAll('.vuln-print-table tbody tr');
              window.__pr_print_had_summary = !!(kpis && kpis.textContent && /Findings/i.test(kpis.textContent));
              window.__pr_print_had_findings = !!(rows && rows.length > 0);
              window.__pr_print_calls++;
            };
            """
        )
        page.goto(f"{base}/vulnerabilities?network_id={net_id.group(1)}&print=1")
        page.wait_for_function("() => window.__pr_print_calls > 0", timeout=20_000)
        assert page.evaluate("() => window.__pr_print_had_summary") is True
        assert page.evaluate("() => window.__pr_print_had_findings") is True
    finally:
        page.close()
    assert errors == []


def test_vulnerabilities_print_waits_for_matching_network_summary(live_app, browser):
    """Print stays disabled until the summary for the selected network arrives; report matches it."""
    from playwright.sync_api import expect

    name_a, name_b = _seed_vuln_networks(live_app["database_url"])
    base = live_app["base"]
    page = browser.new_page()
    errors: list[str] = []
    page.on("pageerror", lambda exc: errors.append(str(exc)))
    try:
        _sign_in(page, base)
        expect(page.get_by_role("heading", name="Network overview")).to_be_visible(timeout=15_000)

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
        expect(page.get_by_label("Network filter: All networks")).to_be_visible(timeout=15_000)

        # Delay filtered summary responses so the Print button observes the loading gate.
        def handle_summary(route):
            if "network_id=" in route.request.url and route.request.method == "GET":
                time.sleep(1.2)
            route.continue_()

        page.route("**/api/vulns/summary*", handle_summary)

        page.evaluate(
            """() => {
              window.__pr_print_calls = 0;
              window.__pr_print_filter = '';
              window.__pr_print_findings = 0;
              window.print = () => {
                const report = document.querySelector('.vuln-print-report');
                const filters = report && report.querySelector('.vuln-print-filters');
                const rows = report && report.querySelectorAll('.vuln-print-table tbody tr');
                window.__pr_print_filter = filters ? (filters.textContent || '') : '';
                window.__pr_print_findings = rows ? rows.length : 0;
                window.__pr_print_calls++;
              };
            }"""
        )

        # Lab Alpha hosts the critical finding (visible under the default CVSS floor);
        # Lab Beta's medium finding may be hidden — use Alpha so the report has rows.
        net_select = page.get_by_label(re.compile(r"^Network filter:"))
        net_select.select_option(label=name_a)
        expect(page).to_have_url(re.compile(r"network_id="), timeout=10_000)
        expect(page.get_by_label(f"Network filter: {name_a}")).to_be_visible(timeout=5_000)

        preparing = page.get_by_role("button", name="Preparing…")
        expect(preparing).to_be_visible(timeout=5_000)
        expect(preparing).to_be_disabled()

        print_btn = page.get_by_role("button", name="Print / PDF report")
        expect(print_btn).to_be_enabled(timeout=15_000)
        print_btn.click()
        page.wait_for_function("() => window.__pr_print_calls > 0", timeout=20_000)
        filt = page.evaluate("() => window.__pr_print_filter")
        assert name_a in filt, filt
        assert name_b not in filt, filt
        assert page.evaluate("() => window.__pr_print_findings") >= 1
        page.unroute("**/api/vulns/summary*")
    finally:
        page.close()
    assert errors == []


def test_vulnerabilities_html_report_download(live_app, browser):
    """HTML report button downloads a self-contained file with expected finding counts."""
    from playwright.sync_api import expect

    from app.core.vuln.summary import invalidate_vuln_summary_cache

    name_a, name_b = _seed_vuln_networks(live_app["database_url"])
    invalidate_vuln_summary_cache()
    base = live_app["base"]
    page = browser.new_page()
    errors: list[str] = []
    page.on("pageerror", lambda exc: errors.append(str(exc)))
    try:
        _sign_in(page, base)
        expect(page.get_by_role("heading", name="Network overview")).to_be_visible(timeout=15_000)
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

        with page.expect_download() as dl_info:
            page.get_by_role("button", name="HTML report").click()
        download = dl_info.value
        path = download.path()
        assert path is not None
        text = Path(path).read_text(encoding="utf-8")
        assert "<!DOCTYPE html>" in text
        assert "PortReveal vulnerability report" in text
        assert "CVE-2024-ALPHA" in text
        assert "CVE-2024-BETA" not in text
        assert name_a in text or "network:" in text
        assert name_b not in text or text.count(name_a) >= 1
        # Summary card for findings (Lab Alpha has one critical finding).
        assert 'class="value">1</div>' in text or ">1</div>" in text
        assert "window.__REPORT_DATA__=" in text
        assert "cdn." not in text.lower()
        suggested = download.suggested_filename or ""
        assert suggested.endswith(".html") or "vulns_" in suggested
    finally:
        page.close()
    assert errors == []


def test_notifications_tabs_and_webhook_crud(live_app, browser):
    """Open each Notifications inner tab; add, test, edit, and delete a webhook."""
    import threading
    from http.server import BaseHTTPRequestHandler, HTTPServer

    from playwright.sync_api import expect

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            length = int(self.headers.get("Content-Length") or 0)
            self.rfile.read(length)
            self.send_response(204)
            self.end_headers()

        def log_message(self, *_args):
            return

    httpd = HTTPServer(("127.0.0.1", 0), Handler)
    port = httpd.server_address[1]
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    hook_url = f"http://127.0.0.1:{port}/hook"

    base = live_app["base"]
    page = browser.new_page()
    errors: list[str] = []
    page.on("pageerror", lambda exc: errors.append(str(exc)))
    try:
        _sign_in(page, base)
        expect(page.get_by_role("heading", name="Network overview")).to_be_visible(timeout=15_000)

        page.get_by_role("link", name="Settings", exact=True).click()
        page.get_by_role("navigation").get_by_role("link", name="Notifications", exact=True).click()
        expect(page).to_have_url(f"{base}/settings/notifications/general", timeout=15_000)
        expect(page.get_by_role("heading", name="Channels")).to_be_visible()

        nav = page.get_by_role("navigation", name="Notification settings")
        for link_name, section, heading in (
            ("Email", "email", "Email"),
            ("Recipients", "recipients", "Recipients"),
            ("Webhooks", "webhooks", "Webhooks"),
            ("CVE Watchlist", "cve-watchlist", "CVE watchlist alerts"),
        ):
            nav.get_by_role("link", name=link_name, exact=True).click()
            expect(page).to_have_url(f"{base}/settings/notifications/{section}")
            expect(page.get_by_role("heading", name=heading)).to_be_visible(timeout=10_000)

        # Recipients: create a group (daily digest default)
        nav.get_by_role("link", name="Recipients", exact=True).click()
        page.get_by_role("button", name="Add group").click()
        page.get_by_label("Name", exact=True).fill("e2e-soc")
        page.get_by_role("button", name="+ Email").click()
        page.get_by_label("Address", exact=True).fill("soc@example.com")
        page.get_by_role("button", name="Save").click()
        expect(page.get_by_text("e2e-soc", exact=True)).to_be_visible(timeout=10_000)
        # Name is a card badge; summary is severity · networks · when (no name prefix).
        expect(page.get_by_test_id("group-summary").filter(has_text="Daily")).to_be_visible()

        # Back to Webhooks for CRUD
        nav.get_by_role("link", name="Webhooks", exact=True).click()
        page.get_by_role("button", name="Add webhook").click()
        page.get_by_label("Name", exact=True).fill("e2e-hook")
        page.get_by_label("URL", exact=True).fill(hook_url)
        page.get_by_role("button", name="Save").click()
        expect(page.get_by_text("e2e-hook", exact=True)).to_be_visible(timeout=10_000)
        # Secret reveal banner (generated on create)
        expect(page.get_by_text("Copy it now", exact=False)).to_be_visible(timeout=5_000)
        page.get_by_role("button", name="Done").click()

        page.get_by_role("button", name="Send test").click()
        expect(page.get_by_text("Test: OK", exact=False)).to_be_visible(timeout=10_000)

        page.get_by_role("button", name="Edit").click()
        page.get_by_label("Name", exact=True).fill("e2e-hook-renamed")
        page.get_by_role("button", name="Save").click()
        expect(page.get_by_text("e2e-hook-renamed", exact=True)).to_be_visible(timeout=10_000)

        page.once("dialog", lambda dialog: dialog.accept())
        page.get_by_role("button", name="Delete").click()
        expect(page.get_by_text("No webhooks yet.")).to_be_visible(timeout=10_000)
    finally:
        page.close()
        httpd.shutdown()
    assert errors == []
