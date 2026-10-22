"""End-to-end smoke test: the built UI served by the real app, driven in headless Chromium.

Covers sign-in -> dashboard -> devices list against a uvicorn subprocess (development mode, mock
scanner, throwaway SQLite database). Marked `e2e` and excluded from the default `npm test`; run it
with `npm run test:e2e`, which builds the frontend first. Skips when frontend/dist or Playwright's
Chromium is missing.
"""
from __future__ import annotations

import os
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
        cwd=BACKEND, env=env, stdout=log, stderr=subprocess.STDOUT,
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
            pytest.skip(f"Playwright Chromium unavailable ({exc.__class__.__name__}); "
                        "run: python -m playwright install chromium")
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
            db.add(Vulnerability(
                cve_id=cve_id, cvss_base=5.0, kev=False,
                summary="e2e below-floor finding for vulnerabilities search",
            ))
            db.flush()
        existing = db.scalars(
            select(DevicePortVuln).where(
                DevicePortVuln.device_port_id == port_row.id,
                DevicePortVuln.cve_id == cve_id,
            )
        ).first()
        if existing is None:
            db.add(DevicePortVuln(
                device_port_id=port_row.id, cve_id=cve_id,
                state=VULN_STATE_CONFIRMED, matched_at=utcnow(),
            ))
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
        findings = page.locator("#vuln-findings")
        search = findings.get_by_label("Search findings")
        expect(search).to_be_visible(timeout=15_000)

        # Default findings table must not show the below-floor row (summary cards may lag cache).
        expect(findings.get_by_role("link", name=cve_id)).to_have_count(0)

        search.fill(cve_id)
        page.wait_for_url(f"**/*q=*{cve_id}*", timeout=10_000)
        expect(findings.get_by_role("link", name=cve_id)).to_be_visible(timeout=15_000)
        expect(findings.get_by_text("Below CVSS floor", exact=True)).to_be_visible()
    finally:
        page.close()
    assert errors == []
