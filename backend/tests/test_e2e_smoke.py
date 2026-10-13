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
def live_app(tmp_path_factory) -> Iterator[str]:
    if not (DIST / "index.html").is_file():
        pytest.skip("frontend/dist is missing; run `npm run build` (npm run test:e2e does)")
    work = tmp_path_factory.mktemp("e2e")
    port = _free_port()
    env = {
        **os.environ,
        "APP_ENV": "development",
        "DEV_SEED": "true",  # admin user, demo network, setup completed, one mock scan queued
        "DEV_ADMIN_USERNAME": "admin",
        "DEV_ADMIN_PASSWORD": PASSWORD,
        "SCANNER_MODE": "mock",
        "MOCK_SCAN_DELAY": "0",
        "BACKGROUND_JOBS": "true",
        "DATABASE_URL": f"sqlite:///{(work / 'e2e.db').as_posix()}",
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
        yield base
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


def test_sign_in_dashboard_and_devices_list(live_app, browser):
    from playwright.sync_api import expect

    page = browser.new_page()
    errors: list[str] = []
    page.on("pageerror", lambda exc: errors.append(str(exc)))
    try:
        page.goto(live_app)
        page.get_by_label("Username").fill("admin")
        page.get_by_label("Password").fill(PASSWORD)
        page.get_by_role("button", name="Sign in").click()

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
