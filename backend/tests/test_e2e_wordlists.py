"""End-to-end: Settings > Web capture wordlist library (upload, select, save, delete; URL import refused).

Reuses the live app + headless Chromium fixtures from test_e2e_smoke. Marked `e2e`; run with
`npm run test:e2e`. Generic placeholder data only.
"""

from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from tests.test_e2e_smoke import _sign_in, browser, live_app  # noqa: F401  (pytest fixtures)

pytestmark = pytest.mark.e2e


def test_wordlist_upload_select_save_and_delete(live_app, browser, tmp_path):  # noqa: F811
    from playwright.sync_api import expect

    wordlist = tmp_path / "e2e-paths.txt"
    wordlist.write_text("# e2e list\nadmin\nportal\n../not-allowed\nadmin\n", encoding="utf-8")

    base = live_app["base"]
    page = browser.new_page()
    errors: list[str] = []
    page.on("pageerror", lambda exc: errors.append(str(exc)))
    try:
        _sign_in(page, base)
        expect(page.get_by_role("heading", name="Network overview")).to_be_visible(timeout=15_000)
        page.goto(f"{base}/settings/web-capture")
        expect(page.get_by_role("heading", name="Wordlists")).to_be_visible(timeout=15_000)
        select = page.get_by_label("Discovery wordlist")
        expect(select).to_have_value("")  # built-in

        # Upload
        page.get_by_role("button", name="Upload wordlist").click()
        page.get_by_label("File", exact=True).set_input_files(str(wordlist))
        page.get_by_label("Name", exact=True).fill("e2e paths")
        page.get_by_role("button", name="Upload", exact=True).click()
        expect(page.get_by_test_id("wordlist-summary")).to_contain_text("Accepted 2 / skipped 2", timeout=15_000)
        row = page.locator("[data-testid^=wordlist-row-]").filter(has_text="e2e paths")
        expect(row).to_be_visible()
        expect(row).to_contain_text("Paths")
        expect(row).to_contain_text("Upload")

        # Select in Web capture and save
        select.select_option(label="e2e paths (2 paths)")
        page.get_by_role("button", name="Save Web Capture settings").click()
        expect(page.get_by_text("Saved.", exact=True)).to_be_visible(timeout=10_000)
        page.reload()
        expect(page.get_by_label("Discovery wordlist")).not_to_have_value("", timeout=15_000)
        expect(row.get_by_text("in use", exact=True)).to_be_visible()

        # Delete (in use: confirm explains the fallback to the built-in list)
        messages: list[str] = []

        def accept(dialog):
            messages.append(dialog.message)
            dialog.accept()

        page.once("dialog", accept)
        row.get_by_role("button", name="Delete").click()
        expect(row).to_have_count(0, timeout=10_000)
        assert messages and "built-in" in messages[0]
        page.reload()
        expect(page.get_by_label("Discovery wordlist")).to_have_value("", timeout=15_000)
        assert not errors, errors
    finally:
        page.close()


def test_wordlist_url_import_to_local_server_is_refused(live_app, browser):  # noqa: F811
    from playwright.sync_api import expect

    hits: list[str] = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            hits.append(self.path)
            body = b"admin\n"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_args):
            return

    httpd = HTTPServer(("127.0.0.1", 0), Handler)
    port = httpd.server_address[1]
    threading.Thread(target=httpd.serve_forever, daemon=True).start()

    base = live_app["base"]
    page = browser.new_page()
    try:
        _sign_in(page, base)
        expect(page.get_by_role("heading", name="Network overview")).to_be_visible(timeout=15_000)
        page.goto(f"{base}/settings/web-capture")
        page.get_by_role("button", name="Import from URL").click()

        page.get_by_role("dialog").locator("input[type=url]").fill(f"http://127.0.0.1:{port}/paths.txt")
        page.get_by_role("button", name="Import", exact=True).click()
        expect(page.get_by_text("Only https:// URLs are allowed.")).to_be_visible(timeout=5_000)

        page.get_by_role("dialog").locator("input[type=url]").fill(f"https://127.0.0.1:{port}/paths.txt")
        page.get_by_role("button", name="Import", exact=True).click()
        expect(page.get_by_text("blocked address", exact=False)).to_be_visible(timeout=15_000)
        assert hits == []  # refused before any connection to the local server
    finally:
        page.close()
        httpd.shutdown()
