"""End-to-end: Domains page - add a domain, run a scan, view the inventory, manual lookup, change event.

Reuses the live app + headless Chromium fixtures from test_e2e_smoke. The app runs with
SCANNER_MODE=mock, so the domain scan uses the simulated backend (core/domains/mock.py): no
subfinder/dnsx run and no DNS query leaves the machine. Marked `e2e`; run with `npm run test:e2e`.
"""

from __future__ import annotations

import pytest

from tests.test_e2e_smoke import _sign_in, browser, live_app  # noqa: F401  (pytest fixtures)

pytestmark = pytest.mark.e2e


def test_domain_add_scan_inventory_lookup_and_change(live_app, browser):  # noqa: F811
    from playwright.sync_api import expect

    base = live_app["base"]
    page = browser.new_page()
    errors: list[str] = []
    page.on("pageerror", lambda exc: errors.append(str(exc)))
    try:
        _sign_in(page, base)
        expect(page.get_by_role("heading", name="Network overview")).to_be_visible(timeout=15_000)

        # Add domain (nav item -> dialog)
        page.get_by_role("link", name="Domains").first.click()
        expect(page.get_by_role("heading", name="Domains", exact=True)).to_be_visible(timeout=15_000)
        page.get_by_role("button", name="Add domain").click()
        page.get_by_test_id("domain-name").fill("example.com")
        page.get_by_label("Wordlist brute force (dnsx)").select_option("custom")
        page.get_by_label("Subdomains to try").fill("www\nintranet")
        page.get_by_label("Zone transfer (AXFR) from internal DNS").check()
        page.get_by_role("button", name="Save", exact=True).click()
        expect(page.get_by_role("heading", name="example.com")).to_be_visible(timeout=15_000)
        expect(page.get_by_text("No scan yet")).to_be_visible()

        # Run a scan (simulated tools) and wait for the inventory
        page.get_by_test_id("domain-scan-now").click()
        table = page.get_by_test_id("subdomain-table")
        expect(table).to_contain_text("www.example.com", timeout=60_000)
        www = table.locator("tr").filter(has_text="www.example.com")
        expect(www).to_contain_text("Both")
        expect(www).to_contain_text("Passive")
        dev = table.locator("tr").filter(has_text="dev.example.com")
        expect(dev).to_contain_text("Internal (authorized)")
        expect(dev).to_contain_text("AXFR")

        # Filters: exposure select narrows the table
        page.get_by_label("Exposure").select_option("external")
        expect(table).to_contain_text("vpn.example.com", timeout=10_000)
        expect(table).not_to_contain_text("intranet.example.com")
        page.get_by_role("button", name="Clear").click()

        # Manual lookup: outside the domain is refused, inside resolves with both views
        lookup = page.get_by_test_id("lookup-input")
        lookup.fill("test.example.org")
        page.get_by_role("button", name="Look up").click()
        expect(page.get_by_role("alert").filter(has_text="not inside a configured domain")).to_be_visible()
        lookup.fill("www.example.com")
        page.get_by_role("button", name="Look up").click()
        result = page.get_by_test_id("lookup-result")
        expect(result).to_contain_text("Both", timeout=15_000)
        expect(result).to_contain_text("198.51.100.10")
        expect(result.get_by_role("button", name="In inventory")).to_be_disabled()

        # Second scan: the simulated scenario adds new.example.com -> a change event
        expect(page.get_by_test_id("domain-scan-now")).to_be_enabled(timeout=60_000)
        page.get_by_test_id("domain-scan-now").click()
        expect(table).to_contain_text("new.example.com", timeout=90_000)
        page.goto(f"{base}/changes?type=subdomain_new&range=24h")
        expect(page.get_by_text("new.example.com").first).to_be_visible(timeout=15_000)
        assert not errors, errors
    finally:
        page.close()
