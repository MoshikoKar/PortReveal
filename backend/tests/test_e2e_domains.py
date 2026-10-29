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
        expect(page.get_by_role("heading", name="Domains", exact=True, level=1)).to_be_visible(timeout=15_000)
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
        expect(dev).to_contain_text("AXFR only")  # short finding label; full label in the title
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


_API = r"""async ([method, path, body]) => {
  const m = document.cookie.match(/(?:^|;\s*)nf_csrf=([^;]+)/);
  const res = await fetch('/api' + path, {
    method,
    headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': m ? decodeURIComponent(m[1]) : '' },
    body: body == null ? undefined : JSON.stringify(body),
  });
  return { status: res.status, body: await res.json().catch(() => null) };
}"""


def test_subdomain_detail_links_to_device(live_app, browser):  # noqa: F811
    """Inventory row -> subdomain page -> the device that answers on its address."""
    import re
    import time

    from playwright.sync_api import expect

    base = live_app["base"]
    page = browser.new_page()
    errors: list[str] = []
    page.on("pageerror", lambda exc: errors.append(str(exc)))
    try:
        _sign_in(page, base)
        expect(page.get_by_role("heading", name="Network overview")).to_be_visible(timeout=15_000)

        # A configured network holding the simulated internal answers: the mock scanner puts srv-web01
        # at offset .10, the same address the simulated DNS gives www.<domain> internally.
        net = page.evaluate(_API, ["POST", "/networks", {"name": "E2E Docs", "cidr": "192.0.2.0/24"}])
        assert net["status"] == 201, net
        started = page.evaluate(_API, ["POST", "/scans", {"scan_type": "standard", "network_ids": [net["body"]["id"]]}])
        assert started["status"] == 200, started
        deadline = time.time() + 90
        while time.time() < deadline:
            found = page.evaluate(_API, ["GET", "/devices?q=192.0.2.10", None])
            if found["status"] == 200 and found["body"]["total"]:
                break
            page.wait_for_timeout(1000)
        else:
            raise AssertionError("mock network scan produced no device at 192.0.2.10")

        dom = page.evaluate(_API, ["POST", "/domains", {"name": "example.net"}])
        assert dom["status"] == 201, dom
        domain_id = dom["body"]["id"]
        assert page.evaluate(_API, ["POST", f"/domains/{domain_id}/scan", None])["status"] == 201

        # Inventory: the name links to the subdomain page
        page.goto(f"{base}/domains/{domain_id}")
        table = page.get_by_test_id("subdomain-table")
        expect(table).to_contain_text("www.example.net", timeout=60_000)
        table.get_by_role("link", name="www.example.net").click()
        expect(page).to_have_url(re.compile(rf"/domains/{domain_id}/subdomains/\d+$"), timeout=15_000)
        expect(page.get_by_role("heading", name="www.example.net")).to_be_visible(timeout=15_000)
        expect(page.get_by_test_id("subdomain-addresses")).to_contain_text("192.0.2.10")
        expect(page.get_by_role("heading", name="Records history")).to_be_visible()

        # Follow the device link; the device page lists the name under "Domain names"
        page.get_by_test_id("subdomain-device-link").first.click()
        expect(page).to_have_url(re.compile(r"/devices/[0-9a-f-]{36}$"), timeout=15_000)
        names = page.get_by_test_id("device-domain-names")
        expect(names).to_contain_text("www.example.net", timeout=15_000)
        expect(names.get_by_role("link", name="www.example.net")).to_be_visible()
        assert not errors, errors
    finally:
        page.close()


def _seed_exposed_subdomain(database_url: str) -> int:
    """A domain with one name whose address belongs to a scored inventory device with an open web port and
    a captured page (no screenshot needed: the ports table's Open column links to the web preview)."""
    from sqlalchemy import create_engine, select
    from sqlalchemy.orm import Session

    from app.db import utcnow
    from app.models import Device, DevicePort, Domain, Subdomain, WebCapture, WebPage

    engine = create_engine(database_url, connect_args={"check_same_thread": False})
    with Session(engine) as db:
        existing = db.scalar(select(Domain).where(Domain.name == "example.org"))
        if existing is not None:
            return existing.id
        d = Domain(name="example.org", enabled=True, wordlist_mode="none", passive_enabled=True, axfr_enabled=False,
                   internal_resolvers=[], public_resolvers=["192.0.2.53"], created_by="e2e")
        dev = Device(current_ip="198.51.100.40", hostname="app01.example.org", exposure_score=72, risk_score=40,
                     combined_score=64, risk_scored_at=utcnow(), last_port_scan_at=utcnow())
        cap = WebCapture(targets="198.51.100.40", status="completed", requested_by="e2e")
        db.add_all([d, dev, cap])
        db.flush()
        db.add(DevicePort(device_id=dev.id, protocol="tcp", port=443, is_open=True, service="https", product="nginx"))
        db.add(WebPage(capture_id=cap.id, device_id=dev.id, ip=dev.current_ip, port=443, scheme="https",
                       host_used="app.example.org", kind="home", url="https://app.example.org/", http_status=200,
                       title="Example app", screenshot_status="skipped"))
        db.add(Subdomain(domain_id=d.id, name="app.example.org", exposure="external", sources=["passive"],
                         ips=[dev.current_ip], hosting=[], records={}, flags=[], status="active",
                         first_seen=utcnow(), last_seen=utcnow()))
        db.commit()
        domain_id = d.id
    engine.dispose()
    return domain_id


def test_inventory_scores_ports_and_web_open_link(live_app, browser):  # noqa: F811
    """Domains inventory shows the linked device's scores; the subdomain page lists its ports with score
    badges, and the port's "Open" link goes to the device's web preview."""
    import re

    from playwright.sync_api import expect

    domain_id = _seed_exposed_subdomain(live_app["database_url"])
    base = live_app["base"]
    page = browser.new_page(viewport={"width": 1280, "height": 900})
    errors: list[str] = []
    page.on("pageerror", lambda exc: errors.append(str(exc)))
    try:
        _sign_in(page, base)
        page.goto(f"{base}/domains/{domain_id}")
        table = page.get_by_test_id("subdomain-table")
        row = table.locator("tr").filter(has_text="app.example.org")
        expect(row.get_by_test_id("subdomain-combined-score")).to_have_text("64", timeout=15_000)
        expect(row.get_by_test_id("subdomain-ports")).to_contain_text("1 open")
        # No horizontal overflow at 1280 with the score columns on
        assert page.evaluate("() => [...document.querySelectorAll('.table-wrap')].every(w => w.scrollWidth <= w.clientWidth)")

        row.get_by_role("link", name="app.example.org").click()
        expect(page).to_have_url(re.compile(rf"/domains/{domain_id}/subdomains/\d+$"), timeout=15_000)
        expect(page.get_by_test_id("subdomain-score-exposure")).to_have_text("72")
        expect(page.get_by_test_id("subdomain-score-combined")).to_have_text("64")
        ports = page.get_by_test_id("subdomain-ports")
        expect(ports).to_contain_text("443")
        expect(ports).to_contain_text("nginx")
        ports.get_by_test_id("port-open").get_by_role("link", name="Preview").click()
        expect(page).to_have_url(re.compile(r"/devices/[0-9a-f-]{36}/web$"), timeout=15_000)
        assert not errors, errors
    finally:
        page.close()
