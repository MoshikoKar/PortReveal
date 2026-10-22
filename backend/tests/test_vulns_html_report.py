"""Unit tests for the self-contained HTML vulnerability report builder."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest

from app.core.vuln.filters import FindingFilters
from app.core.vuln.html_report import (
    build_html_report,
    compute_stats,
    finding_dict,
    format_filter_line,
)


def _finding(**kwargs):
    base = dict(
        cve_id="CVE-2024-1",
        device_uuid="u1",
        device_ip="10.99.0.1",
        device_hostname="host-a.lab.example",
        network="Mock Lab",
        network_id=1,
        port=22,
        protocol="tcp",
        service="ssh",
        product="OpenSSH",
        version="7.4",
        state="confirmed",
        cvss_base=9.8,
        cvss_vector="CVSS:3.1/AV:N",
        kev=True,
        epss=0.9,
        summary="Sample title",
        first_seen_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        matched_at=datetime(2026, 1, 2, tzinfo=timezone.utc),
        hidden_reasons=None,
    )
    base.update(kwargs)
    return finding_dict(**base)


def test_format_filter_line_matches_print_wording():
    assert format_filter_line(FindingFilters()) == "All networks (no filters)"
    assert format_filter_line(FindingFilters(q="openssh")) == 'Search: "openssh" · Includes hidden'
    assert format_filter_line(FindingFilters(q="openssh", only_hidden=True)) == 'Search: "openssh" · Only hidden'
    assert (
        format_filter_line(
            FindingFilters(network_id="1", q="2024", only_hidden=True),
            network_name="Lab Alpha",
        )
        == 'network: Lab Alpha · Search: "2024" · Only hidden'
    )


def test_build_html_report_escapes_and_embeds_json():
    findings = [
        _finding(
            device_hostname="</script><script>alert(1)</script>",
            summary='Title with <b>html</b> & "quotes"',
            hidden_reasons=["Below CVSS floor"],
        )
    ]
    html = build_html_report(
        findings=findings,
        filter_line='network: Mock Lab · Search: "x" · Includes hidden',
        generated_at=datetime(2026, 10, 22, 12, 0, tzinfo=timezone.utc),
    )
    assert "</script><script>alert" not in html
    assert "\\u003c" in html or "&lt;" in html
    assert html.count("<script>") == 2
    assert "CVE-2024-1" in html
    assert "Top devices by risk" in html
    assert "Top CVEs by affected devices" in html
    assert "chart-hbar" in html
    assert "rank-list" in html
    assert "Ranked by KEV count" in html
    assert "chart-summary" in html
    assert "function compareIps" in html
    assert "visibleColCount" in html
    assert "Below floor" in html  # shortened badge label in JS
    assert "First seen (weekly)" not in html
    assert "KEV share" not in html
    assert "beforeprint" in html
    assert "@page" in html and "A4 landscape" in html
    assert "data-theme-set" in html
    assert "grid-template-columns: 1fr 1fr" in html  # print charts 2×2
    stats = compute_stats(findings)
    assert stats.findings_total == 1
    assert stats.kev_count == 1
    assert stats.device_count == 1
    assert stats.severity_counts["critical"] == 1
    assert stats.top_devices
    assert len(stats.top_devices[0]) == 3
    assert "KEV" in stats.top_devices[0][2]
    assert stats.top_cves


def test_compute_stats_top_lists():
    findings = [
        _finding(cve_id="CVE-2024-100", device_uuid="d1", device_ip="10.0.0.1", cvss_base=9.8, kev=True),
        _finding(cve_id="CVE-2024-100", device_uuid="d2", device_ip="10.0.0.2", cvss_base=9.8, kev=True),
        _finding(cve_id="CVE-2024-200", device_uuid="d1", device_ip="10.0.0.1", cvss_base=5.0, kev=False),
    ]
    stats = compute_stats(findings)
    assert stats.top_cves[0][0] == "CVE-2024-100"
    assert stats.top_cves[0][1] == 2
    # d1 has 1 KEV + medium; d2 has 1 KEV only — d1 ranks first (same KEV, higher CVSS sum)
    assert stats.top_devices[0][0].startswith("10.0.0.1")
    assert stats.top_devices[0][1] >= stats.top_devices[-1][1]
    assert "KEV 1" in stats.top_devices[0][2]


def test_top_device_bar_follows_lexicographic_rank():
    """High count must not lengthen a bar past a device that ranks higher on Critical."""
    findings = [
        # Ranks first: 1 critical, 0 high
        _finding(
            cve_id="CVE-2024-1",
            device_uuid="crit",
            device_ip="10.0.0.1",
            cvss_base=9.5,
            kev=False,
        ),
        # Ranks second: 0 critical, many high + large CVSS sum (old weight inverted bars)
        *[
            _finding(
                cve_id=f"CVE-2024-{i}",
                device_uuid="highs",
                device_ip="10.0.0.2",
                cvss_base=7.0,
                kev=False,
            )
            for i in range(10, 25)
        ],
    ]
    stats = compute_stats(findings)
    assert stats.top_devices[0][0].startswith("10.0.0.1")
    assert stats.top_devices[1][0].startswith("10.0.0.2")
    assert stats.top_devices[0][1] > stats.top_devices[1][1]
    assert "Crit 1" in stats.top_devices[0][2]
    assert "High 15" in stats.top_devices[1][2]


def test_html_report_print_description_and_cve_compact():
    html = build_html_report(findings=[_finding()], filter_line="All networks (no filters)")
    assert 'class="detail-desc"' in html
    assert "detail-desc { grid-column: 1 / -1" in html
    assert "Group-by-CVE print" in html or "group-by-cve th.col-device" in html
    assert "text-overflow: ellipsis" in html


def test_report_js_embeds_all_sortable_columns():
    """Static check (no browser): every sortable column is wired in the inline JS."""
    html = build_html_report(findings=[_finding()], filter_line="All networks (no filters)")
    for needle in (
        "function compareCveIds",
        "case 'epss':",
        "case 'title':",
        "case 'port':",
        "case 'state':",
        "case 'severity':",
        "case 'cvss':",
        "case 'cve':",
        "SEV_DESC",
        "beforeprint",
        "data-theme-set",
        "Top devices by risk",
        "Top CVEs by affected devices",
        "A4 landscape",
        "compareIps",
        "chart-hbar",
        "visibleColCount",
        "Ranked by KEV count",
        "chart-summary",
    ):
        assert needle in html, needle


def _cve_parts(cve_id: str) -> tuple[int, int]:
    import re

    m = re.match(r"^CVE-(\d+)-(\d+)$", cve_id, re.I)
    return (int(m.group(1)), int(m.group(2))) if m else (0, 0)


def _ip_parts(ip: str) -> tuple[int, ...]:
    bits = ip.split(".")
    if len(bits) != 4 or not all(b.isdigit() for b in bits):
        return (999, 999, 999, 999)
    return tuple(int(b) for b in bits)


def test_cve_numeric_sort_mirror():
    """CVE year+id ordering (mirrors compareCveIds): 999 < 10000 < 73180 < 900002."""
    ids = ["CVE-2024-10000", "CVE-2024-999", "CVE-2026-900002", "CVE-2026-73180"]
    ordered = sorted(ids, key=_cve_parts)
    assert ordered == [
        "CVE-2024-999",
        "CVE-2024-10000",
        "CVE-2026-73180",
        "CVE-2026-900002",
    ]


def test_ip_numeric_sort_mirror():
    """Device IP ordering (mirrors compareIps): .5 before .10 (not lexical)."""
    ips = ["10.99.0.10", "10.99.0.5", "10.99.0.2", "10.99.0.100"]
    ordered = sorted(ips, key=_ip_parts)
    assert ordered == ["10.99.0.2", "10.99.0.5", "10.99.0.10", "10.99.0.100"]


@pytest.mark.e2e
@pytest.mark.parametrize(
    "key,dir_,field,expected_first",
    [
        # CVE numeric asc / desc
        ("cve", 1, "cve_id", "CVE-2024-999"),
        ("cve", -1, "cve_id", "CVE-2026-900002"),
        ("severity", -1, "severity", "critical"),
        ("epss", -1, "epss", 0.9),
        ("title", 1, "summary", "Alpha title"),
        ("title", -1, "summary", "Zulu title"),
        ("port", 1, "port", 22),
        ("port", -1, "port", 8080),
        ("state", 1, "state", "confirmed"),
        ("state", -1, "state", "potential"),
        ("cvss", -1, "cvss_base", 9.8),
    ],
)
def test_report_js_sort_helpers(key, dir_, field, expected_first, tmp_path: Path):
    """Each sortable column uses __REPORT_API__.compareFindings / compareCveIds correctly."""
    pytest.importorskip("playwright")
    from playwright.sync_api import sync_playwright

    findings = [
        _finding(
            cve_id="CVE-2024-10000",
            device_uuid="d1",
            device_ip="10.0.0.2",
            port=443,
            state="potential",
            cvss_base=5.0,
            epss=0.1,
            summary="Zulu title",
        ),
        _finding(
            cve_id="CVE-2024-999",
            device_uuid="d2",
            device_ip="10.0.0.1",
            port=22,
            state="confirmed",
            cvss_base=9.8,
            epss=0.9,
            summary="Alpha title",
        ),
        _finding(
            cve_id="CVE-2026-900002",
            device_uuid="d3",
            device_ip="10.0.0.3",
            port=80,
            state="dismissed",
            cvss_base=3.0,
            epss=0.05,
            summary="Middle title",
        ),
        _finding(
            cve_id="CVE-2026-73180",
            device_uuid="d4",
            device_ip="10.0.0.4",
            port=8080,
            state="confirmed",
            cvss_base=7.5,
            epss=0.4,
            summary="Beta title",
        ),
    ]
    html = build_html_report(findings=findings, filter_line="All networks (no filters)")
    path = tmp_path / "sort.html"
    path.write_text(html, encoding="utf-8")

    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page()
        page.goto(path.as_uri())
        page.wait_for_function("() => window.__REPORT_API__")

        if key == "cve" and dir_ == 1:
            order = page.evaluate(
                """() => {
                  const ids = ['CVE-2024-10000','CVE-2024-999','CVE-2026-900002','CVE-2026-73180'];
                  return ids.slice().sort(window.__REPORT_API__.compareCveIds);
                }"""
            )
            assert order == [
                "CVE-2024-999",
                "CVE-2024-10000",
                "CVE-2026-73180",
                "CVE-2026-900002",
            ]

        first = page.evaluate(
            """([k, dir, field]) => {
              const data = window.__REPORT_DATA__.slice()
                .sort((a,b)=>window.__REPORT_API__.compareFindings(a,b,k,dir));
              return data[0][field];
            }""",
            [key, dir_, field],
        )
        assert first == expected_first

        if key == "severity":
            mild = page.evaluate(
                """() => {
                  const data = window.__REPORT_DATA__.slice()
                    .sort((a,b)=>window.__REPORT_API__.compareFindings(a,b,'severity',1));
                  return data[0].severity;
                }"""
            )
            assert mild in ("low", "medium", "unknown")
        browser.close()


@pytest.mark.e2e
def test_report_print_css_forces_light_and_expands_groups(tmp_path: Path):
    pytest.importorskip("playwright")
    from playwright.sync_api import sync_playwright

    findings = [_finding(cve_id=f"CVE-2024-{i}", device_uuid=f"d{i}", device_ip=f"10.0.0.{i}") for i in range(1, 6)]
    html = build_html_report(findings=findings, filter_line="All networks (no filters)")
    path = tmp_path / "print.html"
    path.write_text(html, encoding="utf-8")

    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page(color_scheme="dark")
        page.goto(path.as_uri())
        page.wait_for_selector("#groups .group")
        # Before print: groups collapsed → no table rows
        assert page.locator("table.findings tbody tr.row").count() == 0
        page.evaluate("() => window.dispatchEvent(new Event('beforeprint'))")
        page.wait_for_selector("table.findings tbody tr.row")
        assert page.locator("table.findings tbody tr.row").count() >= 5
        # Detail rows stay hidden unless previously expanded
        assert page.locator("tr.detail-row.print-show").count() == 0
        # Print media: light background forced
        page.emulate_media(media="print")
        bg = page.evaluate("() => getComputedStyle(document.body).backgroundColor")
        # rgb(255, 255, 255) or similar
        assert "255" in bg
        browser.close()


@pytest.mark.e2e
def test_expanded_row_survives_resort(tmp_path: Path):
    pytest.importorskip("playwright")
    from playwright.sync_api import sync_playwright

    findings = [
        _finding(cve_id="CVE-2024-1", device_uuid="d1", device_ip="10.0.0.1", cvss_base=9.8),
        _finding(cve_id="CVE-2024-2", device_uuid="d1", device_ip="10.0.0.1", cvss_base=5.0),
    ]
    html = build_html_report(findings=findings, filter_line="All networks (no filters)")
    path = tmp_path / "expand.html"
    path.write_text(html, encoding="utf-8")

    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page()
        page.goto(path.as_uri())
        page.locator(".group-head").first.click()
        page.wait_for_selector("table.findings tbody tr.row")
        page.locator("table.findings tbody tr.row").first.click()
        page.wait_for_selector("tr.detail-row")
        before = page.evaluate("() => window.__REPORT_API__.getExpandedRows()")
        assert len(before) == 1
        page.evaluate("() => window.__REPORT_API__.setSort('cvss', 1)")
        page.wait_for_timeout(50)
        after = page.evaluate("() => window.__REPORT_API__.getExpandedRows()")
        assert after == before
        assert page.locator("tr.detail-row").count() == 1
        browser.close()


def _table_title_metrics(page):
    return page.evaluate(
        """() => {
          const table = document.querySelector('table.findings');
          const title = document.querySelector('th.col-title');
          if (!table || !title) return null;
          const tw = table.getBoundingClientRect().width;
          const titleW = title.getBoundingClientRect().width;
          const detail = document.querySelector('tr.detail-row > td');
          return {
            tableW: tw,
            titleW,
            colspan: detail ? detail.colSpan : null,
            visibleCols: window.__REPORT_API__.visibleColCount(),
          };
        }"""
    )


@pytest.mark.e2e
def test_detail_open_does_not_shrink_table_or_title(tmp_path: Path):
    """Opening a detail row must keep table/Title width (colspan = visible cols)."""
    pytest.importorskip("playwright")
    from playwright.sync_api import sync_playwright

    findings = [
        _finding(
            cve_id="CVE-2024-1",
            device_uuid="d1",
            device_ip="10.0.0.1",
            cvss_base=9.8,
            summary="A reasonably long title so the Title column has something to measure against.",
            hidden_reasons=["Below CVSS floor"],
        ),
        _finding(cve_id="CVE-2024-2", device_uuid="d1", device_ip="10.0.0.1", cvss_base=5.0),
    ]
    html = build_html_report(findings=findings, filter_line="All networks (no filters)")
    path = tmp_path / "width.html"
    path.write_text(html, encoding="utf-8")

    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page(viewport={"width": 1400, "height": 900})
        page.goto(path.as_uri())
        page.locator(".group-head").first.click()
        page.wait_for_selector("table.findings tbody tr.row")
        before = _table_title_metrics(page)
        assert before and before["tableW"] > 1000
        assert before["titleW"] > 300
        # device grouping hides device+network → 9 visible of 11
        assert before["visibleCols"] == 9

        page.locator("table.findings tbody tr.row").first.click()
        page.wait_for_selector("tr.detail-row")
        after = _table_title_metrics(page)
        assert after["colspan"] == 9
        assert abs(after["tableW"] - before["tableW"]) < 2
        assert abs(after["titleW"] - before["titleW"]) < 2

        # Short badge text with full reason in tooltip
        tip = page.locator(".col-state .hidden-reason").first.get_attribute("title")
        text = page.locator(".col-state .hidden-reason").first.inner_text()
        assert tip == "Below CVSS floor"
        assert text == "Below floor"
        browser.close()
