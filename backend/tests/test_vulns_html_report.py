"""Unit tests for the self-contained HTML vulnerability report builder."""

from __future__ import annotations

from datetime import datetime, timezone

from app.core.vuln.filters import FindingFilters
from app.core.vuln.html_report import (
    build_html_report,
    compute_stats,
    finding_dict,
    format_filter_line,
)


def test_format_filter_line_matches_print_wording():
    assert format_filter_line(FindingFilters()) == "All networks (no filters)"
    assert format_filter_line(FindingFilters(q="openssh")) == 'Search: "openssh" · Includes hidden'
    assert (
        format_filter_line(FindingFilters(q="openssh", only_hidden=True))
        == 'Search: "openssh" · Only hidden'
    )
    assert (
        format_filter_line(
            FindingFilters(network_id="1", q="2024", only_hidden=True),
            network_name="Lab Alpha",
        )
        == 'network: Lab Alpha · Search: "2024" · Only hidden'
    )


def test_build_html_report_escapes_and_embeds_json():
    findings = [
        finding_dict(
            cve_id="CVE-2024-1",
            device_uuid="u1",
            device_ip="10.99.0.1",
            device_hostname='</script><script>alert(1)</script>',
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
            summary='Title with <b>html</b> & "quotes"',
            first_seen_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
            matched_at=datetime(2026, 1, 2, tzinfo=timezone.utc),
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
    stats = compute_stats(findings)
    assert stats.findings_total == 1
    assert stats.kev_count == 1
    assert stats.device_count == 1
    assert stats.severity_counts["critical"] == 1
