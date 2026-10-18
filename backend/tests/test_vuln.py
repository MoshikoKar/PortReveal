"""Vulnerability core (spec section 5): CPE<->CVE matching, risk scoring, feed sync."""
from __future__ import annotations

import gzip
import json
from datetime import datetime, timedelta, timezone

import pytest

from app.core.vuln import match, score, sync
from app.core.vuln import summary as vuln_summary
from app.models import (
    VULN_STATE_CONFIRMED,
    VULN_STATE_DISMISSED,
    VULN_STATE_POTENTIAL,
    DevicePortVuln,
    VulnCpeMatch,
    VulnDailySnapshot,
    Vulnerability,
    VulnFeedState,
    VulnFindingLifecycle,
)
from app.settings_store import VulnSettings

from .helpers import ScriptedScanner, device_by_ip, host, make_network, port, scan

T = datetime(2026, 1, 20, tzinfo=timezone.utc)


# --- match.py: CPE normalization & version comparison ---------------------------------------------
def test_normalize_cpe_22_to_23():
    assert match.normalize_cpe("cpe:/a:openbsd:openssh:7.4") == "cpe:2.3:a:openbsd:openssh:7.4:*:*:*:*:*:*:*"
    assert match.normalize_cpe("cpe:2.3:a:openbsd:openssh:7.4:*:*:*:*:*:*:*") == \
        "cpe:2.3:a:openbsd:openssh:7.4:*:*:*:*:*:*:*"
    assert match.normalize_cpe("not a cpe") is None


def test_cpe_vendor_product_and_version():
    cpe = "cpe:2.3:a:openbsd:openssh:7.4:*:*:*:*:*:*:*"
    assert match.cpe_vendor_product(cpe) == ("openbsd", "openssh")
    assert match.cpe_version(cpe) == "7.4"
    wildcard = "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*"
    assert match.cpe_version(wildcard) is None
    assert match.cpe_vendor_product("cpe:2.3:a:*:*:*:*:*:*:*:*:*:*") is None


def test_compare_versions_and_range():
    assert match.compare_versions("7.4", "7.4") == 0
    assert match.compare_versions("7.4", "7.10") < 0  # numeric token compare, not lexical
    assert match.compare_versions("8.9p1", "8.9") > 0
    assert match.version_in_range("7.0", "4.4", True, "7.5", False)
    assert not match.version_in_range("7.5", "4.4", True, "7.5", True)  # exclusive end: 7.5 excluded
    assert match.version_in_range("7.5", "4.4", True, "7.5", False)  # inclusive end: 7.5 included
    assert not match.version_in_range("4.3", "4.4", True, None, None)  # before inclusive start


def test_match_port_cpes_range_confirmed_vs_potential(db):
    v = Vulnerability(cve_id="CVE-2024-0001", cvss_base=7.5)
    db.add(v)
    db.flush()  # the vulnerabilities row must exist before vuln_cpe_match can FK-reference it
    db.add(VulnCpeMatch(cve_id=v.cve_id, cpe23="cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*",
                        vendor_product="openbsd:openssh", version_start="4.4", version_start_incl=True,
                        version_end="7.5", version_end_excl=True))
    db.commit()

    # Reliable identification with an in-range version: confirmed.
    results = match.match_port_cpes(db, "cpe:/a:openbsd:openssh", "7.4", "probed", 10)
    assert [r.state for r in results] == [VULN_STATE_CONFIRMED]
    assert results[0].cve_id == "CVE-2024-0001"

    # Weak/guessed identification: same version evidence, but not `confirmed`.
    results = match.match_port_cpes(db, "cpe:/a:openbsd:openssh", "7.4", "table", 3)
    assert [r.state for r in results] == [VULN_STATE_POTENTIAL]

    # Out of range: no match at all.
    assert match.match_port_cpes(db, "cpe:/a:openbsd:openssh", "9.0", "probed", 10) == []

    # No version evidence at all and the CVE needs a range: cannot say either way.
    assert match.match_port_cpes(db, "cpe:/a:openbsd:openssh", None, "probed", 10) == []


def test_match_port_cpes_pinned_version(db):
    v = Vulnerability(cve_id="CVE-2024-0002", cvss_base=5.0)
    db.add(v)
    db.flush()
    db.add(VulnCpeMatch(cve_id=v.cve_id, cpe23="cpe:2.3:a:acme:widget:1.2:*:*:*:*:*:*:*",
                        vendor_product="acme:widget"))
    db.commit()
    assert [r.state for r in match.match_port_cpes(db, "cpe:/a:acme:widget:1.2", None, "probed", 10)] == \
        [VULN_STATE_CONFIRMED]  # pinned directly in the nmap CPE: exact evidence
    assert match.match_port_cpes(db, "cpe:/a:acme:widget:1.3", None, "probed", 10) == []


def test_match_port_cpes_generic_product_is_always_potential(db):
    v = Vulnerability(cve_id="CVE-2024-0003")
    db.add(v)
    db.flush()
    db.add(VulnCpeMatch(cve_id=v.cve_id, cpe23="cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*",
                        vendor_product="acme:widget"))
    db.commit()
    # Even with a confident, specific version, a product-wide CVE (no range, no pin) never confirms.
    results = match.match_port_cpes(db, "cpe:/a:acme:widget:9.9", None, "probed", 10)
    assert [r.state for r in results] == [VULN_STATE_POTENTIAL]


def test_sync_port_matches_preserves_dismissed_and_removes_stale(db):
    net = make_network(db)
    scan(ScriptedScanner([host("10.0.0.1", [port(22, "ssh", "OpenSSH", "7.4")], mac="00:11:22:33:44:01")]),
         network_id=net.id)
    d = device_by_ip(db, "10.0.0.1")
    p = next(pp for pp in d.ports if pp.port == 22)
    p.cpe = "cpe:/a:openbsd:openssh:7.4"
    db.add(Vulnerability(cve_id="CVE-2024-0001", cvss_base=7.5))
    db.flush()
    db.add(VulnCpeMatch(cve_id="CVE-2024-0001", cpe23="cpe:2.3:a:openbsd:openssh:7.4:*:*:*:*:*:*:*",
                        vendor_product="openbsd:openssh"))
    db.commit()

    stats = match.sync_port_matches(db, [p], now=T)
    db.commit()
    assert stats["matched"] == 1
    row = db.query(DevicePortVuln).filter_by(device_port_id=p.id, cve_id="CVE-2024-0001").one()
    assert row.state == VULN_STATE_CONFIRMED

    # Dismiss it, then rematch: dismissal survives.
    row.state = VULN_STATE_DISMISSED
    db.commit()
    match.sync_port_matches(db, [p], now=T)
    db.commit()
    row = db.query(DevicePortVuln).filter_by(device_port_id=p.id, cve_id="CVE-2024-0001").one()
    assert row.state == VULN_STATE_DISMISSED

    # The device is patched past the vulnerable range: the stale (non-dismissed) match would be
    # removed, but this one stays dismissed, so it is left alone rather than resurrected or deleted.
    p.version = "9.0"
    db.commit()
    match.sync_port_matches(db, [p], now=T)
    db.commit()
    assert db.query(DevicePortVuln).filter_by(device_port_id=p.id, cve_id="CVE-2024-0001").one().state == \
        VULN_STATE_DISMISSED


def test_sync_port_matches_removes_stale_non_dismissed(db):
    net = make_network(db)
    scan(ScriptedScanner([host("10.0.0.1", [port(22, "ssh", "OpenSSH", "7.4")], mac="00:11:22:33:44:01")]),
         network_id=net.id)
    d = device_by_ip(db, "10.0.0.1")
    p = next(pp for pp in d.ports if pp.port == 22)
    p.cpe = "cpe:/a:openbsd:openssh:7.4"
    db.add(Vulnerability(cve_id="CVE-2024-0001", cvss_base=7.5))
    db.flush()
    db.add(VulnCpeMatch(cve_id="CVE-2024-0001", cpe23="cpe:2.3:a:openbsd:openssh:7.4:*:*:*:*:*:*:*",
                        vendor_product="openbsd:openssh"))
    db.commit()
    match.sync_port_matches(db, [p], now=T)
    db.commit()
    assert db.query(DevicePortVuln).filter_by(device_port_id=p.id).count() == 1

    # Rescanned with a newer version: nmap's own CPE string is the version evidence (not the
    # separate free-text DevicePort.version field), so it is what needs to change here.
    p.cpe = "cpe:/a:openbsd:openssh:9.0"
    db.commit()
    match.sync_port_matches(db, [p], now=T)
    db.commit()
    assert db.query(DevicePortVuln).filter_by(device_port_id=p.id).count() == 0


# --- score.py ---------------------------------------------------------------------------------------
def test_vuln_score_cvss_default_and_epss_multiplier():
    plain = score.VulnRow("CVE-1", cvss_base=5.0, epss_percentile=None, kev=False, state=VULN_STATE_CONFIRMED)
    assert round(score.vuln_score(plain)) == 24  # soft-compress(10 * 5.0)
    low_epss = score.VulnRow("CVE-1", cvss_base=5.0, epss_percentile=0.0, kev=False, state=VULN_STATE_CONFIRMED)
    assert round(score.vuln_score(low_epss)) == 15  # soft-compress(50 * 0.6)
    high_epss = score.VulnRow("CVE-1", cvss_base=5.0, epss_percentile=1.0, kev=False, state=VULN_STATE_CONFIRMED)
    assert round(score.vuln_score(high_epss)) == 24  # soft-compress(50 * 1.0)
    missing_cvss = score.VulnRow("CVE-1", cvss_base=None, epss_percentile=None, kev=False, state=VULN_STATE_CONFIRMED)
    assert round(score.vuln_score(missing_cvss)) == 24  # default CVSS 5.0


def test_vuln_score_kev_floor_and_potential_discount():
    kev = score.VulnRow("CVE-1", cvss_base=3.0, epss_percentile=None, kev=True, state=VULN_STATE_CONFIRMED)
    # Weak KEV: raw floored to KEV_FLOOR (medium threshold), then soft-compressed.
    assert round(score.vuln_score(kev)) == round(score._compress(max(30 * 1.5, float(score.KEV_FLOOR))))
    strong_kev = score.VulnRow("CVE-1", cvss_base=9.0, epss_percentile=None, kev=True, state=VULN_STATE_CONFIRMED)
    pts = score.vuln_score(strong_kev)
    assert 40 < pts < 70  # soft-compress(135); one KEV is not near 100
    potential = score.VulnRow("CVE-1", cvss_base=10.0, epss_percentile=None, kev=False, state=VULN_STATE_POTENTIAL)
    assert round(score.vuln_score(potential)) == 24  # soft-compress(50)


def test_compute_risk_worst_dominates_with_residual_saturation():
    vulns = [
        score.VulnRow("CVE-1", 9.8, None, True, VULN_STATE_CONFIRMED),
        score.VulnRow("CVE-2", 9.0, None, True, VULN_STATE_CONFIRMED),
        score.VulnRow("CVE-3", 5.0, None, False, VULN_STATE_CONFIRMED),
    ]
    risk, factors = score.compute_risk(vulns)
    # Two KEVs clear high; residual saturation still keeps the total well below 100.
    assert score.risk_band_for_score(score.combine(risk, 0)) == "high"
    assert risk < 90
    assert factors[0]["factor"] == "CVE-1"


def test_compute_risk_empty_is_zero():
    assert score.compute_risk([]) == (0, [])


def test_compute_risk_caps_at_five_vulnerabilities():
    many = [score.VulnRow(f"CVE-{i}", 2.0, None, False, VULN_STATE_CONFIRMED) for i in range(10)]
    risk, factors = score.compute_risk(many)
    assert len(factors) == 5
    assert 0 < risk < 40  # five mild findings stay well below the high band


def test_combine_uses_exposure_headroom_not_multiply_to_ceiling():
    assert score.combine(60, 0) == 60
    assert score.combine(60, 100) == 65
    assert score.combine(80, 100) == 82
    # Mid-risk + max exposure must not jump to 100 / high.
    assert score.combine(50, 100) < 70
    assert score.risk_band_for_score(score.combine(50, 100)) == "medium"


def test_single_kev_lands_in_medium_band():
    """A lone KEV should not clear the high band — that needs more findings."""
    risk, _ = score.compute_risk([
        score.VulnRow("CVE-KEV", 9.8, None, True, VULN_STATE_CONFIRMED),
    ])
    assert score.risk_band_for_score(score.combine(risk, 0)) == "medium"
    assert score.risk_band_for_score(score.combine(risk, 100)) == "medium"


def test_apply_risk_scores_end_to_end(db):
    net = make_network(db)
    scan(ScriptedScanner([host("10.0.0.1", [port(22, "ssh", "OpenSSH", "7.4")], mac="00:11:22:33:44:01")]),
         network_id=net.id)
    d = device_by_ip(db, "10.0.0.1")
    p = next(pp for pp in d.ports if pp.port == 22)
    db.add(Vulnerability(cve_id="CVE-2024-0009", cvss_base=9.0, kev=True))
    db.add(DevicePortVuln(device_port_id=p.id, cve_id="CVE-2024-0009", state=VULN_STATE_CONFIRMED, matched_at=T))
    db.commit()

    score.apply_risk_scores(db, [d.id], now=T)
    db.commit()
    d = device_by_ip(db, "10.0.0.1")
    assert 30 <= d.risk_score < 60  # single KEV → medium band after residual weight
    assert d.combined_score == score.combine(d.risk_score, d.exposure_score)
    assert d.risk_scored_at is not None
    assert d.profile.risk_factors[0]["factor"] == "CVE-2024-0009"


def test_apply_risk_scores_spread_devices_across_combined_bands(db):
    """Two KEVs → high; one KEV → medium; one mild → low."""
    net = make_network(db)
    scan(ScriptedScanner([
        host("10.0.0.1", [port(22, "ssh", "OpenSSH", "7.4")], mac="00:11:22:33:44:01"),
        host("10.0.0.2", [port(80, "http", "nginx", "1.24.0")], mac="00:11:22:33:44:02"),
        host("10.0.0.3", [port(443, "https", "Apache httpd", "2.4.57")], mac="00:11:22:33:44:03"),
    ]), network_id=net.id)
    d_high, d_med, d_low = (device_by_ip(db, ip) for ip in ("10.0.0.1", "10.0.0.2", "10.0.0.3"))
    p_high = next(p for p in d_high.ports if p.port == 22)
    p_med = next(p for p in d_med.ports if p.port == 80)
    p_low = next(p for p in d_low.ports if p.port == 443)
    db.add_all([
        Vulnerability(cve_id="CVE-HIGH-A", cvss_base=9.8, kev=True),
        Vulnerability(cve_id="CVE-HIGH-B", cvss_base=9.0, kev=True),
        Vulnerability(cve_id="CVE-MED", cvss_base=9.8, kev=True),
        Vulnerability(cve_id="CVE-LOW", cvss_base=2.0, kev=False),
    ])
    db.add_all([
        DevicePortVuln(device_port_id=p_high.id, cve_id="CVE-HIGH-A", state=VULN_STATE_CONFIRMED, matched_at=T),
        DevicePortVuln(device_port_id=p_high.id, cve_id="CVE-HIGH-B", state=VULN_STATE_CONFIRMED, matched_at=T),
        DevicePortVuln(device_port_id=p_med.id, cve_id="CVE-MED", state=VULN_STATE_CONFIRMED, matched_at=T),
        DevicePortVuln(device_port_id=p_low.id, cve_id="CVE-LOW", state=VULN_STATE_CONFIRMED, matched_at=T),
    ])
    db.commit()
    score.apply_risk_scores(db, [d_high.id, d_med.id, d_low.id], now=T)
    db.commit()
    bands = {
        score.risk_band_for_score(device_by_ip(db, "10.0.0.1").combined_score),
        score.risk_band_for_score(device_by_ip(db, "10.0.0.2").combined_score),
        score.risk_band_for_score(device_by_ip(db, "10.0.0.3").combined_score),
    }
    assert bands == {"high", "medium", "low"}
    d_high = device_by_ip(db, "10.0.0.1")
    assert d_high.risk_score > 0 and d_high.combined_score == score.combine(d_high.risk_score, d_high.exposure_score)


def test_mock_lab_devices_spread_across_risk_bands(db):
    """Real Mock Lab inventory + match_all path should yield high 2 / medium 7 / low 0.

    A fresh ``npm run dev`` standard scan uses scenario step 0 (Tomcat appears only after the
    step advances). Real NVD-style version pinning gives most OpenSSH hosts a single KEV
    (medium); only srv-web01 (nginx KEV) and srv-intranet (httpd KEV) clear high. An overly
    dense universal-SSH-KEV fixture wrongly produced high 5 / medium 2 / low 2.
    """
    from collections import Counter

    from sqlalchemy import select

    from app.core.vuln.match import match_all
    from app.models import Device, DevicePort, DevicePortVuln, VulnCpeMatch
    from app.scanner.mock_scanner import MockScanner

    net = make_network(db, cidr="10.99.0.0/24", name="Mock Lab")
    scan(MockScanner([(net.id, "10.99.0.0/24", 0)]), network_id=net.id)

    def _vuln(cve_id, cvss, kev, vendor_product, ver_end):
        vendor, product = vendor_product.split(":", 1)
        db.add(Vulnerability(cve_id=cve_id, cvss_base=cvss, kev=kev))
        db.flush()
        db.add(VulnCpeMatch(
            cve_id=cve_id,
            cpe23=f"cpe:2.3:a:{vendor}:{product}:*:*:*:*:*:*:*:*",
            vendor_product=vendor_product,
            version_end=ver_end, version_end_excl=True,
        ))

    # Version-ranged rows (confirmed matches) shaped like a real cache: one shared OpenSSH KEV,
    # plus product KEVs that only apply to web01's nginx 1.24.0 and intranet's httpd 2.4.57.
    _vuln("CVE-SSH-KEV", 9.8, True, "openbsd:openssh", "10.0")
    _vuln("CVE-NGINX-KEV", 9.8, True, "f5:nginx", "1.25.0")
    _vuln("CVE-NGINX-MID", 7.5, False, "f5:nginx", "1.25.0")
    _vuln("CVE-HTTPD-KEV", 9.1, True, "apache:http_server", "2.4.58")
    _vuln("CVE-PG-MID", 5.5, False, "postgresql:postgresql", "16.0")
    _vuln("CVE-DNSMASQ-KEV", 9.0, True, "thekelleys:dnsmasq", "2.90")
    _vuln("CVE-SAMBA-MID", 6.5, False, "samba:samba", "4.20")
    db.commit()

    match_all(db, now=T)
    score.apply_risk_scores(db, list(db.scalars(select(Device.id))), now=T)
    db.commit()

    finding_devices = list(db.scalars(
        select(Device).where(Device.id.in_(
            select(DevicePort.device_id).join(DevicePortVuln).where(
                DevicePortVuln.state != VULN_STATE_DISMISSED,
            ).distinct()
        ))
    ).all())
    scores = {
        d.current_ip: (d.hostname, d.risk_score, d.combined_score, d.exposure_score)
        for d in finding_devices
    }
    assert len(finding_devices) == 9, scores
    bands = Counter(score.risk_band_for_score(d.combined_score) for d in finding_devices)
    assert dict(bands) == {"high": 2, "medium": 7}, scores
    high_ips = {
        d.current_ip for d in finding_devices
        if score.risk_band_for_score(d.combined_score) == "high"
    }
    assert high_ips == {"10.99.0.10", "10.99.0.12"}, scores
    assert score.risk_band_for_score(device_by_ip(db, "10.99.0.1").combined_score) == "medium"


# --- sync.py ---------------------------------------------------------------------------------------
NVD_PAYLOAD = {
    "totalResults": 1,
    "vulnerabilities": [{
        "cve": {
            "id": "CVE-2024-1111",
            "published": "2024-01-01T00:00:00.000",
            "lastModified": "2024-01-05T00:00:00.000",
            "descriptions": [{"lang": "en", "value": "A test vulnerability."}],
            "metrics": {"cvssMetricV31": [{"cvssData": {
                "baseScore": 8.1, "baseSeverity": "HIGH", "vectorString": "CVSS:3.1/AV:N",
            }}]},
            "configurations": [{"nodes": [{"cpeMatch": [{
                "vulnerable": True,
                "criteria": "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*",
                "versionStartIncluding": "4.4", "versionEndExcluding": "7.5",
            }]}]}],
        },
    }],
}


def test_parse_cve_item_extracts_cvss_and_cpe_ranges():
    data, matches = sync._parse_cve_item(NVD_PAYLOAD["vulnerabilities"][0])
    assert data["cve_id"] == "CVE-2024-1111"
    assert data["cvss_base"] == 8.1 and data["severity"] == "high"
    assert data["summary"] == "A test vulnerability."
    assert len(matches) == 1
    m = matches[0]
    assert m["vendor_product"] == "openbsd:openssh"
    assert m["version_start"] == "4.4" and m["version_start_incl"] is True
    assert m["version_end"] == "7.5" and m["version_end_excl"] is True


def test_upsert_cve_writes_vulnerability_and_cpe_matches(db):
    data, matches = sync._parse_cve_item(NVD_PAYLOAD["vulnerabilities"][0])
    sync.upsert_cve(db, data, matches)
    db.commit()
    v = db.get(Vulnerability, "CVE-2024-1111")
    assert v.cvss_base == 8.1
    assert db.query(VulnCpeMatch).filter_by(cve_id="CVE-2024-1111").count() == 1

    # Re-upserting with no matches replaces the old ones (not appends).
    sync.upsert_cve(db, data, [])
    db.commit()
    assert db.query(VulnCpeMatch).filter_by(cve_id="CVE-2024-1111").count() == 0


def test_sync_nvd_paginates_and_advances_cursor(db):
    first_modified = T - timedelta(days=3)
    second_modified = T - timedelta(days=1)
    first = json.loads(json.dumps(NVD_PAYLOAD["vulnerabilities"][0]))
    first["cve"]["lastModified"] = first_modified.strftime("%Y-%m-%dT%H:%M:%S.000")
    page1 = {"totalResults": 2, "vulnerabilities": [first]}
    second = json.loads(json.dumps(NVD_PAYLOAD["vulnerabilities"][0]))
    second["cve"]["id"] = "CVE-2024-2222"
    second["cve"]["lastModified"] = second_modified.strftime("%Y-%m-%dT%H:%M:%S.000")
    page2 = {"totalResults": 2, "vulnerabilities": [second]}
    calls = []

    def fetch(url, params, headers):
        calls.append(params["startIndex"])
        return json.dumps(page1 if params["startIndex"] == 0 else page2).encode()

    # A recent cursor keeps this to one 120-day window (a fresh/empty cache instead looks back
    # FULL_SYNC_LOOKBACK_DAYS, which would call this single-window fake fetch many times over).
    db.add(VulnFeedState(source="nvd", last_modified_cursor=(T - timedelta(days=10)).isoformat(),
                         record_count=0, mirror_complete=True))
    db.commit()
    cfg = VulnSettings(enabled=True)
    result = sync.sync_nvd(db, cfg, fetch=fetch, now=T, sleep=lambda _s: None)
    db.commit()
    assert result["count"] == 2 and result["error"] is None
    assert calls == [0, 1]  # second page requested because start_index(1) < totalResults(2)
    assert db.get(Vulnerability, "CVE-2024-1111") is not None
    assert db.get(Vulnerability, "CVE-2024-2222") is not None
    state = db.get(VulnFeedState, "nvd")
    assert state.last_synced_at == T
    assert state.last_modified_cursor.startswith(second_modified.strftime("%Y-%m-%d"))


def test_sync_nvd_records_error_without_raising(db):
    def fetch(url, params, headers):
        raise RuntimeError("network unreachable")

    cfg = VulnSettings(enabled=True)
    result = sync.sync_nvd(db, cfg, fetch=fetch, now=T, sleep=lambda _s: None)
    db.commit()
    assert result["error"] == "network unreachable"
    state = db.get(VulnFeedState, "nvd")
    assert state.last_error == "network unreachable"


KEV_PAYLOAD = {"vulnerabilities": [{"cveID": "CVE-2024-1111", "dateAdded": "2024-02-01"}]}


def test_sync_kev_flags_existing_and_creates_bare_row(db):
    db.add(Vulnerability(cve_id="CVE-2024-1111", cvss_base=8.1))
    db.commit()

    def fetch(url, params, headers):
        return json.dumps(KEV_PAYLOAD).encode()

    result = sync.sync_kev(db, fetch=fetch, now=T)
    db.commit()
    assert result["count"] == 1
    v = db.get(Vulnerability, "CVE-2024-1111")
    assert v.kev is True and v.kev_added_at is not None

    # A KEV CVE with no NVD row yet gets a bare placeholder (enriched by the next NVD sync).
    kev2 = {"vulnerabilities": [{"cveID": "CVE-2024-9999", "dateAdded": "2024-02-02"}]}

    def fetch2(url, params, headers):
        return json.dumps(kev2).encode()

    sync.sync_kev(db, fetch=fetch2, now=T)
    db.commit()
    bare = db.get(Vulnerability, "CVE-2024-9999")
    assert bare is not None and bare.kev is True and bare.cvss_base is None


def test_sync_epss_enriches_known_cves_only(db):
    db.add(Vulnerability(cve_id="CVE-2024-1111"))
    db.commit()
    csv_text = "#model_version:v2023.03.01\ncve,epss,percentile\nCVE-2024-1111,0.42,0.9\nCVE-UNKNOWN,0.1,0.1\n"
    gz = gzip.compress(csv_text.encode())

    def fetch(url, params, headers):
        return gz

    result = sync.sync_epss(db, fetch=fetch, now=T)
    db.commit()
    assert result["count"] == 1  # the unknown CVE is skipped (no NVD/KEV row to enrich)
    v = db.get(Vulnerability, "CVE-2024-1111")
    assert v.epss == pytest.approx(0.42) and v.epss_percentile == pytest.approx(0.9)
    assert db.get(Vulnerability, "CVE-UNKNOWN") is None


def test_sync_epss_handles_already_decompressed_body(db):
    db.add(Vulnerability(cve_id="CVE-2024-1111"))
    db.commit()
    csv_text = "cve,epss,percentile\nCVE-2024-1111,0.1,0.2\n"

    def fetch(url, params, headers):
        return csv_text.encode()  # some mirrors / test fixtures are not gzipped

    sync.sync_epss(db, fetch=fetch, now=T)
    db.commit()
    assert db.get(Vulnerability, "CVE-2024-1111").epss == pytest.approx(0.1)


def test_sync_due_disabled_offline_empty_and_interval(db):
    cfg = VulnSettings(enabled=False)
    assert sync.sync_due(db, cfg, now=T) is False
    cfg = VulnSettings(enabled=True, offline_mode=True)
    assert sync.sync_due(db, cfg, now=T) is False
    cfg = VulnSettings(enabled=True)
    assert sync.sync_due(db, cfg, now=T) is True  # empty cache: sync immediately

    db.add(Vulnerability(cve_id="CVE-2024-0001"))
    db.add(VulnFeedState(source="nvd", last_synced_at=T, record_count=1, mirror_complete=True))
    db.commit()
    assert sync.sync_due(db, cfg, now=T + timedelta(hours=1)) is False
    assert sync.sync_due(db, cfg, now=T + timedelta(hours=200)) is True  # past the 168h default


def test_sync_all_only_runs_configured_sources(db):
    calls = []

    def fetch(url, params, headers):
        calls.append(url)
        if "nvd" in url:
            return json.dumps({"totalResults": 0, "vulnerabilities": []}).encode()
        if "kev" in url.lower() or "cisa" in url:
            return json.dumps({"vulnerabilities": []}).encode()
        return gzip.compress(b"cve,epss,percentile\n")

    # Recent cursor: one 120-day window instead of a ~10-year first-sync crawl.
    db.add(VulnFeedState(source="nvd", last_modified_cursor=(T - timedelta(days=1)).isoformat(),
                         record_count=0, mirror_complete=True))
    db.commit()
    cfg = VulnSettings(enabled=True, sources=["nvd"])
    sync.sync_all(db, cfg, fetch=fetch, now=T)
    db.commit()
    assert len(calls) == 1 and sync.NVD_API_URL in calls[0]


def test_sync_and_rescore_matches_and_scores_after_sync(db):
    net = make_network(db)
    scan(ScriptedScanner([host("10.0.0.1", [port(22, "ssh", "OpenSSH", "4.5")], mac="00:11:22:33:44:01")]),
         network_id=net.id)
    d = device_by_ip(db, "10.0.0.1")
    p = next(pp for pp in d.ports if pp.port == 22)
    p.cpe = "cpe:/a:openbsd:openssh:4.5"
    db.commit()

    def fetch(url, params, headers):
        if sync.NVD_API_URL in url:
            return json.dumps({"totalResults": 1, "vulnerabilities": [NVD_PAYLOAD["vulnerabilities"][0]]}).encode() \
                if params["startIndex"] == 0 else json.dumps({"totalResults": 1, "vulnerabilities": []}).encode()
        if "cisa" in url:
            return json.dumps({"vulnerabilities": []}).encode()
        return gzip.compress(b"cve,epss,percentile\n")

    # Recent cursor: one 120-day window instead of a ~10-year first-sync crawl.
    db.add(VulnFeedState(source="nvd", last_modified_cursor=(T - timedelta(days=1)).isoformat(),
                         record_count=0, mirror_complete=True))
    db.commit()
    cfg = VulnSettings(enabled=True)
    sync.sync_and_rescore(db, cfg, fetch=fetch, now=T)
    db.commit()

    d = device_by_ip(db, "10.0.0.1")
    assert db.query(DevicePortVuln).filter_by(device_port_id=p.id, cve_id="CVE-2024-1111").one().state == \
        VULN_STATE_CONFIRMED
    assert d.risk_score > 0 and d.risk_scored_at is not None

    # Sync completion also maintains the finding lifecycle and the dashboard summary/snapshot.
    assert db.query(VulnFindingLifecycle).filter_by(cve_id="CVE-2024-1111").count() == 1
    assert db.query(VulnDailySnapshot).filter_by(network_id=None, snapshot_date=T.date()).count() == 1
    summary = vuln_summary.get_vuln_summary(db, now=T)
    assert summary["confirmed_count"] == 1


def _mirror_year_payload(year: int, cve_id: str) -> bytes:
    item = {
        "cve": {
            "id": cve_id,
            "published": f"{year}-01-01T00:00:00.000",
            "lastModified": f"{year}-06-01T00:00:00.000",
            "descriptions": [{"lang": "en", "value": f"test {cve_id}"}],
            "metrics": {"cvssMetricV31": [{"cvssData": {
                "baseScore": 5.0, "baseSeverity": "MEDIUM", "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
            }}]},
            "configurations": [],
        }
    }
    return gzip.compress(json.dumps({"vulnerabilities": [item]}).encode())


def test_sync_nvd_mirror_resumes_remaining_years_after_partial_failure(db, monkeypatch):
    """A mid-mirror failure must leave resume state so the next sync continues, not skip to API-only."""
    monkeypatch.setattr(sync, "NVD_MIRROR_START_YEAR", 2024)
    now = datetime(2025, 6, 15, tzinfo=timezone.utc)
    calls: list[str] = []

    def fetch_fail_second(url, params, headers):
        calls.append(url)
        if sync.NVD_API_URL in url:
            return json.dumps({"totalResults": 0, "vulnerabilities": []}).encode()
        if "nvdcve-2.0-2024" in url:
            return _mirror_year_payload(2024, "CVE-2024-MIRROR")
        if "nvdcve-2.0-2025" in url:
            raise RuntimeError("mirror year 2025 failed")
        if "modified" in url:
            return gzip.compress(json.dumps({"vulnerabilities": []}).encode())
        raise AssertionError(f"unexpected url {url}")

    cfg = VulnSettings(enabled=True, sources=["nvd"])
    result = sync.sync_nvd(db, cfg, fetch=fetch_fail_second, now=now, sleep=lambda _s: None)
    db.commit()
    assert result["error"]
    state = db.get(VulnFeedState, "nvd")
    assert state.mirror_complete is False
    assert state.mirror_next_year == 2025
    assert db.get(Vulnerability, "CVE-2024-MIRROR") is not None
    assert db.get(Vulnerability, "CVE-2025-MIRROR") is None
    # Cache is non-empty and a cursor may exist — the old bug skipped the mirror here.
    assert not sync.is_cache_empty(db)

    calls.clear()

    def fetch_resume(url, params, headers):
        calls.append(url)
        if sync.NVD_API_URL in url:
            return json.dumps({"totalResults": 0, "vulnerabilities": []}).encode()
        if "nvdcve-2.0-2024" in url:
            raise AssertionError("2024 already mirrored; must not re-fetch")
        if "nvdcve-2.0-2025" in url:
            return _mirror_year_payload(2025, "CVE-2025-MIRROR")
        if "modified" in url:
            return gzip.compress(json.dumps({"vulnerabilities": []}).encode())
        raise AssertionError(f"unexpected url {url}")

    result2 = sync.sync_nvd(db, cfg, fetch=fetch_resume, now=now, sleep=lambda _s: None)
    db.commit()
    assert result2["error"] is None
    state = db.get(VulnFeedState, "nvd")
    assert state.mirror_complete is True
    assert state.mirror_next_year is None
    assert db.get(Vulnerability, "CVE-2025-MIRROR") is not None
    assert any("nvdcve-2.0-2025" in u for u in calls)
    assert not any("nvdcve-2.0-2024" in u for u in calls)


def test_mirror_releases_writer_lock_between_years(db, monkeypatch):
    """Other writers (session touch, scan insert) must get the SQLite lock while the mirror runs."""
    import sqlite3

    monkeypatch.setattr(sync, "NVD_MIRROR_START_YEAR", 2024)
    now = datetime(2025, 6, 15, tzinfo=timezone.utc)
    path = db.get_bind().url.database
    writes: list[str] = []

    def other_writer() -> None:
        conn = sqlite3.connect(path, timeout=0.5)
        try:
            conn.execute("INSERT INTO app_settings (key, value, updated_at) VALUES (?, '1', '2025-06-15')",
                         (f"probe-{len(writes)}",))
            conn.commit()
            writes.append("ok")
        finally:
            conn.close()

    def fetch(url, params, headers):
        if sync.NVD_API_URL in url:
            return json.dumps({"totalResults": 0, "vulnerabilities": []}).encode()
        if "nvdcve-2.0-2025" in url or "modified" in url:
            other_writer()  # 2024 was ingested just before: its write must already be committed
            return _mirror_year_payload(2025, "CVE-2025-MIRROR") if "2025" in url else \
                gzip.compress(json.dumps({"vulnerabilities": []}).encode())
        if "nvdcve-2.0-2024" in url:
            return _mirror_year_payload(2024, "CVE-2024-MIRROR")
        raise AssertionError(f"unexpected url {url}")

    result = sync.sync_nvd(db, VulnSettings(enabled=True, sources=["nvd"]), fetch=fetch, now=now,
                           sleep=lambda _s: None)
    assert result["error"] is None
    assert writes == ["ok", "ok"]


def test_ingest_commits_in_batches(db, monkeypatch):
    monkeypatch.setattr(sync, "INGEST_COMMIT_BATCH", 2)
    commits: list[int] = []
    real_commit = db.commit
    monkeypatch.setattr(db, "commit", lambda: (commits.append(1), real_commit())[1])
    payload = {"vulnerabilities": [{"cve": {"id": f"CVE-2024-{i:04d}"}} for i in range(5)]}
    count, _ = sync._ingest_nvd_payload(db, payload)
    assert count == 5
    assert len(commits) == 3  # after rows 2 and 4, plus the final one


def test_sync_due_when_mirror_incomplete(db):
    db.add(Vulnerability(cve_id="CVE-2024-PARTIAL"))
    db.add(VulnFeedState(source="nvd", last_synced_at=T, record_count=1, mirror_complete=False,
                         mirror_next_year=2022))
    db.commit()
    cfg = VulnSettings(enabled=True)
    assert sync.sync_due(db, cfg, now=T + timedelta(hours=1)) is True


def test_parent_clears_summary_cache_when_sync_child_exits(db):
    """Child-process refresh only clears the child's cache; the parent must invalidate on reap.

    Repro shape: warm /api/vulns/summary, child sync updates VulnFeedState, status shows the new
    last_synced_at, but summary kept the old oldest_synced_at until TTL. sync_running() reaping
    the finished child (same path as the watcher after matching finishes) clears the parent cache.
    """
    from app.settings_store import put_section

    put_section(db, VulnSettings(enabled=True, sources=["nvd", "kev", "epss"]))
    old = T - timedelta(days=3)
    new = T - timedelta(hours=1)
    for source in ("nvd", "kev", "epss"):
        db.add(VulnFeedState(source=source, last_synced_at=old, record_count=0, mirror_complete=True))
    db.commit()
    vuln_summary.invalidate_vuln_summary_cache()
    warm = vuln_summary.get_vuln_summary(db, now=T)
    assert warm["feed"]["oldest_synced_at"] == old

    for source in ("nvd", "kev", "epss"):
        db.get(VulnFeedState, source).last_synced_at = new
    db.commit()
    # Still cached in this (parent) process — the bug before parent-side reap.
    assert vuln_summary.get_vuln_summary(db, now=T)["feed"]["oldest_synced_at"] == old

    class _DeadChild:
        def is_alive(self) -> bool:
            return False

        def join(self, timeout=None) -> None:
            return None

    sync._sync_process = _DeadChild()
    assert sync.sync_running() is False
    assert sync._sync_process is None
    fresh = vuln_summary.get_vuln_summary(db, now=T)
    assert fresh["feed"]["oldest_synced_at"] == new
