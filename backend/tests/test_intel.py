"""Inventory intelligence: rule tags, device types, exposure score, HTTP sync, watches, digest."""
from __future__ import annotations

from datetime import timedelta

import pytest
from sqlalchemy import event as sa_event
from sqlalchemy import select

from app.core import watches
from app.core.exposure import compute, level
from app.core.notify import _pending_all, format_daily_digest
from app.core.tagging import DeviceFacts, Service, apply_tags, classify, load_facts, normalize_tag
from app.core.watches import evaluate, evaluate_all
from app.core.web_capture import CaptureContext, run_web_capture
from app.db import utcnow
from app.models import (
    TAG_SOURCE_RULE,
    TAG_SOURCE_SUPPRESSED,
    Device,
    DeviceProfile,
    DeviceTag,
    Event,
    Network,
    PortHttp,
    SavedSearch,
    SavedSearchHit,
    WebCapture,
)
from app.settings_store import NotificationSettings

from .helpers import ScriptedScanner, device_by_ip, event_types, host, make_network, port, scan


def facts(ports: list[tuple], *, vendor=None, os_name=None, hostname=None, zone=None, first_seen=None) -> DeviceFacts:
    d = Device(current_ip="10.0.0.5", vendor=vendor, os_name=os_name, hostname=hostname,
               first_seen=first_seen or utcnow() - timedelta(days=30))
    net = Network(name="n", cidr="10.0.0.0/24", zone=zone)
    svcs = [Service(p[0], "tcp", p[1] if len(p) > 1 else None, p[2] if len(p) > 2 else None, None, None, None)
            for p in ports]
    return DeviceFacts(d, net, svcs)


# --- rules ---------------------------------------------------------------------------------------------
def test_rules_tag_and_pick_highest_priority_type():
    tags, dtype, confidence, evidence = classify(
        facts([(88, "kerberos-sec"), (389, "ldap"), (445, "microsoft-ds"), (3389, "ms-wbt-server")]))
    assert dtype == "domain-controller"
    assert {"domain-controller", "windows", "remote-access"} <= tags.keys()
    assert tags["domain-controller"] == "ports 88, 389, 445 open"
    assert confidence == 100 and evidence[0]["detail"] == "ports 88, 389, 445 open"

    tags, dtype, _, _ = classify(facts([(80, "http"), (9100, "jetdirect")]))
    assert dtype == "printer" and "web-server" in tags and tags["printer"] == "port 9100/tcp open"

    tags, dtype, _, _ = classify(facts([(443, "https", "nginx")], hostname="truenas01"))
    assert dtype == "nas" and tags["nas"] == "TrueNAS identified from host details"

    tags, dtype, _, _ = classify(facts([(11434, "http", "Ollama")]))
    assert dtype == "ai-llm" and tags["ai-llm"] == "product Ollama on 11434/tcp"

    tags, dtype, _, _ = classify(facts([(554, "rtsp")], vendor="Hangzhou Hikvision"))
    assert dtype == "camera"
    assert classify(facts([])) == ({}, None, 0, [])


def test_media_device_not_printer_or_camera_on_weak_ports():
    """Consumer AV: junk LPD + AirTunes RTSP + smart-TV product → media-device, not printer/camera."""
    tags, dtype, _, _ = classify(facts([
        (515, "tcpwrapped"),
        (7000, "rtsp", "AirTunes rtspd"),
        (3001, "http", "LG smart TV http service"),
    ]))
    assert dtype == "media-device"
    assert "media-device" in tags and "printer" not in tags and "camera" not in tags

    tags, dtype, _, _ = classify(facts([(8008, "http", "Chromecast"), (515, "tcpwrapped")]))
    assert dtype == "media-device" and "printer" not in tags

    tags, dtype, _, _ = classify(facts([(8060, "http", "Roku")], hostname="roku-living-room"))
    assert dtype == "media-device"


def test_weak_evidence_alone_does_not_set_high_stakes_type():
    assert classify(facts([(515, "tcpwrapped")])) == ({}, None, 0, [])
    assert classify(facts([(631, "tcpwrapped")])) == ({}, None, 0, [])
    tags, dtype, _, _ = classify(facts([(7000, "rtsp", "AirTunes rtspd")]))
    assert dtype == "media-device" and "camera" not in tags
    # Corroborated weak printer port still tags.
    tags, dtype, _, _ = classify(facts([(515, "printer")]))
    assert dtype == "printer" and tags["printer"].startswith("service")


def test_true_printer_and_camera_still_match():
    tags, dtype, _, _ = classify(facts([(9100, "jetdirect")]))
    assert dtype == "printer" and tags["printer"] == "port 9100/tcp open"
    tags, dtype, _, _ = classify(facts([(554, "rtsp")], vendor="Hangzhou Hikvision"))
    assert dtype == "camera"
    tags, dtype, _, _ = classify(facts([(8554, "rtsp", "Hikvision DS")]))
    assert dtype == "camera" and "camera" in tags


def test_low_confidence_classification_is_unknown_not_a_guess():
    """A bare HTTP port (web-server, priority 10) is real evidence but too weak to assert alone."""
    tags, dtype, confidence, evidence = classify(facts([(80, "http")]))
    assert dtype == "unknown"
    assert "web-server" in tags  # the tag still reflects the weak evidence
    assert 0 < confidence < 35
    assert evidence and evidence[0]["detail"]


def test_agreeing_signals_raise_confidence_over_a_single_signal():
    one_signal = classify(facts([(9100, "jetdirect")])).confidence
    two_signals = classify(facts([(9100, "jetdirect")], hostname="printer-lobby")).confidence
    assert two_signals > one_signal
    assert classify(facts([(9100, "jetdirect")], hostname="printer-lobby")).type == "printer"


def test_discovery_name_is_a_classification_signal():
    d = Device(current_ip="10.0.0.5", discovery_name="Synology DiskStation")
    net = Network(name="n", cidr="10.0.0.0/24")
    tags, dtype, confidence, _ = classify(DeviceFacts(d, net, []))
    assert dtype == "nas" and confidence > 0
    assert "nas" in tags and "synology" in tags["nas"].lower()


def test_snmp_sysdescr_is_a_classification_signal():
    f = facts([(161, "snmp")])
    f.services[0].snmp_descr = "Cisco IOS Software, C2960 Software"
    tags, dtype, confidence, _ = classify(f)
    assert dtype == "network-device" and confidence > 0
    assert "cisco" in tags["network-device"].lower()


def test_manual_tag_override_wins_over_computed_type(db):
    net = make_network(db)
    scan(ScriptedScanner([host("10.0.0.12", [port(9100, "jetdirect")], mac="02:00:00:00:00:12")]),
         network_id=net.id)
    d = device_by_ip(db, "10.0.0.12")
    assert d.device_type == "printer"  # computed, before any override

    db.add(DeviceTag(device_id=d.id, tag="camera", source="manual", reason="actually a camera"))
    db.commit()
    apply_tags(db, load_facts(db, [d.id]), now=utcnow(), report_ids=set())
    db.commit()
    db.expire_all()
    d = device_by_ip(db, "10.0.0.12")
    assert d.device_type == "camera" and d.type_confidence == 100
    prof = db.scalar(select(DeviceProfile).where(DeviceProfile.device_id == d.id))
    assert prof.type_evidence[0]["factor"] == "manual"

    # It persists across re-classification even though the port evidence still says "printer".
    apply_tags(db, load_facts(db, [d.id]), now=utcnow(), report_ids=set())
    db.commit()
    db.expire_all()
    assert device_by_ip(db, "10.0.0.12").device_type == "camera"


def test_suppressed_tag_skips_type_and_survives_reapply(db):
    net = make_network(db)
    scan(ScriptedScanner([host("10.0.0.9", [port(80, "http"), port(9100, "jetdirect")],
                               mac="02:00:00:00:00:09")]), network_id=net.id)
    d = device_by_ip(db, "10.0.0.9")
    assert d.device_type == "printer" and {t.tag for t in d.tags} >= {"printer", "web-server"}

    row = next(t for t in d.tags if t.tag == "printer")
    row.source, row.reason = TAG_SOURCE_SUPPRESSED, "dismissed by test"
    db.commit()

    facts_list = load_facts(db, [d.id])
    apply_tags(db, facts_list, now=utcnow(), report_ids=set())
    db.commit()
    db.expire_all()
    d = device_by_ip(db, "10.0.0.9")
    by = {t.tag: t.source for t in d.tags}
    assert by.get("printer") == TAG_SOURCE_SUPPRESSED
    # With printer suppressed, only the weak "web-server" signal remains (priority 10): too low
    # to confidently assert a type (spec 9.1/9.5), so it falls back to "unknown" rather than guess.
    assert d.device_type == "unknown" and d.type_confidence < 35
    assert "printer" not in {t.tag for t in d.tags if t.source == TAG_SOURCE_RULE}

    # Clearing suppress restores the rule on the next apply.
    db.delete(next(t for t in d.tags if t.tag == "printer"))
    db.commit()
    apply_tags(db, load_facts(db, [d.id]), now=utcnow(), report_ids=set())
    db.commit()
    db.expire_all()
    d = device_by_ip(db, "10.0.0.9")
    assert d.device_type == "printer"
    assert any(t.tag == "printer" and t.source == TAG_SOURCE_RULE for t in d.tags)


def test_normalize_tag():
    assert normalize_tag("  Lab Servers_2 ") == "lab-servers-2"
    assert normalize_tag("PCI--zone!") == "pci-zone"
    for bad in ("", "!!!", "x" * 61):
        with pytest.raises(ValueError):
            normalize_tag(bad)


# --- exposure -------------------------------------------------------------------------------------------
def test_exposure_factors_zone_boost_and_cap():
    score, factors = compute(facts([(23, "telnet"), (3306, "mysql"), (21, "ftp")]), [], utcnow())
    assert score == 65 and level(score) == "high"
    assert [f["factor"] for f in factors] == ["telnet", "mysql", "ftp"]

    score, factors = compute(facts([(3389, "ms-wbt-server"), (445, "microsoft-ds")], zone="users"), [], utcnow())
    by = {f["factor"]: f for f in factors}
    assert by["rdp"]["points"] == 38 and "users zone" in by["rdp"]["detail"]
    assert by["smb"]["points"] == 20  # file sharing is not boosted
    assert score == 58 and level(score) == "medium"

    f = facts([(23,), (2375,), (3389,), (5900,), (445,)], first_seen=utcnow())
    score, factors = compute(f, ["2375/tcp"], utcnow())
    assert score == 100 and {"new_host", "unique_service"} <= {x["factor"] for x in factors}
    assert level(10) == "low"


# --- local discovery (mDNS/SSDP/NetBIOS) enrichment, spec section 9.2 -------------------------------------
def test_enrich_local_names_writes_discovery_name_and_source(db, monkeypatch):
    from app.core import intel as intel_mod

    net = make_network(db)
    scan(ScriptedScanner([host("10.0.0.20", [port(445, "microsoft-ds")], mac="02:00:00:00:00:20")]),
         network_id=net.id)
    d = device_by_ip(db, "10.0.0.20")

    monkeypatch.setattr("app.core.discovery.collect_local_names",
                        lambda ips, **kw: {"10.0.0.20": ("OFFICE-PC", "netbios")})
    intel_mod._enrich_local_names(db, {d.id: d})
    db.commit()
    db.expire_all()
    d = device_by_ip(db, "10.0.0.20")
    assert (d.discovery_name, d.discovery_source) == ("OFFICE-PC", "netbios")


def test_enrich_local_names_skipped_when_discovery_disabled(db, monkeypatch):
    from app.core import intel as intel_mod
    from app.settings_store import DiscoverySettings, put_section

    put_section(db, DiscoverySettings(enabled=False))
    db.commit()
    net = make_network(db)
    scan(ScriptedScanner([host("10.0.0.21", [port(445, "microsoft-ds")], mac="02:00:00:00:00:21")]),
         network_id=net.id)
    d = device_by_ip(db, "10.0.0.21")

    called = []
    monkeypatch.setattr("app.core.discovery.collect_local_names", lambda ips, **kw: called.append(1) or {})
    intel_mod._enrich_local_names(db, {d.id: d})
    assert called == []
    assert device_by_ip(db, "10.0.0.21").discovery_name is None


def test_enrich_local_names_persists_across_quiet_pass_and_ages_out(db, monkeypatch):
    from datetime import timedelta

    from app.core import intel as intel_mod
    from app.db import utcnow

    net = make_network(db)
    scan(ScriptedScanner([host("10.0.0.22", [port(445, "microsoft-ds")], mac="02:00:00:00:00:22")]),
         network_id=net.id)
    d = device_by_ip(db, "10.0.0.22")

    monkeypatch.setattr("app.core.discovery.collect_local_names",
                        lambda ips, **kw: {"10.0.0.22": ("NAS-BOX", "mdns")})
    intel_mod._enrich_local_names(db, {d.id: d})
    db.commit()
    db.expire_all()
    d = device_by_ip(db, "10.0.0.22")
    assert (d.discovery_name, d.discovery_source) == ("NAS-BOX", "mdns")
    assert d.discovery_name_seen_at is not None
    heard_at = d.discovery_name_seen_at

    # Quiet pass: must keep the name (not wipe), and must not refresh seen_at.
    monkeypatch.setattr("app.core.discovery.collect_local_names", lambda ips, **kw: {})
    intel_mod._enrich_local_names(db, {d.id: d})
    db.commit()
    db.expire_all()
    d = device_by_ip(db, "10.0.0.22")
    assert (d.discovery_name, d.discovery_source) == ("NAS-BOX", "mdns")
    assert d.discovery_name_seen_at == heard_at

    # Past TTL: age out.
    d.discovery_name_seen_at = utcnow() - timedelta(days=intel_mod.DISCOVERY_NAME_TTL_DAYS + 1)
    db.commit()
    intel_mod._enrich_local_names(db, {d.id: d})
    db.commit()
    db.expire_all()
    d = device_by_ip(db, "10.0.0.22")
    assert d.discovery_name is None and d.discovery_source is None and d.discovery_name_seen_at is None


# --- scan pipeline ----------------------------------------------------------------------------------------
def test_scan_tags_and_scores_silently_then_reports_changes(db):
    net = make_network(db)
    hosts = [host("10.0.0.1", [port(22, "ssh"), port(80, "http")], mac="02:00:00:00:00:01")]
    s1 = scan(ScriptedScanner(hosts), network_id=net.id)
    assert event_types(db, s1.id) == []  # baseline: first classification is silent
    d = device_by_ip(db, "10.0.0.1")
    # "web-server" alone (priority 10) is too weak to assert confidently: falls back to "unknown".
    assert {t.tag for t in d.tags} == {"remote-access", "web-server"} and d.device_type == "unknown"
    assert d.classified_at is not None and d.exposure_score == 10  # new host
    db.add(DeviceTag(device_id=d.id, tag="keep-me", source="manual"))
    db.commit()

    hosts[0].ports = [port(80, "http"), port(3306, "mysql")]
    s2 = scan(ScriptedScanner(hosts), network_id=net.id)
    evs = [e for e in db.scalars(select(Event).where(Event.scan_id == s2.id)).unique() if e.event_type.startswith("tag_")]
    assert sorted((e.event_type, e.new_value or e.old_value) for e in evs) == [
        ("tag_added", "database"), ("tag_removed", "remote-access")]
    assert all(e.notify for e in evs)
    d = device_by_ip(db, "10.0.0.1")
    assert {t.tag for t in d.tags} == {"database", "keep-me", "web-server"} and d.device_type == "database"
    assert d.exposure_score == 30
    prof = db.scalar(select(DeviceProfile).where(DeviceProfile.device_id == d.id))
    assert {f["factor"] for f in prof.exposure_factors} == {"mysql", "new_host"}


def test_web_capture_fills_port_http_and_retags(db):
    net = make_network(db)
    scan(ScriptedScanner([host("10.0.0.11", [port(443, "https")])]), network_id=net.id)
    d = device_by_ip(db, "10.0.0.11")
    cap = WebCapture(targets="10.0.0.11")
    db.add(cap)
    db.commit()
    run_web_capture(cap.id, CaptureContext(cap.id))
    db.expire_all()
    h = db.scalar(select(PortHttp).where(PortHttp.device_id == d.id))
    assert (h.scheme, h.status, h.title, h.server, h.login, h.default_page) == (
        "https", 200, "VMware ESXi", "VMware ESXi", True, False)
    d = device_by_ip(db, "10.0.0.11")
    assert d.device_type == "hypervisor"
    prof = db.scalar(select(DeviceProfile).where(DeviceProfile.device_id == d.id))
    assert "http_login" in {f["factor"] for f in prof.exposure_factors}


def test_mock_lab_web_host_is_not_misclassified_as_hypervisor(db):
    """srv-web01-style last octet (.10) gets nginx mock HTML, not the ESXi scenario."""
    net = make_network(db, cidr="10.99.0.0/24", name="Mock Lab")
    scan(ScriptedScanner([
        host("10.99.0.10", [port(22, "ssh", "OpenSSH", "8.9p1"), port(443, "https", "nginx", "1.24.0")],
             mac="02:4E:01:00:02:10", hostname="srv-web01.net1.lab.local"),
    ]), network_id=net.id)
    d = device_by_ip(db, "10.99.0.10")
    cap = WebCapture(targets="10.99.0.10")
    db.add(cap)
    db.commit()
    run_web_capture(cap.id, CaptureContext(cap.id))
    db.expire_all()
    h = db.scalar(select(PortHttp).where(PortHttp.device_id == d.id))
    assert h is not None and h.title == "Welcome to nginx" and h.server == "nginx"
    d = device_by_ip(db, "10.99.0.10")
    assert d.device_type != "hypervisor"


# --- watches --------------------------------------------------------------------------------------------
def test_evaluate_all_loads_saved_searches_once(db):
    db.add_all([
        SavedSearch(name="SSH", query="port:22"),
        SavedSearch(name="HTTPS", query="port:443"),
        SavedSearch(name="RDP", query="port:3389"),
    ])
    db.commit()
    saved_search_selects: list[str] = []

    def record_saved_search_select(_conn, _cursor, statement, _parameters, _context, _executemany):
        if "FROM saved_searches" in statement:
            saved_search_selects.append(statement)

    bind = db.get_bind()
    sa_event.listen(bind, "before_cursor_execute", record_saved_search_select)
    try:
        assert evaluate_all(db) == 0
    finally:
        sa_event.remove(bind, "before_cursor_execute", record_saved_search_select)

    assert len(saved_search_selects) == 1


def test_watch_baselines_then_alerts_and_drops_stale_hits(db):
    net = make_network(db)
    a = host("10.0.0.1", [port(3389, "ms-wbt-server")], mac="02:00:00:00:00:01")
    b = host("10.0.0.2", [port(22, "ssh")], mac="02:00:00:00:00:02")
    scan(ScriptedScanner([a, b]), network_id=net.id)
    db.add_all([SavedSearch(name="RDP", query="port:3389"),
                SavedSearch(name="No telnet", query="port:23", kind="policy", alert=False),
                SavedSearch(name="Broken", query="nosuch:1")])
    db.commit()
    assert evaluate_all(db) == 0  # baseline
    db.commit()
    rdp, policy, broken = db.scalars(select(SavedSearch).order_by(SavedSearch.id)).all()
    assert rdp.initialized and rdp.last_count == 1 and broken.last_error == "unknown field 'nosuch'"

    b.ports = [port(3389, "ms-wbt-server"), port(23, "telnet")]
    s = scan(ScriptedScanner([a, b]), network_id=net.id)  # watches run after the scan
    assert s.status == "completed"
    db.expire_all()
    alerts = [e for e in db.scalars(select(Event)).unique() if e.event_type in ("watch_match", "policy_violation")]
    assert sorted((e.event_type, e.ip, e.notify) for e in alerts) == [
        ("policy_violation", "10.0.0.2", False), ("watch_match", "10.0.0.2", True)]
    assert db.get(SavedSearch, rdp.id).last_count == 2

    a.ports = [port(22, "ssh")]
    scan(ScriptedScanner([a, b]), network_id=net.id)
    db.expire_all()
    hits = db.scalars(select(SavedSearchHit.device_id).where(SavedSearchHit.search_id == rdp.id)).all()
    assert hits == [device_by_ip(db, "10.0.0.2").id]


def test_digest_always_includes_watch_alerts(db):
    net = make_network(db)
    scan(ScriptedScanner([host("10.0.0.1", [port(3389, "ms-wbt-server")])]), network_id=net.id)
    d = device_by_ip(db, "10.0.0.1")
    db.add(Event(device_id=d.id, event_type="watch_match", severity="high", ip=d.current_ip, new_value="RDP",
                 message="m", notify=True))
    db.commit()
    cfg = NotificationSettings(event_types=[])
    pending = _pending_all(db, cfg)
    assert [e.event_type for e in pending] == ["watch_match"]
    _, plain, html_body = format_daily_digest(pending)
    assert "Watches (1)" in plain and "Watch matches" in html_body and "RDP" in plain


def test_watch_evaluation_walks_matches_in_chunks(db, monkeypatch):
    monkeypatch.setattr(watches, "CHUNK", 2)  # force several chunks with a handful of hosts
    net = make_network(db)
    hosts = [host(f"10.0.0.{i}", [port(22, "ssh")], mac=f"02:00:00:00:00:{i:02x}") for i in range(1, 6)]
    scan(ScriptedScanner(hosts), network_id=net.id)
    db.add(SavedSearch(name="SSH", query="port:22"))
    db.commit()
    assert evaluate_all(db) == 0  # baseline: all five recorded silently
    db.commit()
    search = db.scalar(select(SavedSearch))
    assert search.last_count == 5
    assert len(db.scalars(select(SavedSearchHit).where(SavedSearchHit.search_id == search.id)).all()) == 5

    more = [host(f"10.0.0.{i}", [port(22, "ssh")], mac=f"02:00:00:00:00:{i:02x}") for i in range(6, 11)]
    scan(ScriptedScanner(hosts + more), network_id=net.id)  # watches run after the scan
    db.expire_all()
    alerts = sorted(e.ip for e in db.scalars(select(Event).where(Event.event_type == "watch_match")).unique())
    assert alerts == sorted(f"10.0.0.{i}" for i in range(6, 11))
    assert db.get(SavedSearch, search.id).last_count == 10


def test_monitor_baselines_then_alerts_matching_host_changes(db):
    net = make_network(db)
    a = host("10.0.0.1", [port(22, "ssh")], mac="02:00:00:00:00:01")
    b = host("10.0.0.2", [port(22, "ssh")], mac="02:00:00:00:00:02")
    scan(ScriptedScanner([a, b]), network_id=net.id)
    db.add(SavedSearch(name="Host 10.0.0.1", query="ip:10.0.0.1", kind="monitor"))
    db.commit()
    assert evaluate_all(db) == 0
    db.commit()
    search = db.scalar(select(SavedSearch))
    assert search.initialized and search.last_count == 1
    assert db.scalars(select(Event).where(Event.event_type == "monitor_change")).unique().all() == []

    a.ports = [port(22, "ssh"), port(445, "microsoft-ds")]
    b.ports = [port(22, "ssh"), port(445, "microsoft-ds")]
    s = scan(ScriptedScanner([a, b]), network_id=net.id)
    db.expire_all()
    alerts = list(db.scalars(select(Event).where(Event.event_type == "monitor_change")).unique())
    assert [(e.ip, e.port, e.notify, e.new_value) for e in alerts] == [
        ("10.0.0.1", 445, True, "Host 10.0.0.1")]
    assert alerts[0].old_value  # source event id, for idempotency
    assert "change watched by 'Host 10.0.0.1'" in alerts[0].message

    n = evaluate(db, db.get(SavedSearch, search.id), scan_id=s.id)
    assert n == 0
    assert len(db.scalars(select(Event).where(Event.event_type == "monitor_change")).unique().all()) == 1


def test_digest_always_includes_monitor_alerts(db):
    net = make_network(db)
    scan(ScriptedScanner([host("10.0.0.1", [port(22, "ssh")])]), network_id=net.id)
    d = device_by_ip(db, "10.0.0.1")
    db.add(Event(device_id=d.id, event_type="monitor_change", severity="high", ip=d.current_ip,
                 new_value="Host 10.0.0.1", old_value="1", message="m", notify=True))
    db.commit()
    cfg = NotificationSettings(event_types=[])
    pending = _pending_all(db, cfg)
    assert [e.event_type for e in pending] == ["monitor_change"]
    _, plain, html_body = format_daily_digest(pending)
    assert "Watches (1)" in plain and "Monitored changes" in html_body and "Host 10.0.0.1" in plain
