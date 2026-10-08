"""Facts-only display, per-device port profiles and per-host scan failure reasons."""
from __future__ import annotations

from app.api.common import device_summary, port_out
from app.api.dashboard import exposed_ports
from app.core.compare import describe_service
from app.netutils import PortScope
from app.scanner.known_ports import PORT_PROFILES, STANDARD_EXTRA_TCP_PORTS
from app.scanner.nmap_parser import ParsedRun
from app.scanner.nmap_scanner import exit_reason
from app.scanner.types import PortObservation, PortProfile, ScanContext

from .helpers import ScriptedScanner, device_by_ip, event_types, host, make_network, port, scan
from .test_scanner import _fake_nmap, _obs

TRUENAS = PORT_PROFILES["truenas"]
APP_PORT = next(p for p in TRUENAS if p not in STANDARD_EXTRA_TCP_PORTS)  # a catalog port outside the standard scope


def _guess(n: int, service: str) -> PortObservation:
    return PortObservation(port=n, service=service, method="table", confidence=3, version_checked=True)


def test_port_table_guess_and_tcpwrapped_are_not_shown_as_service_names(db):
    net = make_network(db)
    wrapped = PortObservation(port=53, service="tcpwrapped", method="probed", confidence=8, version_checked=True)
    scan(ScriptedScanner([host("10.0.0.1", [port(22, "ssh", "OpenSSH", "9.6"), _guess(6668, "irc"), wrapped])]),
         network_id=net.id)
    d = device_by_ip(db, "10.0.0.1")
    shown = {p.port: port_out(p)["service"] for p in d.ports}
    assert shown == {22: "ssh", 53: "open, no response", 6668: "unknown"}
    assert {p["port"]: p["service"] for p in device_summary(d)["open_ports"]} == shown
    assert {r["port"]: r["service"] for r in exposed_ports(db)}[6668] == "unknown"
    assert describe_service("irc", None, None, "table") == "unknown"
    assert describe_service("http", "nginx", "1.24", "probed") == "nginx 1.24 (http)"
    assert next(p for p in d.ports if p.port == 6668).service == "irc"  # raw value kept, only display changes


def test_truenas_ports_only_for_verified_devices(db):
    net = make_network(db)
    nas = host("10.0.0.5", [port(443, "https"), port(APP_PORT, "http")], hostname="truenas.example")
    other = host("10.0.0.6", [port(22, "ssh"), port(APP_PORT, "http")])
    sc = ScriptedScanner([nas, other])
    scan(sc, network_id=net.id)
    assert sc.extra_ports == [()]  # nothing verified before the first scan
    d = device_by_ip(db, "10.0.0.5")
    assert (d.port_profile, d.port_profile_source) == ("truenas", "hostname")
    assert device_by_ip(db, "10.0.0.6").port_profile is None

    sc = ScriptedScanner([nas, other])
    s = scan(sc, network_id=net.id)
    assert event_types(db, s.id) == []  # first scan covering the profile ports records them silently
    by_batch = dict(zip((tuple(b) for b in sc.port_targets), sc.extra_ports, strict=True))
    assert by_batch == {("10.0.0.6",): (), ("10.0.0.5",): TRUENAS}
    assert APP_PORT in {p.port for p in device_by_ip(db, "10.0.0.5").ports if p.is_open}
    assert APP_PORT not in {p.port for p in device_by_ip(db, "10.0.0.6").ports}

    # The profile port was covered last time, so its closing is a real change on that device only.
    s = scan(ScriptedScanner([host("10.0.0.5", [port(443, "https")], hostname="truenas.example"), other]),
             network_id=net.id)
    assert event_types(db, s.id) == ["port_closed"]


def test_admin_none_profile_beats_auto_detection(db):
    net = make_network(db)
    nas = host("10.0.0.5", [port(443, "https")], hostname="truenas.example")
    scan(ScriptedScanner([nas]), network_id=net.id)
    d = device_by_ip(db, "10.0.0.5")
    d.port_profile, d.port_profile_source = "none", "manual"
    db.commit()
    sc = ScriptedScanner([nas])
    scan(sc, network_id=net.id)
    assert sc.extra_ports == [()] and device_by_ip(db, "10.0.0.5").port_profile == "none"


def test_scan_failure_reason_recorded_then_cleared(db):
    net = make_network(db)
    hosts = [host("10.0.0.1", [port(22, "ssh")])]
    scan(ScriptedScanner(hosts), network_id=net.id)
    failed = scan(ScriptedScanner(hosts, fail_ports=True), network_id=net.id)
    d = device_by_ip(db, "10.0.0.1")
    assert d.port_scan_failed and "simulated port scan failure" in d.scan_failure
    assert d.scan_failure_scan_id == failed.id
    assert device_summary(d)["scan_failure"] == d.scan_failure
    scan(ScriptedScanner(hosts), network_id=net.id)
    d = device_by_ip(db, "10.0.0.1")
    assert not d.port_scan_failed and d.scan_failure is None and d.scan_failure_scan_id is None


def test_profile_ports_scanned_but_not_in_scan_wide_scope(monkeypatch):
    portmap = ParsedRun(hosts=[_obs("10.0.0.5", (22, "OpenSSH"))], port_scope="ignored")
    sc, calls = _fake_nmap(monkeypatch, portmap)
    res = sc.scan_ports(["10.0.0.5"], PortProfile(full=False, extra_ports=TRUENAS), ScanContext(1))
    args = calls[0][0]
    assert APP_PORT in PortScope(args[args.index("-p") + 1])
    assert APP_PORT not in PortScope(res.port_scope) and res.extra_ports == TRUENAS


def test_host_missing_from_port_scan_is_reported_down(monkeypatch):
    sc, _ = _fake_nmap(monkeypatch, ParsedRun(hosts=[], port_scope="22"))
    h = sc.scan_ports(["10.0.0.8"], PortProfile(full=False), ScanContext(1)).hosts[0]
    assert h.port_scan_failed and h.failure_reason.startswith("host down during the port scan")


def test_exit_reason_names_external_stops():
    assert "interrupted" in exit_reason(3221225786)
    assert exit_reason(-9) == "killed by signal 9"
    assert exit_reason(1) == "exited with code 1"
