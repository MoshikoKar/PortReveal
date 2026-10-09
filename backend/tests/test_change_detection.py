"""Critical change-detection rules, driven through the real scan pipeline."""
from __future__ import annotations

from app.models import (
    DEVICE_ACTIVE,
    DEVICE_NOT_DETECTED,
    DEVICE_UNKNOWN,
    SCAN_COMPLETED,
    SCAN_FAILED,
    SCAN_PARTIAL,
    Network,
)
from app.settings_store import ScanSettings, put_section

from .helpers import ScriptedScanner, device_by_ip, devices, event_types, events, host, make_network, port, scan

MAC_A = "00:11:22:33:44:01"
MAC_B = "00:11:22:33:44:02"
MAC_C = "00:11:22:33:44:03"


def baseline_hosts():
    return [
        host("10.0.0.1", [port(22, "ssh", "OpenSSH", "8.9p1"), port(443, "https", "nginx", "1.24.0")],
             mac=MAC_A, hostname="srv-a.corp"),
        host("10.0.0.2", [port(3389, "ms-wbt-server", "Microsoft Terminal Services")], mac=MAC_B, hostname="ws-b.corp"),
    ]


def test_baseline_generates_no_events(db):
    net = make_network(db)
    s = scan(ScriptedScanner(baseline_hosts()), network_id=net.id)
    assert s.status == SCAN_COMPLETED
    assert s.is_baseline
    assert events(db) == []
    assert len(devices(db)) == 2
    db.expire_all()
    assert db.get(Network, net.id).baseline_scan_id == s.id


def test_scan_before_baseline_is_silent_until_baseline_exists(db):
    net = make_network(db)
    scan(ScriptedScanner(baseline_hosts()), scan_type="discovery", network_id=net.id)
    assert events(db) == []
    db.expire_all()
    assert db.get(Network, net.id).baseline_scan_id is None  # discovery never creates the baseline
    scan(ScriptedScanner(baseline_hosts()), network_id=net.id)
    assert events(db) == []


def test_new_host_detected(db):
    net = make_network(db)
    scan(ScriptedScanner(baseline_hosts()), network_id=net.id)
    hosts = baseline_hosts() + [host("10.0.0.3", [port(445, "microsoft-ds")], mac=MAC_C, hostname="ws-c.corp")]
    s = scan(ScriptedScanner(hosts), network_id=net.id)
    evs = events(db, s.id)
    assert [e.event_type for e in evs] == ["device_discovered"]
    assert "TCP/445" in evs[0].message
    assert evs[0].notify is True
    # the new host's ports are part of the discovery event, not separate port events
    assert device_by_ip(db, "10.0.0.3").ports[0].port == 445


def test_port_opened_closed_reopened_one_event_per_transition(db):
    net = make_network(db)
    base = baseline_hosts()
    scan(ScriptedScanner(base), network_id=net.id)  # baseline: 22, 443 open on A

    with_9000 = baseline_hosts()
    with_9000[0].ports.append(port(9000, "http", "Golang net/http server"))
    s1 = scan(ScriptedScanner(with_9000), network_id=net.id)
    assert event_types(db, s1.id) == ["port_opened"]

    s2 = scan(ScriptedScanner(with_9000), network_id=net.id)  # still open
    assert event_types(db, s2.id) == []

    s3 = scan(ScriptedScanner(baseline_hosts()), network_id=net.id)  # closes
    evs = events(db, s3.id)
    assert [e.event_type for e in evs] == ["port_closed"]
    assert evs[0].port == 9000

    s4 = scan(ScriptedScanner(baseline_hosts()), network_id=net.id)  # stays closed
    assert event_types(db, s4.id) == []

    s5 = scan(ScriptedScanner(with_9000), network_id=net.id)  # opens again -> new event
    assert event_types(db, s5.id) == ["port_opened"]


def test_service_and_version_changes(db):
    net = make_network(db)
    scan(ScriptedScanner(baseline_hosts()), network_id=net.id)
    changed = baseline_hosts()
    changed[0].ports = [port(22, "ssh", "OpenSSH", "9.6p1"), port(443, "https", "Apache httpd", "2.4.57")]
    s = scan(ScriptedScanner(changed), network_id=net.id)
    evs = {e.event_type: e for e in events(db, s.id)}
    assert set(evs) == {"service_changed", "version_changed"}
    assert "nginx" in evs["service_changed"].old_value and "Apache" in evs["service_changed"].new_value
    assert "8.9p1" in evs["version_changed"].old_value and "9.6p1" in evs["version_changed"].new_value


def test_unreliable_service_guess_does_not_create_change(db):
    net = make_network(db)
    scan(ScriptedScanner(baseline_hosts()), network_id=net.id)
    flaky = baseline_hosts()
    guess = port(443, "http", None, None)
    guess.method, guess.confidence = "table", 3
    flaky[0].ports = [port(22, "ssh", "OpenSSH", "8.9p1"), guess]
    s = scan(ScriptedScanner(flaky), network_id=net.id)
    assert event_types(db, s.id) == []
    p443 = next(p for p in device_by_ip(db, "10.0.0.1").ports if p.port == 443)
    assert p443.product == "nginx"  # reliable data is not downgraded


def test_ip_change_detected_by_mac(db):
    net = make_network(db)
    scan(ScriptedScanner(baseline_hosts()), network_id=net.id)
    moved = baseline_hosts()
    moved[1].ip = "10.0.0.50"
    s = scan(ScriptedScanner(moved), network_id=net.id)
    evs = events(db, s.id)
    assert [e.event_type for e in evs] == ["ip_changed"]
    assert evs[0].old_value == "10.0.0.2" and evs[0].new_value == "10.0.0.50"
    assert len(devices(db)) == 2
    d = device_by_ip(db, "10.0.0.50")
    assert {i.ip for i in d.ips} == {"10.0.0.2", "10.0.0.50"}


def test_ip_change_detected_by_hostname_without_mac(db):
    net = make_network(db)
    hosts = [host("10.0.0.7", [port(22, "ssh", "OpenSSH")], hostname="build-server.corp")]
    scan(ScriptedScanner(hosts), network_id=net.id)
    hosts[0].ip = "10.0.0.8"
    s = scan(ScriptedScanner(hosts), network_id=net.id)
    assert event_types(db, s.id) == ["ip_changed"]
    assert len(devices(db)) == 1


def test_ip_reused_by_different_machine_creates_new_device(db):
    net = make_network(db)
    scan(ScriptedScanner(baseline_hosts()), network_id=net.id)
    hosts = baseline_hosts()
    hosts[1] = host("10.0.0.2", [port(80, "http")], mac=MAC_C, hostname="printer.corp")
    s = scan(ScriptedScanner(hosts), network_id=net.id, )
    types = event_types(db, s.id)
    assert "device_discovered" in types
    assert "ip_changed" not in types
    assert len(devices(db)) == 3


def test_disappearance_needs_consecutive_misses_and_reappearance(db):
    net = make_network(db)
    scan(ScriptedScanner(baseline_hosts()), network_id=net.id)
    only_a = baseline_hosts()[:1]

    s1 = scan(ScriptedScanner(only_a), network_id=net.id)
    assert event_types(db, s1.id) == []
    assert device_by_ip(db, "10.0.0.2").status == DEVICE_UNKNOWN

    s2 = scan(ScriptedScanner(only_a), network_id=net.id)
    assert event_types(db, s2.id) == ["device_disappeared"]
    assert device_by_ip(db, "10.0.0.2").status == DEVICE_NOT_DETECTED

    s3 = scan(ScriptedScanner(only_a), network_id=net.id)
    assert event_types(db, s3.id) == []  # no duplicate disappearance

    s4 = scan(ScriptedScanner(baseline_hosts()), network_id=net.id)
    assert event_types(db, s4.id) == ["device_reappeared"]
    assert device_by_ip(db, "10.0.0.2").status == DEVICE_ACTIVE


def test_unknown_host_seen_again_is_silent(db):
    net = make_network(db)
    scan(ScriptedScanner(baseline_hosts()), network_id=net.id)
    scan(ScriptedScanner(baseline_hosts()[:1]), network_id=net.id)  # one miss -> unknown
    s = scan(ScriptedScanner(baseline_hosts()), network_id=net.id)
    assert event_types(db, s.id) == []
    assert device_by_ip(db, "10.0.0.2").status == DEVICE_ACTIVE


def test_failed_scan_preserves_previous_state(db):
    net = make_network(db)
    scan(ScriptedScanner(baseline_hosts()), network_id=net.id)
    s = scan(ScriptedScanner([], fail_all=True), network_id=net.id)
    assert s.status == SCAN_FAILED
    assert events(db) == []
    assert all(d.status == DEVICE_ACTIVE for d in devices(db))
    assert sum(1 for p in device_by_ip(db, "10.0.0.1").ports if p.is_open) == 2


def test_partial_scan_adds_but_never_removes(db, monkeypatch):
    net = make_network(db, cidr="10.0.0.0/23")
    put_section(db, ScanSettings(discovery_chunk_size=256, parallelism=1))  # deterministic chunk order
    db.commit()
    scan(ScriptedScanner(baseline_hosts()), network_id=net.id)
    # First discovery chunk (10.0.0.0/24) fails, host A's port 443 'closes', new host in second chunk
    hosts = [host("10.0.1.9", [port(80, "http")], mac=MAC_C)]
    s = scan(ScriptedScanner(hosts, fail_discovery=True), network_id=net.id)
    assert s.status == SCAN_PARTIAL
    assert event_types(db, s.id) == ["device_discovered"]  # additions still recorded
    assert {d.current_ip: d.status for d in devices(db)}["10.0.0.2"] == DEVICE_ACTIVE  # no removals


def test_port_scan_failure_marks_host_without_closing_ports(db):
    net = make_network(db)
    scan(ScriptedScanner(baseline_hosts()), network_id=net.id)
    s = scan(ScriptedScanner(baseline_hosts(), fail_ports=True), network_id=net.id)
    assert s.status == SCAN_PARTIAL
    assert event_types(db, s.id) == []
    a = device_by_ip(db, "10.0.0.1")
    assert a.port_scan_failed is True
    assert sum(1 for p in a.ports if p.is_open) == 2


def test_mass_disappearance_guard(db):
    net = make_network(db)
    many = [host(f"10.0.0.{i}", [port(22, "ssh")], mac=f"00:11:22:33:55:{i:02X}") for i in range(1, 31)]
    scan(ScriptedScanner(many), network_id=net.id)
    s = scan(ScriptedScanner(many[:2]), network_id=net.id)  # 28 of 30 vanish at once
    assert s.status == SCAN_PARTIAL
    assert "Mass-change guard" in (s.notes or "")
    assert event_types(db, s.id) == []
    assert sum(1 for d in devices(db) if d.status == DEVICE_ACTIVE) == 30


def test_exclusions_are_never_scanned(db):
    from app.models import Exclusion

    net = make_network(db)
    db.add(Exclusion(value="10.0.0.2, 10.0.0.100-10.0.0.255", enabled=True))
    db.commit()
    scanner = ScriptedScanner(baseline_hosts())
    scan(scanner, network_id=net.id)
    from app.netutils import AddressSet

    scanned = AddressSet.from_specs([t for chunk in scanner.discovery_targets for t in chunk])
    assert "10.0.0.2" not in scanned and "10.0.0.150" not in scanned and "10.0.0.1" in scanned
    assert [d.current_ip for d in devices(db)] == ["10.0.0.1"]


def test_full_scan_high_ports_first_coverage_is_silent_then_tracked(db):
    net = make_network(db)
    scan(ScriptedScanner(baseline_hosts()), network_id=net.id)
    hosts = baseline_hosts()
    hosts[0].ports.append(port(49664, "msrpc", "Microsoft Windows RPC"))
    s1 = scan(ScriptedScanner(hosts), scan_type="full", targets="10.0.0.1")
    assert event_types(db, s1.id) == []  # first full coverage: recorded silently
    assert any(p.port == 49664 and p.is_open for p in device_by_ip(db, "10.0.0.1").ports)

    s2 = scan(ScriptedScanner(hosts), network_id=net.id)  # standard scan cannot see 49664
    assert event_types(db, s2.id) == []
    assert any(p.port == 49664 and p.is_open for p in device_by_ip(db, "10.0.0.1").ports)

    hosts[0].ports.append(port(50001, "unknown"))
    s3 = scan(ScriptedScanner(hosts), scan_type="full", targets="10.0.0.1")
    assert event_types(db, s3.id) == ["port_opened"]


def test_events_outside_networks_are_recorded_but_not_emailed(db):
    make_network(db)
    s = scan(ScriptedScanner([host("192.168.5.5", [port(80, "http")])]), targets="192.168.5.5")
    evs = events(db, s.id)
    assert [e.event_type for e in evs] == ["device_discovered"]
    assert evs[0].notify is False


def test_mock_scenario_end_to_end(db):
    """The bundled mock scenario through the real runner (as used by `npm run dev`)."""
    from app.core.manager import create_scan
    from app.core.runner import run_scan
    from app.db import session_scope

    net = make_network(db, cidr="10.99.0.0/24", name="Mock Lab")
    per_scan = []
    for _ in range(7):
        with session_scope() as s:
            scan_id = create_scan(s, "standard", network=s.get(Network, net.id)).id
        assert run_scan(scan_id) == SCAN_COMPLETED
        per_scan.append(sorted(event_types(db, scan_id)))
    assert per_scan == [
        [],
        ["device_discovered", "port_closed", "port_opened", "tag_removed"],  # the closed port carried a rule tag
        ["ip_changed", "service_changed", "version_changed"],
        ["device_disappeared", "port_opened"],
        ["device_reappeared", "port_closed"],
        ["port_opened"],
        [],
    ]


def test_exposed_ports_labelled_by_most_common_service(db):
    from app.api.dashboard import exposed_ports

    net = make_network(db)
    scan(ScriptedScanner([
        host("10.0.0.1", [port(3389, "ms-wbt-server"), port(445, "tcpwrapped")]),
        host("10.0.0.2", [port(3389, "ms-wbt-server"), port(445, "tcpwrapped")]),
        host("10.0.0.3", [port(3389, "ssh"), port(445, "microsoft-ds")]),
    ]), network_id=net.id)
    rows = {r["port"]: r for r in exposed_ports(db)}
    assert rows[3389]["count"] == 3 and rows[3389]["service"] == "ms-wbt-server"  # not max() -> "ssh"
    assert rows[445]["service"] == "microsoft-ds"  # a named service beats tcpwrapped
    assert exposed_ports(db, network_id=net.id + 1) == []


def test_device_load_is_scoped_but_identity_matching_sees_all_devices(db):
    from app.core.compare import ScanOutcome, _Applier
    from app.db import utcnow
    from app.models import Scan
    from app.netutils import AddressSet

    net_a = make_network(db, cidr="10.0.0.0/24", name="A")
    net_b = make_network(db, cidr="10.1.0.0/24", name="B")
    scan(ScriptedScanner(baseline_hosts()), network_id=net_a.id)
    scan(ScriptedScanner([host("10.1.0.5", [port(80, "http")], mac=MAC_C, hostname="cam-c.corp"),
                          host("10.1.0.6", [port(80, "http")], hostname="cam-d.corp")]), network_id=net_b.id)

    # MAC_C moved from network B into A: matched although its old IP is outside the scan targets.
    moved = host("10.0.0.60", [port(80, "http")], mac=MAC_C, hostname="cam-c.corp")
    outcome = ScanOutcome(scan_type="standard", targets=AddressSet.from_specs(net_a.cidr),
                          hosts={h.ip: h for h in [*baseline_hosts(), moved]})
    applier = _Applier(db, db.query(Scan).first(), outcome, ScanSettings(), utcnow())
    loaded, matches = applier.load_devices(list(outcome.hosts.values()))

    assert matches["10.0.0.60"] is not None and matches["10.0.0.60"].current_ip == "10.1.0.5"
    assert sorted(d.current_ip for d in loaded) == ["10.0.0.1", "10.0.0.2", "10.1.0.5"]  # not 10.1.0.6

    s = scan(ScriptedScanner([*baseline_hosts(), moved]), network_id=net_a.id)
    assert event_types(db, s.id) == ["ip_changed"]
    assert len(devices(db)) == 4
