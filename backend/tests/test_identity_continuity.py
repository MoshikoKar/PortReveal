"""Device identity across DHCP address changes (issue #37).

Scenario tests run through the real scan pipeline; matcher tests call `match_hosts_detailed` with
synthetic devices. All addresses are documentation ranges and all MACs are made up.
"""
from __future__ import annotations

import random
from datetime import datetime, timezone
from types import SimpleNamespace

from app.core import discovery
from app.core.identity import match_hosts_detailed
from app.models import DevicePort
from app.scanner.types import HostObservation

from .helpers import ScriptedScanner, device_by_ip, devices, event_types, events, host, make_network, port, scan

MAC_A = "00:11:22:33:44:01"
MAC_B = "00:11:22:33:44:02"
MAC_C = "00:11:22:33:44:03"
T = datetime(2026, 1, 1, tzinfo=timezone.utc)


def dev(id, ip, mac=None, hostname=None, status="active", network_id=None):
    return SimpleNamespace(id=id, current_ip=ip, mac=mac, hostname=hostname, status=status,
                           last_seen=T, network_id=network_id)


def hosts_at(ip, mac=None, hostname=None, mac_source=None):
    return HostObservation(ip=ip, mac=mac, hostname=hostname, mac_source=mac_source)


# --- scenarios through the scan pipeline ---------------------------------------------------------

def _baseline():
    return [
        host("10.0.0.1", [port(22, "ssh", "OpenSSH", "8.9p1")], mac=MAC_A, hostname="srv-a.corp"),
        host("10.0.0.2", [port(3389, "ms-wbt-server", "Microsoft Terminal Services")], mac=MAC_B,
             hostname="ws-b.corp"),
    ]


def test_dhcp_move_keeps_device_ports_timestamps_and_explains_the_match(db):
    net = make_network(db)
    scan(ScriptedScanner(_baseline()), network_id=net.id)
    before = device_by_ip(db, "10.0.0.2")
    device_id = before.id
    opened = {p.port: p.opened_at for p in db.query(DevicePort).filter_by(device_id=device_id)}

    moved = _baseline()
    moved[1].ip = "10.0.0.50"
    s = scan(ScriptedScanner(moved), network_id=net.id)

    assert event_types(db, s.id) == ["ip_changed"]
    (ev,) = events(db, s.id)
    assert "(matched by mac)" in ev.message
    assert len(devices(db)) == 2
    moved_dev = device_by_ip(db, "10.0.0.50")
    assert moved_dev.id == device_id
    after = {p.port: p.opened_at for p in db.query(DevicePort).filter_by(device_id=device_id)}
    assert after == opened


def test_hostname_move_is_refused_when_old_address_is_held_by_another_mac(db):
    """A device with a MAC that is not observed, whose old address now answers with another MAC,
    may simply be offline. A host without a MAC is then a new device, not a merge."""
    net = make_network(db)
    scan(ScriptedScanner(_baseline()), network_id=net.id)
    hosts = [
        host("10.0.0.2", [port(3389, "ms-wbt-server")], mac=MAC_C, hostname="other.corp"),
        host("10.0.0.60", [port(3389, "ms-wbt-server")], hostname="ws-b.corp"),
    ]
    scan(ScriptedScanner(hosts), network_id=net.id)
    assert device_by_ip(db, "10.0.0.60").mac is None
    # A, B (not detected at its old address) and two new devices: nothing merged.
    assert len(devices(db)) == 4


def test_hostname_move_still_works_for_a_device_without_mac(db):
    net = make_network(db)
    hosts = [host("10.0.0.7", [port(22, "ssh", "OpenSSH")], hostname="build-server.corp")]
    scan(ScriptedScanner(hosts), network_id=net.id)
    hosts[0].ip = "10.0.0.8"
    s = scan(ScriptedScanner(hosts), network_id=net.id)
    assert event_types(db, s.id) == ["ip_changed"]
    assert len(devices(db)) == 1


# --- matcher rules --------------------------------------------------------------------------------

def test_stale_router_arp_mac_with_conflicting_name_is_not_used():
    d = dev(1, "10.0.0.5", mac=MAC_A, hostname="laptop-a.corp")
    h = hosts_at("10.0.0.9", mac=MAC_A, hostname="printer.corp", mac_source="snmp")
    assert match_hosts_detailed([h], [d])["10.0.0.9"] is None


def test_router_arp_mac_is_used_when_names_do_not_conflict():
    d = dev(1, "10.0.0.5", mac=MAC_A, hostname="laptop-a.corp")
    h = hosts_at("10.0.0.9", mac=MAC_A, hostname=None, mac_source="snmp")
    assert match_hosts_detailed([h], [d])["10.0.0.9"] == (d, "mac")


def test_own_mac_is_not_subject_to_the_router_arp_rule():
    d = dev(1, "10.0.0.5", mac=MAC_A, hostname="laptop-a.corp")
    h = hosts_at("10.0.0.9", mac=MAC_A, hostname="printer.corp", mac_source="netbios")
    assert match_hosts_detailed([h], [d])["10.0.0.9"] == (d, "mac")


def test_shared_address_across_networks_without_mac_is_new_device():
    d = dev(1, "10.0.0.5", network_id=1)
    h = hosts_at("10.0.0.5")
    networks = {"10.0.0.5": 2}
    assert match_hosts_detailed([h], [d], networks.get)["10.0.0.5"] is None


def test_same_address_same_network_without_mac_still_matches():
    d = dev(1, "10.0.0.5", network_id=1)
    networks = {"10.0.0.5": 1}
    assert match_hosts_detailed([hosts_at("10.0.0.5")], [d], networks.get)["10.0.0.5"] == (d, "ip")


def test_cross_network_move_by_mac_is_still_allowed():
    d = dev(1, "10.0.0.5", mac=MAC_A, network_id=1)
    networks = {"10.0.0.9": 2}
    h = hosts_at("10.0.0.9", mac=MAC_A)
    assert match_hosts_detailed([h], [d], networks.get)["10.0.0.9"] == (d, "mac")


def test_invariants_hold_over_random_scans():
    """Synthetic inputs only: small pools force collisions in MAC, address and name."""
    rng = random.Random(37)
    macs = [f"00:11:22:33:44:{i:02X}" for i in range(1, 6)]
    names = ["alpha.corp", "beta.corp", "printer", None]
    for _ in range(400):
        pool_devices = [
            dev(i, f"10.0.0.{rng.randint(1, 8)}", mac=rng.choice(macs + [None]),
                hostname=rng.choice(names), network_id=rng.choice([1, 2]))
            for i in range(rng.randint(0, 6))
        ]
        ips = {f"10.0.0.{rng.randint(1, 8)}" for _ in range(rng.randint(1, 6))}
        observed = [
            HostObservation(ip=ip, mac=rng.choice(macs + [None]), hostname=rng.choice(names),
                            mac_source=rng.choice([None, "snmp"]))
            for ip in sorted(ips)
        ]
        networks = {ip: rng.choice([1, 2]) for ip in ips}
        result = match_hosts_detailed(observed, pool_devices, networks.get)

        matched = [m[0].id for m in result.values() if m is not None]
        assert len(matched) == len(set(matched)), "one device matched to two hosts in a scan"
        mac_counts = {mac: sum(1 for h in observed if h.mac == mac) for mac in macs}
        for h in observed:
            m = result[h.ip]
            if m is None:
                continue
            d, _via = m
            usable = h.mac is not None and mac_counts[h.mac] == 1
            if usable and d.mac:
                assert d.mac == h.mac, "a usable MAC never matches a device with a different MAC"


# --- NetBIOS MAC before identity matching ----------------------------------------------------------

def test_netbios_macs_are_collected_before_matching(monkeypatch):
    seen = {}

    def fake_query(ips, *, timeout, macs):
        seen["ips"] = list(ips)
        macs["10.0.0.9"] = MAC_B
        return {}

    monkeypatch.setattr(discovery, "query_netbios_names", fake_query)
    assert discovery.collect_netbios_macs(["10.0.0.9"]) == {"10.0.0.9": MAC_B}
    assert seen["ips"] == ["10.0.0.9"]


def test_netbios_mac_collection_is_silent_on_error(monkeypatch):
    def boom(*a, **k):
        raise OSError("no socket")

    monkeypatch.setattr(discovery, "query_netbios_names", boom)
    assert discovery.collect_netbios_macs(["10.0.0.9"]) == {}
    assert discovery.collect_netbios_macs([]) == {}
