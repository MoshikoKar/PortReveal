from datetime import datetime, timezone
from types import SimpleNamespace

from app.core.identity import is_generic_hostname, match_hosts, normalize_mac
from app.scanner.types import HostObservation

T = datetime(2026, 1, 1, tzinfo=timezone.utc)


def dev(id, ip, mac=None, hostname=None, status="active"):
    return SimpleNamespace(id=id, current_ip=ip, mac=mac, hostname=hostname, status=status, last_seen=T)


def test_mac_match_wins_over_ip():
    d1 = dev(1, "10.0.0.5", mac="AA:AA:AA:AA:AA:01")
    d2 = dev(2, "10.0.0.6", mac="AA:AA:AA:AA:AA:02")
    hosts = [HostObservation(ip="10.0.0.6", mac="aa-aa-aa-aa-aa-01")]
    assert match_hosts(hosts, [d1, d2])["10.0.0.6"] is d1


def test_swapped_ips_resolved_by_mac():
    d1 = dev(1, "10.0.0.5", mac="AA:AA:AA:AA:AA:01")
    d2 = dev(2, "10.0.0.6", mac="AA:AA:AA:AA:AA:02")
    hosts = [HostObservation(ip="10.0.0.5", mac="AA:AA:AA:AA:AA:02"),
             HostObservation(ip="10.0.0.6", mac="AA:AA:AA:AA:AA:01")]
    m = match_hosts(hosts, [d1, d2])
    assert m["10.0.0.5"] is d2 and m["10.0.0.6"] is d1


def test_same_ip_different_mac_is_new_device():
    d1 = dev(1, "10.0.0.5", mac="AA:AA:AA:AA:AA:01")
    m = match_hosts([HostObservation(ip="10.0.0.5", mac="BB:BB:BB:BB:BB:01")], [d1])
    assert m["10.0.0.5"] is None


def test_same_ip_without_mac_matches():
    d1 = dev(1, "10.0.0.5", hostname="srv.corp")
    assert match_hosts([HostObservation(ip="10.0.0.5")], [d1])["10.0.0.5"] is d1
    assert match_hosts([HostObservation(ip="10.0.0.5", hostname="srv.corp.")], [d1])["10.0.0.5"] is d1


def test_same_ip_conflicting_hostname_is_new_device():
    d1 = dev(1, "10.0.0.5", hostname="srv-old.corp")
    assert match_hosts([HostObservation(ip="10.0.0.5", hostname="laptop-x.corp")], [d1])["10.0.0.5"] is None


def test_generic_hostnames_do_not_identify():
    assert is_generic_hostname("10-0-0-5.dhcp.corp", "10.0.0.5")
    assert is_generic_hostname("host-5.0.0.10.in-addr.corp", "10.0.0.5")
    assert not is_generic_hostname("fileserver.corp", "10.0.0.5")
    # generic PTR on a reused IP must not prevent the IP match, nor cause a hostname match elsewhere
    d1 = dev(1, "10.0.0.9", hostname="10-0-0-9.dhcp.corp")
    m = match_hosts([HostObservation(ip="10.0.0.20", hostname="10-0-0-20.dhcp.corp")], [d1])
    assert m["10.0.0.20"] is None


def test_hostname_move_requires_unique_candidate():
    d1 = dev(1, "10.0.0.5", hostname="app.corp")
    d2 = dev(2, "10.0.1.5", hostname="app.corp")
    assert match_hosts([HostObservation(ip="10.0.2.5", hostname="app.corp")], [d1, d2])["10.0.2.5"] is None
    assert match_hosts([HostObservation(ip="10.0.2.5", hostname="app.corp")], [d1])["10.0.2.5"] is d1


def test_duplicate_mac_in_scan_is_ignored():
    """Proxy-ARP style: many IPs answer with the router's MAC -> MAC is not an identity."""
    router = dev(1, "10.0.0.1", mac="CC:CC:CC:CC:CC:01")
    hosts = [HostObservation(ip="10.0.0.1", mac="CC:CC:CC:CC:CC:01"),
             HostObservation(ip="10.0.0.77", mac="CC:CC:CC:CC:CC:01")]
    m = match_hosts(hosts, [router])
    assert m["10.0.0.1"] is router
    assert m["10.0.0.77"] is None


def test_each_device_claimed_once():
    d1 = dev(1, "10.0.0.5", hostname="srv.corp")
    hosts = [HostObservation(ip="10.0.0.5", hostname="srv.corp"), HostObservation(ip="10.0.0.6", hostname="srv.corp")]
    m = match_hosts(hosts, [d1])
    assert m["10.0.0.5"] is d1 and m["10.0.0.6"] is None


def test_normalize_mac():
    assert normalize_mac("aa-bb-cc-dd-ee-ff") == "AA:BB:CC:DD:EE:FF"
    assert normalize_mac("aabb.ccdd.eeff") == "AA:BB:CC:DD:EE:FF"
    assert normalize_mac("garbage") is None
