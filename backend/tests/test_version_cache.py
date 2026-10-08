"""Service version cache: which open ports may skip -sV, driven through the real scan pipeline."""
from __future__ import annotations

from datetime import timedelta

from sqlalchemy import update

from app.db import utcnow
from app.models import DevicePort
from app.scanner.types import PortObservation
from app.settings_store import ScanSettings, put_section

from .helpers import ScriptedScanner, device_by_ip, event_types, host, make_network, port, scan

MAC_A = "00:11:22:33:44:01"
MAC_B = "00:11:22:33:44:02"


def table_port(n: int, service: str = "http") -> PortObservation:
    """What a port-map pass without -sV reports: nmap's port-table guess."""
    return PortObservation(port=n, service=service, method="table", confidence=3)


def first_hosts():
    return [host("10.0.0.1", [port(22, "ssh", "OpenSSH", "8.9p1"), port(443, "https", "nginx", "1.24.0")], mac=MAC_A)]


def test_detected_versions_feed_the_next_scan(db):
    net = make_network(db)
    scan(ScriptedScanner(first_hosts()), network_id=net.id)
    assert all(p.version_checked_at is not None for p in device_by_ip(db, "10.0.0.1").ports)

    sc = ScriptedScanner(first_hosts())
    scan(sc, network_id=net.id)
    assert sc.version_caches == [{"10.0.0.1": frozenset({22, 443})}]


def test_cached_ports_keep_their_version_without_events(db):
    net = make_network(db)
    scan(ScriptedScanner(first_hosts()), network_id=net.id)
    # warm-cache result: port map only, no -sV on the cached ports
    s = scan(ScriptedScanner([host("10.0.0.1", [table_port(22, "ssh"), table_port(443, "https")], mac=MAC_A)]),
             network_id=net.id)
    assert event_types(db, s.id) == []
    ports = {p.port: p for p in device_by_ip(db, "10.0.0.1").ports}
    assert (ports[22].product, ports[22].version) == ("OpenSSH", "8.9p1")
    assert (ports[443].product, ports[443].version) == ("nginx", "1.24.0")


def test_force_option_and_disabled_cache_send_no_cache(db):
    net = make_network(db)
    scan(ScriptedScanner(first_hosts()), network_id=net.id)
    sc = ScriptedScanner(first_hosts())
    scan(sc, network_id=net.id, ignore_version_cache=True)
    put_section(db, ScanSettings(version_cache_days=0))
    db.commit()
    scan(sc, network_id=net.id)
    assert sc.version_caches == [{}, {}]


def test_expired_versions_are_not_cached(db):
    net = make_network(db)
    scan(ScriptedScanner(first_hosts()), network_id=net.id)
    db.execute(update(DevicePort).where(DevicePort.port == 443)
               .values(version_checked_at=utcnow() - timedelta(days=8)))
    db.commit()
    sc = ScriptedScanner(first_hosts())
    scan(sc, network_id=net.id)
    assert sc.version_caches == [{"10.0.0.1": frozenset({22})}]


def test_other_device_on_same_ip_gets_no_cache(db):
    net = make_network(db)
    scan(ScriptedScanner(first_hosts()), network_id=net.id)
    sc = ScriptedScanner([host("10.0.0.1", [port(22, "ssh", "OpenSSH", "9.6p1")], mac=MAC_B)])
    scan(sc, network_id=net.id)
    assert sc.version_caches == [{}]


def test_closed_ports_are_not_cached(db):
    net = make_network(db)
    scan(ScriptedScanner(first_hosts()), network_id=net.id)
    scan(ScriptedScanner([host("10.0.0.1", [port(22, "ssh", "OpenSSH", "8.9p1")], mac=MAC_A)]), network_id=net.id)
    sc = ScriptedScanner(first_hosts())
    scan(sc, network_id=net.id)  # 443 reopened: it must be version-scanned again
    assert sc.version_caches == [{"10.0.0.1": frozenset({22})}]
