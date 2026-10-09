"""TrueNAS Apps catalog ports are scanned only on TrueNAS-identified hosts."""
from __future__ import annotations

from app.scanner.identify_truenas import host_looks_like_truenas, looks_like_truenas
from app.scanner.known_ports import STANDARD_EXTRA_TCP_PORTS, TRUENAS_APPS_TCP_PORTS
from app.scanner.types import HostObservation, PortObservation

from .helpers import ScriptedScanner, device_by_ip, host, make_network, port, scan

MAC_A = "00:11:22:33:44:01"
MAC_B = "00:11:22:33:44:02"


def test_truenas_ports_not_in_standard_extra():
    assert TRUENAS_APPS_TCP_PORTS
    assert 30013 in TRUENAS_APPS_TCP_PORTS  # jellyfin catalog default
    assert 32400 in TRUENAS_APPS_TCP_PORTS  # plex
    overlap = set(TRUENAS_APPS_TCP_PORTS) & set(STANDARD_EXTRA_TCP_PORTS)
    assert overlap <= {30000}  # SGLang also documents 30000


def test_looks_like_truenas_from_hostname_os_vendor_product():
    assert looks_like_truenas(hostname="truenas.local")
    assert looks_like_truenas(os_name="TrueNAS SCALE 24.10")
    assert looks_like_truenas(vendor="iXsystems")
    assert looks_like_truenas(ports=[PortObservation(port=80, product="TrueNAS middleware")])
    assert not looks_like_truenas(hostname="nas01.local", vendor="Synology")
    assert not host_looks_like_truenas(HostObservation(ip="10.0.0.1", hostname="laptop"))


def test_truenas_catalog_ports_only_on_identified_host(db):
    net = make_network(db)
    other = host("10.0.0.1", [port(22, "ssh"), port(30013, "http", "Jellyfin")], mac=MAC_A, hostname="srv-web")
    tn = host(
        "10.0.0.2",
        [port(80, "http"), port(30013, "http", "Jellyfin"), port(30041, "http", "Immich")],
        mac=MAC_B,
        hostname="truenas.lab",
    )
    scan(ScriptedScanner([other, tn]), network_id=net.id)

    web = device_by_ip(db, "10.0.0.1")
    assert {p.port for p in web.ports if p.is_open} == {22}  # 30013 not scanned / not kept

    nas = device_by_ip(db, "10.0.0.2")
    assert {p.port for p in nas.ports if p.is_open} == {80, 30013, 30041}


def test_truenas_catalog_ports_on_full_scan(db):
    """Full scans also probe TrueNAS Apps catalog ports (host-timeout often misses 3XXXX)."""
    net = make_network(db)
    catalog_port = next(p for p in TRUENAS_APPS_TCP_PORTS if p >= 30000)
    tn = host(
        "10.0.0.2",
        [port(80, "http"), port(catalog_port, "http")],
        mac=MAC_B,
        hostname="truenas.lab",
    )
    scan(ScriptedScanner([tn]), scan_type="full", targets="10.0.0.2")
    nas = device_by_ip(db, "10.0.0.2")
    assert {p.port for p in nas.ports if p.is_open} == {80, catalog_port}
