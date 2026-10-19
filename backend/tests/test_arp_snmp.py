"""MACs for routed / site-to-site VPN hosts: router ARP table over SNMP, and NetBIOS unit IDs.

All addresses are documentation/test ranges and all MACs are made up.
"""
from __future__ import annotations

import struct

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.api.auth import limiter
from app.core import arp_snmp
from app.core.arp_snmp import (
    NET_TO_MEDIA_PHYS,
    NET_TO_MEDIA_TYPE,
    NET_TO_PHYSICAL_PHYS,
    NET_TO_PHYSICAL_TYPE,
    ArpSource,
    SnmpTarget,
    enrich_from_arp,
    fetch_arp_table,
    parse_arp_table,
    unique_macs,
)
from app.core.discovery.netbios import parse_nbstat_mac, parse_nbstat_response, query_netbios_names
from app.core.intel import apply_netbios_macs
from app.main import app
from app.models import AuditLog, Device
from app.scanner.types import HostObservation
from app.security import encrypt_secret

from .helpers import ScriptedScanner, device_by_ip, devices, host, make_network, port, scan

MAC_A = bytes.fromhex("02AA00000001")
MAC_B = bytes.fromhex("02AA00000002")
MAC_PROXY = bytes.fromhex("02AA000000FE")


def _media(ip: str, mac: bytes, if_index: int = 3) -> tuple[str, object]:
    return f"{NET_TO_MEDIA_PHYS}.{if_index}.{ip}", mac


def _media_type(ip: str, value: int, if_index: int = 3) -> tuple[str, object]:
    return f"{NET_TO_MEDIA_TYPE}.{if_index}.{ip}", value


# --- parsing -----------------------------------------------------------------------------------

def test_parse_ip_net_to_media_drops_invalid_zero_and_multicast():
    rows = [
        _media("10.9.0.5", MAC_A),
        _media("10.9.0.6", MAC_B), _media_type("10.9.0.6", 2),       # router marked it invalid
        _media("10.9.0.7", b"\x00" * 6),                             # unset
        _media("10.9.0.8", bytes.fromhex("01005E000001")),           # multicast bit
        _media("10.9.0.9", b"\x02\xaa"),                             # truncated
        _media_type("10.9.0.5", 3),                                  # dynamic
    ]
    assert parse_arp_table(rows) == {"10.9.0.5": "02:AA:00:00:00:01"}


def test_parse_ip_net_to_physical_ipv4_only():
    rows = [
        (f"{NET_TO_PHYSICAL_PHYS}.4.1.4.10.9.0.5", MAC_A),
        (f"{NET_TO_PHYSICAL_PHYS}.4.2.16." + ".".join(["0"] * 15 + ["1"]), MAC_B),  # IPv6: ignored
        (f"{NET_TO_PHYSICAL_TYPE}.4.1.4.10.9.0.5", 3),
    ]
    assert parse_arp_table(rows) == {"10.9.0.5": "02:AA:00:00:00:01"}


def test_mac_listed_for_several_ips_is_dropped():
    # Proxy-ARP / a downstream router answering for routed hosts: the MAC is not a host identity.
    table = {"10.9.0.5": "02:AA:00:00:00:01", "10.9.0.20": "02:AA:00:00:00:FE", "10.9.0.21": "02:AA:00:00:00:FE"}
    assert unique_macs(table) == {"10.9.0.5": "02:AA:00:00:00:01"}


def test_fetch_falls_back_to_ip_net_to_physical():
    walked: list[str] = []

    def walk(target, root, timeout):
        walked.append(root)
        return [(f"{NET_TO_PHYSICAL_PHYS}.4.1.4.10.9.0.5", MAC_A)] if root == NET_TO_PHYSICAL_PHYS else []

    assert fetch_arp_table(SnmpTarget("192.0.2.1", community="c"), walk=walk) == {"10.9.0.5": "02:AA:00:00:00:01"}
    assert walked == [NET_TO_MEDIA_PHYS, NET_TO_PHYSICAL_PHYS, NET_TO_PHYSICAL_TYPE]


# --- enrichment --------------------------------------------------------------------------------

def _fake_walk(rows):
    def walk(target, root, timeout):
        return [r for r in rows if r[0].startswith(root + ".")]
    return walk


def test_enrich_fills_only_mac_less_hosts_in_scope(monkeypatch):
    monkeypatch.setattr(arp_snmp, "walk_subtree", _fake_walk([
        _media("10.9.0.5", MAC_A), _media("10.9.0.6", MAC_B), _media("10.8.0.5", bytes.fromhex("02AA00000003")),
    ]))
    live = {
        "10.9.0.5": HostObservation(ip="10.9.0.5"),
        "10.9.0.6": HostObservation(ip="10.9.0.6", mac="02:BB:00:00:00:06"),  # scanner's own ARP wins
        "10.8.0.5": HostObservation(ip="10.8.0.5"),  # outside this network's CIDR
    }
    src = ArpSource(network="Branch", cidr="10.9.0.0/24", target=SnmpTarget("192.0.2.1", community="c"))
    notes = enrich_from_arp(live, [src])
    assert (live["10.9.0.5"].mac, live["10.9.0.5"].mac_source) == ("02:AA:00:00:00:01", "snmp")
    assert live["10.9.0.6"].mac == "02:BB:00:00:00:06" and live["10.9.0.6"].mac_source is None
    assert live["10.8.0.5"].mac is None
    assert notes == ["Router ARP (SNMP) for Branch: MAC found for 1 of 1 host(s)"]


def test_enrich_failure_is_a_note_not_an_error(monkeypatch):
    def boom(target, root, timeout):
        raise arp_snmp.SnmpError("No SNMP response received before timeout")

    monkeypatch.setattr(arp_snmp, "walk_subtree", boom)
    live = {"10.9.0.5": HostObservation(ip="10.9.0.5")}
    src = ArpSource(network="Branch", cidr="10.9.0.0/24", target=SnmpTarget("192.0.2.1", community="c"))
    notes = enrich_from_arp(live, [src])
    assert live["10.9.0.5"].mac is None
    assert notes and "failed: No SNMP response" in notes[0]


# --- scan pipeline -----------------------------------------------------------------------------

class LiveScriptedScanner(ScriptedScanner):
    """Reports a real-scanner mode so the ARP step runs; still no network I/O (walker is faked)."""

    mode = "nmap"


def _snmp_network(db, cidr="10.9.0.0/24"):
    net = make_network(db, cidr=cidr, name="Branch")
    net.vpn_s2s = True
    net.arp_snmp = {"host": "192.0.2.1", "port": 161, "version": "2c", "community_enc": encrypt_secret("c")}
    db.commit()
    return net


def test_scan_learns_macs_from_router_and_keeps_identity_when_router_is_down(db, monkeypatch):
    net = _snmp_network(db)
    monkeypatch.setattr(arp_snmp, "walk_subtree", _fake_walk([
        _media("10.9.0.5", MAC_A), _media("10.9.0.20", MAC_PROXY), _media("10.9.0.21", MAC_PROXY),
    ]))
    hosts = [host("10.9.0.5", [port(22, "ssh")]), host("10.9.0.20", [port(80)]), host("10.9.0.21", [port(80)])]
    first = scan(LiveScriptedScanner(hosts), network_id=net.id)
    assert first.status == "completed"
    d = device_by_ip(db, "10.9.0.5")
    assert (d.mac, d.mac_source) == ("02:AA:00:00:00:01", "snmp")
    assert device_by_ip(db, "10.9.0.20").mac is None and device_by_ip(db, "10.9.0.21").mac is None
    assert "Router ARP (SNMP) for Branch: MAC found for 1 of 3 host(s)" in first.notes

    def down(target, root, timeout):
        raise arp_snmp.SnmpError("No SNMP response received before timeout")

    monkeypatch.setattr(arp_snmp, "walk_subtree", down)
    second = scan(LiveScriptedScanner(hosts), network_id=net.id)
    assert second.status == "completed" and "failed" in second.notes
    assert len(devices(db)) == 3  # no MAC this time is not a contradiction: same devices
    assert device_by_ip(db, "10.9.0.5").mac == "02:AA:00:00:00:01"


def test_mock_scanner_never_polls_snmp(db, monkeypatch):
    net = _snmp_network(db)

    def never(*a, **k):
        raise AssertionError("SNMP must not be polled in mock mode")

    monkeypatch.setattr(arp_snmp, "walk_subtree", never)
    assert scan(ScriptedScanner([host("10.9.0.5")]), network_id=net.id).status == "completed"


# --- NetBIOS -----------------------------------------------------------------------------------

def _nbstat(name: str, unit_id: bytes | None) -> bytes:
    header = struct.pack(">HHHHHH", 0x5A5A, 0x8400, 0, 1, 0, 0)
    rr_head = struct.pack(">HHI", 0x0021, 1, 0)
    rdata = bytes([1]) + name.encode().ljust(15)[:15] + b"\x00" + b"\x04\x00"
    if unit_id is not None:
        rdata += unit_id + b"\x00" * 40  # statistics block after the unit ID
    return header + bytes([32]) + b"A" * 32 + b"\x00" + rr_head + struct.pack(">H", len(rdata)) + rdata


def test_parse_nbstat_mac():
    assert parse_nbstat_mac(_nbstat("PC-1", MAC_A)) == "02:AA:00:00:00:01"
    assert parse_nbstat_mac(_nbstat("NAS-1", b"\x00" * 6)) is None  # Samba reports zeros
    assert parse_nbstat_mac(_nbstat("PC-1", None)) is None
    assert parse_nbstat_response(_nbstat("PC-1", MAC_A))[0]["name"] == "PC-1"  # name parsing unchanged


def test_query_netbios_names_collects_macs():
    def transact(ips, timeout):
        yield _nbstat("PC-1", MAC_A), ("10.9.0.5", 137)

    macs: dict[str, str] = {}
    assert query_netbios_names(["10.9.0.5"], transact=transact, macs=macs) == {"10.9.0.5": "PC-1"}
    assert macs == {"10.9.0.5": "02:AA:00:00:00:01"}


def test_apply_netbios_macs_fills_only_free_unclaimed_macs(db):
    a = Device(current_ip="10.9.0.5")
    b = Device(current_ip="10.9.0.6", mac="02:BB:00:00:00:06", mac_source="arp")
    c = Device(current_ip="10.9.0.7")
    holder = Device(current_ip="10.9.0.8", mac="02:AA:00:00:00:02")
    db.add_all([a, b, c, holder])
    db.flush()
    macs = {"10.9.0.5": "02:AA:00:00:00:01", "10.9.0.6": "02:AA:00:00:00:09", "10.9.0.7": "02:AA:00:00:00:02"}
    assert apply_netbios_macs(db, [a, b, c], macs) == 1
    assert (a.mac, a.mac_source) == ("02:AA:00:00:00:01", "netbios")
    assert b.mac == "02:BB:00:00:00:06"  # never replaced
    assert c.mac is None  # another device already holds it


# --- API ---------------------------------------------------------------------------------------

@pytest.fixture
def client(db_env):
    limiter.reset()
    with TestClient(app) as c:
        yield c


def _admin(client) -> dict:
    assert client.post("/api/setup/admin", json={"username": "admin", "password": "correct-horse-1"}).status_code == 200
    return {"X-CSRF-Token": client.cookies.get("nf_csrf", "")}


def test_arp_snmp_secrets_are_write_only(client, db):
    h = _admin(client)
    body = {"name": "Branch", "cidr": "10.9.0.0/24", "vpn_s2s": True,
            "arp_snmp": {"host": "192.0.2.1", "version": "2c", "community": "s3cret-community"}}
    r = client.post("/api/networks", json=body, headers=h)
    assert r.status_code == 201, r.text
    net = r.json()
    assert net["arp_snmp"] == {"host": "192.0.2.1", "port": 161, "version": "2c", "user": None,
                               "auth_protocol": None, "priv_protocol": None,
                               "community_set": True, "auth_key_set": False, "priv_key_set": False}
    assert "s3cret-community" not in r.text
    assert not any("s3cret-community" in (a.details or "") for a in db.scalars(select(AuditLog)).all())

    # Omitted secret = keep it.
    body["arp_snmp"] = {"host": "192.0.2.2", "version": "2c"}
    r = client.put(f"/api/networks/{net['id']}", json=body, headers=h)
    assert r.status_code == 200, r.text
    assert r.json()["arp_snmp"]["community_set"] is True and r.json()["arp_snmp"]["host"] == "192.0.2.2"

    # Switching to v3 drops the community; v3 secrets must be supplied.
    body["arp_snmp"] = {"host": "192.0.2.2", "version": "3", "user": "ro", "auth_protocol": "SHA256",
                        "auth_key": "authpass1", "priv_protocol": "AES", "priv_key": "privpass1"}
    out = client.put(f"/api/networks/{net['id']}", json=body, headers=h).json()["arp_snmp"]
    assert (out["community_set"], out["auth_key_set"], out["priv_key_set"]) == (False, True, True)

    body["arp_snmp"] = None
    assert client.put(f"/api/networks/{net['id']}", json=body, headers=h).json()["arp_snmp"] is None


@pytest.mark.parametrize("arp, status", [
    ({"host": "192.0.2.1", "version": "2c"}, 422),                                    # no community
    ({"host": "192.0.2.1", "version": "3"}, 422),                                     # no user
    ({"host": "192.0.2.1", "version": "3", "user": "ro", "priv_protocol": "AES", "priv_key": "privpass1"}, 422),
    ({"host": "192.0.2.1", "version": "3", "user": "ro", "auth_protocol": "SHA", "auth_key": "short"}, 422),
    ({"host": "not a host!", "version": "2c", "community": "c"}, 422),
    ({"host": "gw.branch.example", "version": "2c", "community": "c"}, 201),
])
def test_arp_snmp_validation(client, arp, status):
    h = _admin(client)
    r = client.post("/api/networks", json={"name": "Branch", "cidr": "10.9.0.0/24", "arp_snmp": arp}, headers=h)
    assert r.status_code == status, r.text


def test_arp_snmp_probe_endpoint(client, monkeypatch):
    h = _admin(client)
    net = client.post("/api/networks", headers=h, json={
        "name": "Branch", "cidr": "10.9.0.0/24",
        "arp_snmp": {"host": "192.0.2.1", "version": "2c", "community": "c"}}).json()
    monkeypatch.setattr(arp_snmp, "walk_subtree", _fake_walk([
        _media("10.9.0.5", MAC_A), _media("10.8.0.5", MAC_B),
    ]))
    r = client.post(f"/api/networks/{net['id']}/arp-snmp/test", headers=h)
    assert r.json() == {"ok": True, "entries": 2, "in_network": 1}

    def down(target, root, timeout):
        raise arp_snmp.SnmpError("No SNMP response received before timeout")

    monkeypatch.setattr(arp_snmp, "walk_subtree", down)
    assert client.post(f"/api/networks/{net['id']}/arp-snmp/test", headers=h).json() == {
        "ok": False, "error": "No SNMP response received before timeout"}
