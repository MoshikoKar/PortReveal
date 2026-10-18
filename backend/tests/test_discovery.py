"""Local-only mDNS/SSDP/NetBIOS device-naming discovery (spec section 9.2)."""
from __future__ import annotations

import struct

import pytest
from fastapi.testclient import TestClient

from app.api.auth import limiter
from app.core.discovery import collect_local_names
from app.core.discovery.dns_names import decode_name, parse_answers
from app.core.discovery.mdns import _clean_name, collect_mdns_names
from app.core.discovery.netbios import (
    build_nbstat_query,
    parse_nbstat_response,
    query_netbios_name,
    query_netbios_names,
)
from app.core.discovery.ssdp import _parse_server_header, collect_ssdp_names
from app.main import app


# --- dns_names.py -----------------------------------------------------------------------------------
def _label(name: str) -> bytes:
    out = b""
    for part in name.split("."):
        out += bytes([len(part)]) + part.encode()
    return out + b"\x00"


def test_decode_name_plain_no_compression():
    data = _label("my-printer.local")
    name, end = decode_name(data, 0)
    assert name == "my-printer.local" and end == len(data)


def test_decode_name_follows_compression_pointer():
    base = _label("local")  # offset 0
    pointer_offset = len(base)
    # "printer" + pointer back to offset 0 ("local")
    data = base + bytes([7]) + b"printer" + bytes([0xC0, 0x00])
    name, end = decode_name(data, pointer_offset)
    assert name == "printer.local"
    assert end == len(data)


def test_decode_name_rejects_forward_or_excessive_pointers():
    # Pointer to a later offset than itself (not backward) must be rejected, not followed.
    data = bytes([0xC0, 0x05]) + _label("local")
    with pytest.raises(ValueError):
        decode_name(data, 0)


def test_decode_name_truncated_raises():
    with pytest.raises(ValueError):
        decode_name(b"\x05abc", 0)  # length 5 but only 3 bytes follow


def _dns_message(ptr_target: str) -> bytes:
    """One question (PTR query) + one PTR answer whose rdata is `ptr_target`."""
    question_name = _label("_services._dns-sd._udp.local")
    header = struct.pack(">HHHHHH", 0, 0x8400, 1, 1, 0, 0)
    question = question_name + struct.pack(">HH", 12, 1)  # PTR, IN
    answer_name = b"\xc0\x0c"  # pointer back to the question name (offset 12)
    rdata = _label(ptr_target)
    answer = answer_name + struct.pack(">HHIH", 12, 1, 120, len(rdata)) + rdata
    return header + question + answer


def test_parse_answers_extracts_ptr_target():
    msg = _dns_message("My Printer._ipp._tcp.local")
    answers = parse_answers(msg)
    assert len(answers) == 1 and answers[0]["type"] == 12
    assert answers[0]["target"] == "My Printer._ipp._tcp.local"


def test_parse_answers_on_garbage_returns_empty():
    assert parse_answers(b"") == []
    assert parse_answers(b"\x00" * 11) == []
    assert parse_answers(b"\x00" * 12) == []  # valid header, zero questions/answers


# --- mdns.py ----------------------------------------------------------------------------------------
def test_clean_name_strips_local_suffix_and_service_labels():
    assert _clean_name("my-printer.local.") == "my-printer"
    assert _clean_name("Office Printer._ipp._tcp.local") == "Office Printer"
    assert _clean_name("") is None


def test_collect_mdns_names_uses_injected_listener():
    msg = _dns_message("Living Room TV._airplay._tcp.local")

    def fake_listen(timeout):
        return [(msg, ("10.0.0.5", 5353))]

    names = collect_mdns_names(timeout=1.0, listen=fake_listen)
    assert names == {"10.0.0.5": "Living Room TV"}


def test_collect_mdns_names_never_raises_on_oserror():
    def fake_listen(timeout):
        raise OSError("no multicast capability")

    assert collect_mdns_names(timeout=1.0, listen=fake_listen) == {}


def test_collect_mdns_names_ignores_unparsable_packets():
    def fake_listen(timeout):
        return [(b"not a dns packet", ("10.0.0.6", 5353))]

    assert collect_mdns_names(timeout=1.0, listen=fake_listen) == {}


# --- ssdp.py ----------------------------------------------------------------------------------------
def test_parse_server_header_case_insensitive():
    resp = b"HTTP/1.1 200 OK\r\nSERVER: Linux/1.0 UPnP/1.0 MyNAS/2.3\r\n\r\n"
    assert _parse_server_header(resp) == "Linux/1.0 UPnP/1.0 MyNAS/2.3"
    assert _parse_server_header(b"HTTP/1.1 200 OK\r\n\r\n") is None


def test_collect_ssdp_names_uses_injected_transactor():
    resp = b"HTTP/1.1 200 OK\r\nServer: Synology/DSM UPnP/1.0\r\n\r\n"

    def fake_transact(timeout):
        return [(resp, ("10.0.0.7", 1900))]

    names = collect_ssdp_names(timeout=1.0, transact=fake_transact)
    assert names == {"10.0.0.7": "Synology/DSM UPnP/1.0"}


def test_collect_ssdp_names_never_raises_on_oserror():
    def fake_transact(timeout):
        raise OSError("network unreachable")

    assert collect_ssdp_names(timeout=1.0, transact=fake_transact) == {}


# --- netbios.py -------------------------------------------------------------------------------------
NBSTAT_QTYPE_FOR_TEST = 0x0021


def _nbstat_response(name: str, *, group: bool = False, suffix: int = 0x00) -> bytes:
    header = struct.pack(">HHHHHH", 0x5A5A, 0x8400, 0, 1, 0, 0)
    encoded_q = b"A" * 32  # placeholder encoded question name (not re-parsed by the response reader)
    name_section = bytes([32]) + encoded_q + b"\x00"
    rr_head = struct.pack(">HHI", NBSTAT_QTYPE_FOR_TEST, 1, 0)
    padded = name.encode().ljust(15)[:15]
    flags = 0x8000 if group else 0x0000
    entry = padded + bytes([suffix]) + struct.pack(">H", flags)
    rdata = bytes([1]) + entry
    rr = name_section + rr_head + struct.pack(">H", len(rdata)) + rdata
    return header + rr


def test_build_nbstat_query_shape():
    q = build_nbstat_query(0x1234)
    assert q[:2] == b"\x12\x34"
    assert q[4:6] == b"\x00\x01"  # qdcount = 1
    assert len(q) == 12 + 1 + 32 + 1 + 2 + 2  # header + namelen + encoded name + nul + qtype + qclass


def test_parse_nbstat_response_finds_unique_workstation_name():
    data = _nbstat_response("MYPRINTER")
    entries = parse_nbstat_response(data)
    assert entries and entries[0]["name"] == "MYPRINTER" and not entries[0]["group"]


def test_parse_nbstat_response_skips_group_names():
    data = _nbstat_response("WORKGROUP", group=True)
    assert parse_nbstat_response(data) == [{"name": "WORKGROUP", "suffix": 0, "group": True}]


def test_query_netbios_name_uses_injected_transactor():
    data = _nbstat_response("DESKTOP-ABC")

    def fake_transact(ip, timeout):
        assert ip == "10.0.0.8"
        return data

    assert query_netbios_name("10.0.0.8", transact=fake_transact) == "DESKTOP-ABC"


def test_query_netbios_name_timeout_returns_none():
    assert query_netbios_name("10.0.0.9", transact=lambda ip, timeout: None) is None


def test_query_netbios_names_batch_matches_by_source_ip():
    data_a = _nbstat_response("HOST-A")
    data_b = _nbstat_response("HOST-B")

    def fake_batch(ips, timeout):
        assert set(ips) == {"10.0.0.10", "10.0.0.11"}
        return [(data_a, ("10.0.0.10", 137)), (data_b, ("10.0.0.11", 137))]

    names = query_netbios_names(["10.0.0.10", "10.0.0.11"], transact=fake_batch)
    assert names == {"10.0.0.10": "HOST-A", "10.0.0.11": "HOST-B"}


def test_query_netbios_names_empty_list_short_circuits():
    assert query_netbios_names([], transact=lambda ips, timeout: (_ for _ in ()).throw(AssertionError())) == {}


# --- orchestrator ------------------------------------------------------------------------------------
def test_collect_local_names_merges_with_netbios_priority(monkeypatch):
    import app.core.discovery as discovery_mod

    monkeypatch.setattr(discovery_mod, "collect_ssdp_names", lambda timeout: {"10.0.0.1": "ssdp-server"})
    monkeypatch.setattr(discovery_mod, "collect_mdns_names", lambda timeout: {"10.0.0.1": "mdns-name",
                                                                              "10.0.0.2": "mdns-only"})
    monkeypatch.setattr(discovery_mod, "query_netbios_names", lambda ips, timeout: {"10.0.0.1": "NETBIOS-NAME"})

    out = collect_local_names(["10.0.0.1", "10.0.0.2"])
    assert out["10.0.0.1"] == ("NETBIOS-NAME", "netbios")  # netbios wins over mdns/ssdp
    assert out["10.0.0.2"] == ("mdns-only", "mdns")


def test_collect_local_names_skips_disabled_sources(monkeypatch):
    import app.core.discovery as discovery_mod

    calls = []
    monkeypatch.setattr(discovery_mod, "collect_ssdp_names", lambda timeout: calls.append("ssdp") or {})
    monkeypatch.setattr(discovery_mod, "collect_mdns_names", lambda timeout: calls.append("mdns") or {})
    monkeypatch.setattr(discovery_mod, "query_netbios_names", lambda ips, timeout: calls.append("netbios") or {})

    collect_local_names(["10.0.0.1"], mdns=False, ssdp=False, netbios=True)
    assert calls == ["netbios"]


def test_collect_local_names_empty_ips_is_a_noop(monkeypatch):
    import app.core.discovery as discovery_mod

    monkeypatch.setattr(discovery_mod, "collect_ssdp_names", lambda timeout: (_ for _ in ()).throw(AssertionError()))
    assert collect_local_names([]) == {}


def test_collect_local_names_caps_netbios_batch_size(monkeypatch):
    import app.core.discovery as discovery_mod

    discovery_mod.reset_netbios_cursor()
    seen = []
    monkeypatch.setattr(discovery_mod, "collect_ssdp_names", lambda timeout: {})
    monkeypatch.setattr(discovery_mod, "collect_mdns_names", lambda timeout: {})
    monkeypatch.setattr(discovery_mod, "query_netbios_names", lambda ips, timeout: seen.extend(ips) or {})

    many_ips = [f"10.0.{i // 256}.{i % 256}" for i in range(discovery_mod.MAX_NETBIOS_QUERIES_PER_PASS + 20)]
    collect_local_names(many_ips)
    assert len(seen) == discovery_mod.MAX_NETBIOS_QUERIES_PER_PASS


def test_netbios_batch_rotates_fairly_across_passes(monkeypatch):
    import app.core.discovery as discovery_mod

    discovery_mod.reset_netbios_cursor()
    batches = []
    monkeypatch.setattr(discovery_mod, "collect_ssdp_names", lambda timeout: {})
    monkeypatch.setattr(discovery_mod, "collect_mdns_names", lambda timeout: {})
    monkeypatch.setattr(discovery_mod, "query_netbios_names",
                        lambda ips, timeout: batches.append(list(ips)) or {})

    # 150 IPs, cap 100: two passes must cover disjoint prefixes of the sorted list (round-robin).
    many_ips = [f"10.0.0.{i}" for i in range(1, 151)]
    collect_local_names(many_ips, mdns=False, ssdp=False, netbios=True)
    collect_local_names(many_ips, mdns=False, ssdp=False, netbios=True)
    assert len(batches) == 2
    assert len(batches[0]) == discovery_mod.MAX_NETBIOS_QUERIES_PER_PASS
    assert len(batches[1]) == discovery_mod.MAX_NETBIOS_QUERIES_PER_PASS
    assert batches[0] != batches[1]
    # Union of two passes should include hosts beyond the first-100 prefix of the old bug.
    covered = set(batches[0]) | set(batches[1])
    assert "10.0.0.150" in covered
    assert len(covered) >= discovery_mod.MAX_NETBIOS_QUERIES_PER_PASS + 20


# --- settings API ------------------------------------------------------------------------------------
@pytest.fixture
def client(db_env):
    limiter.reset()
    with TestClient(app) as c:
        yield c


def csrf(c: TestClient) -> dict:
    return {"X-CSRF-Token": c.cookies.get("nf_csrf", "")}


@pytest.fixture
def admin(client):
    assert client.post("/api/setup/admin", json={"username": "admin", "password": "correct-horse-1"}).status_code == 200
    return client


def test_discovery_settings_default_passive_only_and_roundtrip(admin):
    """Spec 9.2: default on only for cheap passive listening; active probes are opt-in."""
    r = admin.get("/api/settings/discovery")
    assert r.status_code == 200
    body = r.json()
    assert body == {"enabled": True, "mdns": True, "ssdp": False, "netbios": False, "timeout_seconds": 2.0}

    r = admin.put("/api/settings/discovery", json={
        "enabled": True, "mdns": False, "ssdp": True, "netbios": True, "timeout_seconds": 5.0,
    }, headers=csrf(admin))
    assert r.status_code == 200
    assert r.json()["mdns"] is False and r.json()["ssdp"] is True and r.json()["timeout_seconds"] == 5.0
    assert admin.get("/api/settings/discovery").json()["netbios"] is True


def test_discovery_settings_rejects_unknown_fields(admin):
    r = admin.put("/api/settings/discovery", json={
        "enabled": True, "mdns": True, "ssdp": True, "netbios": True, "timeout_seconds": 2.0, "nmap_args": "-sU",
    }, headers=csrf(admin))
    assert r.status_code == 422


def test_viewer_cannot_change_discovery_settings(client, db):
    from .helpers import make_network

    make_network(db)
    assert client.post("/api/setup/admin", json={"username": "owner2", "password": "correct-horse-1"}).status_code == 200
    assert client.post("/api/users", json={"username": "viewer3", "password": "correct-horse-1", "role": "viewer"},
                       headers=csrf(client)).status_code == 201
    client.post("/api/auth/logout", headers=csrf(client))
    assert client.post("/api/auth/login", json={"username": "viewer3", "password": "correct-horse-1"}).status_code == 200
    assert client.get("/api/settings/discovery").status_code == 403
