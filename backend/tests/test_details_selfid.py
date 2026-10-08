"""Kept NSE facts, one-line port summaries, RTSP DESCRIBE and device self-identification parsers."""
from __future__ import annotations

import base64
import hashlib
import plistlib
import socket
import struct
import threading
from datetime import datetime, timezone

from app.core.port_facts import cert_facts, device_flags, is_private_mac, port_summary, script_identity
from app.core.selfid import (
    _PTR,
    _TXT,
    dns_query,
    ipp_request,
    mdns_identity,
    parse_airplay_info,
    parse_dns,
    parse_ipp,
    parse_upnp,
    probe_device,
)
from app.core.web_capture.rtsp import rtsp_describe
from app.models import DevicePort
from app.scanner.known_ports import is_raw_print_port
from app.scanner.nmap_parser import parse_nmap_xml
from app.scanner.types import PortObservation

from .helpers import ScriptedScanner, device_by_ip, host, make_network, scan

XML = """<?xml version="1.0"?>
<nmaprun><host><status state="up"/><address addr="10.0.0.9" addrtype="ipv4"/>
<ports>
<port protocol="tcp" portid="443"><state state="open"/><service name="http" tunnel="ssl" method="probed" conf="10"/>
<script id="ssl-cert" output="Subject: commonName=nas.example">
<table key="subject"><elem key="commonName">nas.example</elem></table>
<table key="issuer"><elem key="commonName">nas.example</elem></table>
<table key="validity"><elem key="notBefore">2020-01-01T00:00:00</elem><elem key="notAfter">2021-03-01T00:00:00</elem></table>
<elem key="pem">-----BEGIN CERTIFICATE-----</elem>
</script>
</port>
<port protocol="tcp" portid="1883"><state state="open"/><service name="mqtt" method="probed" conf="10"/>
<script id="mqtt-subscribe" output="Topics and their most recent payloads: secret"/></port>
</ports>
<hostscript><script id="smb2-security-mode" output="3:1:1: Message signing enabled but not required">
<table key="3:1:1"><elem>Message signing enabled but not required</elem></table></script>
<script id="nbstat" output="NetBIOS name: FILESRV, NetBIOS user: &lt;unknown&gt;"/></hostscript>
</host><runstats><finished exit="success"/></runstats></nmaprun>"""


def test_parser_keeps_allowlisted_scripts_only():
    h = parse_nmap_xml(XML).hosts[0]
    https, mqtt = h.ports
    assert set(https.scripts) == {"ssl-cert"} and "pem" not in https.scripts["ssl-cert"]["data"]
    assert https.scripts["ssl-cert"]["data"]["validity"]["notAfter"] == "2021-03-01T00:00:00"
    assert mqtt.scripts == {}  # never stored
    assert set(h.scripts) == {"smb2-security-mode", "nbstat"}


def test_port_summary_and_flags_restate_script_output():
    h = parse_nmap_xml(XML).hosts[0]
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    text, flags = cert_facts(h.ports[0].scripts, now)
    assert text == "cert: nas.example · expired 2021-03 · self-signed"
    assert set(flags) == {"TLS expired", "TLS self-signed"}
    line, smb_flags = port_summary(445, "microsoft-ds", "probed", None, h.scripts)
    assert line == "FILESRV · signing not required" and smb_flags == ["SMB signing not required"]
    assert script_identity(h.scripts) == {"name": ("FILESRV", "NetBIOS")}

    key = base64.b64encode(b"k" * 51).decode()
    ssh = {"scripts": {"ssh-hostkey": {"output": "", "data": [{"type": "ssh-ed25519", "key": key, "bits": "256"}]}}}
    fp = base64.b64encode(hashlib.sha256(b"k" * 51).digest()).decode().rstrip("=")
    assert port_summary(22, "ssh", "probed", ssh)[0] == f"key ED25519 SHA256:{fp[:12]}…"

    socks = {"scripts": {"socks-auth-info": {"output": "\n  No authentication\n  Username and password", "data": []}}}
    rtsp = {"rtsp": {"auth": "none", "describe_status": 200}}
    telnet = DevicePort(port=23, service="telnet", method="probed", details=None)
    ports = [DevicePort(port=1080, service="socks5", method="probed", details=socks),
             DevicePort(port=554, service="rtsp", method="probed", details=rtsp), telnet,
             DevicePort(port=2323, service="telnet", method="table", details=None)]  # a guess flags nothing
    assert device_flags(ports, None) == ["SOCKS without auth", "RTSP without password", "Telnet open"]


def test_private_mac_and_raw_print_ports():
    assert is_private_mac("62:27:28:DB:8C:E4") and is_private_mac("12:A4:BF:8F:0B:20")
    assert not is_private_mac("00:41:A3:F2:02:F2") and not is_private_mac(None)
    assert is_raw_print_port(9100) and is_raw_print_port(9107) and not is_raw_print_port(9108)


def test_script_details_follow_the_version_cache(db):
    net = make_network(db)
    cert = {"ssl-cert": {"output": "Subject: commonName=a", "data": {"subject": {"commonName": "a"}}}}
    fresh = PortObservation(port=443, service="https", method="probed", confidence=10, version_checked=True,
                            scripts=cert)
    scan(ScriptedScanner([host("10.0.0.1", [fresh])]), network_id=net.id)
    assert device_by_ip(db, "10.0.0.1").ports[0].details == {"scripts": cert}
    cached = PortObservation(port=443, service="https", method="table", confidence=3)  # no -sV this time
    scan(ScriptedScanner([host("10.0.0.1", [cached])]), network_id=net.id)
    assert device_by_ip(db, "10.0.0.1").ports[0].details == {"scripts": cert}
    rechecked = PortObservation(port=443, service="https", method="probed", confidence=10, version_checked=True)
    scan(ScriptedScanner([host("10.0.0.1", [rechecked])]), network_id=net.id)
    assert device_by_ip(db, "10.0.0.1").ports[0].details is None  # re-versioned: old output replaced


def test_tls_cert_and_netbios_verify_truenas_profile(db):
    net = make_network(db)
    cert = {"ssl-cert": {"output": "", "data": {"subject": {"commonName": "truenas.home.arpa"}}}}
    po = PortObservation(port=443, service="https", method="probed", confidence=10, version_checked=True,
                         scripts=cert)
    scan(ScriptedScanner([host("10.0.0.7", [po])]), network_id=net.id)
    d = device_by_ip(db, "10.0.0.7")
    assert (d.port_profile, d.port_profile_source) == ("truenas", "TLS cert")


# ---- self-identification parsers --------------------------------------------------------------

def _rr(name: str, rtype: int, rdata: bytes) -> bytes:
    return dns_query(0, [(name, rtype)])[12:-4] + struct.pack("!HHIH", rtype, 1, 120, len(rdata)) + rdata


def _txt(*items: str) -> bytes:
    return b"".join(bytes([len(i.encode())]) + i.encode() for i in items)


def test_dns_parse_reads_ptr_and_txt():
    ptr_target = dns_query(0, [("Living Room._airplay._tcp.local", 1)])[12:-4]
    msg = struct.pack("!6H", 7, 0x8400, 0, 2, 0, 0)
    msg += _rr("_airplay._tcp.local", _PTR, ptr_target)
    msg += _rr("Living Room._airplay._tcp.local", _TXT, _txt("model=AppleTV6,2", "flags=0x4"))
    recs = parse_dns(msg)
    assert recs[0] == ("_airplay._tcp.local", _PTR, "Living Room._airplay._tcp.local")
    assert recs[1][2] == ["model=AppleTV6,2", "flags=0x4"]


def test_mdns_identity_uses_only_announced_values():
    asked: list[list[tuple[str, int]]] = []

    def fake(ip, questions):
        asked.append(questions)
        if len(asked) == 1:
            return [("9.0.0.10.in-addr.arpa", _PTR, "tv-living.local"),
                    ("_googlecast._tcp.local", _PTR, "chromecast-abc._googlecast._tcp.local")]
        return [("chromecast-abc._googlecast._tcp.local", _TXT, ["md=Chromecast Ultra", "fn=Living Room TV"])]

    found = mdns_identity("10.0.0.9", records_for=fake)
    assert len(asked) == 2  # one PTR query, then one TXT query for the announced instance
    assert found["name"] == ("tv-living", "mDNS")
    assert found["model"] == ("Chromecast Ultra", "mDNS _googlecast._tcp")
    assert "manufacturer" not in found and "firmware" not in found  # never inferred


def test_samba_finder_icon_model_is_not_a_device_model():
    def fake(ip, questions):
        if questions[0][1] == _PTR:
            return [("_smb._tcp.local", _PTR, "nas._smb._tcp.local"),
                    ("_device-info._tcp.local", _PTR, "nas._device-info._tcp.local")]
        return [("nas._device-info._tcp.local", _TXT, ["model=MacPro7,1@ECOLOR=226,226,224"])]

    assert "model" not in mdns_identity("10.0.0.5", records_for=fake)


def test_upnp_airplay_ipp_parsers():
    xml = b"""<root xmlns="urn:schemas-upnp-org:device-1-0"><device><friendlyName>[LG] webOS TV</friendlyName>
    <manufacturer>LG Electronics</manufacturer><modelName>OLED55C1</modelName><modelNumber>55C1</modelNumber>
    <deviceList><device><modelName>sub</modelName></device></deviceList></device></root>"""
    assert parse_upnp(xml) == {"name": ("[LG] webOS TV", "UPnP"), "model": ("OLED55C1 55C1", "UPnP"),
                               "manufacturer": ("LG Electronics", "UPnP")}
    info = plistlib.dumps({"model": "AppleTV6,2", "name": "Den", "osBuildVersion": "21J354"}, fmt=plistlib.FMT_BINARY)
    assert parse_airplay_info(info) == {"name": ("Den", "AirPlay"), "model": ("AppleTV6,2", "AirPlay"),
                                        "firmware": ("21J354", "AirPlay")}

    req = ipp_request("ipp://10.0.0.5:631/ipp/print")
    assert req[:4] == b"\x02\x00\x00\x0b" and req.endswith(b"\x03")

    def attr(tag, name, value):
        return bytes([tag]) + struct.pack("!H", len(name)) + name + struct.pack("!H", len(value)) + value
    resp = struct.pack("!BBHI", 2, 0, 0, 1) + b"\x01" + attr(0x47, b"attributes-charset", b"utf-8") + b"\x04"
    resp += attr(0x41, b"printer-make-and-model", b"HP LaserJet M404")
    resp += attr(0x41, b"printer-device-id", b"MFG:HP;MDL:LaserJet M404;")
    resp += attr(0x41, b"printer-firmware-string-version", b"002.2049A") + b"\x03"
    assert parse_ipp(resp) == {"model": ("HP LaserJet M404", "IPP"), "firmware": ("002.2049A", "IPP"),
                               "manufacturer": ("HP", "IPP")}


def test_probe_device_skips_unconfirmed_and_raw_print_ports(monkeypatch):
    import app.core.selfid as selfid

    calls = []
    monkeypatch.setattr(selfid, "mdns_identity", lambda ip, src: {})
    monkeypatch.setattr(selfid, "upnp_identity", lambda ip, src: {})
    monkeypatch.setattr(selfid, "airplay_identity", lambda ip, port, src: calls.append(("airplay", port)) or {})
    monkeypatch.setattr(selfid, "ipp_identity", lambda ip, port, src: calls.append(("ipp", port)) or {})
    ports = [DevicePort(port=7000, service="rtsp", product="AirTunes rtspd", method="probed"),
             DevicePort(port=631, service="ipp", method="table"),  # port-number guess: not confirmed
             DevicePort(port=9100, service="ipp", product="ipp", method="probed")]  # raw print port: never
    probe_device("10.0.0.3", ports)
    assert calls == [("airplay", 7000)]


def test_rtsp_describe_reads_status_once():
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    got: list[bytes] = []

    def serve():
        conn, _ = srv.accept()
        got.append(conn.recv(1024))
        conn.sendall(b"RTSP/1.0 401 Unauthorized\r\nCSeq: 2\r\n\r\n")
        conn.close()

    t = threading.Thread(target=serve)
    t.start()
    assert rtsp_describe("127.0.0.1", srv.getsockname()[1]) == 401
    t.join()
    srv.close()
    assert got[0].startswith(b"DESCRIBE rtsp://127.0.0.1:")
