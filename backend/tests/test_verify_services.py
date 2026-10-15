"""Weak nmap service labels are re-checked with one protocol-correct request."""
from __future__ import annotations

import socketserver
import threading
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager

from app.scanner.types import HostObservation, PortObservation, ScanContext
from app.scanner.verify_services import (
    VERIFIED_METHOD,
    needs_verification,
    verify_hosts,
    verify_port,
)

from .helpers import ScriptedScanner, device_by_ip, event_types, events, host, make_network, port, scan


def echo_httpd(request: bytes) -> bytes:
    """Embedded camera/DVR web server: echoes the request's protocol token in the status line."""
    line = request.split(b"\r\n", 1)[0]
    proto = line.rsplit(b" ", 1)[-1]
    if proto in (b"HTTP/1.0", b"HTTP/1.1"):
        return (proto + b" 401 Unauthorized\r\nWWW-Authenticate: Basic realm=\"\"\r\n"
                b"Server: embedded httpd\r\nConnection: close\r\n\r\n<HTML>401</HTML>")
    return (proto + b" 505 HTTP Version Not Supported\r\nServer: embedded httpd\r\n"
            b"Connection: close\r\n\r\nOnly 1.0 & 1.1!")


def real_rtsp(request: bytes) -> bytes:
    if request.startswith(b"OPTIONS"):
        return b"RTSP/1.0 200 OK\r\nCSeq: 1\r\nServer: cam-rtsp 1.0\r\nPublic: OPTIONS, DESCRIBE\r\n\r\n"
    return b"RTSP/1.0 400 Bad Request\r\nCSeq: 0\r\n\r\n"


@contextmanager
def tcp_server(respond: Callable[[bytes], bytes]) -> Iterator[int]:
    class Handler(socketserver.BaseRequestHandler):
        def handle(self) -> None:
            data = b""
            while b"\r\n\r\n" not in data:
                chunk = self.request.recv(1024)
                if not chunk:
                    return
                data += chunk
            self.request.sendall(respond(data))

    srv = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Handler)
    srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        yield srv.server_address[1]
    finally:
        srv.shutdown()
        srv.server_close()


def nmap_soft(port_no: int, service: str | None) -> PortObservation:
    """What nmap's XML gives for a bare status-line soft match: probed, conf 10, no product."""
    return PortObservation(port=port_no, service=service, method="probed", confidence=10)


def test_only_weak_labels_need_verification():
    assert needs_verification(nmap_soft(80, "rtsp"))
    assert needs_verification(nmap_soft(80, "sip"))
    assert needs_verification(nmap_soft(9000, "unknown"))
    assert needs_verification(nmap_soft(9000, None))
    assert not needs_verification(PortObservation(port=554, service="rtsp", product="Hikvision rtsp",
                                                  method="probed", confidence=10))
    assert not needs_verification(nmap_soft(23, "telnet"))
    assert not needs_verification(nmap_soft(443, "tcpwrapped"))
    assert not needs_verification(nmap_soft(5060, "sip"))  # telephony: never probed
    # port-table guess: nmap already tried GET + TLS there, nothing to learn
    assert not needs_verification(PortObservation(port=7050, service="unknown", method="table", confidence=3))
    assert not needs_verification(PortObservation(port=80, protocol="udp", service="rtsp", method="probed"))
    assert not needs_verification(PortObservation(port=80, service="http", method=VERIFIED_METHOD))
    # HTTP soft matches carry no product: checked to find one
    assert needs_verification(nmap_soft(8080, "http-proxy"))
    assert needs_verification(nmap_soft(8443, "https-alt"))
    assert not needs_verification(PortObservation(port=80, service="http", product="nginx", method="probed"))


def test_echoing_web_server_labelled_rtsp_becomes_http():
    with tcp_server(echo_httpd) as p:
        po = nmap_soft(p, "rtsp")
        assert verify_port("127.0.0.1", po)
    # protocol + product, no version: 9 on PortReveal's scale; the 401 challenge is kept as info
    assert (po.service, po.product, po.method, po.confidence) == ("http", "embedded httpd", VERIFIED_METHOD, 9)
    assert po.extra_info == "Basic auth required"


def test_real_rtsp_server_keeps_label():
    with tcp_server(real_rtsp) as p:
        po = nmap_soft(p, "rtsp")
        assert verify_port("127.0.0.1", po)
    assert (po.service, po.product, po.method) == ("rtsp", "cam-rtsp 1.0", VERIFIED_METHOD)


def test_unknown_port_answering_http_is_identified():
    with tcp_server(echo_httpd) as p:
        po = nmap_soft(p, None)
        assert verify_port("127.0.0.1", po)
    assert po.service == "http" and po.method == VERIFIED_METHOD


def test_inconclusive_or_unreachable_leaves_nmap_label():
    po = nmap_soft(80, "rtsp")
    assert not verify_port("127.0.0.1", po, send=lambda *_: None)
    assert (po.service, po.method) == ("rtsp", "probed")
    with tcp_server(lambda _req: b"SSH-2.0-dropbear\r\n\r\n") as p:
        po = nmap_soft(p, "unknown")
        assert not verify_port("127.0.0.1", po)
    assert (po.service, po.method) == ("unknown", "probed")


def test_verify_hosts_skips_identified_ports_and_failed_hosts():
    sent: list[tuple[int, bytes]] = []

    def send(_ip: str, port_no: int, _tls: bool, payload: bytes) -> bytes | None:
        sent.append((port_no, payload))
        return b"HTTP/1.0 200 OK\r\n\r\n"

    hosts = [
        HostObservation(ip="10.0.0.9", ports=[
            nmap_soft(80, "rtsp"),
            PortObservation(port=22, service="ssh", product="OpenSSH", method="probed", confidence=10),
        ]),
        HostObservation(ip="10.0.0.10", ports=None, port_scan_failed=True),
    ]
    assert verify_hosts(hosts, ScanContext(1), send=send) == 1
    assert [p for p, _ in sent] == [80, 80]  # RTSP check, then HTTP check; never port 22
    assert hosts[0].ports[0].service == "http"


def test_verification_correction_is_identification_and_not_flapped(db):
    net = make_network(db)
    weak = nmap_soft(80, "rtsp")
    scan(ScriptedScanner([host("10.0.0.7", [port(23, "telnet"), weak])]), network_id=net.id)

    fixed = PortObservation(port=80, service="http", product="embedded httpd",
                            method=VERIFIED_METHOD, confidence=10)
    s = scan(ScriptedScanner([host("10.0.0.7", [port(23, "telnet"), fixed])]), network_id=net.id)
    evs = [e for e in events(db, s.id) if e.event_type.startswith("service_")]
    assert [e.event_type for e in evs] == ["service_detected"]  # not service_changed
    assert "embedded httpd" in evs[0].new_value

    # A later run where verification could not reach the port must not flip it back to rtsp.
    s = scan(ScriptedScanner([host("10.0.0.7", [port(23, "telnet"), nmap_soft(80, "rtsp")])]),
             network_id=net.id)
    assert not [t for t in event_types(db, s.id) if t.startswith(("service_", "tag_"))]
    p80 = next(p for p in device_by_ip(db, "10.0.0.7").ports if p.port == 80)
    assert (p80.service, p80.product, p80.method) == ("http", "embedded httpd", VERIFIED_METHOD)


UNDERTOW_404 = (b"HTTP/1.0 404 Not Found\r\nX-Frame-Options: SAMEORIGIN\r\nContent-Type: text/html\r\n\r\n"
                b"<html><head><title>Error</title></head><body>404 - Not Found</body></html>")


def test_http_soft_match_gets_product_from_response():
    po = nmap_soft(8080, "http-proxy")
    assert verify_port("10.0.0.9", po, send=lambda *_: UNDERTOW_404)
    assert (po.service, po.product, po.extra_info, po.confidence) == ("http", "Undertow", None, 9)


def test_tls_only_port_silent_to_plaintext_is_retried_over_tls():
    """Netty/Keycloak TLS port nmap mislabelled plain "rtsp": plaintext gets silence, TLS gets HTTP."""
    calls: list[tuple[bool, bytes]] = []

    def send(_ip: str, _port: int, tls: bool, payload: bytes) -> bytes | None:
        calls.append((tls, payload[:7]))
        if not tls:
            return b""  # connected, server said nothing
        return b"HTTP/1.0 200 OK\r\n\r\n<html><h2>Keycloak Management Interface</h2></html>"

    po = nmap_soft(9000, "rtsp")
    assert verify_port("10.0.0.9", po, send=send)
    assert (po.service, po.tunnel, po.product, po.extra_info) == (
        "http", "ssl", "Keycloak", "Keycloak Management Interface")
    assert calls == [(False, b"OPTIONS"), (False, b"GET / H"), (True, b"GET / H")]


def test_unreachable_port_is_not_retried_over_tls():
    calls: list[bool] = []

    def send(_ip: str, _port: int, tls: bool, _payload: bytes) -> bytes | None:
        calls.append(tls)
        return None  # no connection at all

    assert not verify_port("10.0.0.9", nmap_soft(8088, "unknown"), send=send)
    assert calls == [False]


def test_verify_hosts_checks_one_port_at_a_time_per_host():
    active: dict[str, int] = {}
    peak: dict[str, int] = {}
    lock = threading.Lock()

    def send(ip: str, _port: int, _tls: bool, _payload: bytes) -> bytes | None:
        with lock:
            active[ip] = active.get(ip, 0) + 1
            peak[ip] = max(peak.get(ip, 0), active[ip])
        time.sleep(0.02)
        with lock:
            active[ip] -= 1
        return b"HTTP/1.0 200 OK\r\n\r\n"

    hosts = [HostObservation(ip=f"10.0.0.{i}", ports=[nmap_soft(p, "unknown") for p in (8080, 8081, 8082)])
             for i in (1, 2, 3)]
    assert verify_hosts(hosts, ScanContext(1), send=send) == 9
    assert peak == {"10.0.0.1": 1, "10.0.0.2": 1, "10.0.0.3": 1}


def test_verify_hosts_stops_at_time_budget():
    hosts = [HostObservation(ip="10.0.0.1", ports=[nmap_soft(8080, "unknown")])]
    assert verify_hosts(hosts, ScanContext(1), send=lambda *_: b"HTTP/1.0 200 OK\r\n\r\n", budget_s=0) == 0
    assert hosts[0].ports[0].service == "unknown"
