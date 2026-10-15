"""Services nmap could not name are identified from the replies it recorded (servicefp)."""
from __future__ import annotations

from xml.sax.saxutils import quoteattr

from app.scanner.nmap_parser import SOFT_MATCH_CONFIDENCE, parse_nmap_xml
from app.scanner.response_fp import http_identity, parse_servicefp, split_server
from app.scanner.types import VERIFIED_METHOD


def _esc(data: bytes) -> str:
    """nmap's servicefp escaping."""
    out = []
    for b in data:
        c = chr(b)
        if c == "\r":
            out.append("\\r")
        elif c == "\n":
            out.append("\\n")
        elif c in '"\\':
            out.append("\\" + c)
        elif c == ".":
            out.append("\\.")
        elif 0x21 <= b < 0x7F:
            out.append(c)
        else:
            out.append(f"\\x{b:02x}")
    return "".join(out)


def servicefp(port: int, replies: dict[str, bytes], tls: bool = False) -> str:
    head = f"SF-Port{port}-TCP:V=7.95%{'T=SSL%' if tls else ''}I=2%D=1/1%Time=0%P=x86_64-pc-linux-gnu"
    body = "".join(f'%r({name},{len(data):X},"{_esc(data)}")' for name, data in replies.items())
    # nmap wraps long fingerprints into "\nSF:" continuation lines
    return (head + body + ";").replace("%r(", "\nSF:%r(")


def port_xml(port: int, name: str, method: str, conf: int, fp: str | None = None,
             tunnel: str | None = None, product: str | None = None) -> str:
    attrs = f'name="{name}" method="{method}" conf="{conf}"'
    if product:
        attrs += f' product="{product}"'
    if tunnel:
        attrs += f' tunnel="{tunnel}"'
    if fp:
        attrs += f" servicefp={quoteattr(fp)}"
    return (f'<port protocol="tcp" portid="{port}"><state state="open" reason="syn-ack"/>'
            f"<service {attrs}/></port>")


def nmap_doc(*ports: str) -> str:
    return (
        '<?xml version="1.0"?><nmaprun><scaninfo type="syn" protocol="tcp" services="1-10000"/>'
        '<host><status state="up" reason="syn-ack"/><address addr="192.0.2.10" addrtype="ipv4"/>'
        f"<ports>{''.join(ports)}</ports></host>"
        '<runstats><finished exit="success"/></runstats></nmaprun>'
    )


KEYCLOAK = (b"HTTP/1.0 200 OK\r\ncontent-length: 120\r\n\r\n<html>\n<h2>Keycloak Management Interface</h2>\n"
            b"<ul><li><a href=\"/health\">/health</a></li></ul>\n</html>\n")
HAL_REDIRECT = b"HTTP/1.0 302 Found\r\nConnection: close\r\nLocation: /console/index.html\r\nContent-Length: 0\r\n\r\n"
UNDERTOW_404 = (b"HTTP/1.0 404 Not Found\r\nX-Frame-Options: SAMEORIGIN\r\nContent-Length: 74\r\n"
                b"Content-Type: text/html\r\n\r\n<html><head><title>Error</title></head><body>404 - Not Found</body></html>")
BAD_REQUEST = b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"


def parsed_ports(*ports: str):
    run = parse_nmap_xml(nmap_doc(*ports))
    return {p.port: p for p in run.hosts[0].ports}


def test_unrecognized_http_services_identified_from_servicefp():
    ports = parsed_ports(
        port_xml(9000, "cslistener", "table", 3, servicefp(9000, {"GetRequest": KEYCLOAK,
                                                                  "SSLSessionReq": BAD_REQUEST}, tls=True), "ssl"),
        port_xml(9993, "palace-2", "table", 3, servicefp(9993, {"GenericLines": BAD_REQUEST,
                                                                "GetRequest": HAL_REDIRECT}, tls=True), "ssl"),
        port_xml(8080, "http-proxy", "table", 3, servicefp(8080, {"GetRequest": UNDERTOW_404,
                                                                  "RTSPRequest": BAD_REQUEST})),
        port_xml(8088, "radan-http", "table", 3, servicefp(8088, {"SSLSessionReq": BAD_REQUEST})),
    )
    kc, hal, und, bare = ports[9000], ports[9993], ports[8080], ports[8088]
    assert (kc.service, kc.tunnel, kc.product, kc.extra_info) == (
        "http", "ssl", "Keycloak", "Keycloak Management Interface")
    assert (hal.service, hal.tunnel, hal.product) == ("http", "ssl", "WildFly management console (HAL)")
    assert (und.service, und.product, und.extra_info) == ("http", "Undertow", None)  # "Error" title dropped
    # Only proof of HTTP: a 400 status line in answer to a TLS hello
    assert (bare.service, bare.product, bare.confidence) == ("http", None, 8)
    assert all(p.method == VERIFIED_METHOD for p in ports.values())
    assert (kc.confidence, hal.confidence) == (9, 9)


def test_non_http_replies_and_real_fingerprints_left_alone():
    ports = parsed_ports(
        port_xml(7050, "unknown", "table", 3, servicefp(7050, {"GenericLines": b"\x01\x12\x00\x00-\x00\x00"})),
        port_xml(443, "http", "probed", 10, tunnel="ssl", product="nginx"),
        port_xml(80, "rtsp", "probed", 10),  # bare soft match: nmap writes no servicefp for it
    )
    assert (ports[7050].service, ports[7050].method, ports[7050].confidence) == ("unknown", "table", 3)
    assert (ports[443].product, ports[443].method, ports[443].confidence) == ("nginx", "probed", 10)
    # soft match keeps its label (verification re-checks it) but no longer claims 10/10
    assert (ports[80].service, ports[80].method, ports[80].confidence) == ("rtsp", "probed", SOFT_MATCH_CONFIDENCE)


def test_servicefp_unescape_round_trip():
    tls, replies = parse_servicefp(servicefp(1, {"GetRequest": KEYCLOAK, "NULL": b"\x00\xff\"\\"}, tls=True))
    assert tls is True
    assert replies == {"GetRequest": KEYCLOAK, "NULL": b"\x00\xff\"\\"}


def test_http_identity_product_version_and_auth():
    assert split_server("Apache/2.4.57 (Red Hat Enterprise Linux) OpenSSL/3.0.7") == (
        "Apache", "2.4.57", "Red Hat Enterprise Linux")
    assert split_server("Microsoft-IIS/10.0") == ("Microsoft-IIS", "10.0", None)
    assert split_server("embedded httpd") == ("embedded httpd", None, None)

    welcome = http_identity(b"HTTP/1.1 200 OK\r\n\r\n<html><title>Welcome to JBoss EAP 8</title></html>")
    assert (welcome.product, welcome.version, welcome.extra_info) == ("JBoss EAP", "8", "Welcome to JBoss EAP 8")

    digest = http_identity(b'HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Digest realm="ManagementRealm"\r\n\r\n')
    assert (digest.status, digest.auth_scheme, digest.extra_info) == (401, "Digest", "Digest auth required")

    assert http_identity(b"RTSP/1.0 404 Not Found\r\n\r\n") is None
    assert http_identity(b"SSH-2.0-OpenSSH_9.6\r\n") is None
