"""Identify services from raw responses — no extra network traffic.

When nmap gets data back but no signature matches, it still records every probe's
reply in the XML ``servicefp`` attribute ("services unrecognized despite returning
data"). The port is then reported by its port-table name (``palace-2``, ``us-srv``,
``cslistener`` …) with ``method="table"``, even when the reply is a plain
``HTTP/1.0 200 OK``. This module reads those replies (and replies PortReveal fetched
itself, see ``verify_services``) and derives protocol, product and version.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from .types import VERIFIED_METHOD, PortObservation

# r(GetRequest,A0,"HTTP/1\.0\x20200…") — the payload is nmap-escaped.
_FP_RESPONSE = re.compile(r'r\((\w+),[0-9A-Fa-f]+,"((?:[^"\\]|\\.)*)"\)', re.S)
_ESCAPE = re.compile(rb"\\(x[0-9A-Fa-f]{2}|.)", re.S)
_ESCAPES = {b"0": b"\0", b"r": b"\r", b"n": b"\n", b"t": b"\t"}

_HTTP_STATUS = re.compile(rb"^HTTP/1\.[01] (\d{3})")
_TITLE = re.compile(rb"<title[^>]*>\s*([^<]{1,200}?)\s*</title>", re.I)
_HEADING = re.compile(rb"<h[12][^>]*>\s*([^<]{1,200}?)\s*</h[12]>", re.I)
# Stock welcome pages that name the product (and often its version) only in the title.
_TITLE_PRODUCT = re.compile(
    r"^Welcome to (JBoss EAP|JBoss AS|WildFly|nginx|Apache Tomcat|Tomcat|Jetty)(?:\s+v?(\d[\w.]*))?", re.I)
_SERVER_VERSION = re.compile(r"^([A-Za-z][\w .+-]*?)/v?(\d[\w.+-]*)(?:\s+\(([^)]*)\))?")

# Probes whose reply can show an HTTP server, most informative first. An HTTP status line in
# reply to junk (TLS hello, SOCKS, bare CRLFs) still proves the listener speaks HTTP.
HTTP_PROBES = ("GetRequest", "HTTPOptions", "FourOhFourRequest", "RTSPRequest", "GenericLines",
               "SSLSessionReq", "TLSSessionReq", "Socks5", "Socks4")

# Products with no Server header that still say who they are in body / headers / redirect.
# (regex over "headers\r\n\r\nbody", product). Keep to distinctive, stable markers.
_BODY_PRODUCTS: tuple[tuple[re.Pattern[bytes], str], ...] = (
    (re.compile(rb"Keycloak", re.I), "Keycloak"),
    (re.compile(rb"\r\nLocation:[^\r\n]*/console/index\.html", re.I), "WildFly management console (HAL)"),
    (re.compile(rb"<title>\s*HAL Management Console", re.I), "WildFly management console (HAL)"),
    (re.compile(rb"\r\nX-Powered-By:\s*Undertow", re.I), "Undertow"),
    # Undertow's built-in error page (WildFly / JBoss EAP): "<body>404 - Not Found</body>"
    (re.compile(rb"<html><head><title>Error</title></head><body>\d{3} - "), "Undertow"),
    (re.compile(rb"<h1>Resource not found</h1>", re.I), "Vert.x web"),
    (re.compile(rb"\r\nX-Powered-By:\s*Express", re.I), "Express"),
    (re.compile(rb"\r\nX-Jenkins:", re.I), "Jenkins"),
    (re.compile(rb"Grafana", re.I), "Grafana"),
    (re.compile(rb"\r\nWWW-Authenticate:\s*NTLM", re.I), "Microsoft HTTPAPI / IIS (NTLM)"),
)


@dataclass
class HttpIdentity:
    status: int
    product: str | None = None
    version: str | None = None
    extra_info: str | None = None  # page title / heading, "Basic auth", …
    auth_scheme: str | None = None  # WWW-Authenticate scheme on 401


def unescape(payload: str) -> bytes:
    """Decode nmap's servicefp escaping (\\xHH, \\0, \\r, \\n, regex-escaped punctuation)."""
    raw = payload.encode("latin-1", errors="replace")

    def sub(m: re.Match[bytes]) -> bytes:
        tok = m.group(1)
        if tok[:1] == b"x" and len(tok) == 3:
            return bytes([int(tok[1:], 16)])
        return _ESCAPES.get(tok, tok)

    return _ESCAPE.sub(sub, raw)


def parse_servicefp(fp: str | None) -> tuple[bool, dict[str, bytes]]:
    """Return (inside TLS, {probe name: reply bytes}) from an nmap servicefp string."""
    if not fp:
        return False, {}
    flat = re.sub(r"\n?SF:", "", fp)
    tls = "%T=SSL%" in flat
    replies: dict[str, bytes] = {}
    for m in _FP_RESPONSE.finditer(flat):
        replies.setdefault(m.group(1), unescape(m.group(2)))
    return tls, replies


def _header(head: bytes, name: bytes) -> str | None:
    m = re.search(rb"\r\n" + name + rb":[ \t]*([^\r\n]+)", head, re.I)
    if not m:
        return None
    value = m.group(1).decode("latin-1").strip()
    return value[:120] or None


def split_server(server: str) -> tuple[str, str | None, str | None]:
    """"Apache/2.4.57 (Red Hat)" -> ("Apache", "2.4.57", "Red Hat"); free text stays product."""
    m = _SERVER_VERSION.match(server)
    if m:
        return m.group(1).strip(), m.group(2), m.group(3)
    return server, None, None


def http_identity(reply: bytes | None) -> HttpIdentity | None:
    """Product/version/title from one HTTP response, or None when the reply is not HTTP."""
    if not reply:
        return None
    m = _HTTP_STATUS.match(reply)
    if not m:
        return None
    head, _, body = reply.partition(b"\r\n\r\n")
    ident = HttpIdentity(status=int(m.group(1)))
    server = _header(head, b"Server") or _header(head, b"X-Powered-By")
    if server:
        ident.product, ident.version, ident.extra_info = split_server(server)
    if not ident.product:
        blob = head + b"\r\n\r\n" + body
        ident.product = next((name for rx, name in _BODY_PRODUCTS if rx.search(blob)), None)
    if ident.status in (401, 407):
        challenge = _header(head, b"WWW-Authenticate") or _header(head, b"Proxy-Authenticate")
        if challenge:
            ident.auth_scheme = challenge.split(None, 1)[0].rstrip(",")[:20]
    if not ident.extra_info:
        tm = _TITLE.search(body) or _HEADING.search(body)
        title = tm.group(1).decode("utf-8", errors="replace").strip() if tm else ""
        if ident.auth_scheme:
            ident.extra_info = f"{ident.auth_scheme} auth required"
        elif title and ident.status < 400:  # an error page's title ("Error", "404") says nothing
            ident.extra_info = title[:80]
        tp = _TITLE_PRODUCT.match(title) if title and not ident.product else None
        if tp:
            ident.product, ident.version = tp.group(1), tp.group(2)
    return ident


def best_http_identity(replies: dict[str, bytes]) -> HttpIdentity | None:
    """The most informative HTTP answer among nmap's probe replies (product beats bare status)."""
    found = [i for i in (http_identity(replies.get(p)) for p in HTTP_PROBES) if i]
    if not found:
        return None
    return max(found, key=lambda i: (bool(i.product), bool(i.version), bool(i.auth_scheme), i.status < 400))


def identity_confidence(protocol_confirmed: bool, product: str | None, version: str | None) -> int:
    """PortReveal's own 0-10 scale: protocol from a response 8, + product 9, + version 10."""
    if not protocol_confirmed:
        return 3
    return 10 if (product and version) else 9 if product else 8


def apply_http_identity(po: PortObservation, ident: HttpIdentity, *, tls: bool) -> None:
    po.service = "http"
    if tls:
        po.tunnel = "ssl"
    po.product, po.version, po.extra_info = ident.product, ident.version, ident.extra_info
    po.cpe = None
    po.method = VERIFIED_METHOD
    po.confidence = identity_confidence(True, po.product, po.version)


def apply_servicefp(po: PortObservation, fp: str | None) -> bool:
    """Identify a port nmap could not match from the replies it recorded. True when identified."""
    tls, replies = parse_servicefp(fp)
    ident = best_http_identity(replies)
    if ident is None:
        return False
    apply_http_identity(po, ident, tls=tls or po.tunnel == "ssl")
    return True
