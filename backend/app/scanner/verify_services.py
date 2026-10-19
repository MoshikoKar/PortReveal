"""Verify weak nmap service labels with one protocol-correct request.

nmap soft-matches text protocols on the response status line alone, e.g.
``softmatch rtsp m|^RTSP/1.0 .*\\r\\n|``. Many web servers echo the request's protocol
token back - embedded camera/DVR httpds and every Netty/Vert.x based server (Keycloak,
Quarkus, …) - so nmap's ``OPTIONS / RTSP/1.0`` probe gets ``RTSP/1.0 404 Not Found``
and the port is reported as ``rtsp`` with method=probed conf=10, indistinguishable
from a real fingerprint. HTTP soft matches (``http-proxy``, ``https-alt``) likewise
carry no product.

Ports with response data nmap could not match are identified for free from the
``servicefp`` it already recorded (``response_fp``). Only the remaining weak labels
are asked directly:

* RTSP label: a real RTSP server answers ``OPTIONS`` with an RTSP status line *and*
  echoes ``CSeq`` (RFC 2326 §12.17). Confirmed RTSP keeps its label.
* Otherwise ``GET / HTTP/1.0`` - the same request nmap's GetRequest probe already
  sent. An ``HTTP/1.x`` status line means the port is HTTP; Server / X-Powered-By /
  body markers give the product. A plain reply that proves the port wants TLS (alert
  record, nginx "plain HTTP request was sent to HTTPS port") is retried once over TLS.

Load stays low: ports of one host are checked one at a time, hosts in parallel, and
the whole step stops at ``VERIFY_BUDGET_S``. Inconclusive ports keep nmap's label.
"""
from __future__ import annotations

import logging
import re
import socket
import ssl
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor

from .known_ports import NEVER_PROBE_TCP_PORTS
from .response_fp import apply_http_identity, http_identity, identity_confidence
from .types import VERIFIED_METHOD, HostObservation, PortObservation, ScanContext

log = logging.getLogger(__name__)

# HTTP-family names nmap gives from a soft match or its port table - no product behind them.
HTTP_FAMILY_LABELS = frozenset({"http", "https", "http-alt", "https-alt", "http-proxy", "ssl/http"})
# Labels nmap derives from a bare status-line soft match (or no match at all).
WEAK_SERVICE_LABELS = frozenset({"", "unknown", "rtsp", "sip"}) | HTTP_FAMILY_LABELS
CONNECT_TIMEOUT_S = 3.0
READ_TIMEOUT_S = 4.0
MAX_RESPONSE_BYTES = 8192
MAX_PARALLEL_HOSTS = 16
VERIFY_BUDGET_S = 90.0

_RTSP_STATUS = re.compile(rb"^RTSP/1\.0 \d{3}")
_CSEQ = re.compile(rb"\r\nCSeq:[ \t]*1\b", re.IGNORECASE)
_SERVER = re.compile(rb"\r\nServer:[ \t]*([^\r\n]+)", re.IGNORECASE)

Exchange = Callable[[str, int, bool, bytes], bytes | None]


def needs_verification(po: PortObservation) -> bool:
    """Weak label: an nmap soft match that named the protocol without identifying a product.

    Port-table guesses (``method="table"``) are not re-checked: nmap already sent the same GET
    and a TLS hello there, and any reply it got was read from ``servicefp`` for free.
    """
    if po.protocol != "tcp" or po.port in NEVER_PROBE_TCP_PORTS or po.method != "probed":
        return False
    if po.product or po.version or po.method == VERIFIED_METHOD:
        return False
    return (po.service or "").strip().lower() in WEAK_SERVICE_LABELS


def exchange(ip: str, port: int, use_tls: bool, payload: bytes) -> bytes | None:
    """Send one request and return the first bytes of the reply.

    None: no connection. b"": connected but the server sent nothing (e.g. a TLS-only port
    given plaintext). A read timeout after some data still returns that data.
    """
    buf = b""
    connected = False
    try:
        with socket.create_connection((ip, port), timeout=CONNECT_TIMEOUT_S) as raw:
            raw.settimeout(READ_TIMEOUT_S)
            sock: socket.socket = raw
            if use_tls:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                sock = ctx.wrap_socket(raw, server_hostname=None)
            connected = True
            sock.sendall(payload)
            while len(buf) < MAX_RESPONSE_BYTES:
                chunk = sock.recv(MAX_RESPONSE_BYTES - len(buf))
                if not chunk:
                    break
                buf += chunk
                head_end = buf.find(b"\r\n\r\n")
                # Headers plus the start of the body (title / product markers) are enough.
                if head_end >= 0 and len(buf) - head_end > 2048:
                    break
    except (OSError, ssl.SSLError, ValueError):
        pass
    return buf if connected else None


def _wants_tls(reply: bytes | None) -> bool:
    """Plaintext reply that shows a TLS listener: silence, a TLS record, or nginx's 400."""
    if reply is None:
        return False
    if not reply:
        return True
    return reply[:2] in (b"\x15\x03", b"\x16\x03") or b"plain HTTP request was sent to HTTPS port" in reply


def _server_header(reply: bytes) -> str | None:
    m = _SERVER.search(reply.split(b"\r\n\r\n", 1)[0])
    if not m:
        return None
    value = m.group(1).decode("latin-1").strip()
    return value[:120] or None


def verify_port(ip: str, po: PortObservation, send: Exchange = exchange) -> bool:
    """Re-check one weak label in place. Returns True when the observation changed."""
    use_tls = po.tunnel == "ssl"
    label = (po.service or "").strip().lower()
    if label == "rtsp":
        reply = send(ip, po.port, use_tls, b"OPTIONS * RTSP/1.0\r\nCSeq: 1\r\n\r\n")
        if reply and _RTSP_STATUS.match(reply) and _CSEQ.search(reply):
            po.product = _server_header(reply)
            po.method = VERIFIED_METHOD
            po.confidence = identity_confidence(True, po.product, None)
            return True
    reply = send(ip, po.port, use_tls, b"GET / HTTP/1.0\r\n\r\n")
    if not use_tls and _wants_tls(reply):
        use_tls = True
        reply = send(ip, po.port, True, b"GET / HTTP/1.0\r\n\r\n")
    ident = http_identity(reply)
    if ident is None:
        return False
    if label and label not in HTTP_FAMILY_LABELS:
        log.info("%s:%d nmap labelled %r but the port answers HTTP; relabelled http", ip, po.port, label)
    apply_http_identity(po, ident, tls=use_tls)
    return True


def verify_hosts(hosts: list[HostObservation], ctx: ScanContext, send: Exchange = exchange,
                 budget_s: float = VERIFY_BUDGET_S) -> int:
    """Verify weak port labels: one port at a time per host, hosts in parallel, time-capped.

    Returns how many observations were confirmed or corrected.
    """
    per_host = [(h.ip, [p for p in (h.ports or []) if needs_verification(p)]) for h in hosts]
    per_host = [(ip, ports) for ip, ports in per_host if ports]
    if not per_host:
        return 0
    deadline = time.monotonic() + budget_s
    skipped = [0]

    def run(job: tuple[str, list[PortObservation]]) -> int:
        ip, ports = job
        changed = 0
        for i, po in enumerate(ports):
            if ctx.cancelled or time.monotonic() >= deadline:
                skipped[0] += len(ports) - i
                break
            changed += verify_port(ip, po, send)
        return changed

    with ThreadPoolExecutor(max_workers=min(MAX_PARALLEL_HOSTS, len(per_host))) as pool:
        changed = sum(pool.map(run, per_host))
    ctx.check_cancelled()
    total = sum(len(ports) for _, ports in per_host)
    log.info("scan %s: verified %d weak service label(s) on %d host(s): %d identified, %d skipped (time cap)",
             ctx.scan_id, total, len(per_host), changed, skipped[0])
    return changed
