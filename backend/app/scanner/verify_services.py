"""Verify ambiguous nmap service labels with one protocol-correct request.

nmap soft-matches text protocols on the response status line alone, e.g.
``softmatch rtsp m|^RTSP/1.0 .*\\r\\n|``. Many embedded web servers (cameras, DVRs)
echo the request's protocol token back, so nmap's ``OPTIONS / RTSP/1.0`` probe on
port 80 gets ``RTSP/1.0 505 HTTP Version Not Supported`` and the port is reported as
``rtsp`` with method=probed conf=10 — indistinguishable from a real fingerprint.

For ports whose nmap label is one of these weak, product-less guesses we ask the
port directly:

* RTSP label: a real RTSP server answers ``OPTIONS`` with an RTSP status line *and*
  echoes ``CSeq`` (RFC 2326 §12.17). Confirmed RTSP keeps its label.
* Otherwise ``GET / HTTP/1.0`` (the same request nmap's GetRequest probe already
  sent): an ``HTTP/1.x`` status line means the port is HTTP.

Confirmed results get ``method="verified"``. When neither check is conclusive the
nmap observation is left exactly as it was.
"""
from __future__ import annotations

import logging
import re
import socket
import ssl
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor

from .known_ports import NEVER_PROBE_TCP_PORTS
from .types import HostObservation, PortObservation, ScanContext

log = logging.getLogger(__name__)

VERIFIED_METHOD = "verified"
# Labels nmap derives from a bare status-line soft match (or no match at all).
WEAK_SERVICE_LABELS = frozenset({"", "unknown", "rtsp", "sip"})
CONNECT_TIMEOUT_S = 3.0
READ_TIMEOUT_S = 4.0
MAX_RESPONSE_BYTES = 4096
MAX_WORKERS = 16

_HTTP_STATUS = re.compile(rb"^HTTP/1\.[01] \d{3}")
_RTSP_STATUS = re.compile(rb"^RTSP/1\.0 \d{3}")
_CSEQ = re.compile(rb"\r\nCSeq:[ \t]*1\b", re.IGNORECASE)
_SERVER = re.compile(rb"\r\nServer:[ \t]*([^\r\n]+)", re.IGNORECASE)

Exchange = Callable[[str, int, bool, bytes], bytes | None]


def needs_verification(po: PortObservation) -> bool:
    """Weak label: nmap named (or failed to name) the service without identifying a product."""
    if po.protocol != "tcp" or po.port in NEVER_PROBE_TCP_PORTS:
        return False
    if po.product or po.version or po.method == VERIFIED_METHOD:
        return False
    return (po.service or "").strip().lower() in WEAK_SERVICE_LABELS


def exchange(ip: str, port: int, use_tls: bool, payload: bytes) -> bytes | None:
    """Send one request and return the first bytes of the reply (None on any failure)."""
    try:
        with socket.create_connection((ip, port), timeout=CONNECT_TIMEOUT_S) as raw:
            raw.settimeout(READ_TIMEOUT_S)
            sock: socket.socket = raw
            if use_tls:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                sock = ctx.wrap_socket(raw, server_hostname=None)
            sock.sendall(payload)
            buf = b""
            while len(buf) < MAX_RESPONSE_BYTES and b"\r\n\r\n" not in buf:
                chunk = sock.recv(MAX_RESPONSE_BYTES - len(buf))
                if not chunk:
                    break
                buf += chunk
            return buf or None
    except (OSError, ssl.SSLError, ValueError):
        return None


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
            po.method, po.confidence = VERIFIED_METHOD, 10
            po.product = _server_header(reply)
            return True
    reply = send(ip, po.port, use_tls, b"GET / HTTP/1.0\r\n\r\n")
    if reply and _HTTP_STATUS.match(reply):
        if label:
            log.info("%s:%d nmap labelled %r but the port answers HTTP; relabelled http", ip, po.port, label)
        po.service = "http"
        po.product = _server_header(reply)
        po.version = None
        po.extra_info = None
        po.cpe = None
        po.method, po.confidence = VERIFIED_METHOD, 10
        return True
    return False


def verify_hosts(hosts: list[HostObservation], ctx: ScanContext, send: Exchange = exchange) -> int:
    """Verify every weak port label across hosts in parallel. Returns how many changed."""
    jobs = [(h.ip, p) for h in hosts for p in (h.ports or []) if needs_verification(p)]
    if not jobs:
        return 0

    def run(job: tuple[str, PortObservation]) -> bool:
        if ctx.cancelled:
            return False
        return verify_port(job[0], job[1], send)

    with ThreadPoolExecutor(max_workers=min(MAX_WORKERS, len(jobs))) as pool:
        changed = sum(pool.map(run, jobs))
    ctx.check_cancelled()
    log.info("scan %s: verified %d weak service label(s), %d confirmed/corrected",
             ctx.scan_id, len(jobs), changed)
    return changed
