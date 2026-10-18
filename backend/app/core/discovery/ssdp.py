"""One-shot SSDP (UPnP) discovery for device names (spec section 9.2).

Sends a single multicast M-SEARCH (the standard UPnP discovery request) and collects replies for a
bounded window. Local-only: SSDP's multicast group is never routed off the LAN, this is not an
nmap UDP scan (no -sU), and nothing collected here is sent anywhere outside this process.
"""
from __future__ import annotations

import logging
import socket
import time
from collections.abc import Callable, Iterable

log = logging.getLogger(__name__)

SSDP_GROUP = "239.255.255.250"
SSDP_PORT = 1900
M_SEARCH = (
    "M-SEARCH * HTTP/1.1\r\n"
    "HOST: 239.255.255.250:1900\r\n"
    'MAN: "ssdp:discover"\r\n'
    "MX: 1\r\n"
    "ST: ssdp:all\r\n\r\n"
).encode("ascii")

Transactor = Callable[[float], Iterable[tuple[bytes, tuple]]]


def _parse_server_header(data: bytes) -> str | None:
    try:
        text = data.decode("ascii", errors="replace")
    except Exception:
        return None
    for line in text.splitlines():
        if line.lower().startswith("server:"):
            value = line.split(":", 1)[1].strip()
            return value[:255] or None
    return None


def _search_live(timeout: float) -> Iterable[tuple[bytes, tuple]]:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.settimeout(0.5)
        sock.sendto(M_SEARCH, (SSDP_GROUP, SSDP_PORT))
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                data, addr = sock.recvfrom(4096)
            except socket.timeout:
                continue
            yield data, addr
    finally:
        sock.close()


def collect_ssdp_names(*, timeout: float = 2.0, transact: Transactor | None = None) -> dict[str, str]:
    """{ip: SERVER header value}, best-effort. `transact` is injectable for tests."""
    results: dict[str, str] = {}
    try:
        for data, addr in (transact or _search_live)(timeout):
            ip = addr[0]
            if ip in results:
                continue
            server = _parse_server_header(data)
            if server:
                results[ip] = server
    except OSError as exc:
        log.debug("SSDP discovery unavailable: %s", exc)
    return results
