"""Targeted NetBIOS Name Service (NBSTAT) query for a device's real computer name (spec section 9.2).

A single UDP unicast query to one already-inventoried host's port 137 -- "a focused query", not a
network scan. Gets the authoritative NetBIOS computer name directly from Windows/Samba hosts, which
is often far more specific than a DNS/mDNS name. Local-only (LAN unicast); never an nmap -sU scan.
"""
from __future__ import annotations

import logging
import socket
import time
from collections.abc import Callable, Iterable

log = logging.getLogger(__name__)

NETBIOS_PORT = 137
NBSTAT_QTYPE = 0x0021
IN_QCLASS = 0x0001
GROUP_FLAG = 0x8000

# One query per host, but a single shared receive window (not timeout-per-host): the cost of a
# batch of N hosts is ~`timeout` total, not N * timeout, however many never answer (spec 9.2:
# the discovery channel's default-on cost must stay low regardless of device count).
BatchTransactor = Callable[[list[str], float], Iterable[tuple[bytes, tuple]]]
Transactor = Callable[[str, float], bytes | None]


def _encode_netbios_name(name16: bytes) -> bytes:
    """RFC 1002 first-level encoding: each byte -> two ASCII nibbles offset from 'A'."""
    out = bytearray()
    for b in name16:
        out.append(0x41 + (b >> 4))
        out.append(0x41 + (b & 0x0F))
    return bytes(out)


# "*" padded to 16 bytes with NUL: the standard NBSTAT wildcard query name.
_NBSTAT_QUERY_NAME = b"*" + b"\x00" * 15


def build_nbstat_query(transaction_id: int) -> bytes:
    encoded = _encode_netbios_name(_NBSTAT_QUERY_NAME)
    header = (
        (transaction_id & 0xFFFF).to_bytes(2, "big")
        + b"\x00\x00"  # flags: standard query, no recursion
        + (1).to_bytes(2, "big")  # qdcount
        + b"\x00\x00" * 3  # ancount, nscount, arcount
    )
    question = bytes([len(encoded)]) + encoded + b"\x00" + NBSTAT_QTYPE.to_bytes(2, "big") + IN_QCLASS.to_bytes(2, "big")
    return header + question


def parse_nbstat_response(data: bytes) -> list[dict]:
    """[{"name", "suffix", "group"}] from an NBSTAT answer's name table. Best-effort."""
    if len(data) < 12:
        return []
    ancount = int.from_bytes(data[6:8], "big")
    if ancount < 1:
        return []
    pos = 12
    if pos >= len(data):
        return []
    name_len = data[pos]
    pos += 1 + name_len + 1  # encoded name + trailing NUL label terminator
    pos += 2 + 2 + 4  # type + class + ttl
    if pos + 2 > len(data):
        return []
    rdlength = int.from_bytes(data[pos:pos + 2], "big")
    pos += 2
    rdata = data[pos:pos + rdlength]
    if not rdata:
        return []
    num_names = rdata[0]
    entries = []
    off = 1
    for _ in range(num_names):
        if off + 18 > len(rdata):
            break
        raw_name = rdata[off:off + 15]
        suffix = rdata[off + 15]
        flags = int.from_bytes(rdata[off + 16:off + 18], "big")
        name = raw_name.decode("ascii", errors="replace").strip()
        if name:
            entries.append({"name": name, "suffix": suffix, "group": bool(flags & GROUP_FLAG)})
        off += 18
    return entries


def _best_name(data: bytes) -> str | None:
    for entry in parse_nbstat_response(data):
        if not entry["group"] and entry["suffix"] == 0x00:
            return entry["name"]
    return None


def _query_one_live(ip: str, timeout: float) -> bytes | None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    try:
        sock.settimeout(timeout)
        sock.sendto(build_nbstat_query(0x5A5A), (ip, NETBIOS_PORT))
        data, _addr = sock.recvfrom(2048)
        return data
    except socket.timeout:
        return None
    finally:
        sock.close()


def query_netbios_name(ip: str, *, timeout: float = 0.5, transact: Transactor | None = None) -> str | None:
    """One host's own (non-group) NetBIOS workstation name (suffix 0x00), or None. Best-effort:
    never raises on a timeout, unreachable host, or unparsable reply."""
    try:
        data = (transact or _query_one_live)(ip, timeout)
    except OSError as exc:
        log.debug("NetBIOS query to %s failed: %s", ip, exc)
        return None
    return _best_name(data) if data else None


def _query_batch_live(ips: list[str], timeout: float) -> Iterable[tuple[bytes, tuple]]:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.settimeout(0.2)
        query = build_nbstat_query(0x5A5A)
        for ip in ips:
            try:
                sock.sendto(query, (ip, NETBIOS_PORT))
            except OSError:
                continue
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                data, addr = sock.recvfrom(2048)
            except socket.timeout:
                continue
            yield data, addr
    finally:
        sock.close()


def query_netbios_names(ips: list[str], *, timeout: float = 0.5,
                        transact: BatchTransactor | None = None) -> dict[str, str]:
    """{ip: name} for every host in `ips` that answered. One shared receive window for the whole
    batch (see BatchTransactor), so the total cost does not scale with how many hosts never
    respond (most non-Windows devices)."""
    results: dict[str, str] = {}
    if not ips:
        return results
    try:
        for data, addr in (transact or _query_batch_live)(ips, timeout):
            ip = addr[0]
            if ip in results or ip not in ips:
                continue
            name = _best_name(data)
            if name:
                results[ip] = name
    except OSError as exc:
        log.debug("NetBIOS batch discovery failed: %s", exc)
    return results
