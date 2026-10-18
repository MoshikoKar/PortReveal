"""Shodan-compatible favicon mmh3 + content hashes for PortHttp grouping."""
from __future__ import annotations

import hashlib
import struct
from collections.abc import Iterable


def _mmh3_x86_32(data: bytes, seed: int = 0) -> int:
    """MurmurHash3 x86 32-bit (signed), matching Shodan's favicon.hash."""
    length = len(data)
    nblocks = length // 4
    h1 = seed & 0xFFFFFFFF
    c1, c2 = 0xCC9E2D51, 0x1B873593

    for i in range(nblocks):
        k1 = struct.unpack_from("<I", data, i * 4)[0]
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF
        h1 ^= k1
        h1 = ((h1 << 13) | (h1 >> 19)) & 0xFFFFFFFF
        h1 = (h1 * 5 + 0xE6546B64) & 0xFFFFFFFF

    tail = data[nblocks * 4 :]
    k1 = 0
    if len(tail) >= 3:
        k1 ^= tail[2] << 16
    if len(tail) >= 2:
        k1 ^= tail[1] << 8
    if len(tail) >= 1:
        k1 ^= tail[0]
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF
        h1 ^= k1

    h1 ^= length
    h1 ^= h1 >> 16
    h1 = (h1 * 0x85EBCA6B) & 0xFFFFFFFF
    h1 ^= h1 >> 13
    h1 = (h1 * 0xC2B2AE35) & 0xFFFFFFFF
    h1 ^= h1 >> 16
    # Shodan stores signed 32-bit
    if h1 >= 0x80000000:
        return h1 - 0x100000000
    return h1


def favicon_hash(data: bytes) -> int:
    """mmh3 of base64-encoded favicon bytes with newlines every 76 chars (Shodan)."""
    import base64

    b64 = base64.encodebytes(data).decode("ascii")
    return _mmh3_x86_32(b64.encode("utf-8"))


def html_hash(html: str | bytes | None) -> str | None:
    if html is None:
        return None
    raw = html.encode("utf-8", errors="replace") if isinstance(html, str) else html
    if not raw:
        return None
    return hashlib.sha256(raw).hexdigest()


def header_set_hash(headers: Iterable[tuple[str, str]] | dict[str, str] | None) -> str | None:
    if not headers:
        return None
    if isinstance(headers, dict):
        items = sorted((k.lower(), v) for k, v in headers.items())
    else:
        items = sorted((k.lower(), v) for k, v in headers)
    blob = "\n".join(f"{k}:{v}" for k, v in items).encode()
    return hashlib.sha256(blob).hexdigest() if blob else None
