"""IPv4 target parsing/validation and compact address sets.

Accepted target syntax (comma, semicolon, whitespace or newline separated):
    10.0.0.5                single IP
    10.0.0.0/24             CIDR
    10.0.0.10-10.0.0.50     full range
    10.0.0.10-50            last-octet range
    server01.corp.local     hostname (ad-hoc scan targets only; resolved once)
"""
from __future__ import annotations

import bisect
import ipaddress
import re
import socket
from collections.abc import Iterable, Iterator

MAX_SCAN_ADDRESSES = 65536
MIN_NETWORK_PREFIX = 16

_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*\.?$"
)
_SPLIT_RE = re.compile(r"[\s,;]+")


class TargetError(ValueError):
    pass


def split_specs(text: str | Iterable[str]) -> list[str]:
    if isinstance(text, str):
        items = _SPLIT_RE.split(text)
    else:
        items = [t for part in text for t in _SPLIT_RE.split(part)]
    return [i.strip() for i in items if i and i.strip()]


def is_hostname(value: str) -> bool:
    return bool(_HOSTNAME_RE.match(value)) and not re.fullmatch(r"[\d.]+", value)


def _ip_int(value: str) -> int:
    try:
        addr = ipaddress.ip_address(value)
    except ValueError as exc:
        raise TargetError(f"Invalid IP address: {value}") from exc
    if addr.version != 4:
        raise TargetError(f"Only IPv4 is supported: {value}")
    return int(addr)


def parse_spec(spec: str, allow_hostname: bool = False) -> tuple[int, int]:
    """Parse one IP/CIDR/range into an inclusive (start, end) integer interval."""
    spec = spec.strip()
    if not spec:
        raise TargetError("Empty target")
    if "/" in spec:
        try:
            net = ipaddress.ip_network(spec, strict=False)
        except ValueError as exc:
            raise TargetError(f"Invalid CIDR: {spec}") from exc
        if net.version != 4:
            raise TargetError(f"Only IPv4 is supported: {spec}")
        return int(net.network_address), int(net.broadcast_address)
    if "-" in spec and re.match(r"^\d", spec):
        left, right = spec.split("-", 1)
        start = _ip_int(left)
        if re.fullmatch(r"\d{1,3}", right):
            last = int(right)
            if last > 255:
                raise TargetError(f"Invalid range: {spec}")
            end = (start & 0xFFFFFF00) | last
        else:
            end = _ip_int(right)
        if end < start:
            raise TargetError(f"Range end is before range start: {spec}")
        return start, end
    if re.fullmatch(r"[\d.]+", spec):
        v = _ip_int(spec)
        return v, v
    if allow_hostname and is_hostname(spec):
        try:
            infos = socket.getaddrinfo(spec, None, socket.AF_INET, socket.SOCK_STREAM)
        except socket.gaierror as exc:
            raise TargetError(f"Cannot resolve hostname: {spec}") from exc
        v = _ip_int(infos[0][4][0])
        return v, v
    raise TargetError(f"Invalid target: {spec}")


def validate_network_cidr(cidr: str) -> str:
    try:
        net = ipaddress.ip_network(cidr.strip(), strict=False)
    except ValueError as exc:
        raise TargetError(f"Invalid CIDR: {cidr}") from exc
    if net.version != 4:
        raise TargetError("Only IPv4 networks are supported")
    if net.prefixlen < MIN_NETWORK_PREFIX:
        raise TargetError(f"Network too large: maximum size is /{MIN_NETWORK_PREFIX} (65,536 addresses)")
    return str(net)


def _int_to_ip(v: int) -> str:
    return str(ipaddress.IPv4Address(v))


class AddressSet:
    """Sorted, merged, inclusive IPv4 integer intervals."""

    __slots__ = ("_iv", "_starts")

    def __init__(self, intervals: Iterable[tuple[int, int]] = ()):
        merged: list[list[int]] = []
        for s, e in sorted(intervals):
            if merged and s <= merged[-1][1] + 1:
                merged[-1][1] = max(merged[-1][1], e)
            else:
                merged.append([s, e])
        self._iv = [(s, e) for s, e in merged]
        self._starts = [s for s, _ in self._iv]

    @classmethod
    def from_specs(cls, specs: str | Iterable[str], allow_hostname: bool = False) -> AddressSet:
        return cls(parse_spec(s, allow_hostname) for s in split_specs(specs))

    @property
    def intervals(self) -> list[tuple[int, int]]:
        return list(self._iv)

    def __len__(self) -> int:
        return sum(e - s + 1 for s, e in self._iv)

    def __bool__(self) -> bool:
        return bool(self._iv)

    def __contains__(self, ip: object) -> bool:
        try:
            v = int(ipaddress.IPv4Address(ip)) if isinstance(ip, str) else int(ip)  # type: ignore[arg-type]
        except ValueError:
            return False
        i = bisect.bisect_right(self._starts, v) - 1
        return i >= 0 and self._iv[i][0] <= v <= self._iv[i][1]

    def subtract(self, other: AddressSet) -> AddressSet:
        result: list[tuple[int, int]] = []
        for s, e in self._iv:
            cur = s
            for os_, oe in other._iv:
                if oe < cur or os_ > e:
                    continue
                if os_ > cur:
                    result.append((cur, os_ - 1))
                cur = max(cur, oe + 1)
                if cur > e:
                    break
            if cur <= e:
                result.append((cur, e))
        return AddressSet(result)

    def union(self, other: AddressSet) -> AddressSet:
        return AddressSet(self._iv + other._iv)

    def addresses(self) -> Iterator[str]:
        for s, e in self._iv:
            for v in range(s, e + 1):
                yield _int_to_ip(v)

    def to_cidrs(self) -> list[str]:
        out: list[str] = []
        for s, e in self._iv:
            out.extend(
                str(n)
                for n in ipaddress.summarize_address_range(ipaddress.IPv4Address(s), ipaddress.IPv4Address(e))
            )
        return out

    def chunks(self, size: int) -> list[list[str]]:
        """Split into groups of CIDR strings, each covering at most `size` addresses."""
        size = max(1, size)
        max_prefix_len = 32 - (size.bit_length() - 1)  # largest power-of-two block <= size
        chunks: list[list[str]] = []
        cur: list[str] = []
        cur_n = 0
        for cidr in self.to_cidrs():
            net = ipaddress.ip_network(cidr)
            parts = [net] if net.num_addresses <= size else list(net.subnets(new_prefix=max_prefix_len))
            for part in parts:
                if cur and cur_n + part.num_addresses > size:
                    chunks.append(cur)
                    cur, cur_n = [], 0
                cur.append(str(part) if part.num_addresses > 1 else str(part.network_address))
                cur_n += part.num_addresses
        if cur:
            chunks.append(cur)
        return chunks

    def describe(self) -> str:
        return ", ".join(self.to_cidrs()[:5]) + (" ..." if len(self.to_cidrs()) > 5 else "")


def ip_sort_key(ip: str | None) -> int:
    try:
        return int(ipaddress.IPv4Address(ip or ""))
    except ValueError:
        return 0


class PortScope:
    """Nmap-style port list ("1,3-4,22,80-90") for membership tests."""

    def __init__(self, text: str | None):
        self.text = text or ""
        iv: list[tuple[int, int]] = []
        for part in self.text.split(","):
            part = part.strip()
            if not part:
                continue
            if "-" in part:
                a, b = part.split("-", 1)
                iv.append((int(a), int(b)))
            else:
                iv.append((int(part), int(part)))
        iv.sort()
        self._iv = iv
        self._starts = [s for s, _ in iv]

    def __contains__(self, port: int) -> bool:
        i = bisect.bisect_right(self._starts, port) - 1
        return i >= 0 and self._iv[i][0] <= port <= self._iv[i][1]

    def __bool__(self) -> bool:
        return bool(self._iv)

    def count(self) -> int:
        return sum(e - s + 1 for s, e in self._iv)

    @staticmethod
    def from_ports(ports: Iterable[int]) -> str:
        ps = sorted(set(ports))
        out: list[str] = []
        i = 0
        while i < len(ps):
            j = i
            while j + 1 < len(ps) and ps[j + 1] == ps[j] + 1:
                j += 1
            out.append(str(ps[i]) if i == j else f"{ps[i]}-{ps[j]}")
            i = j + 1
        return ",".join(out)
