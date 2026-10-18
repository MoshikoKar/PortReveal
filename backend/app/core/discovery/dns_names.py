"""Minimal DNS message name decoding (RFC 1035 section 4.1.4 compression), shared by mdns.py.

Pure byte-level parsing, no sockets -- fully unit-testable with synthetic packets.
"""
from __future__ import annotations

MAX_POINTER_JUMPS = 20


def decode_name(data: bytes, offset: int) -> tuple[str, int]:
    """(dotted name, offset immediately after the name in `data`). Follows compression pointers
    up to MAX_POINTER_JUMPS to bound worst-case work on a hostile/malformed packet."""
    labels: list[str] = []
    pos = offset
    jumps = 0
    end_pos: int | None = None  # offset after the name as read from the ORIGINAL position
    while True:
        if pos >= len(data):
            raise ValueError("truncated DNS name")
        length = data[pos]
        if length == 0:
            pos += 1
            if end_pos is None:
                end_pos = pos
            break
        if length & 0xC0 == 0xC0:
            if pos + 1 >= len(data):
                raise ValueError("truncated DNS compression pointer")
            if jumps >= MAX_POINTER_JUMPS:
                raise ValueError("too many DNS compression pointer jumps")
            pointer = ((length & 0x3F) << 8) | data[pos + 1]
            if end_pos is None:
                end_pos = pos + 2
            if pointer >= pos:
                raise ValueError("DNS compression pointer does not point backward")
            pos = pointer
            jumps += 1
            continue
        pos += 1
        if pos + length > len(data):
            raise ValueError("truncated DNS label")
        labels.append(data[pos:pos + length].decode("ascii", errors="replace"))
        pos += length
    return ".".join(labels), end_pos


# Record types we care about for a human-readable device name.
TYPE_A = 1
TYPE_PTR = 12
TYPE_SRV = 33


def parse_answers(data: bytes) -> list[dict]:
    """[{"name", "type", "rdata", "target"?}] for every question+answer record in a DNS message.
    `target` is the decoded name inside PTR/SRV rdata, when present. Best-effort: returns whatever
    was parsed successfully before hitting a malformed record, never raises.
    """
    if len(data) < 12:
        return []
    qdcount = int.from_bytes(data[4:6], "big")
    ancount = int.from_bytes(data[6:8], "big")
    pos = 12
    try:
        for _ in range(qdcount):
            _, pos = decode_name(data, pos)
            pos += 4  # qtype(2) + qclass(2)
    except ValueError:
        return []
    answers: list[dict] = []
    for _ in range(ancount):
        try:
            name, pos = decode_name(data, pos)
            if pos + 10 > len(data):
                break
            rtype = int.from_bytes(data[pos:pos + 2], "big")
            pos += 8  # type(2) + class(2) + ttl(4)
            rdlength = int.from_bytes(data[pos:pos + 2], "big")
            pos += 2
            rdata_start = pos
            rdata = data[pos:pos + rdlength]
            pos += rdlength
        except (ValueError, IndexError):
            break
        entry = {"name": name, "type": rtype, "rdata": rdata}
        if rtype == TYPE_PTR:
            try:
                target, _ = decode_name(data, rdata_start)
                entry["target"] = target
            except ValueError:
                pass
        elif rtype == TYPE_SRV and len(rdata) > 6:
            try:
                target, _ = decode_name(data, rdata_start + 6)  # priority+weight+port
                entry["target"] = target
            except ValueError:
                pass
        answers.append(entry)
    return answers
