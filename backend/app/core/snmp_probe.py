"""Read-only SNMPv2c GET of sys* OIDs — no auth bruteforce; community from settings only."""
from __future__ import annotations

import logging
import socket
import struct
from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db import utcnow
from ..models import DevicePort, PortSnmp
from ..security import decrypt_secret
from ..settings_store import get_section

log = logging.getLogger(__name__)

# SNMPv2-MIB
OID_SYSDESCR = (1, 3, 6, 1, 2, 1, 1, 1, 0)
OID_SYSOBJECTID = (1, 3, 6, 1, 2, 1, 1, 2, 0)
OID_SYSNAME = (1, 3, 6, 1, 2, 1, 1, 5, 0)
OID_SYSCONTACT = (1, 3, 6, 1, 2, 1, 1, 4, 0)
OID_SYSLOCATION = (1, 3, 6, 1, 2, 1, 1, 6, 0)

# Small vendor map from enterprise OID prefix under 1.3.6.1.4.1.*
_ENTERPRISE: dict[int, str] = {
    9: "Cisco",
    11: "HP",
    43: "3Com",
    311: "Microsoft",
    674: "Dell",
    12356: "Fortinet",
    14988: "MikroTik",
    2021: "Net-SNMP",
    8072: "Net-SNMP",
    25506: "H3C",
    2636: "Juniper",
    1916: "Extreme",
    4526: "Netgear",
    14179: "Aruba",
}


@dataclass
class SnmpInfo:
    sys_descr: str | None = None
    sys_name: str | None = None
    sys_object_id: str | None = None
    sys_location: str | None = None
    sys_contact: str | None = None
    vendor: str | None = None
    model: str | None = None


def _encode_length(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    if n < 0x100:
        return bytes([0x81, n])
    return bytes([0x82, (n >> 8) & 0xFF, n & 0xFF])


def _encode_oid(oid: tuple[int, ...]) -> bytes:
    body = bytes([40 * oid[0] + oid[1]])
    for n in oid[2:]:
        if n < 128:
            body += bytes([n])
        else:
            stack = []
            while n:
                stack.append(n & 0x7F)
                n >>= 7
            for i, b in enumerate(reversed(stack)):
                body += bytes([b | (0x80 if i < len(stack) - 1 else 0)])
    return b"\x06" + _encode_length(len(body)) + body


def _encode_octet(s: str) -> bytes:
    raw = s.encode("utf-8")
    return b"\x04" + _encode_length(len(raw)) + raw


def _encode_int(n: int) -> bytes:
    if n == 0:
        return b"\x02\x01\x00"
    neg = n < 0
    if neg:
        n = -n
    buf = []
    while n:
        buf.append(n & 0xFF)
        n >>= 8
    if buf[-1] & 0x80:
        buf.append(0x00)
    raw = bytes(reversed(buf))
    if neg:
        raw = bytes((~b) & 0xFF for b in raw)
    return b"\x02" + _encode_length(len(raw)) + raw


def _encode_null() -> bytes:
    return b"\x05\x00"


def _encode_seq(tag: int, *parts: bytes) -> bytes:
    body = b"".join(parts)
    return bytes([tag]) + _encode_length(len(body)) + body


def _build_get(community: str, request_id: int, oid: tuple[int, ...]) -> bytes:
    varbind = _encode_seq(0x30, _encode_oid(oid), _encode_null())
    varbind_list = _encode_seq(0x30, varbind)
    pdu = _encode_seq(0xA0, _encode_int(request_id), _encode_int(0), _encode_int(0), varbind_list)
    return _encode_seq(0x30, _encode_int(1), _encode_octet(community), pdu)


def _parse_tlv(data: bytes, i: int) -> tuple[int, bytes, int]:
    tag = data[i]
    i += 1
    length = data[i]
    i += 1
    if length & 0x80:
        n = length & 0x7F
        length = int.from_bytes(data[i : i + n], "big")
        i += n
    return tag, data[i : i + length], i + length


def _decode_oid(body: bytes) -> str:
    if not body:
        return ""
    first = body[0]
    out = [str(first // 40), str(first % 40)]
    i = 1
    while i < len(body):
        n = 0
        while True:
            b = body[i]
            i += 1
            n = (n << 7) | (b & 0x7F)
            if not (b & 0x80):
                break
        out.append(str(n))
    return "." + ".".join(out)


def _decode_value(tag: int, body: bytes) -> str | None:
    if tag == 0x04:  # OCTET STRING
        try:
            return body.decode("utf-8")
        except UnicodeDecodeError:
            return body.decode("latin-1", errors="replace")
    if tag == 0x06:  # OBJECT IDENTIFIER
        return _decode_oid(body)
    if tag in (0x02, 0x41, 0x42, 0x43, 0x46):
        return str(int.from_bytes(body, "big"))
    return None


def _extract_varbind_value(packet: bytes) -> str | None:
    try:
        _, seq, _ = _parse_tlv(packet, 0)
        i = 0
        for _ in range(3):  # version, community, pdu
            tag, body, i = _parse_tlv(seq, i if _ == 0 else i)
            if _ == 0:
                i = 0
                tag, body, nxt = _parse_tlv(seq, 0)
                i = nxt
                continue
            if tag in (0xA0, 0xA1, 0xA2):  # response PDU
                # request-id, error-status, error-index, varbind-list
                j = 0
                for __ in range(3):
                    _, _, j = _parse_tlv(body, j)
                _, vbl, _ = _parse_tlv(body, j)
                _, vb, _ = _parse_tlv(vbl, 0)
                # oid + value
                k = 0
                _, _, k = _parse_tlv(vb, 0)
                vtag, vbody, _ = _parse_tlv(vb, k)
                return _decode_value(vtag, vbody)
        return None
    except (IndexError, struct.error, ValueError):
        return None


def snmp_get(ip: str, community: str, oid: tuple[int, ...], *, port: int = 161, timeout: float = 2.0) -> str | None:
    req_id = 1
    pkt = _build_get(community, req_id, oid)
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            sock.sendto(pkt, (ip, port))
            data, _ = sock.recvfrom(65535)
            return _extract_varbind_value(data)
    except OSError:
        return None


def vendor_from_object_id(oid: str | None) -> tuple[str | None, str | None]:
    if not oid:
        return None, None
    parts = [p for p in oid.strip(".").split(".") if p.isdigit()]
    # 1.3.6.1.4.1.<enterprise>...
    if len(parts) >= 7 and parts[:6] == ["1", "3", "6", "1", "4", "1"]:
        ent = int(parts[6])
        return _ENTERPRISE.get(ent), None
    return None, None


def probe_snmp(ip: str, community: str, *, port: int = 161) -> SnmpInfo | None:
    descr = snmp_get(ip, community, OID_SYSDESCR, port=port)
    if descr is None:
        return None
    name = snmp_get(ip, community, OID_SYSNAME, port=port)
    obj = snmp_get(ip, community, OID_SYSOBJECTID, port=port)
    loc = snmp_get(ip, community, OID_SYSLOCATION, port=port)
    contact = snmp_get(ip, community, OID_SYSCONTACT, port=port)
    vendor, model = vendor_from_object_id(obj)
    return SnmpInfo(descr, name, obj, loc, contact, vendor, model)


def enrich_device_snmp(db: Session, device_id: int, ip: str) -> bool:
    from ..settings_store import SnmpSettings as SnmpCfg

    cfg = get_section(db, SnmpCfg)
    if not cfg.enabled:
        return False
    community = decrypt_secret(cfg.community_enc) if cfg.community_enc else cfg.community
    if not community:
        return False
    ports = db.scalars(select(DevicePort).where(
        DevicePort.device_id == device_id, DevicePort.is_open.is_(True),
        DevicePort.port == 161,
    )).all()
    if not ports:
        # Also try when service name says snmp on another port
        ports = db.scalars(select(DevicePort).where(
            DevicePort.device_id == device_id, DevicePort.is_open.is_(True),
            DevicePort.service.ilike("%snmp%"),
        )).all()
    if not ports:
        return False
    info = probe_snmp(ip, community, port=ports[0].port)
    if info is None:
        return False
    p = ports[0]
    now = utcnow()
    row = db.scalar(select(PortSnmp).where(PortSnmp.device_port_id == p.id))
    if row is None:
        row = PortSnmp(device_port_id=p.id, device_id=device_id, first_seen=now)
        db.add(row)
    row.device_id = device_id
    row.sys_descr = info.sys_descr
    row.sys_name = info.sys_name
    row.sys_object_id = info.sys_object_id
    row.sys_location = info.sys_location
    row.sys_contact = info.sys_contact
    row.vendor = info.vendor
    row.model = info.model
    row.last_seen = now
    return True
