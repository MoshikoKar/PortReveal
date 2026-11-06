"""Learn MACs of routed / site-to-site VPN hosts from the remote gateway's ARP table (SNMP).

ARP is L2-only: a scanner behind a router (or across an S2S tunnel) never sees the MACs of the hosts
it discovers. The remote site's router does -- its ARP table maps each neighbour's IP to the MAC that
actually answered. This reads that table with a read-only SNMP walk of IP-MIB, so every MAC is real
L2 data from the device that owns the segment, never a guess.

Guards: entries the router marks invalid, zero/broadcast/multicast MACs, and any MAC the table lists
for more than one IP (proxy-ARP, or a downstream router answering for routed hosts) are dropped.
Only hosts the scan found *without* a MAC are filled. Fail-soft: an error becomes a scan note and
never changes the scan's result.
"""
from __future__ import annotations

import asyncio
import logging
from collections import Counter
from collections.abc import Callable, Iterable
from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import Network
from ..netutils import AddressSet, TargetError
from ..scanner.types import HostObservation
from ..security import decrypt_secret
from .identity import normalize_mac
from .oui import vendor_for

log = logging.getLogger(__name__)

# IP-MIB. Most routers still populate the deprecated ipNetToMediaTable; some newer agents only
# implement its RFC 4293 replacement, ipNetToPhysicalTable.
NET_TO_MEDIA_PHYS = "1.3.6.1.2.1.4.22.1.2"     # .<ifIndex>.<a.b.c.d> = MAC
NET_TO_MEDIA_TYPE = "1.3.6.1.2.1.4.22.1.4"     # 2 = invalid
NET_TO_PHYSICAL_PHYS = "1.3.6.1.2.1.4.35.1.4"  # .<ifIndex>.<addrType>.<len>.<addr...> = MAC
NET_TO_PHYSICAL_TYPE = "1.3.6.1.2.1.4.35.1.6"  # 2 = invalid
# RFC 4293: TimeStamp (TimeTicks) of last ARP refresh; compare with sysUpTime for age.
NET_TO_PHYSICAL_LAST = "1.3.6.1.2.1.4.35.1.7"
SYS_UPTIME_OID = "1.3.6.1.2.1.1.3.0"
_INVALID = 2

DEFAULT_TIMEOUT_S = 3.0
MAX_ROWS = 50_000  # ceiling for one walk; far above any single router's ARP table
# Skip physical-table entries older than this when LastUpdated is available (DHCP churn window).
# Media-table-only agents have no age: those entries are still filled; matching treats snmp as weak.
ARP_MAX_AGE_S = 600

AUTH_PROTOCOLS = ("MD5", "SHA", "SHA224", "SHA256", "SHA384", "SHA512")
# AES192/AES256 = Blumenthal key extension (net-snmp); the "C" variants = Reeder (Cisco and others).
PRIV_PROTOCOLS = ("DES", "3DES", "AES", "AES192", "AES256", "AES192C", "AES256C")


class SnmpError(Exception):
    pass


@dataclass(frozen=True)
class SnmpTarget:
    host: str
    port: int = 161
    version: str = "2c"
    community: str = ""
    user: str = ""
    auth_protocol: str | None = None
    auth_key: str = ""
    priv_protocol: str | None = None
    priv_key: str = ""


@dataclass(frozen=True)
class ArpSource:
    """One network's gateway, captured while the scan's DB session is open."""

    network: str
    cidr: str
    target: SnmpTarget


def target_from_config(cfg: dict | None) -> SnmpTarget | None:
    """Decrypted target from a `Network.arp_snmp` value, or None when not configured."""
    if not cfg or not cfg.get("host"):
        return None
    return SnmpTarget(
        host=cfg["host"], port=int(cfg.get("port") or 161), version=cfg.get("version") or "2c",
        community=decrypt_secret(cfg.get("community_enc")), user=cfg.get("user") or "",
        auth_protocol=cfg.get("auth_protocol"), auth_key=decrypt_secret(cfg.get("auth_key_enc")),
        priv_protocol=cfg.get("priv_protocol"), priv_key=decrypt_secret(cfg.get("priv_key_enc")),
    )


def load_arp_sources(db: Session) -> list[ArpSource]:
    out = []
    for net in db.scalars(select(Network).where(Network.archived_at.is_(None))).all():
        target = target_from_config(net.arp_snmp)
        if target is not None:
            out.append(ArpSource(network=net.name, cidr=net.cidr, target=target))
    return out


# ---- parsing (pure) ---------------------------------------------------------------------------

def _suffix(oid: str, root: str) -> tuple[int, ...]:
    if not oid.startswith(root + "."):
        return ()
    try:
        return tuple(int(x) for x in oid[len(root) + 1:].split("."))
    except ValueError:
        return ()


def _media_ip(sub: tuple[int, ...]) -> str | None:
    # ipNetToMedia index: ifIndex, then the 4 IPv4 octets.
    return ".".join(map(str, sub[1:5])) if len(sub) == 5 else None


def _physical_ip(sub: tuple[int, ...]) -> str | None:
    # ipNetToPhysical index: ifIndex, InetAddressType (1 = ipv4), length-prefixed address.
    return ".".join(map(str, sub[3:7])) if len(sub) == 7 and sub[1] == 1 and sub[2] == 4 else None


_TABLES = ((NET_TO_MEDIA_PHYS, NET_TO_MEDIA_TYPE, _media_ip),
           (NET_TO_PHYSICAL_PHYS, NET_TO_PHYSICAL_TYPE, _physical_ip))


def _usable_mac(raw: object) -> str | None:
    if not isinstance(raw, (bytes, bytearray)) or len(raw) != 6:
        return None
    if raw[0] & 0x01 or raw == b"\x00" * 6:  # multicast/broadcast bit, or an unset entry
        return None
    return normalize_mac(bytes(raw).hex())


def parse_arp_table(rows: Iterable[tuple[str, object]]) -> dict[str, str]:
    """{ip: MAC} from walked IP-MIB rows (OCTET STRING values as bytes, INTEGER values as int)."""
    rows = list(rows)
    table: dict[str, str] = {}
    for phys_root, type_root, ip_of in _TABLES:
        invalid = {_suffix(oid, type_root) for oid, value in rows if value == _INVALID} - {()}
        for oid, value in rows:
            sub = _suffix(oid, phys_root)
            if not sub or sub in invalid:
                continue
            ip, mac = ip_of(sub), _usable_mac(value)
            if ip and mac:
                table.setdefault(ip, mac)
    return table


def _age_seconds(sys_uptime: int | None, last_updated: object) -> float | None:
    """Age of an ipNetToPhysical entry in seconds, or None when either stamp is missing."""
    if sys_uptime is None or not isinstance(last_updated, int):
        return None
    # TimeTicks wrap at 2^32; unsigned difference handles wrap.
    return ((sys_uptime - last_updated) & 0xFFFFFFFF) / 100.0


def parse_arp_table_fresh(
    rows: Iterable[tuple[str, object]],
    *,
    sys_uptime: int | None = None,
    max_age_s: float = ARP_MAX_AGE_S,
) -> dict[str, str]:
    """Like parse_arp_table, but drops physical-table rows whose LastUpdated age exceeds max_age_s.

    Precedence when both tables appear in ``rows``:
    - Physical entries are authoritative. Age-stale physical rows are omitted.
    - An IP that appears in the physical table (even when its row is dropped as stale or
      unusable) is never filled from the media table afterward — reviving an unaged media
      MAC after rejecting stale physical evidence would bypass freshness.
    - Media may only supplement IPs with no physical row at all (no age column; matching
      still treats snmp as weak). Losing a stale physical MAC (empty for that IP) is not a bug.
    """
    rows = list(rows)
    table: dict[str, str] = {}
    # Physical table first: apply age when both stamps exist; record every IP seen so media
    # cannot revive contradictory/stale authoritative evidence.
    invalid_phys = {_suffix(oid, NET_TO_PHYSICAL_TYPE) for oid, value in rows if value == _INVALID} - {()}
    last_by_sub = {_suffix(oid, NET_TO_PHYSICAL_LAST): value
                   for oid, value in rows if _suffix(oid, NET_TO_PHYSICAL_LAST)}
    phys_ips_seen: set[str] = set()
    for oid, value in rows:
        sub = _suffix(oid, NET_TO_PHYSICAL_PHYS)
        if not sub or sub in invalid_phys:
            continue
        ip = _physical_ip(sub)
        if not ip:
            continue
        phys_ips_seen.add(ip)
        mac = _usable_mac(value)
        if not mac:
            continue
        age = _age_seconds(sys_uptime, last_by_sub.get(sub))
        if age is not None and age > max_age_s:
            continue
        table[ip] = mac
    # Media table: no age column — keep usable entries only for IPs absent from physical.
    invalid_media = {_suffix(oid, NET_TO_MEDIA_TYPE) for oid, value in rows if value == _INVALID} - {()}
    for oid, value in rows:
        sub = _suffix(oid, NET_TO_MEDIA_PHYS)
        if not sub or sub in invalid_media:
            continue
        ip, mac = _media_ip(sub), _usable_mac(value)
        if not ip or not mac or ip in phys_ips_seen:
            continue
        table.setdefault(ip, mac)
    return table


def unique_macs(table: dict[str, str]) -> dict[str, str]:
    """Drop every MAC listed for more than one IP: it identifies a router/proxy, not a host."""
    counts = Counter(table.values())
    return {ip: mac for ip, mac in table.items() if counts[mac] == 1}


# ---- SNMP I/O -------------------------------------------------------------------------------

# (target, subtree root OID, timeout) -> [(oid, value)]; injectable for tests.
Walker = Callable[[SnmpTarget, str, float], list[tuple[str, object]]]


def _auth(t: SnmpTarget):
    from pysnmp.hlapi.v3arch import asyncio as h

    if t.version != "3":
        return h.CommunityData(t.community, mpModel=1)
    auth = {"MD5": h.usmHMACMD5AuthProtocol, "SHA": h.usmHMACSHAAuthProtocol,
            "SHA224": h.usmHMAC128SHA224AuthProtocol, "SHA256": h.usmHMAC192SHA256AuthProtocol,
            "SHA384": h.usmHMAC256SHA384AuthProtocol, "SHA512": h.usmHMAC384SHA512AuthProtocol}
    priv = {"DES": h.usmDESPrivProtocol, "3DES": h.usm3DESEDEPrivProtocol, "AES": h.usmAesCfb128Protocol,
            "AES192": h.usmAesBlumenthalCfb192Protocol, "AES256": h.usmAesBlumenthalCfb256Protocol,
            "AES192C": h.usmAesCfb192Protocol, "AES256C": h.usmAesCfb256Protocol}
    return h.UsmUserData(
        t.user,
        authKey=t.auth_key or None,
        privKey=t.priv_key or None,
        authProtocol=auth[t.auth_protocol] if t.auth_protocol else h.usmNoAuthProtocol,
        privProtocol=priv[t.priv_protocol] if t.priv_protocol else h.usmNoPrivProtocol,
    )


def _plain(value: object) -> object:
    if type(value).__name__ in ("NoSuchObject", "NoSuchInstance", "EndOfMibView", "Null"):
        return None
    if hasattr(value, "asOctets"):
        return bytes(value.asOctets())
    try:
        return int(value)  # type: ignore[call-overload]
    except (TypeError, ValueError):
        return None


async def _walk(t: SnmpTarget, root: str, timeout: float) -> list[tuple[str, object]]:
    from pysnmp.hlapi.v3arch.asyncio import (
        ContextData,
        ObjectIdentity,
        ObjectType,
        SnmpEngine,
        UdpTransportTarget,
        bulk_walk_cmd,
    )

    engine = SnmpEngine()
    try:
        transport = await UdpTransportTarget.create((t.host, t.port), timeout=timeout, retries=1)
        rows: list[tuple[str, object]] = []
        async for err_ind, err_status, err_idx, var_binds in bulk_walk_cmd(
            engine, _auth(t), transport, ContextData(), 0, 25, ObjectType(ObjectIdentity(root)),
            lexicographicMode=False,
        ):
            if err_ind:
                raise SnmpError(str(err_ind))
            if err_status:
                raise SnmpError(f"{err_status.prettyPrint()} (index {err_idx})")
            rows.extend((str(name), _plain(value)) for name, value in var_binds)
            if len(rows) >= MAX_ROWS:
                break
        return rows
    finally:
        engine.close_dispatcher()


def walk_subtree(target: SnmpTarget, root: str, timeout: float) -> list[tuple[str, object]]:
    """Blocking GETBULK walk of one subtree. Runs its own event loop (call from a worker thread)."""
    return asyncio.run(_walk(target, root, timeout))


def _read_sys_uptime(target: SnmpTarget, walk: Walker, timeout: float) -> int | None:
    """sysUpTime.0 as TimeTicks integer, or None when the agent does not answer."""
    try:
        rows = walk(target, SYS_UPTIME_OID, timeout)
    except Exception:
        return None
    for oid, value in rows:
        if oid == SYS_UPTIME_OID or oid.startswith(SYS_UPTIME_OID + "."):
            return value if isinstance(value, int) else None
    return None


def fetch_arp_table(target: SnmpTarget, *, timeout: float = DEFAULT_TIMEOUT_S,
                    walk: Walker | None = None, max_age_s: float = ARP_MAX_AGE_S) -> dict[str, str]:
    """{ip: MAC} for every usable, single-IP entry in the gateway's ARP table. Raises on SNMP errors.

    Table precedence (intentional, conservative — do not "fix" empty results by mixing tables):
    - When the physical PHYS walk returns any rows, ipNetToPhysicalTable alone is authoritative
      for this poll. LastUpdated age drops stale DHCP leftovers. The media table is not walked
      afterward: falling back to the same IP's unaged media row after rejecting its physical row
      as stale would bypass freshness and reintroduce false identity. An empty result after
      filtering all physical rows as stale is therefore not a bug (loss of a stale MAC).
    - ipNetToMediaTable is used only when the physical PHYS walk is empty (classic-only agents).
      Those entries have no age; matching still treats snmp MACs as weak.
    - Walks that yield no usable IPv4 MAC rows return {}.
    """
    walk = walk or walk_subtree
    # Prefer the RFC 4293 table when the agent fills it (age available). Do not mix in media.
    phys_rows = walk(target, NET_TO_PHYSICAL_PHYS, timeout)
    if phys_rows:
        rows = (phys_rows
                + walk(target, NET_TO_PHYSICAL_TYPE, timeout)
                + walk(target, NET_TO_PHYSICAL_LAST, timeout))
        uptime = _read_sys_uptime(target, walk, timeout)
        return unique_macs(parse_arp_table_fresh(rows, sys_uptime=uptime, max_age_s=max_age_s))
    media_rows = walk(target, NET_TO_MEDIA_PHYS, timeout)
    if media_rows:
        return unique_macs(parse_arp_table(media_rows + walk(target, NET_TO_MEDIA_TYPE, timeout)))
    return {}


def _reason(exc: Exception) -> str:
    return str(exc) or type(exc).__name__


def enrich_from_arp(live: dict[str, HostObservation], sources: list[ArpSource], *,
                    timeout: float = DEFAULT_TIMEOUT_S) -> list[str]:
    """Fill `mac` / `mac_source` / `vendor` of MAC-less hosts from each source's ARP table, in
    place. Returns one scan note per gateway polled."""
    notes: list[str] = []
    for src in sources:
        try:
            scope = AddressSet.from_specs(src.cidr)
        except TargetError:
            continue
        missing = [h for h in live.values() if not h.mac and h.ip in scope]
        if not missing:
            continue
        try:
            table = fetch_arp_table(src.target, timeout=timeout)
        except Exception as exc:
            log.warning("router ARP (SNMP) for %s via %s failed: %s", src.network, src.target.host, _reason(exc))
            notes.append(f"Router ARP (SNMP) for {src.network} via {src.target.host} failed: {_reason(exc)}")
            continue
        learned = 0
        for h in missing:
            mac = table.get(h.ip)
            if mac:
                h.mac, h.mac_source, h.vendor = mac, "snmp", h.vendor or vendor_for(mac)
                learned += 1
        notes.append(f"Router ARP (SNMP) for {src.network}: MAC found for {learned} of {len(missing)} host(s)")
    return notes
