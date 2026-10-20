"""Compare published public-IP geography against a network's expected countries.

Private, loopback, link-local and CGNAT addresses are never geolocated. Candidate IPs come from
forward-DNS of names already in inventory (hostname, dns_name, TLS CN/SAN, HTTP redirect hosts)
and from Device.current_ip when that address is public.

Lookups are cached (DNS + MMDB) with a TTL. Missing MMDB files skip the scan (status unavailable)
and kick a background DB-IP download; they never fail the scan.
"""
from __future__ import annotations

import ipaddress
import logging
import re
import socket
from collections.abc import Callable, Iterable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime, timedelta
from urllib.parse import urlparse

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db import utcnow
from ..models import (
    EV_GEO_MISMATCH,
    GEO_MISMATCH,
    GEO_MISMATCH_CDN,
    GEO_NOT_CHECKED,
    GEO_OK,
    GEO_SOURCE_DEVICE_IP,
    GEO_SOURCE_PUBLISHED_NAME,
    GEO_UNAVAILABLE,
    Device,
    Event,
    GeoLookupCache,
    Network,
    PortHttp,
    PortTls,
)
from ..settings_store import GeoSettings, get_section
from .compare import _Applier
from .geo_sync import asn_db_path, country_db_path, ensure_geo_dbs, maxmind_country_path
from .identity import normalize_hostname

log = logging.getLogger(__name__)

CDN_MISMATCH_LABEL = "behind CDN – location reflects CDN edge, not origin"
DNS_TIMEOUT_SECONDS = 3.0
TAG = "geo-mismatch"

# RFC1918 + CGNAT: never geolocated. Documentation (TEST-NET) ranges stay eligible so tests can
# use them as stand-ins for public addresses without leaking real infrastructure.
_SKIP_NETS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("fc00::/7"),
)
_LOCAL_SUFFIXES = (
    ".local", ".lan", ".home", ".internal", ".localhost", ".docker.internal",
    ".containers.internal", ".corp.local",
)
_HOST_RE = re.compile(
    r"^(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$"
)

Resolver = Callable[[str], list[str]]
IpLookup = Callable[[str], "GeoRecord | None"]


@dataclass(frozen=True)
class GeoRecord:
    country: str | None
    asn: int | None = None
    as_org: str | None = None


@dataclass(frozen=True)
class Candidate:
    ip: str
    source: str
    name: str | None
    record: GeoRecord


def is_public_ip(value: str) -> bool:
    try:
        addr = ipaddress.ip_address(value)
    except ValueError:
        return False
    if addr.is_loopback or addr.is_link_local or addr.is_multicast or addr.is_unspecified:
        return False
    return not any(addr in net for net in _SKIP_NETS)


def normalize_country(code: str | None) -> str | None:
    if not code:
        return None
    c = code.strip().upper()
    return c if len(c) == 2 and c.isalpha() else None


def normalize_expected(raw) -> list[str]:
    if not raw:
        return []
    if isinstance(raw, str):
        raw = [raw]
    out: list[str] = []
    for item in raw:
        code = normalize_country(str(item) if item is not None else None)
        if code and code not in out:
            out.append(code)
    return out


def _usable_name(name: str | None) -> str | None:
    n = normalize_hostname(name)
    if not n or "." not in n:
        return None
    if any(n.endswith(suf) for suf in _LOCAL_SUFFIXES):
        return None
    try:
        ipaddress.ip_address(n)
        return None
    except ValueError:
        pass
    if not _HOST_RE.match(n):
        return None
    return n


def _host_from_url(value: str | None) -> str | None:
    if not value:
        return None
    text = value.strip()
    if "://" not in text:
        if "/" in text or " " in text:
            return None
        return _usable_name(text)
    try:
        parsed = urlparse(text)
    except ValueError:
        return None
    host = parsed.hostname
    return _usable_name(host)


def _split_tls_names(cn: str | None, san: str | None) -> list[str]:
    out: list[str] = []
    for raw in (cn or "", san or ""):
        for part in re.split(r"[\s,;]+", raw):
            part = part.strip()
            if part.lower().startswith("dns:"):
                part = part[4:]
            if part.startswith("*."):
                part = part[2:]
            n = _usable_name(part)
            if n and n not in out:
                out.append(n)
    return out


def harvest_published_names(device: Device, http_rows: Iterable[PortHttp],
                            tls_rows: Iterable[PortTls]) -> list[str]:
    names: list[str] = []
    for raw in (device.dns_name, device.hostname):
        n = _usable_name(raw)
        if n and n not in names:
            names.append(n)
    for t in tls_rows:
        for n in _split_tls_names(t.cn, t.san):
            if n not in names:
                names.append(n)
    for h in http_rows:
        n = _host_from_url(h.location)
        if n and n not in names:
            names.append(n)
        title = (h.title or "").strip()
        if title.lower().startswith("http://") or title.lower().startswith("https://"):
            n = _host_from_url(title)
            if n and n not in names:
                names.append(n)
    return names


def _dns_resolve(name: str) -> list[str]:
    def _call() -> list[str]:
        infos = socket.getaddrinfo(name, None, type=socket.SOCK_STREAM)
        ips: list[str] = []
        for info in infos:
            ip = info[4][0]
            if is_public_ip(ip) and ip not in ips:
                ips.append(ip)
        return ips

    with ThreadPoolExecutor(max_workers=1) as pool:
        fut = pool.submit(_call)
        try:
            return fut.result(timeout=DNS_TIMEOUT_SECONDS)
        except Exception:
            return []


def _open_reader(path) -> object | None:
    try:
        import maxminddb
    except ImportError:
        log.warning("maxminddb package is not installed; geo lookups disabled")
        return None
    try:
        return maxminddb.open_database(str(path))
    except Exception:
        log.exception("could not open MMDB %s", path)
        return None


def _country_from_db(rec: dict | None) -> str | None:
    if not rec:
        return None
    country = rec.get("country") if isinstance(rec, dict) else None
    if isinstance(country, dict):
        return normalize_country(country.get("iso_code") or country.get("alpha2")
                                 or country.get("isoCode"))
    registered = rec.get("registered_country") if isinstance(rec, dict) else None
    if isinstance(registered, dict):
        return normalize_country(registered.get("iso_code") or registered.get("alpha2"))
    return normalize_country(rec.get("country_code") if isinstance(rec, dict) else None)


def _asn_from_db(rec: dict | None) -> tuple[int | None, str | None]:
    if not isinstance(rec, dict):
        return None, None
    asn = rec.get("autonomous_system_number") or rec.get("asn") or rec.get("autonomous_system_org_number")
    org = rec.get("autonomous_system_organization") or rec.get("as_org") or rec.get("organization")
    try:
        asn_i = int(asn) if asn is not None else None
    except (TypeError, ValueError):
        asn_i = None
    org_s = str(org).strip()[:200] if org else None
    return asn_i, org_s or None


def build_lookup(cfg: GeoSettings) -> IpLookup | None:
    country_path = maxmind_country_path(cfg) or (country_db_path() if country_db_path().is_file() else None)
    if country_path is None:
        return None
    country_reader = _open_reader(country_path)
    if country_reader is None:
        return None
    asn_reader = _open_reader(asn_db_path()) if asn_db_path().is_file() else None

    def lookup(ip: str) -> GeoRecord | None:
        try:
            crec = country_reader.get(ip)
        except Exception:
            crec = None
        country = _country_from_db(crec if isinstance(crec, dict) else None)
        asn, org = None, None
        if asn_reader is not None:
            try:
                arec = asn_reader.get(ip)
            except Exception:
                arec = None
            asn, org = _asn_from_db(arec if isinstance(arec, dict) else None)
        if country is None and asn is None:
            return None
        return GeoRecord(country=country, asn=asn, as_org=org)

    return lookup


def _cache_get(db: Session, key: str, now: datetime) -> dict | None:
    row = db.get(GeoLookupCache, key)
    if row is None or row.expires_at <= now:
        return None
    return dict(row.payload or {})


def _cache_put(db: Session, key: str, kind: str, payload: dict, expires: datetime) -> None:
    row = db.get(GeoLookupCache, key)
    if row is None:
        db.add(GeoLookupCache(cache_key=key, kind=kind, payload=payload, expires_at=expires))
    else:
        row.kind = kind
        row.payload = payload
        row.expires_at = expires


def resolve_name_cached(db: Session, name: str, now: datetime, ttl: timedelta,
                        resolver: Resolver) -> list[str]:
    key = f"dns:{name.lower()}"
    hit = _cache_get(db, key, now)
    if hit is not None and "ips" in hit:
        return [ip for ip in hit["ips"] if isinstance(ip, str) and is_public_ip(ip)]
    ips = resolver(name)
    _cache_put(db, key, "dns", {"ips": ips}, now + ttl)
    return ips


def lookup_ip_cached(db: Session, ip: str, now: datetime, ttl: timedelta,
                     lookup: IpLookup) -> GeoRecord | None:
    key = f"ip:{ip}"
    hit = _cache_get(db, key, now)
    if hit is not None:
        return GeoRecord(
            country=normalize_country(hit.get("country")),
            asn=int(hit["asn"]) if hit.get("asn") is not None else None,
            as_org=hit.get("as_org"),
        )
    rec = lookup(ip)
    if rec is None:
        _cache_put(db, key, "ip", {"country": None, "asn": None, "as_org": None}, now + ttl)
        return None
    _cache_put(db, key, "ip", {"country": rec.country, "asn": rec.asn, "as_org": rec.as_org}, now + ttl)
    return rec


def _cdn_set(cfg: GeoSettings) -> dict[int, str]:
    return {e.asn: (e.label or f"AS{e.asn}") for e in cfg.cdn_asns}


def _severity(cdn: bool) -> str:
    return "medium" if cdn else "high"


def _fingerprint(status: str, country: str | None, ip: str | None, cdn: bool) -> str:
    return f"{status}|{country or ''}|{ip or ''}|{int(cdn)}"


def _apply_device(device: Device, status: str, *, country: str | None, ip: str | None,
                  asn: int | None, org: str | None, cdn: bool, source: str | None,
                  name: str | None, now: datetime) -> None:
    device.geo_status = status
    device.geo_country = country
    device.geo_ip = ip
    device.geo_asn = asn
    device.geo_as_org = org
    device.geo_cdn = cdn
    device.geo_source = source
    device.geo_name = name
    device.geo_checked_at = now
    device.geo_mismatch = status in (GEO_MISMATCH, GEO_MISMATCH_CDN)


def _mismatch_event(device: Device, scan_id: int | None, expected: list[str], cand: Candidate,
                    cdn: bool, cdn_label: str | None, mode: str, now: datetime) -> Event:
    expected_s = ",".join(expected)
    bits = [cand.record.country or "??", cand.ip]
    if cand.record.asn:
        bits.append(f"AS{cand.record.asn}")
    if cand.record.as_org:
        bits.append(cand.record.as_org)
    if cand.name:
        bits.append(cand.name)
    if cdn:
        bits.append(CDN_MISMATCH_LABEL)
    loc = cand.record.country or "an unknown country"
    msg = (f"Published name {cand.name} resolves to {cand.ip} in {loc} "
           f"(expected {expected_s})" if cand.name
           else f"Public address {cand.ip} is in {loc} (expected {expected_s})")
    if cdn:
        msg = f"{msg}. {CDN_MISMATCH_LABEL}"
        if cdn_label:
            msg = f"{msg} ({cdn_label})"
    return Event(
        created_at=now, scan_id=scan_id, device=device, event_type=EV_GEO_MISMATCH,
        severity=_severity(cdn), ip=device.current_ip, old_value=expected_s,
        new_value=" ".join(bits), message=msg, notify=mode == "alert",
    )


def check_devices_geo(db: Session, device_ids: Iterable[int], *, scan_id: int | None = None,
                      now: datetime | None = None, resolver: Resolver | None = None,
                      lookup: IpLookup | None = None, ensure_dbs: bool = True) -> list[Event]:
    """Update geo_* on scanned devices and emit geo_mismatch events. Returns created events."""
    ids = [i for i in dict.fromkeys(device_ids) if i is not None]
    if not ids:
        return []
    now = now or utcnow()
    cfg = get_section(db, GeoSettings)
    devices = list(db.scalars(select(Device).where(Device.id.in_(ids))).all())
    net_ids = {d.network_id for d in devices if d.network_id is not None}
    networks = {n.id: n for n in db.scalars(select(Network).where(Network.id.in_(net_ids))).all()} if net_ids else {}
    needed = [
        d for d in devices
        if normalize_expected(
            networks[d.network_id].expected_countries if d.network_id in networks else None
        )
    ]
    if not needed:
        return []

    if lookup is None:
        if ensure_dbs:
            ensure_geo_dbs(db, cfg)
        lookup = build_lookup(cfg)
    if lookup is None:
        for d in needed:
            d.geo_status = GEO_UNAVAILABLE
            d.geo_checked_at = now
        db.flush()
        return []

    resolver = resolver or _dns_resolve
    ttl = timedelta(hours=cfg.cache_ttl_hours)
    cdn_asns = _cdn_set(cfg)
    http_by: dict[int, list[PortHttp]] = {}
    tls_by: dict[int, list[PortTls]] = {}
    for row in db.scalars(select(PortHttp).where(PortHttp.device_id.in_([d.id for d in needed]))):
        http_by.setdefault(row.device_id, []).append(row)
    for row in db.scalars(select(PortTls).where(PortTls.device_id.in_([d.id for d in needed]))):
        tls_by.setdefault(row.device_id, []).append(row)

    events: list[Event] = []
    for d in needed:
        net = networks.get(d.network_id) if d.network_id else None
        expected = normalize_expected(net.expected_countries if net else None)
        mode = _Applier.mode_for(net)
        prev_fp = _fingerprint(d.geo_status or "", d.geo_country, d.geo_ip, bool(d.geo_cdn))
        candidates: list[Candidate] = []
        names = harvest_published_names(d, http_by.get(d.id, []), tls_by.get(d.id, []))
        for name in names:
            for ip in resolve_name_cached(db, name, now, ttl, resolver):
                rec = lookup_ip_cached(db, ip, now, ttl, lookup)
                if rec is None or not rec.country:
                    continue
                candidates.append(Candidate(ip=ip, source=GEO_SOURCE_PUBLISHED_NAME, name=name, record=rec))
        if is_public_ip(d.current_ip):
            rec = lookup_ip_cached(db, d.current_ip, now, ttl, lookup)
            if rec is not None and rec.country:
                candidates.append(Candidate(ip=d.current_ip, source=GEO_SOURCE_DEVICE_IP, name=None, record=rec))

        if not candidates:
            _apply_device(d, GEO_NOT_CHECKED, country=None, ip=None, asn=None, org=None,
                          cdn=False, source=None, name=None, now=now)
            continue

        mismatch = [c for c in candidates if c.record.country not in expected]
        if not mismatch:
            keep = candidates[0]
            cdn = keep.record.asn in cdn_asns if keep.record.asn else False
            _apply_device(d, GEO_OK, country=keep.record.country, ip=keep.ip, asn=keep.record.asn,
                          org=keep.record.as_org, cdn=cdn, source=keep.source, name=keep.name, now=now)
            continue

        # Prefer a non-CDN mismatch when both exist so the higher-severity finding is stored.
        chosen = next((c for c in mismatch if not (c.record.asn and c.record.asn in cdn_asns)), mismatch[0])
        cdn = bool(chosen.record.asn and chosen.record.asn in cdn_asns)
        status = GEO_MISMATCH_CDN if cdn else GEO_MISMATCH
        _apply_device(d, status, country=chosen.record.country, ip=chosen.ip, asn=chosen.record.asn,
                      org=chosen.record.as_org, cdn=cdn, source=chosen.source, name=chosen.name, now=now)
        fp = _fingerprint(status, chosen.record.country, chosen.ip, cdn)
        if fp != prev_fp:
            events.append(_mismatch_event(d, scan_id, expected, chosen, cdn,
                                          cdn_asns.get(chosen.record.asn or 0), mode, now))

    for ev in events:
        db.add(ev)
    db.flush()
    return events
