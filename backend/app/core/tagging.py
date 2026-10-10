"""Rule-based device tags and device types, computed from stored nmap and Web Capture data.

Rules are plain data. A rule fires on its first matching evidence, and that evidence becomes the
tag's human-readable reason. Rules manage `source=rule` tags; manual and suppressed tags are
operator overrides: manual pins a tag, suppressed keeps a matching rule from applying.
"""
from __future__ import annotations

import re
from collections import defaultdict
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db import utcnow
from ..models import (
    EV_TAG_ADDED,
    EV_TAG_REMOVED,
    EVENT_SEVERITY,
    TAG_SOURCE_MANUAL,
    TAG_SOURCE_RULE,
    TAG_SOURCE_SUPPRESSED,
    Device,
    DevicePort,
    DeviceProfile,
    DeviceTag,
    Event,
    Network,
    PortHttp,
)
from ..scanner.identify_truenas import looks_like_truenas
from .compare import _Applier, device_label
from .query.compile import service_from
from .web_capture.identify_ai import AI_PRODUCTS
from .web_capture.inventory import is_web_service

MAX_TAG_LEN = 60
_TAG_INVALID = re.compile(r"[^a-z0-9-]+")

# Service names that are not useful corroboration for port-based type tags.
_WEAK_SERVICES = frozenset({"", "tcpwrapped", "unknown"})

_PRINTER_SERVICES = ("printer", "jetdirect", "ipp")
_PRINTER_PRODUCTS = ("printer", "laserjet", "officejet", "jetdirect")
_PRINTER_WEAK_PORTS = frozenset({515, 631})

_CAMERA_PRODUCTS = ("hikvision", "axis", "dahua")
_MEDIA_PRODUCTS = (
    "webos", "smart tv", "smarttv", "bravia", "tizen", "roku", "android tv", "apple tv",
    "chromecast", "fire tv", "airtunes", "airplay", "dlna", "samsung tv", "lg smart",
    "playstation", "xbox", "nintendo",
)
_MEDIA_HOST = ("webos", "smart tv", "bravia", "tizen", "roku", "chromecast", "apple tv",
               "playstation", "xbox", "nintendo")
_MEDIA_HTTP = ("webos", "smart tv", "bravia", "tizen", "roku", "chromecast", "apple tv",
               "fire tv", "lg smart", "samsung tv")


def normalize_tag(name: str) -> str:
    """Lowercase `[a-z0-9-]`, at most 60 characters. Raises ValueError when nothing usable is left."""
    tag = re.sub(r"-{2,}", "-", _TAG_INVALID.sub("-", (name or "").strip().lower())).strip("-")
    if not tag:
        raise ValueError("tag must contain letters or digits")
    if len(tag) > MAX_TAG_LEN:
        raise ValueError(f"tag is longer than {MAX_TAG_LEN} characters")
    return tag


# --- facts: everything the rules and the exposure score read, batch-loaded per chunk --------------
@dataclass
class Service:
    port: int
    proto: str
    service: str | None
    product: str | None
    version: str | None
    extra_info: str | None
    cpe: str | None
    title: str | None = None
    server: str | None = None
    login: bool = False
    default_page: bool = False

    @property
    def label(self) -> str:
        return f"{self.port}/{self.proto}"


@dataclass
class DeviceFacts:
    device: Device
    network: Network | None
    services: list[Service] = field(default_factory=list)
    tags: list[DeviceTag] = field(default_factory=list)
    profile: DeviceProfile | None = None

    @property
    def open_ports(self) -> set[int]:
        return {s.port for s in self.services}


def load_facts(db: Session, device_ids: list[int]) -> list[DeviceFacts]:
    if not device_ids:
        return []
    networks = {n.id: n for n in db.scalars(select(Network)).all()}
    facts = {d.id: DeviceFacts(d, networks.get(d.network_id))
             for d in db.scalars(select(Device).where(Device.id.in_(device_ids)).order_by(Device.id))}
    for p, h in db.execute(
        select(DevicePort, PortHttp).select_from(service_from(True))
        .where(DevicePort.device_id.in_(device_ids), DevicePort.is_open.is_(True))
        .order_by(DevicePort.device_id, DevicePort.port)
    ).all():
        facts[p.device_id].services.append(Service(
            p.port, p.protocol, p.service, p.product, p.version, p.extra_info, p.cpe,
            h.title if h else None, h.server if h else None, bool(h and h.login), bool(h and h.default_page),
        ))
    for t in db.scalars(select(DeviceTag).where(DeviceTag.device_id.in_(device_ids))):
        facts[t.device_id].tags.append(t)
    for prof in db.scalars(select(DeviceProfile).where(DeviceProfile.device_id.in_(device_ids))):
        facts[prof.device_id].profile = prof
    return list(facts.values())


# --- rules -------------------------------------------------------------------------------------------
@dataclass(frozen=True)
class Rule:
    tag: str
    type: str | None = None
    priority: int = 0
    ports: tuple[int, ...] = ()          # any of these open (strong ports only for high-stakes types)
    all_ports: tuple[int, ...] = ()      # every one of these open
    services: tuple[str, ...] = ()       # substring of the nmap service name
    products: tuple[str, ...] = ()       # substring of product / version / extra info / CPE
    product_names: frozenset[str] = frozenset()  # exact product name (case-insensitive)
    host: tuple[str, ...] = ()           # substring of vendor / OS
    hostnames: tuple[str, ...] = ()      # substring of hostname / DNS name
    http: tuple[str, ...] = ()           # substring of HTTP title / Server header
    check: Callable[[DeviceFacts], str | None] | None = None


def _is_weak_service(name: str | None) -> bool:
    return (name or "").strip().lower() in _WEAK_SERVICES


def _first(values, needles: tuple[str, ...]) -> tuple[str, str] | None:
    for v in values:
        low = (v or "").lower()
        for n in needles:
            if n in low:
                return v, n
    return None


def _truenas(f: DeviceFacts) -> str | None:
    d = f.device
    if looks_like_truenas(hostname=d.hostname, dns_name=d.dns_name, os_name=d.os_name, vendor=d.vendor):
        return "TrueNAS identified from host details"
    return None


def _web(f: DeviceFacts) -> str | None:
    s = next((s for s in f.services if is_web_service(s.service)), None)
    return f"web service {s.service} on {s.label}" if s else None


def _printer_weak_ports(f: DeviceFacts) -> str | None:
    """515/631 only count as printer when the service fingerprint is printer-like (not tcpwrapped)."""
    for s in f.services:
        if s.port not in _PRINTER_WEAK_PORTS or _is_weak_service(s.service):
            continue
        if hit := _first([s.service], _PRINTER_SERVICES):
            return f"service {hit[0]} on {s.label}"
        if hit := _first([s.product, s.version, s.extra_info, s.cpe], _PRINTER_PRODUCTS):
            return f"'{hit[0]}' on {s.label}"
    return None


def _camera_rtsp(f: DeviceFacts) -> str | None:
    """Bare RTSP is ambiguous (AirPlay, media stacks). Require camera product/vendor evidence."""
    for s in f.services:
        svc = (s.service or "").lower()
        if "rtsp" not in svc:
            continue
        if _first([s.product, s.version, s.extra_info, s.cpe], _MEDIA_PRODUCTS):
            continue
        if hit := _first([s.product, s.version, s.extra_info, s.cpe], _CAMERA_PRODUCTS):
            return f"'{hit[0]}' on {s.label}"
        d = f.device
        if hit := _first([d.vendor, d.os_name], ("hikvision", "axis communications", "dahua")):
            return f"vendor/OS '{hit[0]}' with rtsp on {s.label}"
        if hit := _first([s.title, s.server], ("hikvision", "dahua")):
            return f"HTTP '{hit[0]}' on {s.label}"
    return None


RULES: tuple[Rule, ...] = (
    Rule("domain-controller", "domain-controller", 100, all_ports=(88, 389, 445)),
    Rule("hypervisor", "hypervisor", 90, products=("vmware esxi", "proxmox"), host=("vmware esxi", "proxmox"),
         http=("vmware esxi", "proxmox")),
    Rule("media-device", "media-device", 85, products=_MEDIA_PRODUCTS, host=_MEDIA_HOST, http=_MEDIA_HTTP),
    # 9100 is a strong printer port; 515/631 need corroboration via _printer_weak_ports.
    Rule("printer", "printer", 80, ports=(9100,), services=_PRINTER_SERVICES,
         products=_PRINTER_PRODUCTS, host=("printer", "laserjet"), hostnames=("printer",),
         check=_printer_weak_ports),
    # 554 is a strong camera port; bare rtsp needs camera evidence via _camera_rtsp.
    Rule("camera", "camera", 80, ports=(554,), products=_CAMERA_PRODUCTS,
         host=("hikvision", "axis communications", "dahua"), http=("hikvision", "dahua"),
         check=_camera_rtsp),
    Rule("nas", "nas", 70, products=("synology", "qnap", "truenas", "freenas"),
         host=("synology", "qnap", "truenas", "freenas"), http=("synology", "qnap", "truenas"), check=_truenas),
    Rule("network-device", "network-device", 60, products=("cisco", "mikrotik", "routeros", "ubiquiti", "fortinet",
                                                           "fortigate"),
         host=("cisco", "mikrotik", "routeros", "ubiquiti", "fortinet"), http=("mikrotik", "fortigate", "unifi")),
    Rule("database", "database", 50, ports=(3306, 5432, 1433, 1521, 27017, 6379),
         services=("mysql", "postgresql", "ms-sql", "oracle-tns", "mongodb", "redis")),
    Rule("ai-llm", "ai-llm", 40, product_names=frozenset(p.lower() for p in AI_PRODUCTS)),
    Rule("iot", "iot", 20, ports=(1883, 8883), services=("mqtt",)),
    Rule("web-server", "web-server", 10, check=_web),
    Rule("windows", services=("msrpc", "microsoft-ds"), host=("windows",)),
    Rule("remote-access", ports=(3389, 5900, 22), services=("ms-wbt-server", "vnc", "ssh")),
)


def rule_reason(rule: Rule, f: DeviceFacts) -> str | None:
    """Why `rule` fires for this device, or None."""
    ports = f.open_ports
    if rule.all_ports and all(p in ports for p in rule.all_ports):
        return "ports " + ", ".join(str(p) for p in rule.all_ports) + " open"
    for s in f.services:
        if s.port in rule.ports:
            return f"port {s.label} open"
    for s in f.services:
        if rule.services and (hit := _first([s.service], rule.services)):
            return f"service {hit[0]} on {s.label}"
        if rule.products and (hit := _first([s.product, s.version, s.extra_info, s.cpe], rule.products)):
            return f"'{hit[0]}' on {s.label}"
        if rule.product_names and (s.product or "").lower() in rule.product_names:
            return f"product {s.product} on {s.label}"
        if rule.http and (hit := _first([s.title, s.server], rule.http)):
            return f"HTTP '{hit[0]}' on {s.label}"
    d = f.device
    if rule.host and (hit := _first([d.vendor, d.os_name], rule.host)):
        return f"vendor/OS '{hit[0]}'"
    if rule.hostnames and (hit := _first([d.hostname, d.dns_name], rule.hostnames)):
        return f"hostname '{hit[0]}'"
    return rule.check(f) if rule.check else None


def classify(f: DeviceFacts, *, suppressed: set[str] | None = None) -> tuple[dict[str, str], str | None]:
    """(tag -> reason, device type) for one device. Suppressed tags are skipped for tag and type."""
    skip = suppressed or set()
    tags: dict[str, str] = {}
    best: Rule | None = None
    for rule in RULES:
        if rule.tag in skip:
            continue
        reason = rule_reason(rule, f)
        if reason is None:
            continue
        tags.setdefault(rule.tag, reason)
        if rule.type and (best is None or rule.priority > best.priority):
            best = rule
    return tags, best.type if best else None


# --- persistence -------------------------------------------------------------------------------------
def _tag_event(f: DeviceFacts, etype: str, tag: str, reason: str | None, mode: str, scan_id: int | None,
               now: datetime) -> Event:
    d = f.device
    verb = "added to" if etype == EV_TAG_ADDED else "removed from"
    return Event(
        created_at=now, scan_id=scan_id, device=d, event_type=etype, severity=EVENT_SEVERITY[etype],
        ip=d.current_ip, old_value=tag if etype == EV_TAG_REMOVED else None,
        new_value=tag if etype == EV_TAG_ADDED else None,
        message=f"Tag {tag} {verb} {device_label(d)}" + (f" ({reason})" if reason else ""),
        notify=mode == "alert",
    )


def apply_tags(db: Session, facts: list[DeviceFacts], *, now: datetime, scan_id: int | None = None,
               report_ids: set[int] | None = None) -> list[Event]:
    """Recompute rule tags and device type. The first classification of a device is silent, and so
    is every device outside `report_ids` when it is given. Suppressed tags stay off while the rule
    still matches; they are dropped when the rule no longer matches."""
    events: list[Event] = []
    for f in facts:
        suppressed = {t.tag: t for t in f.tags if t.source == TAG_SOURCE_SUPPRESSED}
        want, dtype = classify(f, suppressed=set(suppressed))
        manual = {t.tag for t in f.tags if t.source == TAG_SOURCE_MANUAL}
        current = {t.tag: t for t in f.tags if t.source == TAG_SOURCE_RULE}
        reportable = f.device.classified_at is not None and (report_ids is None or f.device.id in report_ids)
        mode = _Applier.mode_for(f.network) if reportable else "silent"
        kept: list[DeviceTag] = [t for t in f.tags if t.source == TAG_SOURCE_MANUAL]
        for tag, reason in want.items():
            if tag in manual:
                continue
            row = current.pop(tag, None)
            if row is None:
                row = DeviceTag(device_id=f.device.id, tag=tag, source=TAG_SOURCE_RULE, reason=reason, created_at=now)
                db.add(row)
                if mode != "silent":
                    events.append(_tag_event(f, EV_TAG_ADDED, tag, reason, mode, scan_id, now))
            else:
                row.reason = reason
            kept.append(row)
        for tag, row in current.items():
            db.delete(row)
            if mode != "silent":
                events.append(_tag_event(f, EV_TAG_REMOVED, tag, None, mode, scan_id, now))
        # Keep suppressions only while the underlying rule would still fire.
        for tag, row in list(suppressed.items()):
            still = next((rule_reason(r, f) for r in RULES if r.tag == tag), None)
            if still is not None:
                kept.append(row)
            else:
                db.delete(row)
        f.tags = kept
        f.device.device_type = dtype
        f.device.classified_at = now
    for ev in events:
        db.add(ev)
    return events


def reclassify_device(db: Session, device_id: int, *, now: datetime | None = None) -> None:
    """Recompute rule tags and type for one device (silent; used after admin tag edits)."""
    facts = load_facts(db, [device_id])
    if facts:
        # report_ids=empty keeps this silent even if the device was classified before
        apply_tags(db, facts, now=now or utcnow(), report_ids=set())


def tags_by_device(db: Session, device_ids: list[int]) -> dict[int, list[DeviceTag]]:
    out: dict[int, list[DeviceTag]] = defaultdict(list)
    for t in db.scalars(select(DeviceTag).where(DeviceTag.device_id.in_(device_ids)).order_by(DeviceTag.tag)):
        out[t.device_id].append(t)
    return out
