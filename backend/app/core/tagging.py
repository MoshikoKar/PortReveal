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
from typing import NamedTuple

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db import utcnow
from ..models import (
    DEVICE_TYPE_UNKNOWN,
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
    PortSnmp,
    PortTls,
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
    web_vnc: bool = False
    snmp_descr: str | None = None   # PortSnmp.sys_descr (spec 9.2 signal)
    snmp_vendor: str | None = None  # PortSnmp.vendor

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
    tls_expired_ports: list[str] = field(default_factory=list)
    tls_expires_soon_ports: list[str] = field(default_factory=list)

    @property
    def open_ports(self) -> set[int]:
        return {s.port for s in self.services}


def load_facts(db: Session, device_ids: list[int]) -> list[DeviceFacts]:
    if not device_ids:
        return []
    networks = {n.id: n for n in db.scalars(select(Network)).all()}
    facts = {d.id: DeviceFacts(d, networks.get(d.network_id))
             for d in db.scalars(select(Device).where(Device.id.in_(device_ids)).order_by(Device.id))}
    snmp_by_port = {s.device_port_id: s for s in db.scalars(
        select(PortSnmp).where(PortSnmp.device_id.in_(device_ids))
    )}
    for p, h in db.execute(
        select(DevicePort, PortHttp).select_from(service_from(True))
        .where(DevicePort.device_id.in_(device_ids), DevicePort.is_open.is_(True))
        .order_by(DevicePort.device_id, DevicePort.port)
    ).all():
        snmp = snmp_by_port.get(p.id)
        facts[p.device_id].services.append(Service(
            p.port, p.protocol, p.service, p.product, p.version, p.extra_info, p.cpe,
            h.title if h else None, h.server if h else None, bool(h and h.login), bool(h and h.default_page),
            bool(h and h.web_vnc), snmp.sys_descr if snmp else None, snmp.vendor if snmp else None,
        ))
    tls_ports = {p.id: p for p in db.scalars(select(DevicePort).where(
        DevicePort.id.in_(select(PortTls.device_port_id).where(PortTls.device_id.in_(device_ids)))
    ))}
    for t in db.scalars(select(PortTls).where(PortTls.device_id.in_(device_ids))):
        f = facts.get(t.device_id)
        if f is None:
            continue
        port = tls_ports.get(t.device_port_id)
        port_label = f"{port.port}/{port.protocol}" if port else f"port_id={t.device_port_id}"
        if t.expired:
            f.tls_expired_ports.append(port_label)
        elif t.expires_soon:
            f.tls_expires_soon_ports.append(port_label)
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
    snmp: tuple[str, ...] = ()           # substring of SNMP sysDescr / vendor (spec 9.2)
    discovery: tuple[str, ...] = ()      # substring of a local mDNS/SSDP/NetBIOS name (spec 9.2)
    check: Callable[[DeviceFacts], str | None] | None = None


# Weighted multi-signal classification (spec section 9.3): every independent *family* of evidence
# that matches a type-bearing rule contributes to that type's score. The first/strongest family
# contributes the rule's own (already-calibrated) priority; each additional, genuinely distinct
# family that also matches the same rule adds a smaller corroboration bonus, so two agreeing weak
# signals score higher than either alone without letting a single bundle of near-duplicate matches
# (e.g. the same port read as both a port number and a service name) inflate the score by itself.
EXTRA_FAMILY_BONUS = 10
# Below this, a type guess is shown as "unknown" rather than asserted (spec 9.1/9.5). Calibrated so
# every existing single-signal rule still classifies confidently (lowest in-use priority is 40,
# ai-llm); only a rule's weakest, least-specific family (e.g. a bare web-server check, priority 10)
# falls under it on its own.
TYPE_CONFIDENCE_THRESHOLD = 35


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
    Rule("media-device", "media-device", 85, products=_MEDIA_PRODUCTS, host=_MEDIA_HOST, http=_MEDIA_HTTP,
         discovery=_MEDIA_HOST),
    # 9100 is a strong printer port; 515/631 need corroboration via _printer_weak_ports.
    Rule("printer", "printer", 80, ports=(9100,), services=_PRINTER_SERVICES,
         products=_PRINTER_PRODUCTS, host=("printer", "laserjet"), hostnames=("printer",),
         snmp=_PRINTER_PRODUCTS, discovery=("printer",) + _PRINTER_PRODUCTS, check=_printer_weak_ports),
    # 554 is a strong camera port; bare rtsp needs camera evidence via _camera_rtsp.
    Rule("camera", "camera", 80, ports=(554,), products=_CAMERA_PRODUCTS,
         host=("hikvision", "axis communications", "dahua"), http=("hikvision", "dahua"),
         discovery=_CAMERA_PRODUCTS, check=_camera_rtsp),
    Rule("nas", "nas", 70, products=("synology", "qnap", "truenas", "freenas"),
         host=("synology", "qnap", "truenas", "freenas"), http=("synology", "qnap", "truenas"),
         discovery=("synology", "qnap", "truenas", "freenas"), check=_truenas),
    Rule("network-device", "network-device", 60, products=("cisco", "mikrotik", "routeros", "ubiquiti", "fortinet",
                                                           "fortigate"),
         host=("cisco", "mikrotik", "routeros", "ubiquiti", "fortinet"), http=("mikrotik", "fortigate", "unifi"),
         snmp=("cisco", "mikrotik", "routeros", "ubiquiti", "fortinet")),
    Rule("database", "database", 50, ports=(3306, 5432, 1433, 1521, 27017, 6379),
         services=("mysql", "postgresql", "ms-sql", "oracle-tns", "mongodb", "redis")),
    Rule("ai-llm", "ai-llm", 40, product_names=frozenset(p.lower() for p in AI_PRODUCTS)),
    # MQTT alone is too weak to assert (priority 20 < threshold); needs a second family
    # (discovery/host/hostname) before "iot" is shown instead of "unknown".
    Rule("iot", "iot", 20, ports=(1883, 8883), services=("mqtt",),
         host=("iot", "esp", "tuya", "shelly", "hue"),
         hostnames=("iot", "esp", "tuya", "shelly", "hue", "mqtt"),
         discovery=("iot", "esp", "tuya", "shelly", "hue", "mqtt")),
    Rule("web-server", "web-server", 10, check=_web),
    Rule("windows", services=("msrpc", "microsoft-ds"), host=("windows",)),
    Rule("remote-access", ports=(3389, 5900, 22), services=("ms-wbt-server", "vnc", "ssh")),
    Rule("web-vnc", "remote-access", 55, http=("novnc", "guacamole", "websockify"),
         check=lambda f: next((f"web VNC UI on {s.label}" for s in f.services if getattr(s, "web_vnc", False)), None)),
)


def rule_matches(rule: Rule, f: DeviceFacts) -> list[tuple[str, str]]:
    """Every independent evidence family that fires for `rule` on this device: [(family, detail)].

    `ports`/`all_ports`/`services` all describe the same underlying observation (an open port, read
    either by number or by its service name) and so count as one "port" family; same for
    `products`/`product_names` (one "product"/banner family). Everything else -- host vendor/OS,
    hostname, HTTP title/server, SNMP, a local discovery name, and bespoke `check` functions -- is
    an independent family, so two of them agreeing raises confidence (spec 9.3).
    """
    out: list[tuple[str, str]] = []
    ports = f.open_ports
    port_hit = False
    if rule.all_ports and all(p in ports for p in rule.all_ports):
        out.append(("port", "ports " + ", ".join(str(p) for p in rule.all_ports) + " open"))
        port_hit = True
    if not port_hit and rule.ports:
        for s in f.services:
            if s.port in rule.ports:
                out.append(("port", f"port {s.label} open"))
                port_hit = True
                break
    if not port_hit and rule.services:
        for s in f.services:
            if hit := _first([s.service], rule.services):
                out.append(("service", f"service {hit[0]} on {s.label}"))
                break
    product_hit = False
    if rule.products:
        for s in f.services:
            if hit := _first([s.product, s.version, s.extra_info, s.cpe], rule.products):
                out.append(("product", f"'{hit[0]}' on {s.label}"))
                product_hit = True
                break
    if not product_hit and rule.product_names:
        for s in f.services:
            if (s.product or "").lower() in rule.product_names:
                out.append(("product", f"product {s.product} on {s.label}"))
                break
    if rule.http:
        for s in f.services:
            if hit := _first([s.title, s.server], rule.http):
                out.append(("http", f"HTTP '{hit[0]}' on {s.label}"))
                break
    if rule.snmp:
        for s in f.services:
            if hit := _first([s.snmp_descr, s.snmp_vendor], rule.snmp):
                out.append(("snmp", f"SNMP '{hit[0]}' on {s.label}"))
                break
    d = f.device
    if rule.host and (hit := _first([d.vendor, d.os_name], rule.host)):
        out.append(("host", f"vendor/OS '{hit[0]}'"))
    if rule.hostnames and (hit := _first([d.hostname, d.dns_name], rule.hostnames)):
        out.append(("hostname", f"hostname '{hit[0]}'"))
    if rule.discovery and (hit := _first([d.discovery_name], rule.discovery)):
        out.append(("discovery", f"local discovery name '{hit[0]}'"))
    if rule.check:
        detail = rule.check(f)
        if detail:
            out.append(("check", detail))
    return out


def rule_reason(rule: Rule, f: DeviceFacts) -> str | None:
    """First matching evidence detail for `rule`, or None. Kept for the suppressed-tag
    revalidation in apply_tags, which only needs a truthy/falsy check plus a human-readable string."""
    matches = rule_matches(rule, f)
    return matches[0][1] if matches else None


class Classification(NamedTuple):
    """4-tuple: unpack as `tags, dtype, confidence, evidence = classify(...)`, or use field names."""

    tags: dict[str, str]
    type: str | None
    confidence: int
    evidence: list[dict]


def classify(f: DeviceFacts, *, suppressed: set[str] | None = None) -> Classification:
    """Tags plus a weighted-evidence device type for one device (spec section 9). Suppressed tags
    are skipped for both tags and type. `type` is "unknown" (not a guess) when some evidence points
    at a type but its combined score stays below TYPE_CONFIDENCE_THRESHOLD; it is None when no
    type-bearing rule matched at all.
    """
    skip = suppressed or set()
    tags: dict[str, str] = {}
    type_scores: dict[str, int] = defaultdict(int)
    type_evidence: dict[str, list[dict]] = defaultdict(list)
    for rule in RULES:
        if rule.tag in skip:
            continue
        matches = rule_matches(rule, f)
        if not matches:
            continue
        tags.setdefault(rule.tag, matches[0][1])
        if not rule.type:
            continue
        type_scores[rule.type] += rule.priority + EXTRA_FAMILY_BONUS * (len(matches) - 1)
        for i, (family, detail) in enumerate(matches):
            points = rule.priority if i == 0 else EXTRA_FAMILY_BONUS
            type_evidence[rule.type].append({"factor": family, "points": points, "detail": detail})
    if not type_scores:
        return Classification(tags, None, 0, [])
    # Deterministic tie-break: highest score, then stable type name.
    best_type = max(type_scores, key=lambda t: (type_scores[t], t))
    confidence = min(100, type_scores[best_type])
    evidence = type_evidence[best_type]
    dtype = best_type if confidence >= TYPE_CONFIDENCE_THRESHOLD else DEVICE_TYPE_UNKNOWN
    return Classification(tags, dtype, confidence, evidence)


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


def _manual_type_override(rule_tags: set[str]) -> Rule | None:
    """A manually-pinned tag that is itself a type-bearing rule's tag wins over the computed
    classification outright (spec 9.3/9.5: "manual override wins and persists")."""
    return next((r for r in RULES if r.type and r.tag in rule_tags), None)


def apply_tags(db: Session, facts: list[DeviceFacts], *, now: datetime, scan_id: int | None = None,
               report_ids: set[int] | None = None) -> list[Event]:
    """Recompute rule tags and device type. The first classification of a device is silent, and so
    is every device outside `report_ids` when it is given. Suppressed tags stay off while the rule
    still matches; they are dropped when the rule no longer matches."""
    events: list[Event] = []
    for f in facts:
        suppressed = {t.tag: t for t in f.tags if t.source == TAG_SOURCE_SUPPRESSED}
        want, dtype, confidence, evidence = classify(f, suppressed=set(suppressed))
        manual = {t.tag for t in f.tags if t.source == TAG_SOURCE_MANUAL}
        override = _manual_type_override(manual)
        if override is not None:
            dtype, confidence = override.type, 100
            evidence = [{"factor": "manual", "points": 100,
                        "detail": f"Manually tagged '{override.tag}'; overrides automatic classification"}]
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
        f.device.type_confidence = confidence
        f.device.classified_at = now
        if f.profile is None:
            f.profile = DeviceProfile(device_id=f.device.id)
            db.add(f.profile)
        f.profile.type_evidence = evidence
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
