"""CPE <-> CVE matching against the local vulnerability cache (spec section 5.5).

Detect-and-display only: no patch suggestions, no backport heuristics. Confidence depends only on
how precise the device's own version evidence is -- `confirmed` for an exact version behind a
reliable identification, `potential` for anything looser (a bare product match, or a version that
came from a weak/guessed service identification).

Nothing here makes a network request: it only reads `vuln_cpe_match` / `vulnerabilities`, already
populated by `sync.py` from the weekly feed download, and the already-stored `device_ports.cpe`
strings nmap produced during a scan.
"""
from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from ...models import (
    VULN_STATE_CONFIRMED,
    VULN_STATE_DISMISSED,
    VULN_STATE_POTENTIAL,
    VULN_SOURCE_CACHE,
    DevicePort,
    DevicePortVuln,
    VulnCpeMatch,
)
from ...scanner.types import VERIFIED_METHOD

_VERSION_TOKEN_RE = re.compile(r"\d+|[A-Za-z]+")


def _version_key(v: str) -> tuple:
    return tuple(int(t) if t.isdigit() else t.lower() for t in _VERSION_TOKEN_RE.findall(v))


def compare_versions(a: str, b: str) -> int:
    """-1 / 0 / 1, comparing dotted/alnum version strings token by token (numeric tokens as ints)."""
    ka, kb = _version_key(a), _version_key(b)
    for x, y in zip(ka, kb):
        if type(x) is not type(y):
            x, y = str(x), str(y)
        if x < y:
            return -1
        if x > y:
            return 1
    return (len(ka) > len(kb)) - (len(ka) < len(kb))


def version_in_range(version: str, start: str | None, start_incl: bool | None,
                     end: str | None, end_excl: bool | None) -> bool:
    if start:
        cmp = compare_versions(version, start)
        if (start_incl and cmp < 0) or (not start_incl and cmp <= 0):
            return False
    if end:
        cmp = compare_versions(version, end)
        if (end_excl and cmp >= 0) or (not end_excl and cmp > 0):
            return False
    return True


def _cpe_field(v: str) -> str:
    return v if v else "*"


def _cpe22_to_23(cpe22: str) -> str | None:
    """`cpe:/a:vendor:product:version:update:edition:language` -> CPE 2.3."""
    body = cpe22[len("cpe:/"):]
    parts = body.split(":")
    if not parts or not parts[0]:
        return None
    parts = (parts + [""] * 7)[:7]
    return "cpe:2.3:" + ":".join(_cpe_field(p) for p in parts) + ":*:*:*:*"


def normalize_cpe(raw: str) -> str | None:
    """CPE 2.2 or 2.3 -> CPE 2.3, or None if it is not a recognizable CPE string."""
    raw = (raw or "").strip()
    if raw.startswith("cpe:2.3:"):
        return raw
    if raw.startswith("cpe:/"):
        return _cpe22_to_23(raw)
    return None


# Small alias table for nmap CPE names that differ from NVD's (spec 5.5).
_CPE_ALIASES: dict[tuple[str, str], tuple[str, str]] = {
    ("apache", "http_server"): ("apache", "http_server"),
    ("apache", "httpd"): ("apache", "http_server"),
    ("openbsd", "openssh"): ("openbsd", "openssh"),
    ("microsoft", "iis"): ("microsoft", "internet_information_services"),
    ("microsoft", "internet_information_server"): ("microsoft", "internet_information_services"),
    ("canonical", "ubuntu_linux"): ("linux", "linux_kernel"),
}


def cpe_vendor_product(cpe23: str) -> tuple[str, str] | None:
    fields = cpe23.split(":")
    if len(fields) < 5 or fields[0] != "cpe" or fields[1] != "2.3":
        return None
    vendor, product = fields[3].lower(), fields[4].lower()
    if not vendor or not product or vendor == "*" or product == "*":
        return None
    return _CPE_ALIASES.get((vendor, product), (vendor, product))


def cpe_version(cpe23: str) -> str | None:
    fields = cpe23.split(":")
    if len(fields) < 6:
        return None
    v = fields[5]
    return v if v and v not in ("*", "-") else None


def _port_reliable(method: str | None, confidence: int | None) -> bool:
    return method in ("probed", VERIFIED_METHOD) or (confidence or 0) >= 8


@dataclass(frozen=True)
class CpeMatchResult:
    cve_id: str
    matched_cpe: str
    state: str  # confirmed | potential


def _match_one(row: VulnCpeMatch, evidence_version: str | None, exact_evidence: bool) -> str | None:
    """`confirmed` / `potential` state for this candidate row, or None if it does not apply."""
    has_range = bool(row.version_start or row.version_end)
    pinned = cpe_version(row.cpe23)
    if has_range:
        if not evidence_version:
            return None
        try:
            if not version_in_range(evidence_version, row.version_start, row.version_start_incl,
                                     row.version_end, row.version_end_excl):
                return None
        except (TypeError, ValueError):
            return None
        return VULN_STATE_CONFIRMED if exact_evidence else VULN_STATE_POTENTIAL
    if pinned:
        if not evidence_version or evidence_version.strip().lower() != pinned.strip().lower():
            return None
        return VULN_STATE_CONFIRMED if exact_evidence else VULN_STATE_POTENTIAL
    # Neither a range nor a pinned version in the CVE's CPE: applies to the product regardless of
    # version. Never `confirmed` purely from a product match -- there is no version evidence for it.
    return VULN_STATE_POTENTIAL


def match_port_cpes(db: Session, port_cpe: str | None, port_version: str | None,
                    port_method: str | None, port_confidence: int | None) -> list[CpeMatchResult]:
    """Candidate CVE matches for one device port's nmap CPE string(s)."""
    raw_cpes = [c for c in (port_cpe or "").split() if c]
    normalized: list[tuple[str, str | None]] = []
    for raw in raw_cpes:
        n = normalize_cpe(raw)
        if n:
            normalized.append((n, cpe_version(n)))
    if not normalized:
        return []
    vendor_products: set[str] = set()
    by_cpe: list[tuple[str, str, str | None]] = []  # (vendor_product, cpe23, pinned_version)
    for cpe23, pinned in normalized:
        vp = cpe_vendor_product(cpe23)
        if vp is None:
            continue
        vendor_product = f"{vp[0]}:{vp[1]}"
        vendor_products.add(vendor_product)
        by_cpe.append((vendor_product, cpe23, pinned))
    if not vendor_products:
        return []
    rows = db.scalars(
        select(VulnCpeMatch).where(VulnCpeMatch.vendor_product.in_(sorted(vendor_products)))
    ).all()
    by_vp: dict[str, list[VulnCpeMatch]] = defaultdict(list)
    for r in rows:
        by_vp[r.vendor_product].append(r)
    reliable = _port_reliable(port_method, port_confidence)
    best: dict[str, CpeMatchResult] = {}
    for vendor_product, _cpe23, pinned in by_cpe:
        evidence_version = pinned or port_version
        exact_evidence = bool(pinned) or (reliable and bool(port_version))
        for r in by_vp.get(vendor_product, ()):
            state = _match_one(r, evidence_version, exact_evidence)
            if state is None:
                continue
            existing = best.get(r.cve_id)
            if existing is None or (existing.state != VULN_STATE_CONFIRMED and state == VULN_STATE_CONFIRMED):
                best[r.cve_id] = CpeMatchResult(cve_id=r.cve_id, matched_cpe=r.cpe23, state=state)
    return list(best.values())


def sync_port_matches(db: Session, ports: list[DevicePort], *, now: datetime) -> dict[str, int]:
    """Recompute `device_port_vulns` for these ports from the local cache. No network access.

    Dismissed matches are never resurrected automatically; matches that no longer apply (CPE/version
    changed) are removed unless they were dismissed.
    """
    stats = {"ports_checked": 0, "matched": 0, "removed": 0}
    port_ids = [p.id for p in ports if p.id is not None]
    if not port_ids:
        return stats
    existing_rows = db.scalars(
        select(DevicePortVuln).where(DevicePortVuln.device_port_id.in_(port_ids))
    ).all()
    by_port: dict[int, list[DevicePortVuln]] = defaultdict(list)
    for row in existing_rows:
        by_port[row.device_port_id].append(row)

    for port in ports:
        if port.id is None or not port.is_open:
            continue
        stats["ports_checked"] += 1
        matches = match_port_cpes(db, port.cpe, port.version, port.method, port.confidence)
        by_cve = {m.cve_id: m for m in matches}
        current = {row.cve_id: row for row in by_port.get(port.id, ())}
        for cve_id, row in current.items():
            if row.state == VULN_STATE_DISMISSED:
                continue
            if cve_id not in by_cve:
                db.delete(row)
                stats["removed"] += 1
        for cve_id, m in by_cve.items():
            row = current.get(cve_id)
            if row is None:
                db.add(DevicePortVuln(
                    device_port_id=port.id, cve_id=cve_id, matched_cpe=m.matched_cpe,
                    state=m.state, source=VULN_SOURCE_CACHE, matched_at=now,
                ))
                stats["matched"] += 1
            elif row.state != VULN_STATE_DISMISSED:
                row.matched_cpe, row.state, row.matched_at = m.matched_cpe, m.state, now
                stats["matched"] += 1
    db.flush()
    return stats


def match_devices(db: Session, device_ids: list[int], *, now: datetime) -> dict[str, int]:
    """Re-run matching for every open port of these devices."""
    if not device_ids:
        return {"ports_checked": 0, "matched": 0, "removed": 0}
    ports = db.scalars(
        select(DevicePort).where(DevicePort.device_id.in_(device_ids), DevicePort.is_open.is_(True))
    ).all()
    return sync_port_matches(db, ports, now=now)


def match_all(db: Session, *, now: datetime, chunk: int = 2000) -> dict[str, int]:
    """Re-run matching for every open port with a CPE in the whole inventory (after a feed sync)."""
    totals = {"ports_checked": 0, "matched": 0, "removed": 0}
    ids = db.scalars(
        select(DevicePort.id).where(DevicePort.is_open.is_(True), DevicePort.cpe.isnot(None))
    ).all()
    for i in range(0, len(ids), chunk):
        batch_ids = ids[i:i + chunk]
        ports = db.scalars(select(DevicePort).where(DevicePort.id.in_(batch_ids))).all()
        stats = sync_port_matches(db, ports, now=now)
        for k in totals:
            totals[k] += stats[k]
    return totals
