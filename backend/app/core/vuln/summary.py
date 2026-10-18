"""Single computed snapshot backing every vulnerability-dashboard card/facet/chart/top-list.

Everything here is derived from already-stored `device_port_vulns` + the local vuln cache: no
outbound requests. Computed in one pass, cached in-process (same TTL-plus-explicit-invalidate
idiom as settings_store.py's `_cache`), and invalidated whenever a scan or feed sync completes
(core/vuln/runner.py, core/vuln/sync.py call `refresh_after_scan_or_sync`).
"""
from __future__ import annotations

import time
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta

from sqlalchemy import and_, case, delete, func, or_, select
from sqlalchemy.orm import Session

from ...models import (
    VULN_STATE_CONFIRMED,
    VULN_STATE_DISMISSED,
    VULN_STATE_POTENTIAL,
    Device,
    DevicePort,
    DevicePortVuln,
    Network,
    VulnCpeMatch,
    VulnDailySnapshot,
    Vulnerability,
    VulnFeedState,
    VulnFindingLifecycle,
)
from ...settings_store import VulnSettings, get_section
from ..mockdata import device_visible
from .buckets import severity_bucket
from .lifecycle import sync_finding_lifecycle
from .score import DEFAULT_CVSS, RISK_HIGH_THRESHOLD, RISK_MEDIUM_THRESHOLD

TOP_N = 10
WEEKS = 12
SNAPSHOT_RETENTION_DAYS = 365
AGE_BUCKETS = ("under_30d", "30_90d", "90_365d", "over_365d", "unknown")
FACET_LIMIT = 20

# Report-only, refreshed in the background after every scan/sync: a short TTL just bounds
# staleness for a second app process sharing the database; invalidate_vuln_summary_cache() covers
# this one. Keyed by database URL, same idiom as settings_store.py's `_cache`, so tests (each on
# their own SQLite file) and multiple configured databases never share a stale entry.
_CACHE_TTL_SECONDS = 30.0
_cache: dict[str, tuple[float, dict]] = {}


def _cache_key(db: Session) -> str:
    return str(db.get_bind().url)


def invalidate_vuln_summary_cache() -> None:
    _cache.clear()


def _age_bucket(ts: datetime | None, now: datetime) -> str:
    if ts is None:
        return "unknown"
    age = now - ts
    if age < timedelta(days=30):
        return "under_30d"
    if age < timedelta(days=90):
        return "30_90d"
    if age < timedelta(days=365):
        return "90_365d"
    return "over_365d"


@dataclass(frozen=True)
class _Finding:
    network_id: int | None
    network_name: str | None
    os_name: str | None
    device_type: str | None
    port: int
    protocol: str
    service: str | None
    cve_id: str
    state: str
    matched_cpe: str | None
    cvss_base: float | None
    kev: bool
    epss: float | None
    published_at: datetime | None
    first_seen_at: datetime | None


def _load_findings(db: Session) -> list[_Finding]:
    """Every non-dismissed, visible finding, with its lifecycle first-seen date joined in.

    The lifecycle join matches on (device uuid, port, protocol, cve_id) -- its natural identity,
    since it has no FK to device_port_vulns -- and only resolves once `sync_finding_lifecycle` has
    run for the current state, which callers must do first.
    """
    rows = db.execute(
        select(Device.network_id, Network.name, Device.os_name, Device.device_type,
               DevicePort.port, DevicePort.protocol, DevicePort.service,
               DevicePortVuln.cve_id, DevicePortVuln.state, DevicePortVuln.matched_cpe,
               Vulnerability.cvss_base, Vulnerability.kev, Vulnerability.epss, Vulnerability.published_at,
               VulnFindingLifecycle.first_seen_at)
        .join(DevicePort, DevicePort.device_id == Device.id)
        .join(DevicePortVuln, DevicePortVuln.device_port_id == DevicePort.id)
        .join(Vulnerability, Vulnerability.cve_id == DevicePortVuln.cve_id)
        .outerjoin(Network, Network.id == Device.network_id)
        .outerjoin(VulnFindingLifecycle, and_(
            VulnFindingLifecycle.device_uuid == Device.uuid,
            VulnFindingLifecycle.port == DevicePort.port,
            VulnFindingLifecycle.protocol == DevicePort.protocol,
            VulnFindingLifecycle.cve_id == DevicePortVuln.cve_id,
        ))
        .where(device_visible(db), DevicePortVuln.state != VULN_STATE_DISMISSED)
    ).all()
    return [_Finding(*r) for r in rows]


def _visible(f: _Finding, cfg: VulnSettings) -> bool:
    """Same display floor as api/devices.py's device_vulns (shared via display.py in part 6)."""
    if not cfg.include_potential and f.state == VULN_STATE_POTENTIAL:
        return False
    if f.kev:
        return True
    effective = f.cvss_base if f.cvss_base is not None else DEFAULT_CVSS
    return effective >= cfg.min_cvss_display


def _top(counter: Counter, n: int = FACET_LIMIT) -> list[dict]:
    return [{"key": k, "count": c} for k, c in counter.most_common(n)]


def _vendor_product_map(db: Session, pairs: set[tuple[str, str]]) -> dict[tuple[str, str], str]:
    if not pairs:
        return {}
    cve_ids = {p[0] for p in pairs}
    out = {}
    for cve_id, cpe23, vendor_product in db.execute(
        select(VulnCpeMatch.cve_id, VulnCpeMatch.cpe23, VulnCpeMatch.vendor_product)
        .where(VulnCpeMatch.cve_id.in_(cve_ids))
    ):
        out[(cve_id, cpe23)] = vendor_product
    return out


def _feed_staleness(db: Session, cfg: VulnSettings, now: datetime) -> dict:
    """Feed/DB age: oldest `last_synced_at` among ENABLED sources only (decision 4); stale at
    2x sync_interval_hours, same rule as the existing background-job staleness (decision 7)."""
    by_source = dict(db.execute(
        select(VulnFeedState.source, VulnFeedState.last_synced_at).where(VulnFeedState.source.in_(cfg.sources))
    ).all())
    timestamps = [by_source.get(s) for s in cfg.sources]
    oldest = min(timestamps) if timestamps and all(t is not None for t in timestamps) else None
    newest = max((t for t in timestamps if t is not None), default=None)
    threshold_hours = cfg.sync_interval_hours * 2
    stale = oldest is None or (now - oldest) > timedelta(hours=threshold_hours)
    return {
        "oldest_synced_at": oldest, "newest_synced_at": newest,
        "stale": stale, "stale_threshold_hours": threshold_hours,
    }


def _week_index(ts: datetime | None, start: datetime, weeks: int) -> int | None:
    if ts is None or ts < start:
        return None
    return min(weeks - 1, max(0, int((ts - start).days // 7)))


def _weekly_series(db: Session, now: datetime, weeks: int = WEEKS) -> list[dict]:
    """New (first_seen_at) vs resolved (resolved_at, decision 3) vs dismissed (dismissed_at) per
    week, oldest first. A dismissed finding is never counted as resolved even if its device was
    later removed. Visibility: excluded when its device still exists and is mock/archived-hidden;
    kept when the device is gone entirely, so a real resolution is never silently dropped."""
    start = now - timedelta(weeks=weeks)
    lc = VulnFindingLifecycle
    visible_or_gone = or_(Device.id.is_(None), device_visible(db))
    rows = db.execute(
        select(lc.first_seen_at, lc.resolved_at, lc.dismissed_at)
        .outerjoin(Device, Device.uuid == lc.device_uuid)
        .where(visible_or_gone)
    ).all()
    counts = {"new": [0] * weeks, "resolved": [0] * weeks, "dismissed": [0] * weeks}
    for first_seen_at, resolved_at, dismissed_at in rows:
        i = _week_index(first_seen_at, start, weeks)
        if i is not None:
            counts["new"][i] += 1
        if resolved_at is not None and dismissed_at is None:
            i = _week_index(resolved_at, start, weeks)
            if i is not None:
                counts["resolved"][i] += 1
        if dismissed_at is not None:
            i = _week_index(dismissed_at, start, weeks)
            if i is not None:
                counts["dismissed"][i] += 1
    return [
        {"week_start": (start + timedelta(weeks=w)).date().isoformat(),
         "new": counts["new"][w], "resolved": counts["resolved"][w], "dismissed": counts["dismissed"][w]}
        for w in range(weeks)
    ]


def _top_lists(db: Session) -> dict:
    """Top CVEs by device count / top devices by combined score -- a superset of the existing
    `/api/reports/vulnerabilities` shape (adds device_type/network_name), just top 10 instead of
    top 20, so the dashboard and the Reports page vuln cards (decision 5) can share one
    computation without diverging."""
    ok = device_visible(db)
    names = {n.id: n.name for n in db.scalars(select(Network)).all()}
    top_devices = db.scalars(
        select(Device).where(ok, Device.risk_score > 0)
        .order_by(Device.combined_score.desc(), Device.risk_score.desc(), Device.id).limit(TOP_N)
    ).all()
    n_dev = func.count(func.distinct(Device.id))
    cve_rows = db.execute(
        select(Vulnerability.cve_id, Vulnerability.cvss_base, Vulnerability.kev, Vulnerability.epss, n_dev)
        .join(DevicePortVuln, DevicePortVuln.cve_id == Vulnerability.cve_id)
        .join(DevicePort, DevicePort.id == DevicePortVuln.device_port_id)
        .join(Device, Device.id == DevicePort.device_id)
        .where(ok, DevicePortVuln.state != VULN_STATE_DISMISSED)
        .group_by(Vulnerability.cve_id, Vulnerability.cvss_base, Vulnerability.kev, Vulnerability.epss)
        .order_by(Vulnerability.kev.desc(), Vulnerability.cvss_base.desc().nulls_last(), n_dev.desc())
        .limit(TOP_N)
    ).all()
    return {
        "top_devices": [
            {"uuid": d.uuid, "ip": d.current_ip, "hostname": d.hostname, "device_type": d.device_type,
             "network_name": names.get(d.network_id), "exposure_score": d.exposure_score or 0,
             "risk_score": d.risk_score or 0, "combined_score": d.combined_score or 0}
            for d in top_devices
        ],
        "top_cves": [
            {"cve_id": c, "cvss_base": cvss, "kev": bool(kev), "epss": epss, "device_count": int(n)}
            for c, cvss, kev, epss, n in cve_rows
        ],
    }


def _risk_device_levels(db: Session) -> dict[str, int]:
    expr = case(
        (Device.combined_score >= RISK_HIGH_THRESHOLD, "high"),
        (Device.combined_score >= RISK_MEDIUM_THRESHOLD, "medium"),
        else_="low",
    )
    levels = {"high": 0, "medium": 0, "low": 0}
    levels.update({
        k: int(v) for k, v in db.execute(select(expr, func.count(Device.id)).where(device_visible(db)).group_by(expr))
    })
    return levels


def refresh_vuln_summary(db: Session, *, now: datetime) -> dict:
    cfg = get_section(db, VulnSettings)
    findings = [f for f in _load_findings(db) if _visible(f, cfg)]

    severity_counts = Counter(severity_bucket(f.cvss_base) for f in findings)
    state_counts = Counter(f.state for f in findings)
    kev_count = sum(1 for f in findings if f.kev)
    epss_high_count = sum(1 for f in findings if f.epss is not None and f.epss >= cfg.epss_high_threshold)

    pairs = {(f.cve_id, f.matched_cpe) for f in findings if f.matched_cpe}
    vp_map = _vendor_product_map(db, pairs)

    facets = {
        "os": _top(Counter(f.os_name or "unknown" for f in findings)),
        "service": _top(Counter(f.service or "unknown" for f in findings)),
        "port": _top(Counter(f.port for f in findings)),
        "network": _top(Counter(f.network_name or "unassigned" for f in findings)),
        "device_type": _top(Counter(f.device_type or "unknown" for f in findings)),
        "vendor_product": _top(Counter(vp_map.get((f.cve_id, f.matched_cpe), "unknown") for f in findings)),
        "cve_age": {b: 0 for b in AGE_BUCKETS} | dict(Counter(_age_bucket(f.published_at, now) for f in findings)),
        "exposure_duration": {b: 0 for b in AGE_BUCKETS}
        | dict(Counter(_age_bucket(f.first_seen_at, now) for f in findings)),
    }

    result = {
        "generated_at": now,
        "epss_threshold": cfg.epss_high_threshold,
        "severity_counts": {b: int(severity_counts.get(b, 0)) for b in ("critical", "high", "medium", "low")},
        "kev_count": kev_count,
        "epss_high_count": epss_high_count,
        "confirmed_count": int(state_counts.get(VULN_STATE_CONFIRMED, 0)),
        "potential_count": int(state_counts.get(VULN_STATE_POTENTIAL, 0)),
        "risk_device_levels": _risk_device_levels(db),
        "feed": _feed_staleness(db, cfg, now),
        "facets": facets,
        "weekly": _weekly_series(db, now),
        **_top_lists(db),
    }
    _cache[_cache_key(db)] = (time.monotonic() + _CACHE_TTL_SECONDS, result)
    return result


def get_vuln_summary(db: Session, *, now: datetime) -> dict:
    """Read-path for the API: serve the cache if warm, else compute (and cache) once."""
    hit = _cache.get(_cache_key(db))
    if hit is not None and hit[0] > time.monotonic():
        return hit[1]
    return refresh_vuln_summary(db, now=now)


def write_daily_snapshot(db: Session, now: datetime) -> None:
    """Upsert today's local-date global row (network_id=None) plus one row per network, then purge
    rows older than a year (decision 6). NULL network_id isn't deduped by the unique constraint in
    SQL on either dialect, so the global row is get-or-created in Python like the per-network ones.
    """
    cfg = get_section(db, VulnSettings)
    findings = [f for f in _load_findings(db) if _visible(f, cfg)]
    device_rows = db.execute(
        select(Device.network_id, Device.risk_score, Device.combined_score).where(device_visible(db))
    ).all()

    by_network_findings: dict[int | None, list[_Finding]] = defaultdict(list)
    for f in findings:
        by_network_findings[f.network_id].append(f)
    by_network_devices: dict[int | None, list[tuple[int, int]]] = defaultdict(list)
    for network_id, risk, combined in device_rows:
        by_network_devices[network_id].append((risk or 0, combined or 0))

    day = now.astimezone().date()

    def _write_row(network_id: int | None, net_findings: list[_Finding], net_devices: list[tuple[int, int]]) -> None:
        sev = Counter(severity_bucket(f.cvss_base) for f in net_findings)
        state_n = Counter(f.state for f in net_findings)
        row = db.scalar(select(VulnDailySnapshot).where(
            VulnDailySnapshot.snapshot_date == day,
            VulnDailySnapshot.network_id == network_id if network_id is not None
            else VulnDailySnapshot.network_id.is_(None),
        ))
        if row is None:
            row = VulnDailySnapshot(network_id=network_id, snapshot_date=day)
            db.add(row)
        row.critical, row.high = sev.get("critical", 0), sev.get("high", 0)
        row.medium, row.low = sev.get("medium", 0), sev.get("low", 0)
        row.kev_count = sum(1 for f in net_findings if f.kev)
        row.confirmed_count = state_n.get(VULN_STATE_CONFIRMED, 0)
        row.potential_count = state_n.get(VULN_STATE_POTENTIAL, 0)
        row.avg_risk_score = sum(r for r, _c in net_devices) / len(net_devices) if net_devices else None
        row.avg_combined_score = sum(c for _r, c in net_devices) / len(net_devices) if net_devices else None
        row.created_at = now

    all_devices = [pair for pairs in by_network_devices.values() for pair in pairs]
    _write_row(None, findings, all_devices)
    network_ids = set(by_network_findings) | set(by_network_devices)
    network_ids.discard(None)
    for network_id in network_ids:
        _write_row(network_id, by_network_findings.get(network_id, []), by_network_devices.get(network_id, []))

    db.flush()
    cutoff = (now - timedelta(days=SNAPSHOT_RETENTION_DAYS)).date()
    db.execute(delete(VulnDailySnapshot).where(VulnDailySnapshot.snapshot_date < cutoff))


def refresh_after_scan_or_sync(db: Session, *, now: datetime) -> dict:
    """Entry point for the two trigger points (end of a vuln job, end of a feed sync): bring the
    lifecycle table up to date first (the summary's facets/weekly series read it), then recompute
    and cache the summary, then write today's snapshot row(s)."""
    sync_finding_lifecycle(db, now=now)
    invalidate_vuln_summary_cache()
    summary = refresh_vuln_summary(db, now=now)
    write_daily_snapshot(db, now)
    return summary
