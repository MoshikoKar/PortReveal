"""Single computed snapshot backing every vulnerability-dashboard card/facet/chart/top-list.

Everything here is derived from already-stored `device_port_vulns` + the local vuln cache: no
outbound requests. Computed in one pass, cached in-process (same TTL-plus-explicit-invalidate
idiom as settings_store.py's `_cache`), and invalidated whenever a scan or feed sync completes
(core/vuln/runner.py, core/vuln/sync.py call `refresh_after_scan_or_sync`).
"""

from __future__ import annotations

import time
from collections import Counter, defaultdict
from dataclasses import dataclass, fields
from datetime import date, datetime, timedelta, timezone

from sqlalchemy import and_, case, delete, func, or_, select
from sqlalchemy.orm import Session

from ...models import (
    SCAN_COMPLETED,
    SCAN_PARTIAL,
    VULN_STATE_CONFIRMED,
    VULN_STATE_DISMISSED,
    VULN_STATE_POTENTIAL,
    Device,
    DevicePort,
    DevicePortVuln,
    Network,
    Scan,
    VulnCpeMatch,
    VulnDailySnapshot,
    Vulnerability,
    VulnFeedState,
    VulnFindingLifecycle,
)
from ...settings_store import VulnSettings, get_section
from ..mockdata import device_visible
from .buckets import severity_bucket
from .display import is_visible, normalize_cve_id
from .filters import NETWORK_UNASSIGNED, FindingFilters, filters_active, search_term
from .lifecycle import sync_finding_lifecycle
from .score import RISK_HIGH_THRESHOLD, RISK_MEDIUM_THRESHOLD

TOP_N = 10
WEEKS = 12
SNAPSHOT_RETENTION_DAYS = 365
SNAPSHOT_DECIMATE_AFTER_DAYS = 90  # rows older than this collapse to one point per week at read time
AGE_BUCKETS = ("under_30d", "30_90d", "90_365d", "over_365d", "unknown")
FACET_LIMIT = 100  # the UI shows 10 per facet and pages through the rest behind "See all"

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
    device_uuid: str
    device_ip: str
    device_hostname: str | None
    device_vendor: str | None
    network_id: int | None
    network_name: str | None
    os_name: str | None
    device_type: str | None
    port: int
    protocol: str
    service: str | None
    product: str | None
    cve_id: str
    cve_summary: str | None
    state: str
    matched_cpe: str | None
    matched_at: datetime | None
    cvss_base: float | None
    kev: bool
    epss: float | None
    published_at: datetime | None
    first_seen_at: datetime | None
    combined_score: int


def _load_findings(db: Session, *, include_dismissed: bool = False) -> list[_Finding]:
    """Every visible finding, with its lifecycle first-seen date joined in.

    The lifecycle join matches on (device uuid, port, protocol, cve_id) -- its natural identity,
    since it has no FK to device_port_vulns -- and only resolves once `sync_finding_lifecycle` has
    run for the current state, which callers must do first. Dismissed rows are omitted unless
    ``include_dismissed`` (summary filtered with ``state=dismissed`` or free-text ``q``).
    """
    cond = [device_visible(db)]
    if not include_dismissed:
        cond.append(DevicePortVuln.state != VULN_STATE_DISMISSED)
    rows = db.execute(
        select(
            Device.uuid,
            Device.current_ip,
            Device.hostname,
            Device.vendor,
            Device.network_id,
            Network.name,
            Device.os_name,
            Device.device_type,
            DevicePort.port,
            DevicePort.protocol,
            DevicePort.service,
            DevicePort.product,
            DevicePortVuln.cve_id,
            Vulnerability.summary,
            DevicePortVuln.state,
            DevicePortVuln.matched_cpe,
            DevicePortVuln.matched_at,
            Vulnerability.cvss_base,
            Vulnerability.kev,
            Vulnerability.epss,
            Vulnerability.published_at,
            VulnFindingLifecycle.first_seen_at,
            Device.combined_score,
        )
        .join(DevicePort, DevicePort.device_id == Device.id)
        .join(DevicePortVuln, DevicePortVuln.device_port_id == DevicePort.id)
        .join(Vulnerability, Vulnerability.cve_id == DevicePortVuln.cve_id)
        .outerjoin(Network, Network.id == Device.network_id)
        .outerjoin(
            VulnFindingLifecycle,
            and_(
                VulnFindingLifecycle.device_uuid == Device.uuid,
                VulnFindingLifecycle.port == DevicePort.port,
                VulnFindingLifecycle.protocol == DevicePort.protocol,
                VulnFindingLifecycle.cve_id == DevicePortVuln.cve_id,
            ),
        )
        .where(*cond)
    ).all()
    return [
        _Finding(
            *r[:-1],
            combined_score=int(r[-1] or 0),
        )
        for r in rows
    ]


def _parse_port_query(term: str) -> tuple[str | None, int | None]:
    """Same split as the list API: ``port:N`` → port-only; pure digits → port + text."""
    lower = term.lower()
    if lower.startswith("port:"):
        raw = term[5:].strip()
        if raw.isdigit():
            port_num = int(raw)
            if 1 <= port_num <= 65535:
                return None, port_num
        return term, None
    if term.isdigit():
        port_num = int(term)
        if 1 <= port_num <= 65535:
            return term, port_num
    return term, None


def _finding_matches_search(f: _Finding, term: str, vp_map: dict[tuple[str, str], str]) -> bool:
    """In-memory counterpart of the list API's ``_search_match_cond``."""
    text, exact_port = _parse_port_query(term)
    if exact_port is not None and f.port == exact_port and text is None:
        return True
    if text is None:
        return exact_port is not None and f.port == exact_port
    needle = text.lower()
    haystacks = [
        f.cve_id,
        f.cve_summary,
        f.device_ip,
        f.device_hostname,
        f.device_vendor,
        f.product,
        f.service,
        f.matched_cpe,
        vp_map.get((f.cve_id, f.matched_cpe or "")),
    ]
    if any(h and needle in h.lower() for h in haystacks):
        return True
    if exact_port is not None and f.port == exact_port:
        return True
    return False


def _visible(f: _Finding, cfg: VulnSettings) -> bool:
    return is_visible(f.state, f.kev, f.cvss_base, cfg)


def _new_since_cutoff(db: Session, kind: str) -> datetime | None:
    if kind == "scan":
        return db.scalar(
            select(Scan.finished_at)
            .where(Scan.status.in_((SCAN_COMPLETED, SCAN_PARTIAL)), Scan.finished_at.isnot(None))
            .order_by(Scan.finished_at.desc())
            .limit(1)
        )
    cfg = get_section(db, VulnSettings)
    timestamps = list(
        db.scalars(
            select(VulnFeedState.last_synced_at).where(
                VulnFeedState.source.in_(cfg.sources),
                VulnFeedState.last_synced_at.isnot(None),
            )
        )
    )
    return max(timestamps) if timestamps else None


def _cpe_match_exists_keys(vp_map: dict[tuple[str, str], str], f: _Finding, vendor: str | None, product: str | None) -> bool:
    """Match the list API's vendor/product facet keys against the summary's CPE map."""
    if vendor == "unknown" and not product:
        return not f.matched_cpe or (f.cve_id, f.matched_cpe) not in vp_map
    key = vp_map.get((f.cve_id, f.matched_cpe or ""))
    if key is None:
        return False
    if vendor and product:
        return key == f"{vendor}:{product}"
    if vendor:
        return key.startswith(f"{vendor}:")
    if product:
        return key.endswith(f":{product}")
    return True


def _apply_finding_filters(
    findings: list[_Finding],
    db: Session,
    filters: FindingFilters | None,
    now: datetime,
    vp_map: dict[tuple[str, str], str],
    *,
    cfg: VulnSettings | None = None,
) -> list[_Finding]:
    """Apply the same FindingFilters as GET /api/vulns to the in-memory summary rows."""
    if not filters_active(filters):
        return findings
    assert filters is not None
    out = findings
    term = search_term(filters)
    if term is not None:
        out = [f for f in out if _finding_matches_search(f, term, vp_map)]
        if filters.only_hidden and cfg is not None:
            out = [f for f in out if not _visible(f, cfg)]
    if filters.state:
        out = [f for f in out if f.state == filters.state]
    if filters.severity:
        out = [f for f in out if severity_bucket(f.cvss_base) == filters.severity]
    if filters.kev is not None:
        out = [f for f in out if f.kev is filters.kev]
    if filters.epss_min is not None:
        out = [f for f in out if f.epss is not None and f.epss >= filters.epss_min]
    if filters.network_id is not None:
        if filters.network_id == NETWORK_UNASSIGNED:
            out = [f for f in out if f.network_id is None]
        else:
            nid = int(filters.network_id)
            out = [f for f in out if f.network_id == nid]
    if filters.service is not None:
        out = [f for f in out if f.service == filters.service]
    if filters.port is not None:
        out = [f for f in out if f.port == filters.port]
    if filters.os_name is not None:
        out = [f for f in out if f.os_name == filters.os_name]
    if filters.device_type is not None:
        out = [f for f in out if f.device_type == filters.device_type]
    if filters.cve_age is not None:
        out = [f for f in out if _age_bucket(f.published_at, now) == filters.cve_age]
    if filters.exposure_duration is not None:
        out = [f for f in out if _age_bucket(f.first_seen_at, now) == filters.exposure_duration]
    if filters.risk_band is not None:
        if filters.risk_band == "high":
            out = [f for f in out if f.combined_score >= RISK_HIGH_THRESHOLD]
        elif filters.risk_band == "medium":
            out = [f for f in out if RISK_MEDIUM_THRESHOLD <= f.combined_score < RISK_HIGH_THRESHOLD]
        else:
            out = [f for f in out if f.combined_score < RISK_MEDIUM_THRESHOLD]
    if filters.vendor is not None or filters.product is not None:
        out = [f for f in out if _cpe_match_exists_keys(vp_map, f, filters.vendor, filters.product)]
    if filters.cve_id is not None:
        want = normalize_cve_id(filters.cve_id)
        out = [f for f in out if f.cve_id == want]
    if filters.device_uuid is not None:
        out = [f for f in out if f.device_uuid == filters.device_uuid]
    if filters.new_since is not None:
        cutoff = _new_since_cutoff(db, filters.new_since)
        if cutoff is None:
            out = []
        else:

            def _ts(f: _Finding) -> datetime | None:
                return f.first_seen_at or f.matched_at

            out = [f for f in out if (ts := _ts(f)) is not None and ts >= cutoff]
    return out


def _top(counter: Counter, n: int = FACET_LIMIT) -> list[dict]:
    return [{"key": k, "count": c} for k, c in counter.most_common(n)]


def _network_facet(findings: list[_Finding], n: int = FACET_LIMIT) -> list[dict]:
    """Keyed by network_id (not name): GET /api/vulns?network_id=... filters on what this facet
    shows. `key` is the string ``unassigned`` for devices with no network (accepted by the list
    API); `label` is always the display name."""
    counts: Counter = Counter()
    labels: dict[int | None, str] = {}
    for f in findings:
        counts[f.network_id] += 1
        labels[f.network_id] = f.network_name or "Unassigned"
    return [
        {"key": network_id if network_id is not None else "unassigned", "label": labels[network_id], "count": count}
        for network_id, count in counts.most_common(n)
    ]


def _vendor_product_map(db: Session, pairs: set[tuple[str, str]]) -> dict[tuple[str, str], str]:
    if not pairs:
        return {}
    cve_ids = {p[0] for p in pairs}
    out = {}
    for cve_id, cpe23, vendor_product in db.execute(
        select(VulnCpeMatch.cve_id, VulnCpeMatch.cpe23, VulnCpeMatch.vendor_product).where(VulnCpeMatch.cve_id.in_(cve_ids))
    ):
        out[(cve_id, cpe23)] = vendor_product
    return out


def _feed_staleness(db: Session, cfg: VulnSettings, now: datetime) -> dict:
    """Feed/DB age: oldest `last_synced_at` among ENABLED sources only (decision 4); stale at
    2x sync_interval_hours, same rule as the existing background-job staleness (decision 7)."""
    by_source = dict(
        db.execute(select(VulnFeedState.source, VulnFeedState.last_synced_at).where(VulnFeedState.source.in_(cfg.sources))).all()
    )
    timestamps = [by_source.get(s) for s in cfg.sources]
    oldest = min(timestamps) if timestamps and all(t is not None for t in timestamps) else None
    newest = max((t for t in timestamps if t is not None), default=None)
    threshold_hours = cfg.sync_interval_hours * 2
    stale = oldest is None or (now - oldest) > timedelta(hours=threshold_hours)
    return {
        "oldest_synced_at": oldest,
        "newest_synced_at": newest,
        "stale": stale,
        "stale_threshold_hours": threshold_hours,
    }


def _week_index(ts: datetime | None, start: datetime, weeks: int) -> int | None:
    if ts is None or ts < start:
        return None
    return min(weeks - 1, max(0, int((ts - start).days // 7)))


def _weekly_series(
    db: Session,
    now: datetime,
    weeks: int = WEEKS,
    *,
    filters: FindingFilters | None = None,
    findings: list[_Finding] | None = None,
) -> list[dict]:
    """New (first_seen_at) vs resolved (resolved_at, decision 3) vs dismissed (dismissed_at) per
    week, oldest first. A dismissed finding is never counted as resolved even if its device was
    later removed. Visibility: excluded when its device still exists and is mock/archived-hidden;
    kept when the device is gone entirely, so a real resolution is never silently dropped.

    When page filters are active, ``new`` comes from the already-filtered findings list (matches
    KPI cards). Resolved/dismissed use the lifecycle table joined to Vulnerability/Device with
    kev/severity/epss/network/device/cve/os/device_type. Port/service/vendor/product/state/age/
    risk_band/new_since still shape ``new`` via findings but may not apply to historical resolved
    rows.
    """
    start = now - timedelta(weeks=weeks)
    counts = {"new": [0] * weeks, "resolved": [0] * weeks, "dismissed": [0] * weeks}
    lc = VulnFindingLifecycle
    visible_or_gone = or_(Device.id.is_(None), device_visible(db))

    if filters_active(filters) and findings is not None:
        assert filters is not None
        for f in findings:
            i = _week_index(f.first_seen_at or f.matched_at, start, weeks)
            if i is not None:
                counts["new"][i] += 1
        cond = [visible_or_gone]
        if filters.network_id == NETWORK_UNASSIGNED:
            cond.append(lc.network_id.is_(None))
        elif filters.network_id is not None:
            cond.append(lc.network_id == int(filters.network_id))
        if filters.device_uuid is not None:
            cond.append(lc.device_uuid == filters.device_uuid)
        if filters.cve_id is not None:
            cond.append(lc.cve_id == normalize_cve_id(filters.cve_id))
        if filters.kev is not None:
            cond.append(Vulnerability.kev.is_(filters.kev))
        if filters.epss_min is not None:
            cond.append(and_(Vulnerability.epss.isnot(None), Vulnerability.epss >= filters.epss_min))
        if filters.os_name is not None:
            cond.append(Device.os_name == filters.os_name)
        if filters.device_type is not None:
            cond.append(Device.device_type == filters.device_type)
        rows = db.execute(
            select(lc.resolved_at, lc.dismissed_at, Vulnerability.cvss_base)
            .outerjoin(Device, Device.uuid == lc.device_uuid)
            .outerjoin(Vulnerability, Vulnerability.cve_id == lc.cve_id)
            .where(*cond)
        ).all()
        for resolved_at, dismissed_at, cvss_base in rows:
            if filters.severity is not None and severity_bucket(cvss_base) != filters.severity:
                continue
            if resolved_at is not None and dismissed_at is None:
                i = _week_index(resolved_at, start, weeks)
                if i is not None:
                    counts["resolved"][i] += 1
            if dismissed_at is not None:
                i = _week_index(dismissed_at, start, weeks)
                if i is not None:
                    counts["dismissed"][i] += 1
    else:
        rows = db.execute(
            select(lc.first_seen_at, lc.resolved_at, lc.dismissed_at)
            .outerjoin(Device, Device.uuid == lc.device_uuid)
            .where(visible_or_gone)
        ).all()
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
        {
            "week_start": (start + timedelta(weeks=w)).date().isoformat(),
            "new": counts["new"][w],
            "resolved": counts["resolved"][w],
            "dismissed": counts["dismissed"][w],
        }
        for w in range(weeks)
    ]


# Snapshot history is pre-aggregated per network (or global); only network_id can reshape it.
_SNAPSHOT_HONORED_FILTERS = frozenset({"network_id"})


def _snapshot_trend_note(filters: FindingFilters | None) -> str | None:
    """Explain when trend charts cannot honor every active filter."""
    if not filters_active(filters):
        return None
    assert filters is not None
    ignored: list[str] = []
    for f in fields(FindingFilters):
        if f.name in _SNAPSHOT_HONORED_FILTERS:
            continue
        if f.name == "q":
            if search_term(filters) is not None:
                ignored.append("q")
            continue
        if f.name == "only_hidden":
            # Bool default False is not None — only list when the flag is actually on.
            if filters.only_hidden:
                ignored.append("only_hidden")
            continue
        if getattr(filters, f.name) is not None:
            ignored.append(f.name)
    if not ignored:
        return None
    return f"Open-vulns / risk trend charts use network-scoped daily snapshots only; not re-filtered by: {', '.join(ignored)}."


def _top_lists(db: Session, findings: list[_Finding] | None = None) -> dict:
    """Top CVEs by device count / top devices by combined score -- a superset of the existing
    `/api/reports/vulnerabilities` shape (adds device_type/network_name), just top 10 instead of
    top 20, so the dashboard and the Reports page vuln cards (decision 5) can share one
    computation without diverging.

    When ``findings`` is provided (filtered summary), derive both lists from that set so cards
    match the active page filters.
    """
    if findings is not None:
        return _top_lists_from_findings(db, findings)
    ok = device_visible(db)
    names = {n.id: n.name for n in db.scalars(select(Network)).all()}
    top_devices = db.scalars(
        select(Device)
        .where(ok, Device.risk_score > 0)
        .order_by(Device.combined_score.desc(), Device.risk_score.desc(), Device.id)
        .limit(TOP_N)
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
            {
                "uuid": d.uuid,
                "ip": d.current_ip,
                "hostname": d.hostname,
                "device_type": d.device_type,
                "network_id": d.network_id,
                "network_name": names.get(d.network_id),
                "exposure_score": d.exposure_score or 0,
                "risk_score": d.risk_score or 0,
                "combined_score": d.combined_score or 0,
            }
            for d in top_devices
        ],
        "top_cves": [
            {"cve_id": c, "cvss_base": cvss, "kev": bool(kev), "epss": epss, "device_count": int(n)}
            for c, cvss, kev, epss, n in cve_rows
        ],
    }


def _top_lists_from_findings(db: Session, findings: list[_Finding]) -> dict:
    """Top devices / CVEs derived from an already-filtered finding set."""
    names = {n.id: n.name for n in db.scalars(select(Network)).all()}
    by_device: dict[str, _Finding] = {}
    device_risk: Counter = Counter()
    for f in findings:
        by_device[f.device_uuid] = f
        device_risk[f.device_uuid] += 1
    # Prefer devices that appear in findings; order by combined_score then finding count.
    scored = sorted(
        by_device.values(),
        key=lambda f: (f.combined_score, device_risk[f.device_uuid]),
        reverse=True,
    )[:TOP_N]
    uuids = [f.device_uuid for f in scored]
    devices = {d.uuid: d for d in db.scalars(select(Device).where(Device.uuid.in_(uuids))).all()} if uuids else {}
    top_devices = []
    for f in scored:
        d = devices.get(f.device_uuid)
        if d is None:
            continue
        top_devices.append(
            {
                "uuid": d.uuid,
                "ip": d.current_ip,
                "hostname": d.hostname,
                "device_type": d.device_type,
                "network_id": d.network_id,
                "network_name": names.get(d.network_id),
                "exposure_score": d.exposure_score or 0,
                "risk_score": d.risk_score or 0,
                "combined_score": d.combined_score or 0,
            }
        )
    cve_devices: dict[str, set[str]] = defaultdict(set)
    cve_meta: dict[str, _Finding] = {}
    for f in findings:
        cve_devices[f.cve_id].add(f.device_uuid)
        cve_meta[f.cve_id] = f
    top_cves = sorted(
        cve_meta.values(),
        key=lambda f: (f.kev, f.cvss_base or 0, len(cve_devices[f.cve_id])),
        reverse=True,
    )[:TOP_N]
    return {
        "top_devices": top_devices,
        "top_cves": [
            {
                "cve_id": f.cve_id,
                "cvss_base": f.cvss_base,
                "kev": bool(f.kev),
                "epss": f.epss,
                "device_count": len(cve_devices[f.cve_id]),
            }
            for f in top_cves
        ],
    }


def _seen_at(f: _Finding) -> datetime | None:
    """Lifecycle first-seen when present; otherwise the match row's matched_at (cold path before
    sync_finding_lifecycle has run)."""
    return f.first_seen_at or f.matched_at


def _new_finding_row(f: _Finding) -> dict:
    return {
        "cve_id": f.cve_id,
        "device_uuid": f.device_uuid,
        "device_ip": f.device_ip,
        "cvss_base": f.cvss_base,
        "kev": f.kev,
        "first_seen_at": _seen_at(f),
    }


def _new_lists(db: Session, findings: list[_Finding], feed: dict) -> dict:
    """Top-N findings first seen at/after the last completed scan, and at/after the newest enabled
    feed sync ("new vulns since last scan / last DB update" from the spec)."""
    last_scan = db.scalar(
        select(Scan.finished_at)
        .where(Scan.status.in_((SCAN_COMPLETED, SCAN_PARTIAL)), Scan.finished_at.isnot(None))
        .order_by(Scan.finished_at.desc())
        .limit(1)
    )
    last_db = feed.get("newest_synced_at")

    def since(cutoff: datetime | None) -> list[dict]:
        if cutoff is None:
            return []
        rows = [f for f in findings if (ts := _seen_at(f)) is not None and ts >= cutoff]
        rows.sort(key=lambda f: _seen_at(f) or datetime.min.replace(tzinfo=timezone.utc), reverse=True)
        return [_new_finding_row(f) for f in rows[:TOP_N]]

    return {
        "new_since_last_scan": since(last_scan),
        "new_since_last_db_update": since(last_db),
    }


def _severity_by_network(findings: list[_Finding]) -> list[dict]:
    """Network x severity matrix ("Severity by network" in the UI -- distinct from the existing
    IP-grid exposure heatmap at /api/reports/heatmap, which this is not named after to avoid
    confusion). `network_id` is None for the unassigned-devices row."""
    by_network: dict[int | None, Counter] = defaultdict(Counter)
    names: dict[int | None, str] = {}
    for f in findings:
        by_network[f.network_id][severity_bucket(f.cvss_base)] += 1
        names[f.network_id] = f.network_name or "Unassigned"
    return [
        {
            "network_id": network_id,
            "network": names[network_id],
            "critical": counts.get("critical", 0),
            "high": counts.get("high", 0),
            "medium": counts.get("medium", 0),
            "low": counts.get("low", 0),
        }
        for network_id, counts in sorted(by_network.items(), key=lambda kv: -sum(kv[1].values()))
    ]


def _decimate_weekly(rows: list[VulnDailySnapshot]) -> list[VulnDailySnapshot]:
    """One row per ISO week (the latest day seen that week): rows are already date-ordered, so the
    later assignment for a given week naturally wins."""
    by_week: dict[date, VulnDailySnapshot] = {}
    for r in rows:
        week_start = r.snapshot_date - timedelta(days=r.snapshot_date.weekday())
        by_week[week_start] = r
    return [by_week[w] for w in sorted(by_week)]


def _snapshot_trend(db: Session, now: datetime, *, network_id: str | None = None) -> list[dict]:
    """Daily snapshot history for the "vuln count over time by severity" and "average network risk
    score over time" trend charts: full resolution for the last 90 days, one point per week beyond
    that (decision 6), read-time only -- no second physical table.

    Default is the global row (``network_id`` NULL). When the page is scoped to a network, read
    that network's snapshot series instead (unassigned has no dedicated snapshot rows → empty).
    """
    if network_id == NETWORK_UNASSIGNED:
        rows = []
    elif network_id is not None:
        rows = list(
            db.scalars(
                select(VulnDailySnapshot)
                .where(VulnDailySnapshot.network_id == int(network_id))
                .order_by(VulnDailySnapshot.snapshot_date)
            )
        )
    else:
        rows = list(
            db.scalars(
                select(VulnDailySnapshot).where(VulnDailySnapshot.network_id.is_(None)).order_by(VulnDailySnapshot.snapshot_date)
            )
        )
    cutoff = (now - timedelta(days=SNAPSHOT_DECIMATE_AFTER_DAYS)).date()
    recent = [r for r in rows if r.snapshot_date >= cutoff]
    old = _decimate_weekly([r for r in rows if r.snapshot_date < cutoff])
    return [
        {
            "date": r.snapshot_date.isoformat(),
            "critical": r.critical,
            "high": r.high,
            "medium": r.medium,
            "low": r.low,
            "avg_risk_score": r.avg_risk_score,
            "avg_combined_score": r.avg_combined_score,
        }
        for r in old + recent
    ]


def _risk_device_levels(db: Session, findings: list[_Finding] | None = None) -> dict[str, int]:
    """Device counts by combined-score band - same cut points as GET /api/vulns?risk_band=.

    When ``findings`` is provided (any active page filter), count distinct devices in that set
    so the High-risk devices KPI matches the filtered findings. Unfiltered: all visible devices.
    """
    if findings is not None:
        levels = {"high": 0, "medium": 0, "low": 0}
        seen: set[str] = set()
        for f in findings:
            if f.device_uuid in seen:
                continue
            seen.add(f.device_uuid)
            if f.combined_score >= RISK_HIGH_THRESHOLD:
                levels["high"] += 1
            elif f.combined_score >= RISK_MEDIUM_THRESHOLD:
                levels["medium"] += 1
            else:
                levels["low"] += 1
        return levels
    expr = case(
        (Device.combined_score >= RISK_HIGH_THRESHOLD, "high"),
        (Device.combined_score >= RISK_MEDIUM_THRESHOLD, "medium"),
        else_="low",
    )
    levels = {"high": 0, "medium": 0, "low": 0}
    levels.update(
        {k: int(v) for k, v in db.execute(select(expr, func.count(Device.id)).where(device_visible(db)).group_by(expr))}
    )
    return levels


def refresh_vuln_summary(db: Session, *, now: datetime, filters: FindingFilters | None = None) -> dict:
    cfg = get_section(db, VulnSettings)
    searching = search_term(filters) is not None
    include_dismissed = searching or (filters is not None and filters.state == VULN_STATE_DISMISSED)
    loaded = _load_findings(db, include_dismissed=include_dismissed)
    # Vendor/product map needs the pre-filter CPE pairs so facet keys stay consistent with the list API.
    pairs_all = {(f.cve_id, f.matched_cpe) for f in loaded if f.matched_cpe}
    vp_map = _vendor_product_map(db, pairs_all)

    if filters is not None and filters.state:
        findings = [f for f in loaded if f.state == filters.state]
    elif searching:
        # Free-text search lifts the display floor (same as GET /api/vulns?q=…).
        findings = list(loaded)
    else:
        findings = [f for f in loaded if _visible(f, cfg)]
    findings = _apply_finding_filters(findings, db, filters, now, vp_map, cfg=cfg)

    severity_counts = Counter(severity_bucket(f.cvss_base) for f in findings)
    state_counts = Counter(f.state for f in findings)
    kev_count = sum(1 for f in findings if f.kev)
    epss_high_count = sum(1 for f in findings if f.epss is not None and f.epss >= cfg.epss_high_threshold)

    facets = {
        "os": _top(Counter(f.os_name or "unknown" for f in findings)),
        "service": _top(Counter(f.service or "unknown" for f in findings)),
        "port": _top(Counter(f.port for f in findings)),
        "network": _network_facet(findings),
        "device_type": _top(Counter(f.device_type or "unknown" for f in findings)),
        "vendor_product": _top(Counter(vp_map.get((f.cve_id, f.matched_cpe), "unknown") for f in findings)),
        "cve_age": {b: 0 for b in AGE_BUCKETS} | dict(Counter(_age_bucket(f.published_at, now) for f in findings)),
        "exposure_duration": {b: 0 for b in AGE_BUCKETS} | dict(Counter(_age_bucket(f.first_seen_at, now) for f in findings)),
    }
    feed = _feed_staleness(db, cfg, now)
    net_scope = filters.network_id if filters else None
    filtered = filters_active(filters)

    result = {
        "generated_at": now,
        "epss_threshold": cfg.epss_high_threshold,
        "severity_counts": {b: int(severity_counts.get(b, 0)) for b in ("critical", "high", "medium", "low", "unknown")},
        "kev_count": kev_count,
        "epss_high_count": epss_high_count,
        "confirmed_count": int(state_counts.get(VULN_STATE_CONFIRMED, 0)),
        "potential_count": int(state_counts.get(VULN_STATE_POTENTIAL, 0)),
        "findings_total": len(findings),
        "risk_device_levels": _risk_device_levels(db, findings if filtered else None),
        "feed": feed,
        "facets": facets,
        "severity_by_network": _severity_by_network(findings),
        "weekly": _weekly_series(db, now, filters=filters, findings=findings if filtered else None),
        "snapshot_trend": _snapshot_trend(db, now, network_id=net_scope),
        "snapshot_trend_note": _snapshot_trend_note(filters),
        **_top_lists(db, findings if filtered else None),
        **_new_lists(db, findings, feed),
    }
    # Only the unfiltered snapshot is cached; filtered views recompute (and leave the cache alone).
    if not filtered:
        _cache[_cache_key(db)] = (time.monotonic() + _CACHE_TTL_SECONDS, result)
    return result


def get_vuln_summary(db: Session, *, now: datetime, filters: FindingFilters | None = None) -> dict:
    """Read-path for the API: serve the cache if warm (unfiltered only), else compute once."""
    if not filters_active(filters):
        hit = _cache.get(_cache_key(db))
        if hit is not None and hit[0] > time.monotonic():
            return hit[1]
        return refresh_vuln_summary(db, now=now, filters=None)
    return refresh_vuln_summary(db, now=now, filters=filters)


def write_daily_snapshot(db: Session, now: datetime) -> None:
    """Upsert today's local-date global row (network_id=None) plus one row per network, then purge
    rows older than a year (decision 6). NULL network_id isn't deduped by the unique constraint in
    SQL on either dialect, so the global row is get-or-created in Python like the per-network ones.
    """
    cfg = get_section(db, VulnSettings)
    findings = [f for f in _load_findings(db) if _visible(f, cfg)]
    device_rows = db.execute(select(Device.network_id, Device.risk_score, Device.combined_score).where(device_visible(db))).all()

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
        row = db.scalar(
            select(VulnDailySnapshot).where(
                VulnDailySnapshot.snapshot_date == day,
                VulnDailySnapshot.network_id == network_id if network_id is not None else VulnDailySnapshot.network_id.is_(None),
            )
        )
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
