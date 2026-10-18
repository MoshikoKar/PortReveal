"""Weekly feed sync: NVD, CISA KEV, FIRST EPSS -- inbound-only downloads into the local cache.

Privacy (spec sections 5.2-5.3): the only network traffic here is an HTTP GET of a public data
file or API page. No device, port, service or network information is ever included in a request;
every function below only reads a response body that was already handed to it.

`fetch` is injectable everywhere a request is made, so this module can be fully unit-tested
without any network access (and so an offline deployment can be driven from a CLI import instead).
"""
from __future__ import annotations

import csv
import gzip
import json
import logging
import threading
import time
from collections.abc import Callable
from datetime import datetime, timedelta, timezone

import httpx
from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from ...models import Vulnerability, VulnCpeMatch, VulnFeedState
from ...security import decrypt_secret
from ...settings_store import VulnSettings
from .match import cpe_vendor_product, normalize_cpe

log = logging.getLogger(__name__)

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"

NVD_WINDOW_DAYS = 120  # NVD API hard limit on the lastMod* window size
NVD_PAGE_SIZE = 2000
NVD_RATE_DELAY_NO_KEY = 6.5  # keep well under 5 requests / 30s
NVD_RATE_DELAY_WITH_KEY = 0.7  # keep well under 50 requests / 30s
# First run / empty cache: look back far enough that nothing plausibly-relevant is missed. A public
# JSON mirror (e.g. fkie-cad/nvd-json-data-feeds) avoids the resulting high page count on a fresh
# install; this module intentionally does not depend on one, so the very first sync on an empty,
# populous cache runs for a while in the background. The CLI "vuln-import" offline path (spec 5.3
# bullet 9) is the recommended route for a fast first load, especially on a disconnected network.
FULL_SYNC_LOOKBACK_DAYS = 3650

Fetcher = Callable[[str, dict | None, dict | None], bytes]


def _default_fetch(url: str, params: dict | None = None, headers: dict | None = None) -> bytes:
    resp = httpx.get(url, params=params, headers=headers, timeout=30.0, follow_redirects=True)
    resp.raise_for_status()
    return resp.content


def _parse_dt(raw: str | None) -> datetime | None:
    if not raw:
        return None
    try:
        dt = datetime.fromisoformat(raw)
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _parse_date(raw: str | None) -> datetime | None:
    if not raw:
        return None
    try:
        return datetime.strptime(raw[:10], "%Y-%m-%d").replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def _pick_cvss(cve: dict) -> tuple[float | None, str | None, str | None]:
    metrics = cve.get("metrics") or {}
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        items = metrics.get(key) or []
        if not items:
            continue
        data = items[0].get("cvssData") or {}
        score = data.get("baseScore")
        if score is None:
            continue
        vector = data.get("vectorString")
        severity = data.get("baseSeverity") or items[0].get("baseSeverity")
        return float(score), vector, severity
    return None, None, None


def _parse_cve_item(item: dict) -> tuple[dict | None, list[dict]]:
    """One NVD API 2.0 `vulnerabilities[]` entry -> (Vulnerability fields, [VulnCpeMatch fields])."""
    cve = item.get("cve") or {}
    cve_id = cve.get("id")
    if not cve_id:
        return None, []
    score, vector, severity = _pick_cvss(cve)
    summary = next(
        (d.get("value") for d in cve.get("descriptions") or [] if d.get("lang") == "en" and d.get("value")), None
    )
    matches: list[dict] = []
    for config in cve.get("configurations") or []:
        for node in config.get("nodes") or []:
            for m in node.get("cpeMatch") or []:
                if not m.get("vulnerable", True):
                    continue
                criteria = m.get("criteria")
                if not criteria:
                    continue
                norm = normalize_cpe(criteria)
                if not norm:
                    continue
                vp = cpe_vendor_product(norm)
                if not vp:
                    continue
                matches.append({
                    "cpe23": norm[:255],
                    "vendor_product": f"{vp[0]}:{vp[1]}"[:200],
                    "version_start": (m.get("versionStartIncluding") or m.get("versionStartExcluding") or None),
                    "version_start_incl": "versionStartIncluding" in m,
                    "version_end": (m.get("versionEndIncluding") or m.get("versionEndExcluding") or None),
                    "version_end_excl": "versionEndExcluding" in m,
                })
    data = {
        "cve_id": cve_id,
        "cvss_base": score,
        "cvss_vector": vector,
        "severity": severity.lower() if severity else None,
        "published_at": _parse_dt(cve.get("published")),
        "last_modified": _parse_dt(cve.get("lastModified")),
        "summary": (summary or "")[:5000] or None,
    }
    return data, matches


def upsert_cve(db: Session, data: dict, matches: list[dict]) -> None:
    row = db.get(Vulnerability, data["cve_id"])
    if row is None:
        row = Vulnerability(cve_id=data["cve_id"])
        db.add(row)
    row.cvss_base = data["cvss_base"]
    row.cvss_vector = data["cvss_vector"]
    row.severity = data["severity"]
    row.published_at = data["published_at"]
    row.last_modified = data["last_modified"]
    row.summary = data["summary"]
    db.flush()  # the CVE row must exist before vuln_cpe_match rows can reference it
    db.execute(delete(VulnCpeMatch).where(VulnCpeMatch.cve_id == data["cve_id"]))
    for m in matches:
        db.add(VulnCpeMatch(cve_id=data["cve_id"], **m))
    # This session has autoflush off (app.db.SessionLocal): a plain `select(VulnCpeMatch)` run by a
    # caller right after upsert_cve (e.g. match.py, in the same sync-and-rescore pass) would
    # otherwise miss these pending rows entirely.
    db.flush()


def _update_feed_state(db: Session, source: str, now: datetime, cursor: datetime | None,
                       count: int, error: str | None) -> None:
    row = db.get(VulnFeedState, source)
    if row is None:
        row = VulnFeedState(source=source, record_count=0)
        db.add(row)
    row.last_synced_at = now
    if cursor is not None:
        row.last_modified_cursor = cursor.isoformat()
    row.record_count = count
    row.last_error = error


def sync_nvd(db: Session, cfg: VulnSettings, *, fetch: Fetcher | None = None,
            now: datetime | None = None, sleep: Callable[[float], None] = time.sleep) -> dict:
    """Incremental NVD sync: resumes from the last `lastModified` cursor seen, or looks back
    `FULL_SYNC_LOOKBACK_DAYS` on an empty cache. Windows are capped to the API's 120-day limit."""
    fetch = fetch or _default_fetch
    now = now or datetime.now(timezone.utc)
    state = db.get(VulnFeedState, "nvd")
    cursor_start = _parse_dt(state.last_modified_cursor) if state and state.last_modified_cursor else None
    window_start = cursor_start or (now - timedelta(days=FULL_SYNC_LOOKBACK_DAYS))
    api_key = decrypt_secret(cfg.nvd_api_key_enc)
    delay = NVD_RATE_DELAY_WITH_KEY if api_key else NVD_RATE_DELAY_NO_KEY
    headers = {"apiKey": api_key} if api_key else None

    count = 0
    latest_modified = cursor_start
    error: str | None = None
    cursor = window_start
    try:
        while cursor < now:
            window_end = min(cursor + timedelta(days=NVD_WINDOW_DAYS), now)
            start_index = 0
            while True:
                params = {
                    "lastModStartDate": cursor.strftime("%Y-%m-%dT%H:%M:%S.000"),
                    "lastModEndDate": window_end.strftime("%Y-%m-%dT%H:%M:%S.000"),
                    "resultsPerPage": NVD_PAGE_SIZE,
                    "startIndex": start_index,
                }
                body = fetch(NVD_API_URL, params, headers)
                payload = json.loads(body)
                items = payload.get("vulnerabilities") or []
                for item in items:
                    data, matches = _parse_cve_item(item)
                    if data is None:
                        continue
                    upsert_cve(db, data, matches)
                    count += 1
                    if data["last_modified"] and (latest_modified is None or data["last_modified"] > latest_modified):
                        latest_modified = data["last_modified"]
                total = payload.get("totalResults", len(items))
                start_index += len(items)
                if not items or start_index >= total:
                    break
                sleep(delay)
            cursor = window_end
    except Exception as exc:  # best-effort: a failed sync never breaks scans or scoring
        error = str(exc)
        log.exception("NVD vulnerability feed sync failed")
    _update_feed_state(db, "nvd", now, latest_modified, count, error)
    return {"count": count, "error": error}


def sync_kev(db: Session, *, fetch: Fetcher | None = None, now: datetime | None = None) -> dict:
    """CISA Known Exploited Vulnerabilities: flags existing CVEs, or creates a bare row for ones
    NVD has not brought in yet (its own CVSS/CPE arrive on the next NVD sync)."""
    fetch = fetch or _default_fetch
    now = now or datetime.now(timezone.utc)
    count = 0
    error: str | None = None
    try:
        payload = json.loads(fetch(KEV_URL, None, None))
        for item in payload.get("vulnerabilities") or []:
            cve_id = item.get("cveID")
            if not cve_id:
                continue
            row = db.get(Vulnerability, cve_id)
            if row is None:
                row = Vulnerability(cve_id=cve_id)
                db.add(row)
                db.flush()
            row.kev = True
            row.kev_added_at = _parse_date(item.get("dateAdded")) or row.kev_added_at
            count += 1
    except Exception as exc:
        error = str(exc)
        log.exception("CISA KEV feed sync failed")
    _update_feed_state(db, "kev", now, None, count, error)
    return {"count": count, "error": error}


def sync_epss(db: Session, *, fetch: Fetcher | None = None, now: datetime | None = None) -> dict:
    """FIRST EPSS: enriches CVEs already known locally (from NVD) with an exploitation probability."""
    fetch = fetch or _default_fetch
    now = now or datetime.now(timezone.utc)
    count = 0
    error: str | None = None
    try:
        raw = fetch(EPSS_URL, None, None)
        try:
            text = gzip.decompress(raw).decode("utf-8")
        except OSError:
            text = raw.decode("utf-8")  # already-decompressed (test fixtures, some mirrors)
        lines = [ln for ln in text.splitlines() if ln and not ln.startswith("#")]
        for row in csv.DictReader(lines):
            cve_id = (row.get("cve") or "").strip()
            if not cve_id:
                continue
            existing = db.get(Vulnerability, cve_id)
            if existing is None:
                continue  # EPSS alone has no CVSS/CPE; only enrich CVEs NVD already brought in
            try:
                existing.epss = float(row["epss"])
                existing.epss_percentile = float(row["percentile"])
            except (KeyError, ValueError):
                continue
            count += 1
    except Exception as exc:
        error = str(exc)
        log.exception("EPSS feed sync failed")
    _update_feed_state(db, "epss", now, None, count, error)
    return {"count": count, "error": error}


def is_cache_empty(db: Session) -> bool:
    return db.scalar(select(Vulnerability.cve_id).limit(1)) is None


def sync_due(db: Session, cfg: VulnSettings, *, now: datetime | None = None) -> bool:
    """Weekly schedule (spec 5.3), plus an immediate first sync when enabled with an empty cache."""
    if not cfg.enabled or cfg.offline_mode:
        return False
    if is_cache_empty(db):
        return True
    now = now or datetime.now(timezone.utc)
    last = db.scalar(select(func.max(VulnFeedState.last_synced_at)))
    if last is None:
        return True
    return now - last >= timedelta(hours=cfg.sync_interval_hours)


def sync_all(db: Session, cfg: VulnSettings, *, fetch: Fetcher | None = None,
            now: datetime | None = None) -> dict:
    """Run every configured source. Best-effort per source: one failing source does not stop the rest."""
    now = now or datetime.now(timezone.utc)
    results: dict[str, dict] = {}
    if "nvd" in cfg.sources:
        results["nvd"] = sync_nvd(db, cfg, fetch=fetch, now=now)
    if "kev" in cfg.sources:
        results["kev"] = sync_kev(db, fetch=fetch, now=now)
    if "epss" in cfg.sources:
        results["epss"] = sync_epss(db, fetch=fetch, now=now)
    return results


def sync_and_rescore(db: Session, cfg: VulnSettings, *, fetch: Fetcher | None = None,
                     now: datetime | None = None) -> dict:
    """Sync every configured source, then re-run local CPE matching and risk scoring everywhere.

    Matching/scoring are local-only (no network); running them right after a sync is what makes
    "scores recomputed ... after sync" true even for devices that were not touched by a scan.
    """
    from ...models import Device
    from .match import match_all
    from .score import apply_risk_scores

    now = now or datetime.now(timezone.utc)
    results = sync_all(db, cfg, fetch=fetch, now=now)
    results["match"] = match_all(db, now=now)
    device_ids = list(db.scalars(select(Device.id)))
    apply_risk_scores(db, device_ids, now=now)
    return results


# --- background trigger (spec 5.3: sync runs in the background, never blocks a scan) --------------
_sync_lock = threading.Lock()
_sync_thread: threading.Thread | None = None


def sync_running() -> bool:
    return _sync_thread is not None and _sync_thread.is_alive()


def trigger_background_sync(cfg: VulnSettings | None = None) -> bool:
    """Start a sync-and-rescore in its own daemon thread. False if one is already running."""
    global _sync_thread
    with _sync_lock:
        if sync_running():
            return False

        def _run() -> None:
            from ...db import session_scope

            try:
                with session_scope() as db:
                    section = cfg
                    if section is None:
                        from ...settings_store import get_section
                        section = get_section(db, VulnSettings)
                    stats = sync_and_rescore(db, section)
                    log.info("vulnerability feed sync finished: %s", stats)
            except Exception:
                log.exception("background vulnerability feed sync failed")

        _sync_thread = threading.Thread(target=_run, name="vuln-sync", daemon=True)
        _sync_thread.start()
        return True
