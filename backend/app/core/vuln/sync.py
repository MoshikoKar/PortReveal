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
from pathlib import Path

import httpx
from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from ...models import VulnCpeMatch, Vulnerability, VulnFeedState
from ...security import decrypt_secret
from ...settings_store import VulnSettings
from .match import cpe_vendor_product, normalize_cpe

log = logging.getLogger(__name__)

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
# Public NVD JSON 2.0 yearly feeds (inbound GET only — no inventory leaves the host). Used for the
# empty-cache initial load so we do not page ~10 years through the rate-limited API (spec 5.3).
NVD_JSON_FEED_BASE = "https://nvd.nist.gov/feeds/json/cve/2.0"
NVD_MIRROR_START_YEAR = 2018  # practical window for CPE-rich CVEs relevant to network services

NVD_WINDOW_DAYS = 120  # NVD API hard limit on the lastMod* window size
NVD_PAGE_SIZE = 2000
NVD_RATE_DELAY_NO_KEY = 6.5  # keep well under 5 requests / 30s
NVD_RATE_DELAY_WITH_KEY = 0.7  # keep well under 50 requests / 30s
# API lookback after a successful mirror (or when the mirror is unavailable): covers recent edits.
FULL_SYNC_LOOKBACK_DAYS = 120

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
                       count: int, error: str | None, *, previous_count: int = 0) -> None:
    """On success, advance the weekly clock and cursor. On failure, record the error but do NOT
    advance ``last_synced_at`` / cursor — otherwise a mid-pagination failure postpones retries for
    a full sync interval and permanently skips CVEs from the failed page."""
    row = db.get(VulnFeedState, source)
    if row is None:
        row = VulnFeedState(source=source, record_count=0)
        db.add(row)
        db.flush()
    row.last_error = error
    if error:
        # Keep prior successful cursor/synced_at; bump record_count only with what we wrote this run.
        if count:
            row.record_count = (row.record_count or 0) + count
        return
    row.last_synced_at = now
    if cursor is not None:
        row.last_modified_cursor = cursor.isoformat()
    row.record_count = previous_count + count if previous_count else (count or row.record_count or 0)


def _ingest_nvd_payload(db: Session, payload: dict) -> tuple[int, datetime | None]:
    count = 0
    latest: datetime | None = None
    for item in payload.get("vulnerabilities") or []:
        data, matches = _parse_cve_item(item)
        if data is None:
            continue
        upsert_cve(db, data, matches)
        count += 1
        if data["last_modified"] and (latest is None or data["last_modified"] > latest):
            latest = data["last_modified"]
    return count, latest


def _load_json_bytes(raw: bytes) -> dict:
    try:
        text = gzip.decompress(raw).decode("utf-8")
    except OSError:
        text = raw.decode("utf-8")
    return json.loads(text)


def _nvd_feed_state(db: Session) -> VulnFeedState:
    row = db.get(VulnFeedState, "nvd")
    if row is None:
        row = VulnFeedState(source="nvd", record_count=0, mirror_complete=False)
        db.add(row)
        db.flush()
    return row


def mirror_incomplete(db: Session) -> bool:
    """True when the yearly NVD JSON mirror has not finished (or has never been attempted)."""
    state = db.get(VulnFeedState, "nvd")
    return state is None or not state.mirror_complete


def sync_nvd_mirror(db: Session, *, fetch: Fetcher | None = None,
                    now: datetime | None = None, sleep: Callable[[float], None] = time.sleep) -> dict:
    """Bootstrap / resume: inbound download of public NVD JSON 2.0 yearly feeds (spec 5.3).

    Progress is persisted per year in ``VulnFeedState.mirror_next_year`` so a mid-mirror failure
    resumes the remaining years on the next sync instead of skipping to the 120-day API window.
    """
    fetch = fetch or _default_fetch
    now = now or datetime.now(timezone.utc)
    state = _nvd_feed_state(db)
    if state.mirror_complete:
        return {"count": 0, "error": None, "latest": None, "complete": True}
    count = 0
    latest: datetime | None = None
    error: str | None = None
    start_year = state.mirror_next_year or NVD_MIRROR_START_YEAR
    years = list(range(start_year, now.year + 1))
    try:
        for year in years:
            url = f"{NVD_JSON_FEED_BASE}/nvdcve-2.0-{year}.json.gz"
            body = fetch(url, None, None)
            payload = _load_json_bytes(body)
            n, lm = _ingest_nvd_payload(db, payload)
            count += n
            if lm and (latest is None or lm > latest):
                latest = lm
            # Persist resume cursor after each successful year before the next fetch can fail.
            state.mirror_next_year = year + 1
            state.mirror_complete = False
            db.flush()
            sleep(0.2)
        # Also pull the "modified" feed so very recent edits are not missed.
        mod = fetch(f"{NVD_JSON_FEED_BASE}/nvdcve-2.0-modified.json.gz", None, None)
        n, lm = _ingest_nvd_payload(db, _load_json_bytes(mod))
        count += n
        if lm and (latest is None or lm > latest):
            latest = lm
        state.mirror_complete = True
        state.mirror_next_year = None
        db.flush()
    except Exception as exc:
        error = str(exc)
        state.mirror_complete = False
        db.flush()
        log.exception("NVD JSON mirror bootstrap failed")
    return {"count": count, "error": error, "latest": latest, "complete": bool(state.mirror_complete)}


def import_nvd_json(db: Session, path: str | Path) -> dict:
    """Offline snapshot import: load one or more NVD 2.0 JSON (optionally .gz) files from disk."""
    root = Path(path)
    files: list[Path]
    if root.is_file():
        files = [root]
    elif root.is_dir():
        files = sorted(list(root.glob("*.json")) + list(root.glob("*.json.gz")))
    else:
        raise FileNotFoundError(f"vuln import path not found: {path}")
    count = 0
    latest: datetime | None = None
    for f in files:
        raw = f.read_bytes()
        payload = _load_json_bytes(raw)
        n, lm = _ingest_nvd_payload(db, payload)
        count += n
        if lm and (latest is None or lm > latest):
            latest = lm
    now = datetime.now(timezone.utc)
    state = _nvd_feed_state(db)
    state.mirror_complete = True
    state.mirror_next_year = None
    _update_feed_state(db, "nvd", now, latest or now, count, None)
    return {"count": count, "files": len(files)}


def sync_nvd(db: Session, cfg: VulnSettings, *, fetch: Fetcher | None = None,
            now: datetime | None = None, sleep: Callable[[float], None] = time.sleep) -> dict:
    """Incremental NVD sync. Incomplete/empty mirror first, then a short API catch-up."""
    fetch = fetch or _default_fetch
    now = now or datetime.now(timezone.utc)
    state = _nvd_feed_state(db)
    cursor_start = _parse_dt(state.last_modified_cursor) if state.last_modified_cursor else None
    mirror_count = 0
    mirror_error: str | None = None
    if not state.mirror_complete:
        mirrored = sync_nvd_mirror(db, fetch=fetch, now=now, sleep=sleep)
        mirror_count = mirrored.get("count") or 0
        if mirrored.get("latest"):
            cursor_start = mirrored["latest"]
        if mirrored.get("error"):
            mirror_error = mirrored["error"]
            # Fall through to API lookback so keyless installs still populate eventually, but keep
            # mirror_complete=False so the next sync resumes remaining years.
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
                n, lm = _ingest_nvd_payload(db, payload)
                count += n
                if lm and (latest_modified is None or lm > latest_modified):
                    latest_modified = lm
                items = payload.get("vulnerabilities") or []
                total = payload.get("totalResults", len(items))
                start_index += len(items)
                if not items or start_index >= total:
                    break
                sleep(delay)
            cursor = window_end
    except Exception as exc:  # best-effort: a failed sync never breaks scans or scoring
        error = str(exc)
        log.exception("NVD vulnerability feed sync failed")
    # Prefer the API error when both failed; keep a single feed_state write (no double INSERT).
    # An incomplete mirror is always an error so sync_due retries promptly.
    state = _nvd_feed_state(db)
    if not state.mirror_complete and not mirror_error:
        mirror_error = f"NVD yearly mirror incomplete; next year {state.mirror_next_year or NVD_MIRROR_START_YEAR}"
    final_error = error or mirror_error
    _update_feed_state(db, "nvd", now, latest_modified, count + mirror_count, final_error)
    return {"count": count + mirror_count, "error": final_error}


def sync_kev(db: Session, *, fetch: Fetcher | None = None, now: datetime | None = None) -> dict:
    """CISA Known Exploited Vulnerabilities: flags existing CVEs, or creates a bare row for ones
    NVD has not brought in yet (its own CVSS/CPE arrive on the next NVD sync)."""
    fetch = fetch or _default_fetch
    now = now or datetime.now(timezone.utc)
    count = 0
    error: str | None = None
    try:
        payload = json.loads(fetch(KEV_URL, None, None))
        seen: set[str] = set()
        for item in payload.get("vulnerabilities") or []:
            cve_id = item.get("cveID")
            if not cve_id:
                continue
            seen.add(cve_id)
            row = db.get(Vulnerability, cve_id)
            if row is None:
                row = Vulnerability(cve_id=cve_id)
                db.add(row)
                db.flush()
            row.kev = True
            row.kev_added_at = _parse_date(item.get("dateAdded")) or row.kev_added_at
            count += 1
        # Clear KEV flags removed from the feed so stale "exploited in the wild" badges do not linger.
        if seen:
            stale = db.scalars(select(Vulnerability).where(Vulnerability.kev.is_(True))).all()
            for row in stale:
                if row.cve_id not in seen:
                    row.kev = False
                    row.kev_added_at = None
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
    """Weekly schedule (spec 5.3), plus an immediate first sync when enabled with an empty cache.

    Honors ``sync_time`` as a best-effort local-time slot (like the daily digest). A prior
    ``last_error`` on any feed forces an immediate retry so a failed page is not postponed a week.
    An incomplete NVD yearly mirror also retries immediately so remaining years are not deferred.
    """
    if not cfg.enabled or cfg.offline_mode:
        return False
    if is_cache_empty(db) or mirror_incomplete(db):
        return True
    now = now or datetime.now(timezone.utc)
    if db.scalar(select(VulnFeedState.source).where(VulnFeedState.last_error.isnot(None)).limit(1)):
        return True
    last = db.scalar(select(func.max(VulnFeedState.last_synced_at)))
    if last is None:
        return True
    if now - last < timedelta(hours=cfg.sync_interval_hours):
        return False
    try:
        hh, mm = (int(x) for x in cfg.sync_time.split(":"))
        due = now.replace(hour=hh, minute=mm, second=0, microsecond=0)
    except ValueError:
        return True
    # Once the interval has elapsed, wait until today's sync_time (or run immediately if past it).
    return now >= due


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
