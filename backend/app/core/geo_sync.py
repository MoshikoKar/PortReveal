"""Inbound download of DB-IP Lite Country and ASN MMDB files (no API key).

Mirrors the vulnerability-feed pattern: public GET only, injectable fetcher, monthly refresh,
first-run when files are missing. MaxMind GeoLite2 is never fetched from here — operators drop
their own file via GeoSettings.maxmind_country_path.
"""
from __future__ import annotations

import gzip
import io
import logging
import threading
from collections.abc import Callable
from datetime import datetime, timedelta
from pathlib import Path

import httpx
from sqlalchemy.orm import Session

from ..config import get_settings
from ..db import session_scope, utcnow
from ..models import GeoFeedState
from ..settings_store import GeoSettings, get_section

log = logging.getLogger(__name__)

DBIP_ATTRIBUTION = "IP Geolocation by DB-IP — https://db-ip.com/ (CC BY 4.0)"
DBIP_LICENSE = "CC BY 4.0"
COUNTRY_SOURCE = "country"
ASN_SOURCE = "asn"
SOURCES = (COUNTRY_SOURCE, ASN_SOURCE)

COUNTRY_FILENAME = "dbip-country-lite.mmdb"
ASN_FILENAME = "dbip-asn-lite.mmdb"

# Public monthly builds. If the current month is not published yet, the previous month is tried.
_DBIP_COUNTRY = "https://download.db-ip.com/free/dbip-country-lite-{ym}.mmdb.gz"
_DBIP_ASN = "https://download.db-ip.com/free/dbip-asn-lite-{ym}.mmdb.gz"

SYNC_INTERVAL = timedelta(days=28)
_FEED_TIMEOUT = httpx.Timeout(180.0, connect=30.0)
Fetcher = Callable[[str], bytes]

_sync_lock = threading.Lock()
_sync_thread: threading.Thread | None = None


def geo_dir() -> Path:
    path = get_settings().data_path / "geo"
    path.mkdir(parents=True, exist_ok=True)
    return path


def country_db_path() -> Path:
    return geo_dir() / COUNTRY_FILENAME


def asn_db_path() -> Path:
    return geo_dir() / ASN_FILENAME


def maxmind_country_path(cfg: GeoSettings) -> Path | None:
    raw = (cfg.maxmind_country_path or "").strip()
    if not raw:
        return None
    p = Path(raw)
    if not p.is_absolute():
        p = get_settings().data_path / p
    return p if p.is_file() else None


def files_ready(cfg: GeoSettings | None = None) -> bool:
    """Country MMDB is required for checks; ASN is best-effort (CDN labels)."""
    if cfg and maxmind_country_path(cfg):
        return True
    return country_db_path().is_file()


def _default_fetch(url: str) -> bytes:
    resp = httpx.get(url, timeout=_FEED_TIMEOUT, follow_redirects=True)
    resp.raise_for_status()
    return resp.content


def _ungzip(raw: bytes) -> bytes:
    if len(raw) >= 2 and raw[0] == 0x1F and raw[1] == 0x8B:
        with gzip.GzipFile(fileobj=io.BytesIO(raw)) as gz:
            return gz.read()
    return raw


def _months_to_try(now: datetime) -> list[str]:
    y, m = now.year, now.month
    out = [f"{y:04d}-{m:02d}"]
    if m == 1:
        out.append(f"{y - 1:04d}-12")
    else:
        out.append(f"{y:04d}-{m - 1:02d}")
    return out


def _feed_row(db: Session, source: str) -> GeoFeedState:
    row = db.get(GeoFeedState, source)
    if row is None:
        row = GeoFeedState(source=source)
        db.add(row)
        db.flush()
    return row


def _download_one(url_template: str, dest: Path, fetch: Fetcher, now: datetime) -> str:
    last_err: Exception | None = None
    for ym in _months_to_try(now):
        url = url_template.format(ym=ym)
        try:
            body = _ungzip(fetch(url))
        except Exception as exc:
            last_err = exc
            log.info("geo feed %s not available: %s", url, exc)
            continue
        if len(body) < 1024 or body[:2] not in (b"\xab\x93", b"\x00\x00"):  # MMDB magic is \xab\x93 later; size guard
            # MMDB files are binary; a tiny body is an error page.
            if len(body) < 64_000:
                last_err = ValueError(f"geo feed {url} is too small ({len(body)} bytes)")
                continue
        tmp = dest.with_suffix(".mmdb.tmp")
        tmp.write_bytes(body)
        tmp.replace(dest)
        return ym
    raise last_err or RuntimeError("geo feed download failed")


def sync_geo_feeds(db: Session, cfg: GeoSettings | None = None, *, fetch: Fetcher | None = None,
                   now: datetime | None = None) -> dict[str, str]:
    """Download Country + ASN Lite MMDBs into the data dir. Returns {source: month}."""
    cfg = cfg or get_section(db, GeoSettings)
    if cfg.offline_mode:
        log.info("geo feed sync skipped (offline mode)")
        return {}
    fetch = fetch or _default_fetch
    now = now or utcnow()
    stats: dict[str, str] = {}
    jobs = (
        (COUNTRY_SOURCE, _DBIP_COUNTRY, country_db_path()),
        (ASN_SOURCE, _DBIP_ASN, asn_db_path()),
    )
    for source, template, dest in jobs:
        row = _feed_row(db, source)
        try:
            month = _download_one(template, dest, fetch, now)
            row.last_synced_at = now
            row.file_month = month
            row.last_error = None
            stats[source] = month
            log.info("geo feed %s updated (DB-IP %s)", source, month)
        except Exception as exc:
            row.last_error = str(exc)[:2000]
            log.warning("geo feed %s failed: %s", source, exc)
    db.flush()
    return stats


def sync_due(db: Session, cfg: GeoSettings | None = None, *, now: datetime | None = None) -> bool:
    cfg = cfg or get_section(db, GeoSettings)
    if cfg.offline_mode:
        return False
    if not country_db_path().is_file():
        return True
    now = now or utcnow()
    row = db.get(GeoFeedState, COUNTRY_SOURCE)
    if row is None or row.last_synced_at is None:
        return True
    return now - row.last_synced_at >= SYNC_INTERVAL


def sync_running() -> bool:
    t = _sync_thread
    return t is not None and t.is_alive()


def trigger_background_sync(cfg: GeoSettings | None = None) -> bool:
    global _sync_thread
    with _sync_lock:
        if sync_running():
            return False

        def _run() -> None:
            try:
                with session_scope() as db:
                    sync_geo_feeds(db, cfg)
            except Exception:
                log.exception("background geo feed sync failed")

        _sync_thread = threading.Thread(target=_run, name="geo-sync", daemon=True)
        _sync_thread.start()
        return True


def ensure_geo_dbs(db: Session, cfg: GeoSettings | None = None) -> bool:
    """Return True when a country MMDB is usable. Kick a background download if missing."""
    cfg = cfg or get_section(db, GeoSettings)
    if files_ready(cfg):
        if sync_due(db, cfg) and not sync_running() and not cfg.offline_mode:
            trigger_background_sync(cfg)
        return True
    if not cfg.offline_mode and not sync_running():
        trigger_background_sync(cfg)
    return files_ready(cfg)
