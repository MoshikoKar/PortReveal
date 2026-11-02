"""Discovery path wordlists: the built-in list and/or stored "paths" lists from the wordlist library."""
from __future__ import annotations

import logging
from collections.abc import Iterable
from itertools import zip_longest
from pathlib import Path

from sqlalchemy.orm import Session

from ...models import Wordlist
from ..wordlists import KIND_PATHS, WordlistError, normalize_path, stored_path
from .classify import APP_PATHS

log = logging.getLogger(__name__)

# Hard ceiling for Web capture app discovery (security monitoring / inventory enrichment).
# Matches WebCaptureSettings.max_discovery_paths; longer stored lists are kept, but only the
# first N paths are candidates for discovery probes.
MAX_DISCOVERY_PATHS = 500
# Back-compat alias for callers/tests that still import the old name.
MAX_WORDLIST_PATHS = MAX_DISCOVERY_PATHS
_cache: dict[str, tuple[float, tuple[str, ...]]] = {}


def discovery_truncation_warning(kind: str, entries: int) -> str | None:
    """Warn when a paths list is longer than the discovery probe ceiling."""
    if kind != KIND_PATHS or entries <= MAX_DISCOVERY_PATHS:
        return None
    return (
        f"Only the first {MAX_DISCOVERY_PATHS:,} paths are used for Web capture app discovery "
        f"({entries:,} in this list)."
    )


def load_wordlist(path: Path) -> tuple[str, ...]:
    """Load a stored list (first MAX_DISCOVERY_PATHS entries); cached on path + mtime. Empty on any problem.

    Stored files hold sanitized entries already; they are validated again as defense in depth.
    """
    try:
        mtime = path.stat().st_mtime
    except OSError as exc:
        log.warning("discovery wordlist unreadable (%s): %s", path.name, exc)
        return ()
    cached = _cache.get(str(path))
    if cached and cached[0] == mtime:
        return cached[1]
    out: list[str] = []
    seen: set[str] = set()
    try:
        with path.open("r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.rstrip("\r\n")
                if line.lstrip(" \t").startswith("#"):
                    continue
                norm, _reason = normalize_path(line)
                if norm and norm not in seen:
                    seen.add(norm)
                    out.append(norm)
                    if len(out) >= MAX_DISCOVERY_PATHS:
                        break
    except OSError as exc:
        log.warning("discovery wordlist read failed (%s): %s", path.name, exc)
        return ()
    result = tuple(out)
    _cache[str(path)] = (mtime, result)
    log.info("discovery wordlist loaded: %d paths from %s", len(result), path.name)
    return result


def _stored_paths(db: Session, wordlist_id: int) -> tuple[str, ...]:
    row = db.get(Wordlist, wordlist_id)
    if row is None or row.kind != KIND_PATHS:
        log.warning("discovery wordlist %s missing or not a paths list; skipped", wordlist_id)
        return ()
    try:
        path = stored_path(row.storage_name)
    except WordlistError:
        return ()
    return load_wordlist(path)


def discovery_paths(db: Session, wordlist_ids: Iterable[int], builtin: bool = False) -> tuple[str, ...]:
    """The selected lists (built-in first) merged round-robin without duplicates, so each one
    contributes to the first few paths a capture tries. Nothing usable selected: the built-in list."""
    sources = [APP_PATHS] if builtin else []
    sources += [p for p in (_stored_paths(db, i) for i in wordlist_ids) if p]
    if not sources:
        return APP_PATHS
    merged = dict.fromkeys(p for row in zip_longest(*sources) for p in row if p is not None)
    return tuple(merged)[:MAX_DISCOVERY_PATHS]
