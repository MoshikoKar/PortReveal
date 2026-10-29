"""Discovery path wordlist: built-in list, or a stored "paths" list from the wordlist library."""
from __future__ import annotations

import logging
from pathlib import Path

from sqlalchemy.orm import Session

from ...models import Wordlist
from ..wordlists import KIND_PATHS, WordlistError, normalize_path, stored_path
from .classify import APP_PATHS

log = logging.getLogger(__name__)

# Hard ceiling regardless of settings, so a huge file cannot turn one capture into a brute-force run.
MAX_WORDLIST_PATHS = 2000
_cache: dict[str, tuple[float, tuple[str, ...]]] = {}


def load_wordlist(path: Path) -> tuple[str, ...]:
    """Load a stored list (first MAX_WORDLIST_PATHS entries); cached on path + mtime. Empty on any problem.

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
                    if len(out) >= MAX_WORDLIST_PATHS:
                        break
    except OSError as exc:
        log.warning("discovery wordlist read failed (%s): %s", path.name, exc)
        return ()
    result = tuple(out)
    _cache[str(path)] = (mtime, result)
    log.info("discovery wordlist loaded: %d paths from %s", len(result), path.name)
    return result


def discovery_paths(db: Session, wordlist_id: int | None) -> tuple[str, ...]:
    """The selected stored list if it exists and is usable, else the built-in list."""
    if not wordlist_id:
        return APP_PATHS
    row = db.get(Wordlist, wordlist_id)
    if row is None or row.kind != KIND_PATHS:
        log.warning("discovery wordlist %s missing or not a paths list; using built-in", wordlist_id)
        return APP_PATHS
    try:
        path = stored_path(row.storage_name)
    except WordlistError:
        return APP_PATHS
    return load_wordlist(path) or APP_PATHS
