"""Discovery path wordlist: built-in list, or a user-supplied file."""
from __future__ import annotations

import logging
from pathlib import Path

from ...config import get_settings
from .classify import APP_PATHS

log = logging.getLogger(__name__)

# Hard ceiling regardless of settings, so a huge file cannot turn one capture into a brute-force run.
MAX_WORDLIST_PATHS = 2000
_cache: dict[str, tuple[float, tuple[str, ...]]] = {}


def _normalise(line: str) -> str | None:
    s = line.strip()
    if not s or s.startswith("#"):
        return None
    # Allow bare words ("admin") or rooted paths ("/admin"); reject absolute URLs and traversal.
    if "://" in s or ".." in s or any(c in s for c in " \t\\"):
        return None
    if not s.startswith("/"):
        s = "/" + s
    return s[:200]


def _resolve(raw: str) -> Path | None:
    p = Path(raw)
    if not p.is_absolute():
        p = get_settings().data_path / p
    return p


def load_wordlist(raw_path: str) -> tuple[str, ...]:
    """Load, normalise and dedupe paths from a file; cached on path + mtime. Empty on any problem."""
    raw_path = (raw_path or "").strip()
    if not raw_path:
        return ()
    path = _resolve(raw_path)
    try:
        mtime = path.stat().st_mtime
    except OSError as exc:
        log.warning("discovery wordlist unreadable (%s): %s", raw_path, exc)
        return ()
    cached = _cache.get(str(path))
    if cached and cached[0] == mtime:
        return cached[1]
    out: list[str] = []
    seen: set[str] = set()
    try:
        with path.open("r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                norm = _normalise(line)
                if norm and norm not in seen:
                    seen.add(norm)
                    out.append(norm)
                    if len(out) >= MAX_WORDLIST_PATHS:
                        break
    except OSError as exc:
        log.warning("discovery wordlist read failed (%s): %s", raw_path, exc)
        return ()
    result = tuple(out)
    _cache[str(path)] = (mtime, result)
    log.info("discovery wordlist loaded: %d paths from %s", len(result), path)
    return result


def discovery_paths(raw_path: str) -> tuple[str, ...]:
    """The wordlist file if one is configured and usable, else the built-in list."""
    return load_wordlist(raw_path) or APP_PATHS
