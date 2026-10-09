"""Value parsing shared by the SQL compiler and the snapshot evaluator."""
from __future__ import annotations

import re
from datetime import date, datetime, time, timedelta, timezone

from .parser import QueryError, Term

_DURATION_RE = re.compile(r"^(\d{1,5})\s*(m|min|h|d|w|mo|y)$", re.I)
_UNITS = {"m": timedelta(minutes=1), "min": timedelta(minutes=1), "h": timedelta(hours=1),
          "d": timedelta(days=1), "w": timedelta(weeks=1), "mo": timedelta(days=30), "y": timedelta(days=365)}
TRUE_WORDS = {"true", "yes", "1", "on", "y"}
FALSE_WORDS = {"false", "no", "0", "off", "n"}


def parse_bool(term: Term, raw: str) -> bool:
    v = raw.strip().lower()
    if v in TRUE_WORDS:
        return True
    if v in FALSE_WORDS:
        return False
    raise QueryError(f"'{term.field}' expects true or false, not '{raw}'", term.pos)


def parse_int(term: Term, raw: str) -> int:
    try:
        return int(raw.strip())
    except ValueError:
        raise QueryError(f"'{term.field}' expects a number, not '{raw}'", term.pos) from None


def int_range(term: Term, op: str, raw: str) -> tuple[int | None, int | None]:
    """Inclusive (low, high) for an integer comparison; None = unbounded."""
    if op == ">":
        return parse_int(term, raw) + 1, None
    if op == ">=":
        return parse_int(term, raw), None
    if op == "<":
        return None, parse_int(term, raw) - 1
    if op == "<=":
        return None, parse_int(term, raw)
    m = re.fullmatch(r"\s*(\d+)\s*-\s*(\d+)\s*", raw)
    if m:
        lo, hi = int(m.group(1)), int(m.group(2))
        if lo > hi:
            lo, hi = hi, lo
        return lo, hi
    n = parse_int(term, raw)
    return n, n


def parse_duration(raw: str) -> timedelta | None:
    m = _DURATION_RE.match(raw.strip())
    if not m:
        return None
    return int(m.group(1)) * _UNITS[m.group(2).lower()]


def _parse_date(raw: str) -> date | None:
    try:
        return date.fromisoformat(raw.strip())
    except ValueError:
        return None


def time_window(term: Term, op: str, raw: str, now: datetime) -> tuple[datetime | None, datetime | None]:
    """(after, before) bounds for a timestamp.

    Durations measure age (`first_seen:<7d` = less than 7 days old); dates compare as dates
    (`last_seen:>2026-09-01`). A bare duration means "<", a bare date means that whole day.
    """
    dur = parse_duration(raw)
    if dur is not None:
        if op in ("", "<", "<="):
            return now - dur, None
        return None, now - dur
    d = _parse_date(raw)
    if d is None:
        raise QueryError(f"'{term.field}' expects a duration like 7d / 12h / 3w or a date like 2026-09-01, "
                         f"not '{raw}'", term.pos)
    start = datetime.combine(d, time.min).astimezone(timezone.utc)
    end = start + timedelta(days=1)
    if op in (">",):
        return end, None
    if op == ">=":
        return start, None
    if op == "<":
        return None, start
    if op == "<=":
        return None, end
    return start, end


def glob_to_like(value: str) -> str:
    """`*` / `?` wildcards to an anchored LIKE pattern (escape char is backslash)."""
    out = []
    for ch in value:
        if ch in "%_\\":
            out.append("\\" + ch)
        elif ch == "*":
            out.append("%")
        elif ch == "?":
            out.append("_")
        else:
            out.append(ch)
    return "".join(out)


def contains_like(value: str) -> str:
    escaped = value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return f"%{escaped}%"


def glob_regex(value: str) -> re.Pattern:
    parts = [".*" if ch == "*" else "." if ch == "?" else re.escape(ch) for ch in value]
    return re.compile("^" + "".join(parts) + "$", re.I | re.S)
