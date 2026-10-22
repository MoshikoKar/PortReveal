"""Shared finding-list filters for GET /api/vulns, /export, and /summary.

Kept in one place so list, CSV export, and dashboard summary share one filter object —
including free-text ``q`` (search includes normally-hidden rows) and ``only_hidden``.
"""

from __future__ import annotations

from dataclasses import dataclass, fields
from urllib.parse import quote

# Facet key for devices with no network; round-trips via ?network_id=unassigned.
NETWORK_UNASSIGNED = "unassigned"

# Formula / injection prefixes Excel/Sheets treat as formulas when a CSV cell starts with them.
CSV_FORMULA_PREFIXES = frozenset("=+-@\t\r")


@dataclass
class FindingFilters:
    severity: str | None = None
    kev: bool | None = None
    epss_min: float | None = None
    # Integer id as a string, or NETWORK_UNASSIGNED for devices with no network.
    network_id: str | None = None
    service: str | None = None
    port: int | None = None
    os_name: str | None = None
    device_type: str | None = None
    state: str | None = None
    cve_age: str | None = None
    exposure_duration: str | None = None
    risk_band: str | None = None
    vendor: str | None = None
    product: str | None = None
    cve_id: str | None = None
    device_uuid: str | None = None
    # first_seen/matched_at >= last completed scan ("scan") or newest enabled feed sync ("db").
    new_since: str | None = None
    # Free-text search; when set, the display floor (dismissed / potential / min_cvss) is skipped.
    q: str | None = None
    # When searching, restrict to rows that would be hidden by the default display rules.
    only_hidden: bool = False


def search_term(f: FindingFilters | None) -> str | None:
    """Non-empty stripped ``q``, or None when search is inactive."""
    if f is None or not f.q:
        return None
    term = f.q.strip()
    return term or None


def filters_active(f: FindingFilters | None) -> bool:
    """True when any filter field is set (summary cache must be bypassed)."""
    if f is None:
        return False
    if search_term(f) is not None:
        return True
    if f.only_hidden:
        return True
    return any(getattr(f, field.name) is not None for field in fields(f) if field.name not in ("q", "only_hidden"))


def parse_network_id_param(raw: str | None) -> str | None:
    """Accept a numeric network id or the facet sentinel ``unassigned``; reject other strings.

    Returns the normalized string, or None when absent. Raises ValueError on bad input
    (API layer maps that to HTTP 422).
    """
    if raw is None or raw == "":
        return None
    if raw == NETWORK_UNASSIGNED:
        return NETWORK_UNASSIGNED
    try:
        return str(int(raw))
    except ValueError as exc:
        raise ValueError("network_id must be an integer or 'unassigned'") from exc


def sanitize_filename_part(value: str, *, max_len: int = 40, ascii_only: bool = False) -> str:
    """Lowercase slug for CSV filenames (network name, cve id, …).

    Underscores are preserved so ``vulns_<slug>_<yyyymmdd>.csv`` stays underscore-delimited.
    When ``ascii_only`` is True, non-ASCII letters are dropped so the result is safe for a
    latin-1 ``Content-Disposition: filename=`` fallback.
    """
    out = []
    for ch in value.strip().lower():
        if ascii_only:
            if ("a" <= ch <= "z") or ("0" <= ch <= "9"):
                out.append(ch)
            elif ch == "_":
                out.append("_")
            elif ch in (" ", "-", "."):
                out.append("-")
            continue
        if ch.isalnum():
            out.append(ch)
        elif ch == "_":
            out.append("_")
        elif ch in (" ", "-", "."):
            out.append("-")
    slug = "".join(out).strip("-_")
    while "--" in slug:
        slug = slug.replace("--", "-")
    while "__" in slug:
        slug = slug.replace("__", "_")
    return (slug or "filtered")[:max_len]


def content_disposition_attachment(filename: str) -> str:
    """``filename=`` ASCII fallback plus RFC 5987 ``filename*=UTF-8''…`` for Unicode names.

    Starlette/uvicorn encode response headers as latin-1; a raw Hebrew ``filename="…"`` 500s.
    Underscores in the ASCII fallback are preserved (``vulns_net_YYYYMMDD.csv``).
    """
    stem, ext = (filename.rsplit(".", 1) + [""])[:2] if "." in filename else (filename, "")
    ascii_stem = sanitize_filename_part(stem, max_len=80, ascii_only=True)
    ascii_name = f"{ascii_stem}.{ext}" if ext else ascii_stem
    ascii_name = ascii_name.replace("\\", "_").replace('"', "_")
    encoded = quote(filename, safe="")
    return f"attachment; filename=\"{ascii_name}\"; filename*=UTF-8''{encoded}"


def csv_safe_cell(value: object) -> object:
    """Neutralize CSV/Excel formula injection on string cells; leave numbers alone."""
    if value is None:
        return ""
    if isinstance(value, (int, float, bool)):
        return value
    text = str(value)
    if text and text[0] in CSV_FORMULA_PREFIXES:
        return "'" + text
    return text
