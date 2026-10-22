"""Shared finding-list filters for GET /api/vulns, /export, and /summary.

Kept in one place so a future free-text ``q`` param (and any other list filter) slots into
the list, CSV export, and dashboard summary without duplicating query wiring.
"""
from __future__ import annotations

from dataclasses import dataclass, fields

# Facet key for devices with no network; round-trips via ?network_id=unassigned.
NETWORK_UNASSIGNED = "unassigned"


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
    # Reserved for a future free-text search param on the findings list / export / summary.
    q: str | None = None


def filters_active(f: FindingFilters | None) -> bool:
    """True when any filter field is set (summary cache must be bypassed)."""
    if f is None:
        return False
    return any(getattr(f, field.name) is not None for field in fields(f))


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


def sanitize_filename_part(value: str, *, max_len: int = 40) -> str:
    """Lowercase slug for CSV filenames (network name, cve id, …)."""
    out = []
    for ch in value.strip().lower():
        if ch.isalnum():
            out.append(ch)
        elif ch in (" ", "-", "_", "."):
            out.append("-")
    slug = "".join(out).strip("-")
    while "--" in slug:
        slug = slug.replace("--", "-")
    return (slug or "filtered")[:max_len]
