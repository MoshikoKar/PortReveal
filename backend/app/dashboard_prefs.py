"""Dashboard layout preferences: allowlists, size limits, and validation.

Kept in sync with frontend/src/dashboard/defaults.ts (widget ids, KPI ids, breakpoints).
"""
from __future__ import annotations

from typing import Any

# Breakpoint → column count (must match the frontend Responsive grid).
BREAKPOINT_COLS: dict[str, int] = {"lg": 24, "md": 20, "sm": 1}
BREAKPOINTS = tuple(BREAKPOINT_COLS.keys())

WIDGET_IDS = frozenset({
    "kpis",
    "recent_changes",
    "scan_status",
    "changes_by_type",
    "exposure_scores",
    "device_types",
    "watch_alerts",
    "exposure_trend",
    "networks",
    "top_ports",
    "top_services",
})

KPI_IDS = frozenset({
    "known_hosts",
    "active",
    "new_hosts_24h",
    "new_ports_24h",
    "service_changes_24h",
    "open_ports",
    "high_exposure",
    "alerts_7d",
})

# minW, minH, maxW, maxH per widget (maxW None = cols of breakpoint).
# minW, minH, maxW, maxH — keep in sync with frontend/src/dashboard/defaults.ts
WIDGET_LIMITS: dict[str, tuple[int, int, int | None, int]] = {
    "kpis": (8, 4, 24, 32),
    "recent_changes": (6, 10, 24, 125),
    "scan_status": (6, 8, 24, 62),
    "changes_by_type": (6, 8, 24, 94),
    "exposure_scores": (6, 10, 24, 94),
    "device_types": (6, 8, 24, 94),
    "watch_alerts": (6, 10, 24, 125),
    "exposure_trend": (6, 8, 24, 62),
    "networks": (6, 8, 24, 94),
    "top_ports": (6, 8, 24, 94),
    "top_services": (6, 8, 24, 94),
}

# v2: fine grid (24/20 columns, 4px rows). v1 prefs already stored are migrated by the frontend on load.
DASHBOARD_SCHEMA_VERSION = 2
MAX_PREFERENCES_BYTES = 64 * 1024
ALLOWED_PREFERENCE_KEYS = frozenset({"dashboard"})
ALLOWED_DASHBOARD_KEYS = frozenset({"v", "layouts", "hidden", "kpiVisible"})


class PreferencesValidationError(ValueError):
    """Raised when a preferences payload fails validation."""


def _require_int(value: Any, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise PreferencesValidationError(f"{field} must be an integer")
    return value


def validate_layout_item(item: Any, cols: int, seen: set[str]) -> dict[str, int | str]:
    if not isinstance(item, dict):
        raise PreferencesValidationError("layout items must be objects")
    unknown = set(item) - {"i", "x", "y", "w", "h"}
    if unknown:
        raise PreferencesValidationError(f"unknown layout item keys: {sorted(unknown)}")
    wid = item.get("i")
    if not isinstance(wid, str) or wid not in WIDGET_IDS:
        raise PreferencesValidationError(f"unknown or missing widget id: {wid!r}")
    if wid in seen:
        raise PreferencesValidationError(f"duplicate widget id in layout: {wid}")
    seen.add(wid)
    x = _require_int(item.get("x"), "x")
    y = _require_int(item.get("y"), "y")
    w = _require_int(item.get("w"), "w")
    h = _require_int(item.get("h"), "h")
    min_w, min_h, max_w, max_h = WIDGET_LIMITS[wid]
    # On narrow breakpoints (sm = 1 col) minW cannot exceed cols.
    floor_w = min(min_w, cols)
    cap_w = min(cols, max_w if max_w is not None else cols)
    if x < 0 or y < 0:
        raise PreferencesValidationError(f"{wid}: x and y must be >= 0")
    if w < floor_w or w > cap_w:
        raise PreferencesValidationError(f"{wid}: w must be between {floor_w} and {cap_w}")
    if h < min_h or h > max_h:
        raise PreferencesValidationError(f"{wid}: h must be between {min_h} and {max_h}")
    if x + w > cols:
        raise PreferencesValidationError(f"{wid}: x + w exceeds {cols} columns")
    return {"i": wid, "x": x, "y": y, "w": w, "h": h}


def validate_dashboard(raw: Any) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise PreferencesValidationError("dashboard must be an object")
    unknown = set(raw) - ALLOWED_DASHBOARD_KEYS
    if unknown:
        raise PreferencesValidationError(f"unknown dashboard keys: {sorted(unknown)}")
    version = raw.get("v", DASHBOARD_SCHEMA_VERSION)
    if version != DASHBOARD_SCHEMA_VERSION:
        raise PreferencesValidationError(f"unsupported dashboard schema version: {version}")

    layouts_in = raw.get("layouts")
    if not isinstance(layouts_in, dict):
        raise PreferencesValidationError("layouts must be an object")
    unknown_bp = set(layouts_in) - set(BREAKPOINTS)
    if unknown_bp:
        raise PreferencesValidationError(f"unknown breakpoints: {sorted(unknown_bp)}")
    layouts: dict[str, list[dict[str, int | str]]] = {}
    for bp in BREAKPOINTS:
        items = layouts_in.get(bp, [])
        if not isinstance(items, list):
            raise PreferencesValidationError(f"layouts.{bp} must be an array")
        seen: set[str] = set()
        cols = BREAKPOINT_COLS[bp]
        layouts[bp] = [validate_layout_item(it, cols, seen) for it in items]

    hidden_in = raw.get("hidden", [])
    if not isinstance(hidden_in, list):
        raise PreferencesValidationError("hidden must be an array")
    hidden: list[str] = []
    for wid in hidden_in:
        if not isinstance(wid, str) or wid not in WIDGET_IDS:
            raise PreferencesValidationError(f"unknown hidden widget id: {wid!r}")
        if wid not in hidden:
            hidden.append(wid)

    kpi_in = raw.get("kpiVisible")
    if kpi_in is None:
        raise PreferencesValidationError("kpiVisible is required")
    if not isinstance(kpi_in, list):
        raise PreferencesValidationError("kpiVisible must be an array")
    kpi_visible: list[str] = []
    for kid in kpi_in:
        if not isinstance(kid, str) or kid not in KPI_IDS:
            raise PreferencesValidationError(f"unknown kpi id: {kid!r}")
        if kid not in kpi_visible:
            kpi_visible.append(kid)
    if not kpi_visible:
        raise PreferencesValidationError("kpiVisible must contain at least one kpi")

    return {
        "v": DASHBOARD_SCHEMA_VERSION,
        "layouts": layouts,
        "hidden": hidden,
        "kpiVisible": kpi_visible,
    }


def validate_preferences_payload(raw: Any, *, raw_bytes: int | None = None) -> dict[str, Any]:
    if raw_bytes is not None and raw_bytes > MAX_PREFERENCES_BYTES:
        raise PreferencesValidationError("preferences payload too large")
    if not isinstance(raw, dict):
        raise PreferencesValidationError("preferences must be an object")
    unknown = set(raw) - ALLOWED_PREFERENCE_KEYS
    if unknown:
        raise PreferencesValidationError(f"unknown preference keys: {sorted(unknown)}")
    if "dashboard" not in raw:
        raise PreferencesValidationError("dashboard is required")
    return {"dashboard": validate_dashboard(raw["dashboard"])}


def merge_preferences(existing: dict | None, incoming: dict[str, Any]) -> dict[str, Any]:
    """Replace known sections from incoming; keep unrelated future top-level keys."""
    out = dict(existing or {})
    out["dashboard"] = incoming["dashboard"]
    return out
