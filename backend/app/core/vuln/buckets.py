"""CVSS -> severity bucket (dashboard section 5): shared by the risk-score pipeline and the
vulnerability dashboard's counts/breakdowns, so both always bucket the same way. Buckets come
from `cvss_base` only -- NVD's own `severity` field is informational and may disagree.

Missing CVSS is ``unknown`` (unscored), not a guessed medium. Risk scoring still substitutes
``DEFAULT_CVSS`` when computing points; display severity does not.
"""
from __future__ import annotations

from sqlalchemy import case

SEVERITY_THRESHOLDS = {"critical": 9.0, "high": 7.0, "medium": 4.0}
SEVERITY_BUCKETS = ("critical", "high", "medium", "low", "unknown")


def severity_bucket(cvss: float | None) -> str:
    """Map a CVSS base score to a band. ``None`` → ``unknown`` (no score in the local cache)."""
    if cvss is None:
        return "unknown"
    if cvss >= SEVERITY_THRESHOLDS["critical"]:
        return "critical"
    if cvss >= SEVERITY_THRESHOLDS["high"]:
        return "high"
    if cvss >= SEVERITY_THRESHOLDS["medium"]:
        return "medium"
    return "low"


def severity_bucket_expr(cvss_col):
    """SQL `case()` equivalent of `severity_bucket()`, for GROUP BY use."""
    return case(
        (cvss_col.is_(None), "unknown"),
        (cvss_col >= SEVERITY_THRESHOLDS["critical"], "critical"),
        (cvss_col >= SEVERITY_THRESHOLDS["high"], "high"),
        (cvss_col >= SEVERITY_THRESHOLDS["medium"], "medium"),
        else_="low",
    )
