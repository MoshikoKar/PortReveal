"""CVSS -> severity bucket (dashboard section 5): shared by the risk-score pipeline and the
vulnerability dashboard's counts/breakdowns, so both always bucket the same way. Buckets come
from `cvss_base` only -- NVD's own `severity` field is informational and may disagree.
"""
from __future__ import annotations

from sqlalchemy import case, func, literal_column

from .score import DEFAULT_CVSS

SEVERITY_THRESHOLDS = {"critical": 9.0, "high": 7.0, "medium": 4.0}


def severity_bucket(cvss: float | None) -> str:
    value = cvss if cvss is not None else DEFAULT_CVSS
    if value >= SEVERITY_THRESHOLDS["critical"]:
        return "critical"
    if value >= SEVERITY_THRESHOLDS["high"]:
        return "high"
    if value >= SEVERITY_THRESHOLDS["medium"]:
        return "medium"
    return "low"


def severity_bucket_expr(cvss_col):
    """SQL `case()` equivalent of `severity_bucket()`, for GROUP BY use.

    literal_column: keeps the SELECT and GROUP BY coalesce() identical on PostgreSQL (see the
    same trick in api/dashboard.py) -- a bound parameter there would make the two expressions
    differ and PostgreSQL rejects GROUP BY on a SELECT alias it can't match.
    """
    value = func.coalesce(cvss_col, literal_column(str(DEFAULT_CVSS)))
    return case(
        (value >= SEVERITY_THRESHOLDS["critical"], "critical"),
        (value >= SEVERITY_THRESHOLDS["high"], "high"),
        (value >= SEVERITY_THRESHOLDS["medium"], "medium"),
        else_="low",
    )
