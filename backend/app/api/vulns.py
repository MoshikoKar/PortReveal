"""CVE-centric vulnerability dashboard (spec section 5.7): one summary endpoint backing every
card/facet/chart/top-list, reading from core/vuln/summary.py's in-process cache.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from ..auth.deps import current_user
from ..core.vuln.summary import get_vuln_summary
from ..db import get_db, utcnow
from ..models import User

router = APIRouter(prefix="/api/vulns", tags=["vulns"])


@router.get("/summary")
def vuln_summary_route(db: Session = Depends(get_db), user: User = Depends(current_user)):
    """Severity/KEV/EPSS/confirmed-potential counts, high-risk device levels, feed staleness,
    facet breakdowns, the weekly new/resolved/dismissed trend and top-10 CVEs/devices. Self-
    populating on a cold cache; otherwise served straight from it (invalidated after every scan
    or feed sync)."""
    return get_vuln_summary(db, now=utcnow())
