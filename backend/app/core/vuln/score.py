"""Risk score (vulnerability-based) and the combined score with exposure (spec section 5.6).

Pure re-scoring from already-stored `device_port_vulns`: no CPE matching here (see match.py) and
no network access. Cheap enough to run on every `refresh_devices` pass, since `combined_score`
also depends on `exposure_score`, which changes far more often than CVE matches do.

Formula (kept here so the PR / operators can read it in one place):

1. **Per-CVE points** — start from ``10 × CVSS`` (missing CVSS → ``DEFAULT_CVSS``), scale by EPSS
   percentile when present (``0.6 + 0.4 × p``), apply KEV (``×1.5``, floored to the *medium*
   band so one KEV alone is not already "high"), and halve potential matches. Then
   **soft-compress** with ``100 × (1 − e^{−raw/COMPRESS_K})``.

2. **Device risk** — take the top ``TOP_N`` compressed scores and fold them with **residual
   saturation**: each finding fills ``PRIMARY_WEIGHT × (SECONDARY_DECAY**i)`` of the *remaining*
   room to 100. One serious finding lands medium; several KEVs/criticals are needed for high.

3. **Combined** — exposure may spend at most ``EXPOSURE_HEADROOM_FRACTION`` of the room left
   below 100 (scaled by ``exposure/100``). It never multiplies risk by up to 1.5.
"""
from __future__ import annotations

import math
from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from ...models import (
    VULN_STATE_DISMISSED,
    VULN_STATE_POTENTIAL,
    Device,
    DevicePort,
    DevicePortVuln,
    DeviceProfile,
    Vulnerability,
)
from ..exposure import MAX_SCORE

DEFAULT_CVSS = 5.0  # "CVSS missing: 50" (spec) == 10 * 5.0
KEV_MULTIPLIER = 1.5
POTENTIAL_MULTIPLIER = 0.5
TOP_N = 5
# Soft-compress raw points (higher K → gentler curve so one critical KEV is not near 100).
COMPRESS_K = 180.0
# First finding uses this fraction of residual room; each next uses SECONDARY_DECAY of that.
PRIMARY_WEIGHT = 0.85
SECONDARY_DECAY = 0.55
# Exposure may fill at most this fraction of the room left under 100 — enough to tip a
# near-threshold host up a band, not enough to push mid-risk devices to 100.
EXPOSURE_HEADROOM_FRACTION = 0.12
RISK_CHUNK = 500
# Dashboard "high-risk devices" card (spec section 5.7): same cut points as exposure.py's
# HIGH_THRESHOLD/MEDIUM_THRESHOLD, since combined_score shares that 0-100 scale.
RISK_HIGH_THRESHOLD = 60
RISK_MEDIUM_THRESHOLD = 30
RISK_BANDS = ("high", "medium", "low")
# KEV alone clears the *medium* band on the raw score before soft-compress — not high.
KEV_FLOOR = RISK_MEDIUM_THRESHOLD


def risk_band_for_score(score: int | float | None) -> str:
    """Combined-score band used by the summary's high-risk device card and GET /api/vulns?risk_band=."""
    s = int(score or 0)
    if s >= RISK_HIGH_THRESHOLD:
        return "high"
    if s >= RISK_MEDIUM_THRESHOLD:
        return "medium"
    return "low"


@dataclass(frozen=True)
class VulnRow:
    cve_id: str
    cvss_base: float | None
    epss_percentile: float | None
    kev: bool
    state: str  # confirmed | potential (dismissed rows are filtered out before this point)


def _round(x: float) -> int:
    return int(math.floor(x + 0.5))


def _compress(raw: float) -> float:
    """Map unbounded raw points into (0, 100) with diminishing returns near the top."""
    if raw <= 0:
        return 0.0
    return MAX_SCORE * (1.0 - math.exp(-raw / COMPRESS_K))


def vuln_score(v: VulnRow) -> float:
    """Compressed points in (0, 100] for one matched vulnerability (float for aggregation)."""
    s = 10.0 * (v.cvss_base if v.cvss_base is not None else DEFAULT_CVSS)
    # Exploitation-probability multiplier: 0.6-1.0, scaled by EPSS percentile. A CVE with no EPSS
    # row yet (not synced) is left at its CVSS-only weight rather than guessed at.
    if v.epss_percentile is not None:
        s *= 0.6 + 0.4 * v.epss_percentile
    if v.kev:
        s = max(s * KEV_MULTIPLIER, float(KEV_FLOOR))
    if v.state == VULN_STATE_POTENTIAL:
        s *= POTENTIAL_MULTIPLIER
    return _compress(max(0.0, s))


def compute_risk(vulns: list[VulnRow]) -> tuple[int, list[dict]]:
    """(risk_score, [{factor, points, detail}]) for one device's non-dismissed matches.

    Residual saturation over the top ``TOP_N`` compressed scores (see module docstring).
    Risk stays separate from exposure; ``combine`` folds them into combined_score.
    """
    if not vulns:
        return 0, []
    scored = sorted(((vuln_score(v), v) for v in vulns), key=lambda x: x[0], reverse=True)
    top = scored[:TOP_N]
    risk_f = 0.0
    factors = []
    for i, (points, v) in enumerate(top):
        weight = PRIMARY_WEIGHT * (SECONDARY_DECAY ** i)
        risk_f = risk_f + (MAX_SCORE - risk_f) * (points / MAX_SCORE) * weight
        bits = [f"CVSS {v.cvss_base:.1f}" if v.cvss_base is not None else "CVSS unknown"]
        if v.kev:
            bits.append("exploited in the wild (KEV)")
        if v.epss_percentile is not None:
            bits.append(f"EPSS {v.epss_percentile:.0%}")
        if v.state == VULN_STATE_POTENTIAL:
            bits.append("potential match (imprecise version)")
        factors.append({
            "factor": v.cve_id,
            "points": _round(points),
            "detail": f"{v.cve_id}: " + ", ".join(bits),
        })
    return min(MAX_SCORE, _round(risk_f)), factors


def combine(risk: int, exposure: int) -> int:
    """Fold exposure into risk using remaining headroom only (no multiply-to-100)."""
    r = max(0, min(MAX_SCORE, int(risk)))
    e = max(0, min(MAX_SCORE, int(exposure or 0)))
    headroom = MAX_SCORE - r
    bonus = headroom * EXPOSURE_HEADROOM_FRACTION * (e / MAX_SCORE)
    return min(MAX_SCORE, _round(r + bonus))


def _load_vulns(db: Session, device_ids: list[int]) -> dict[int, list[VulnRow]]:
    rows = db.execute(
        select(DevicePort.device_id, DevicePortVuln.cve_id, DevicePortVuln.state,
               Vulnerability.cvss_base, Vulnerability.epss_percentile, Vulnerability.kev)
        .join(DevicePortVuln, DevicePortVuln.device_port_id == DevicePort.id)
        .join(Vulnerability, Vulnerability.cve_id == DevicePortVuln.cve_id)
        .where(DevicePort.device_id.in_(device_ids), DevicePortVuln.state != VULN_STATE_DISMISSED)
    ).all()
    out: dict[int, list[VulnRow]] = {}
    best: dict[int, dict[str, VulnRow]] = {}
    for device_id, cve_id, state, cvss_base, epss_percentile, kev in rows:
        row = VulnRow(cve_id=cve_id, cvss_base=cvss_base, epss_percentile=epss_percentile, kev=kev, state=state)
        by_cve = best.setdefault(device_id, {})
        prev = by_cve.get(cve_id)
        # Same CVE on multiple ports: keep the stronger state (confirmed > potential).
        if prev is None or (prev.state == VULN_STATE_POTENTIAL and state != VULN_STATE_POTENTIAL):
            by_cve[cve_id] = row
    for device_id, by_cve in best.items():
        out[device_id] = list(by_cve.values())
    return out


def _apply_chunk(db: Session, device_ids: list[int], *, now: datetime) -> None:
    by_device = _load_vulns(db, device_ids)
    devices = {d.id: d for d in db.scalars(select(Device).where(Device.id.in_(device_ids)))}
    profiles = {
        p.device_id: p for p in db.scalars(select(DeviceProfile).where(DeviceProfile.device_id.in_(device_ids)))
    }
    for device_id, dev in devices.items():
        risk, factors = compute_risk(by_device.get(device_id, []))
        dev.risk_score = risk
        dev.combined_score = combine(risk, dev.exposure_score or 0)
        dev.risk_scored_at = now
        profile = profiles.get(device_id)
        if profile is None:
            profile = DeviceProfile(device_id=device_id)
            db.add(profile)
            profiles[device_id] = profile
        profile.risk_factors = factors


def apply_risk_scores(db: Session, device_ids: list[int], *, now: datetime) -> None:
    ids = sorted(set(device_ids))
    for i in range(0, len(ids), RISK_CHUNK):
        _apply_chunk(db, ids[i:i + RISK_CHUNK], now=now)
        db.flush()
