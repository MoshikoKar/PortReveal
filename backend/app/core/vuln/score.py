"""Risk score (vulnerability-based) and the combined score with exposure (spec section 5.6).

Pure re-scoring from already-stored `device_port_vulns`: no CPE matching here (see match.py) and
no network access. Cheap enough to run on every `refresh_devices` pass, since `combined_score`
also depends on `exposure_score`, which changes far more often than CVE matches do.
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
SECONDARY_WEIGHT = 0.2
# One CVE must not alone saturate the 0-100 scale: leave headroom for secondary
# findings and for exposure in combine(), so devices spread across low/medium/high.
MAX_SINGLE_VULN_POINTS = 70
COMBINED_EXPOSURE_DIVISOR = 200
RISK_CHUNK = 500
# Dashboard "high-risk devices" card (spec section 5.7): same cut points as exposure.py's
# HIGH_THRESHOLD/MEDIUM_THRESHOLD, since combined_score shares that 0-100 scale.
RISK_HIGH_THRESHOLD = 60
RISK_MEDIUM_THRESHOLD = 30
RISK_BANDS = ("high", "medium", "low")
# KEV alone clears the high-risk band floor; the old floor of 80 collapsed almost every
# KEV-bearing host straight into combined=100 once exposure was applied.
KEV_FLOOR = RISK_HIGH_THRESHOLD


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


def vuln_score(v: VulnRow) -> int:
    """s_c in [0, MAX_SINGLE_VULN_POINTS] for one matched vulnerability.

    Capped below 100 so risk and exposure both still move the combined score (spec 5.6):
    a lone critical/KEV finding lands in the high band without pinning every host at 100.
    """
    s = 10.0 * (v.cvss_base if v.cvss_base is not None else DEFAULT_CVSS)
    # Exploitation-probability multiplier: 0.6-1.0, scaled by EPSS percentile. A CVE with no EPSS
    # row yet (not synced) is left at its CVSS-only weight rather than guessed at.
    if v.epss_percentile is not None:
        s *= 0.6 + 0.4 * v.epss_percentile
    if v.kev:
        s = max(s * KEV_MULTIPLIER, KEV_FLOOR)
    if v.state == VULN_STATE_POTENTIAL:
        s *= POTENTIAL_MULTIPLIER
    return max(0, min(MAX_SINGLE_VULN_POINTS, _round(s)))


def compute_risk(vulns: list[VulnRow]) -> tuple[int, list[dict]]:
    """(risk_score, [{factor, points, detail}]) for one device's non-dismissed matches.

    R = min(100, s_1 + 0.2 * (s_2 + s_3 + s_4 + s_5)): the worst vulnerability sets the floor,
    the next four add a capped contribution, so many medium findings never outrank one bad one.
    Risk is kept separate from exposure; ``combine`` folds them into combined_score.
    """
    if not vulns:
        return 0, []
    scored = sorted(((vuln_score(v), v) for v in vulns), key=lambda x: x[0], reverse=True)
    top = scored[:TOP_N]
    worst = top[0][0]
    secondary = sum(points for points, _v in top[1:])
    risk = min(MAX_SCORE, _round(worst + SECONDARY_WEIGHT * secondary))
    factors = []
    for points, v in top:
        bits = [f"CVSS {v.cvss_base:.1f}" if v.cvss_base is not None else "CVSS unknown"]
        if v.kev:
            bits.append("exploited in the wild (KEV)")
        if v.epss_percentile is not None:
            bits.append(f"EPSS {v.epss_percentile:.0%}")
        if v.state == VULN_STATE_POTENTIAL:
            bits.append("potential match (imprecise version)")
        factors.append({"factor": v.cve_id, "points": points, "detail": f"{v.cve_id}: " + ", ".join(bits)})
    return risk, factors


def combine(risk: int, exposure: int) -> int:
    """C = min(100, R × (1 + exposure/200)): exposure amplifies risk (up to +50%), never replaces it."""
    return min(MAX_SCORE, _round(risk * (1 + exposure / COMBINED_EXPOSURE_DIVISOR)))


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
