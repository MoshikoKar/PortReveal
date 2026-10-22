"""Shared display floor for vulnerability findings: `include_potential` / `min_cvss_display`
(spec section 5). One predicate so the per-device list (api/devices.py), the dashboard summary
(core/vuln/summary.py) and the CVE-centric list (api/vulns.py) never drift apart.
"""
from __future__ import annotations

from ...models import VULN_STATE_DISMISSED, VULN_STATE_POTENTIAL, DevicePortVuln, Vulnerability
from ...settings_store import VulnSettings
from .score import DEFAULT_CVSS

# Badge labels for findings the default list hides; returned on GET /api/vulns when `q` is set.
REASON_BELOW_CVSS_FLOOR = "Below CVSS floor"
REASON_DISMISSED = "Dismissed"
REASON_POTENTIAL_HIDDEN = "Potential (hidden)"


def normalize_cve_id(cve_id: str) -> str:
    """Canonical CVE id for lookups and storage (NVD form is uppercase)."""
    return (cve_id or "").strip().upper()


def is_visible(state: str, kev: bool, cvss_base: float | None, cfg: VulnSettings) -> bool:
    """False if a finding with this state/KEV/CVSS is below the display floor. A dismissed finding
    is never hidden by the floor -- it stays visible in its own `dismissed` view regardless of
    CVSS/potential settings. KEV is never hidden by the CVSS floor either: exploited-in-the-wild
    entries must remain visible. Missing CVSS is treated as `score.py`'s DEFAULT_CVSS, consistent
    with risk scoring.
    """
    if state == VULN_STATE_DISMISSED:
        return True
    if not cfg.include_potential and state == VULN_STATE_POTENTIAL:
        return False
    if kev:
        return True
    effective_cvss = cvss_base if cvss_base is not None else DEFAULT_CVSS
    return effective_cvss >= cfg.min_cvss_display


def hidden_reasons(state: str, kev: bool, cvss_base: float | None, cfg: VulnSettings) -> list[str]:
    """Why a finding is absent from the default CVE-centric list (no `state=` / no `q`).

    The list endpoint excludes dismissed and (when configured) potential and below-floor rows
    separately from ``is_visible`` (which treats dismissed as floor-visible for the dismissed view).
    Search results use these labels as row badges.
    """
    reasons: list[str] = []
    if state == VULN_STATE_DISMISSED:
        reasons.append(REASON_DISMISSED)
    if not cfg.include_potential and state == VULN_STATE_POTENTIAL:
        reasons.append(REASON_POTENTIAL_HIDDEN)
    # CVSS floor never applies to dismissed (same as is_visible) or to KEV.
    if state != VULN_STATE_DISMISSED and not kev:
        effective_cvss = cvss_base if cvss_base is not None else DEFAULT_CVSS
        if effective_cvss < cfg.min_cvss_display:
            reasons.append(REASON_BELOW_CVSS_FLOOR)
    return reasons


def should_display(dpv: DevicePortVuln, vuln: Vulnerability, cfg: VulnSettings) -> bool:
    return is_visible(dpv.state, vuln.kev, vuln.cvss_base, cfg)
