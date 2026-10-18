"""Shared display floor for vulnerability findings: `include_potential` / `min_cvss_display`
(spec section 5). One predicate so the per-device list (api/devices.py), the dashboard summary
(core/vuln/summary.py) and the CVE-centric list (api/vulns.py) never drift apart.
"""
from __future__ import annotations

from ...models import VULN_STATE_DISMISSED, VULN_STATE_POTENTIAL, DevicePortVuln, Vulnerability
from ...settings_store import VulnSettings
from .score import DEFAULT_CVSS


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


def should_display(dpv: DevicePortVuln, vuln: Vulnerability, cfg: VulnSettings) -> bool:
    return is_visible(dpv.state, vuln.kev, vuln.cvss_base, cfg)
