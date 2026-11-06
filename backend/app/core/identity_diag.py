"""Privacy-preserving identity diagnostics: counts only, never addresses or names.

Used after a scan to explain *why* unmatched hosts became new devices, without putting
inventory identifiers into scan notes or logs.
"""
from __future__ import annotations

from collections.abc import Mapping

from ..scanner.types import HostObservation
from .identity import identity_hostname, is_generic_hostname, normalize_hostname, normalize_mac

# Stable reason codes for aggregate notes / metrics (synthetic ground-truth tests use the same set).
REASON_NO_USABLE_MAC = "no_usable_mac"
REASON_GENERIC_HOSTNAME = "generic_or_missing_hostname"
REASON_PROXY_OR_DUPLICATE_MAC = "duplicate_mac_in_scan"
REASON_OTHER = "other"


def classify_unmatched(h: HostObservation, mac_counts: Mapping[str, int]) -> str:
    """Why this host did not match an existing device (coarse, privacy-safe)."""
    mac = normalize_mac(h.mac)
    if mac and mac_counts.get(mac, 0) > 1:
        return REASON_PROXY_OR_DUPLICATE_MAC
    if not mac:
        hn = normalize_hostname(h.hostname)
        if hn is None or is_generic_hostname(hn, h.ip) or identity_hostname(h.hostname, h.ip) is None:
            return REASON_GENERIC_HOSTNAME if hn else REASON_NO_USABLE_MAC
        # Has a unique non-generic name but still unmatched (ambiguous/conflicted/cross-net).
        return REASON_OTHER
    if identity_hostname(h.hostname, h.ip) is None:
        return REASON_GENERIC_HOSTNAME
    return REASON_OTHER


def format_identity_notes(reasons: Mapping[str, int]) -> list[str]:
    """One scan note listing counts; empty when nothing new."""
    total = sum(reasons.values())
    if not total:
        return []
    parts = [f"{n} {code}" for code, n in sorted(reasons.items()) if n]
    return [f"Identity: {total} new device(s) ({', '.join(parts)})"]
