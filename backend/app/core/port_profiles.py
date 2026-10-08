"""Per-device extra port profiles (e.g. the TrueNAS SCALE Apps catalog ports).

A profile is applied only to devices verified from what they report about themselves
(hostname, web UI title, ...) or set by an admin. Once set it stays set: auto-detection never
clears it, and an admin's choice ("none" included) is never overridden by auto-detection.
"""
from __future__ import annotations

from ..models import Device
from ..scanner.known_ports import PORT_PROFILES

PROFILE_NONE = "none"  # admin explicitly disabled extra ports for this device
SOURCE_MANUAL = "manual"
# Case-insensitive marker a device's own self-description must contain to verify the profile.
_MARKERS = {"truenas": "truenas"}


def profile_ports(profile: str | None) -> tuple[int, ...]:
    return PORT_PROFILES.get(profile or "", ())


def auto_mark(dev: Device, text: str | None, source: str) -> bool:
    """Set a profile on `dev` when `text` (something the device reported) verifies one."""
    if dev.port_profile is not None or not text:
        return False
    low = text.lower()
    for profile, marker in _MARKERS.items():
        if marker in low:
            dev.port_profile, dev.port_profile_source = profile, source
            return True
    return False
