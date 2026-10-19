"""MAC vendor (OUI) lookup from nmap's own `nmap-mac-prefixes` file.

nmap fills `vendor` itself for hosts it ARPs on the local segment. MACs learned another way (router
ARP table over SNMP, NetBIOS) carry no vendor, so this reads the same file nmap uses -- consistent
names, no extra dependency. Best-effort: no file found -> no vendor.
"""
from __future__ import annotations

import logging
import shutil
from functools import lru_cache
from pathlib import Path

from ..config import get_settings

log = logging.getLogger(__name__)

_FILE = "nmap-mac-prefixes"
_SHARE_DIRS = (
    "/usr/share/nmap", "/usr/local/share/nmap", "/opt/homebrew/share/nmap",
    r"C:\Program Files (x86)\Nmap", r"C:\Program Files\Nmap",
)


def _candidates() -> list[Path]:
    out: list[Path] = []
    exe = shutil.which(get_settings().nmap_path)
    if exe:
        here = Path(exe).resolve().parent
        out += [here / _FILE, here.parent / "share" / "nmap" / _FILE]
    out += [Path(d) / _FILE for d in _SHARE_DIRS]
    return out


@lru_cache(maxsize=1)
def _table() -> dict[str, str]:
    for path in _candidates():
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        table: dict[str, str] = {}
        for line in lines:
            prefix, _, name = line.partition(" ")
            # 6 hex digits (MA-L); newer files also list longer MA-M / MA-S prefixes.
            if not line.startswith("#") and 6 <= len(prefix) <= 9 and name.strip():
                table[prefix.upper()] = name.strip()
        log.debug("OUI table: %d prefixes from %s", len(table), path)
        return table
    log.info("No %s file found; MACs learned outside nmap will have no vendor name", _FILE)
    return {}


def vendor_for(mac: str | None) -> str | None:
    """Vendor for a normalized MAC (AA:BB:CC:DD:EE:FF), longest listed prefix first."""
    if not mac:
        return None
    hexchars = mac.replace(":", "").upper()
    table = _table()
    for n in (9, 8, 7, 6):
        if (name := table.get(hexchars[:n])) is not None:
            return name
    return None
