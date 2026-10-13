"""RDP still capture via FreeRDP — empty credentials only; soft-skip on NLA/auth."""
from __future__ import annotations

import logging
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

from .screenshot import ScreenshotResult, _to_webp

log = logging.getLogger(__name__)


# Windows Scoop nightlies ship sdl-freerdp; Linux packages ship xfreerdp.
_FREERDP_CLIENTS = (
    "wfreerdp",
    "xfreerdp",
    "wlfreerdp",
    "sdl-freerdp",
    "sdl3-freerdp",
)


def freerdp_available() -> bool:
    for name in (*_FREERDP_CLIENTS, "freerdp"):
        if shutil.which(name):
            return True
    return False


def _freerdp_bin() -> str | None:
    for name in _FREERDP_CLIENTS:
        p = shutil.which(name)
        if p:
            return p
    return None


@dataclass
class RdpShot:
    status: str  # captured | skipped | failed
    data: bytes | None = None
    error: str | None = None
    auth_required: bool = False


def grab_rdp_frame(ip: str, port: int = 3389, *, timeout: float = 12.0) -> RdpShot:
    """Try an unauthenticated FreeRDP screenshot. Never retries with credentials."""
    exe = _freerdp_bin()
    if not exe:
        return RdpShot("skipped", error="freerdp unavailable")
    with tempfile.TemporaryDirectory(prefix="nf-rdp-") as tmp:
        out = Path(tmp) / "shot.bmp"
        # /auth-only fails fast when NLA requires credentials; /cert:ignore for LAN mis-issued certs.
        # Empty user/pass only — product policy forbids credential guessing.
        args = [
            exe,
            f"/v:{ip}:{port}",
            "/u:",
            "/p:",
            "/cert:ignore",
            f"/timeout:{int(timeout * 1000)}",
            f"/screenshot:{out}",
            "/bpp:16",
            "+glyph-cache",
            "/size:1024x768",
        ]
        kw: dict = {"capture_output": True, "timeout": timeout + 5}
        if sys.platform == "win32":
            kw["creationflags"] = subprocess.CREATE_NO_WINDOW  # type: ignore[attr-defined]
        try:
            proc = subprocess.run(args, **kw)
        except subprocess.TimeoutExpired:
            return RdpShot("skipped", error="rdp timeout", auth_required=True)
        except OSError as exc:
            return RdpShot("failed", error=str(exc))
        text = ((proc.stderr or b"") + (proc.stdout or b"")).decode("utf-8", errors="replace").lower()
        if any(x in text for x in ("nla", "credssp", "authentication", "login failed", "access denied")):
            return RdpShot("skipped", error="skipped_auth", auth_required=True)
        if not out.is_file() or out.stat().st_size < 64:
            return RdpShot("skipped", error="skipped_auth" if proc.returncode else "no frame", auth_required=True)
        try:
            webp = _to_webp(out.read_bytes())
        except Exception as exc:
            return RdpShot("failed", error=f"encode failed: {exc}")
        return RdpShot("captured", data=webp)


def is_rdp_service(service: str | None, port: int | None = None) -> bool:
    s = (service or "").strip().lower()
    if s in ("ms-wbt-server", "rdp") or "ms-wbt" in s or s.endswith("/rdp"):
        return True
    return port == 3389 and (not s or s in ("unknown", "tcpwrapped"))
