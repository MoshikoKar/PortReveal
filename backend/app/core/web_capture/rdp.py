"""RDP still capture via FreeRDP — empty credentials only; soft-skip on NLA/auth.

Shodan-style behaviour: when the server allows a session without Network Level
Authentication, FreeRDP can reach the Windows logon/greeter bitmap and
``/screenshot`` captures it. No passwords are tried. If the server requires NLA
(CredSSP), the protocol never draws a desktop — there is no frame to capture.
"""
from __future__ import annotations

import logging
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

from .screenshot import _to_webp

log = logging.getLogger(__name__)


# Windows Scoop nightlies ship sdl-freerdp; Linux packages ship xfreerdp.
_FREERDP_CLIENTS = (
    "wfreerdp",
    "xfreerdp",
    "wlfreerdp",
    "sdl-freerdp",
    "sdl3-freerdp",
)

# Prefer TLS without NLA so the Windows logon screen is reachable (Shodan-style).
# Negotiate last: many LAN hosts force NLA and that path only yields skipped_auth.
_SEC_PROFILES: tuple[tuple[str, ...], ...] = (
    ("/sec:tls",),
    ("/sec:rdp",),
    (),  # server-negotiated (often NLA)
)

_AUTH_MARKERS = (
    "nla",
    "credssp",
    "authentication",
    "login failed",
    "access denied",
    "errconnect_logon_failure",
    "errconnect_authentication_failed",
    "status_logon_failure",
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


def _run_freerdp(exe: str, args: list[str], *, timeout: float) -> tuple[int, str]:
    kw: dict = {"capture_output": True, "timeout": timeout + 5}
    if sys.platform == "win32":
        kw["creationflags"] = subprocess.CREATE_NO_WINDOW  # type: ignore[attr-defined]
    try:
        proc = subprocess.run(args, **kw)
    except subprocess.TimeoutExpired:
        return -1, "timeout"
    except OSError as exc:
        return -2, str(exc)
    text = ((proc.stderr or b"") + (proc.stdout or b"")).decode("utf-8", errors="replace").lower()
    return proc.returncode, text


def grab_rdp_frame(ip: str, port: int = 3389, *, timeout: float = 12.0) -> RdpShot:
    """Capture the pre-auth RDP logon bitmap when the server allows it.

    Empty ``/u:`` / ``/p:`` only — never retries with credentials. Tries ``/sec:tls``
    first so hosts without NLA yield a Shodan-style login-screen still.
    """
    exe = _freerdp_bin()
    if not exe:
        return RdpShot("skipped", error="freerdp unavailable")
    with tempfile.TemporaryDirectory(prefix="nf-rdp-") as tmp:
        out = Path(tmp) / "shot.bmp"
        saw_auth = False
        last_text = ""
        for profile in _SEC_PROFILES:
            if out.is_file():
                out.unlink(missing_ok=True)
            # /cert:ignore for LAN mis-issued certs; empty user/pass avoids FreeRDP's
            # local credential dialog so the *remote* greeter can appear.
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
                *profile,
            ]
            code, text = _run_freerdp(exe, args, timeout=timeout)
            last_text = text
            if code == -2:
                return RdpShot("failed", error=text)
            if code == -1:
                saw_auth = True
                continue
            if out.is_file() and out.stat().st_size >= 64:
                try:
                    webp = _to_webp(out.read_bytes())
                except Exception as exc:
                    return RdpShot("failed", error=f"encode failed: {exc}")
                return RdpShot("captured", data=webp)
            if any(m in text for m in _AUTH_MARKERS):
                saw_auth = True
                continue
            if code != 0:
                saw_auth = True
        # No bitmap: almost always NLA/CredSSP (nothing to draw before auth).
        if saw_auth or any(m in last_text for m in _AUTH_MARKERS):
            return RdpShot(
                "skipped",
                error="skipped_auth",
                auth_required=True,
            )
        return RdpShot("skipped", error="no frame", auth_required=False)


def is_rdp_service(service: str | None, port: int | None = None) -> bool:
    s = (service or "").strip().lower()
    if s in ("ms-wbt-server", "rdp") or "ms-wbt" in s or s.endswith("/rdp"):
        return True
    return port == 3389 and (not s or s in ("unknown", "tcpwrapped"))
