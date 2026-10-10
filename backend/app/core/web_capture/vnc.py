"""Native VNC still capture — no-password / empty-password only; never wordlists."""
from __future__ import annotations

import logging
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

from .rtsp import ffmpeg_available
from .screenshot import _to_webp

log = logging.getLogger(__name__)

# RFB security types
SEC_INVALID = 0
SEC_NONE = 1
SEC_VNC = 2
SEC_TIGHT = 16


@dataclass
class VncShot:
    status: str
    data: bytes | None = None
    error: str | None = None
    auth_required: bool = False


def is_vnc_service(service: str | None, port: int | None = None) -> bool:
    s = (service or "").strip().lower()
    if s == "vnc" or s.startswith("vnc-") or s.startswith("vnc/") or "/vnc" in s:
        return True
    if port is not None and 5900 <= port <= 5910 and (not s or s in ("unknown", "tcpwrapped")):
        return True
    return False


def vnc_tool_available() -> bool:
    return bool(shutil.which("vncsnapshot") or ffmpeg_available())


def _rfb_security(ip: str, port: int, *, timeout: float = 4.0) -> tuple[str, bool]:
    """Return (status, auth_required). status is 'none', 'auth', or 'fail'."""
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            banner = sock.recv(12)
            if not banner.startswith(b"RFB "):
                return "fail", False
            sock.sendall(b"RFB 003.008\n")
            n = sock.recv(1)
            if not n:
                return "fail", False
            count = n[0]
            types = sock.recv(count) if count else b""
            if SEC_NONE in types:
                sock.sendall(bytes([SEC_NONE]))
                # Server init follows; we only care that no-auth is offered.
                return "none", False
            if SEC_VNC in types or SEC_TIGHT in types:
                return "auth", True
            return "auth", True
    except OSError:
        return "fail", False


def _vncsnapshot(ip: str, port: int, out: Path, *, timeout: float) -> bool:
    exe = shutil.which("vncsnapshot")
    if not exe:
        return False
    # Empty password via -passwd /dev/null style — vncsnapshot uses -passwd file;
    # without -passwd it tries none. Never pass a password file with guesses.
    args = [exe, "-quality", "5", f"{ip}::{port}", str(out)]
    kw: dict = {"capture_output": True, "timeout": timeout + 3}
    if sys.platform == "win32":
        kw["creationflags"] = subprocess.CREATE_NO_WINDOW  # type: ignore[attr-defined]
    try:
        subprocess.run(args, **kw)
    except (OSError, subprocess.TimeoutExpired):
        return False
    return out.is_file() and out.stat().st_size > 64


def _ffmpeg_vnc(ip: str, port: int, out: Path, *, timeout: float) -> bool:
    exe = shutil.which("ffmpeg")
    if not exe:
        return False
    # ffmpeg VNC demuxer — only works for no-auth / empty-pass servers.
    args = [
        exe, "-hide_banner", "-loglevel", "error",
        "-f", "vnc", "-i", f"{ip}:{port}",
        "-frames:v", "1", "-y", str(out),
    ]
    kw: dict = {"capture_output": True, "timeout": timeout + 3}
    if sys.platform == "win32":
        kw["creationflags"] = subprocess.CREATE_NO_WINDOW  # type: ignore[attr-defined]
    try:
        subprocess.run(args, **kw)
    except (OSError, subprocess.TimeoutExpired):
        return False
    return out.is_file() and out.stat().st_size > 64


def grab_vnc_frame(ip: str, port: int = 5900, *, timeout: float = 10.0) -> VncShot:
    status, auth = _rfb_security(ip, port, timeout=min(timeout, 4.0))
    if status == "fail":
        return VncShot("failed", error="vnc handshake failed")
    if status == "auth":
        return VncShot("skipped", error="skipped_auth", auth_required=True)
    with tempfile.TemporaryDirectory(prefix="nf-vnc-") as tmp:
        raw = Path(tmp) / "frame.png"
        ok = _vncsnapshot(ip, port, raw, timeout=timeout) or _ffmpeg_vnc(ip, port, raw, timeout=timeout)
        if not ok:
            return VncShot("skipped", error="no frame (tool missing or empty desktop)")
        try:
            return VncShot("captured", data=_to_webp(raw.read_bytes()))
        except Exception as exc:
            return VncShot("failed", error=str(exc))
