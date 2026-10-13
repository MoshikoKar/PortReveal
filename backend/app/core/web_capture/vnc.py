"""Native VNC still capture — no-password / empty-password only; never wordlists.

A minimal RFB client (RFC 6143) asks the server for one full framebuffer in Raw encoding. It needs no
external tool. `vncsnapshot`, when installed, is a fallback for servers whose framebuffer
exchange the built-in client cannot complete. Servers that require a password are never sent one.
"""
from __future__ import annotations

import logging
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from io import BytesIO
from pathlib import Path

from .screenshot import _to_webp

log = logging.getLogger(__name__)

# RFB security types
SEC_INVALID = 0
SEC_NONE = 1
SEC_VNC = 2
SEC_TIGHT = 16

# Client -> server message types
_SET_PIXEL_FORMAT = 0
_SET_ENCODINGS = 2
_FRAMEBUFFER_UPDATE_REQUEST = 3
# Server -> client message types
_FRAMEBUFFER_UPDATE = 0
_SET_COLOUR_MAP_ENTRIES = 1
_BELL = 2
_SERVER_CUT_TEXT = 3

_ENCODING_RAW = 0
_BYTES_PER_PIXEL = 4
# 32 bpp, depth 24, little endian, true colour, 8 bits per channel, red/green/blue at bits 16/8/0:
# each pixel arrives as bytes B, G, R, padding.
_PIXEL_FORMAT = struct.pack(">BBBBHHHBBB3x", 32, 24, 0, 1, 255, 255, 255, 16, 8, 0)
# A larger desktop is refused before any pixel is read (16.7 Mpx = 64 MiB of raw pixels).
MAX_PIXELS = 4096 * 4096
_MAX_TEXT = 1 << 20  # desktop name, failure reasons, clipboard text


@dataclass
class VncShot:
    status: str
    data: bytes | None = None
    error: str | None = None
    auth_required: bool = False


class RfbError(Exception):
    """The framebuffer exchange failed after a successful no-auth handshake."""


class RfbHandshakeError(RfbError):
    """No connection, not an RFB server, or the server refused the session."""


class RfbAuthRequired(RfbError):
    """The server offers no security type without a password."""


def is_vnc_service(service: str | None, port: int | None = None) -> bool:
    s = (service or "").strip().lower()
    if s == "vnc" or s.startswith("vnc-") or s.startswith("vnc/") or "/vnc" in s:
        return True
    if port is not None and 5900 <= port <= 5910 and (not s or s in ("unknown", "tcpwrapped")):
        return True
    return False


class _Conn:
    """Blocking socket reads bounded by one deadline for the whole exchange."""

    def __init__(self, sock: socket.socket, deadline: float):
        self.sock = sock
        self.deadline = deadline

    def recv_exact(self, n: int) -> bytes:
        buf = bytearray()
        while len(buf) < n:
            left = self.deadline - time.monotonic()
            if left <= 0:
                raise RfbError("timed out")
            self.sock.settimeout(left)
            try:
                chunk = self.sock.recv(min(n - len(buf), 1 << 20))
            except TimeoutError as exc:
                raise RfbError("timed out") from exc
            except OSError as exc:
                raise RfbError(f"connection error ({type(exc).__name__})") from exc
            if not chunk:
                raise RfbError("connection closed by server")
            buf += chunk
        return bytes(buf)

    def u8(self) -> int:
        return self.recv_exact(1)[0]

    def u16(self) -> int:
        return struct.unpack(">H", self.recv_exact(2))[0]

    def u32(self) -> int:
        return struct.unpack(">I", self.recv_exact(4))[0]

    def skip(self, n: int) -> None:
        while n > 0:
            n -= len(self.recv_exact(min(n, 1 << 16)))

    def text(self, limit: int = _MAX_TEXT) -> str:
        n = self.u32()
        if n > limit:
            raise RfbError("server string too long")
        return self.recv_exact(n).decode("latin-1", "replace")

    def send(self, data: bytes) -> None:
        self.sock.settimeout(max(0.1, self.deadline - time.monotonic()))
        try:
            self.sock.sendall(data)
        except OSError as exc:
            raise RfbError(f"connection error ({type(exc).__name__})") from exc


def _handshake(c: _Conn) -> None:
    """Protocol version and security (None only). Raises RfbAuthRequired for password servers."""
    try:
        banner = c.recv_exact(12)
    except RfbError as exc:
        raise RfbHandshakeError(f"no RFB banner: {exc}") from exc
    if not banner.startswith(b"RFB ") or banner[7:8] != b"." or not banner.endswith(b"\n"):
        raise RfbHandshakeError("not an RFB server")
    try:
        minor = int(banner[8:11])
    except ValueError as exc:
        raise RfbHandshakeError("not an RFB server") from exc
    # 3.3, 3.7 and 3.8 are the published versions; anything newer speaks 3.8, odd older ones 3.3.
    minor = 8 if minor >= 8 else 7 if minor == 7 else 3
    c.send(b"RFB 003.%03d\n" % minor)

    if minor == 3:
        sec = c.u32()  # the server decides
        if sec == SEC_INVALID:
            raise RfbHandshakeError(f"server refused the session: {c.text()[:200]}")
        if sec != SEC_NONE:
            raise RfbAuthRequired()
        return
    count = c.u8()
    if count == 0:
        raise RfbHandshakeError(f"server refused the session: {c.text()[:200]}")
    if SEC_NONE not in c.recv_exact(count):
        raise RfbAuthRequired()
    c.send(bytes([SEC_NONE]))
    if minor == 8 and c.u32() != 0:  # SecurityResult (3.7 sends none for the None type)
        raise RfbHandshakeError(f"security handshake failed: {c.text()[:200]}")


def _read_framebuffer(c: _Conn, width: int, height: int) -> bytes:
    """Request the whole screen until every pixel has arrived; returns BGRX rows."""
    fb = bytearray(width * height * _BYTES_PER_PIXEL)
    covered = 0
    request = struct.pack(">BBHHHH", _FRAMEBUFFER_UPDATE_REQUEST, 0, 0, 0, width, height)
    c.send(request)
    while True:
        kind = c.u8()
        if kind == _FRAMEBUFFER_UPDATE:
            c.skip(1)
            for _ in range(c.u16()):
                x, y, w, h, encoding = struct.unpack(">HHHHi", c.recv_exact(12))
                if encoding != _ENCODING_RAW:
                    raise RfbError(f"server sent unrequested encoding {encoding}")
                if x + w > width or y + h > height:
                    raise RfbError("rectangle outside the framebuffer")
                row = w * _BYTES_PER_PIXEL
                for r in range(h):
                    start = ((y + r) * width + x) * _BYTES_PER_PIXEL
                    fb[start:start + row] = c.recv_exact(row)
                covered += w * h
            if covered >= width * height:
                return bytes(fb)
            c.send(request)  # a partial update: ask for the full screen again
        elif kind == _SET_COLOUR_MAP_ENTRIES:
            c.skip(3)
            c.skip(c.u16() * 6)
        elif kind == _BELL:
            pass
        elif kind == _SERVER_CUT_TEXT:
            c.skip(3)
            c.text()
        else:
            raise RfbError(f"unknown server message type {kind}")


def _rfb_grab(ip: str, port: int, *, timeout: float) -> bytes:
    """One frame from a no-auth VNC server as PNG bytes."""
    deadline = time.monotonic() + timeout
    try:
        sock = socket.create_connection((ip, port), timeout=min(timeout, 4.0))
    except OSError as exc:
        raise RfbHandshakeError(f"connect failed ({type(exc).__name__})") from exc
    with sock:
        c = _Conn(sock, deadline)
        _handshake(c)
        c.send(b"\x01")  # ClientInit: shared, so viewers already connected stay connected
        width, height = c.u16(), c.u16()
        c.skip(16)  # server pixel format: replaced by ours below
        c.text(limit=4096)  # desktop name
        if not width or not height:
            raise RfbError("empty framebuffer")
        if width * height > MAX_PIXELS:
            raise RfbError(f"framebuffer {width}x{height} is too large")
        c.send(struct.pack(">B3x", _SET_PIXEL_FORMAT) + _PIXEL_FORMAT)
        c.send(struct.pack(">BxHi", _SET_ENCODINGS, 1, _ENCODING_RAW))
        pixels = _read_framebuffer(c, width, height)
    from PIL import Image

    out = BytesIO()
    Image.frombuffer("RGB", (width, height), pixels, "raw", "BGRX", 0, 1).save(out, format="PNG")
    return out.getvalue()


def _vncsnapshot(ip: str, port: int, out: Path, *, timeout: float) -> bool:
    exe = shutil.which("vncsnapshot")
    if not exe:
        return False
    # Without -passwd vncsnapshot only tries servers without a password. Never pass a password file.
    args = [exe, "-quality", "5", f"{ip}::{port}", str(out)]
    kw: dict = {"capture_output": True, "timeout": timeout + 3}
    if sys.platform == "win32":
        kw["creationflags"] = subprocess.CREATE_NO_WINDOW  # type: ignore[attr-defined]
    try:
        subprocess.run(args, **kw)
    except (OSError, subprocess.TimeoutExpired):
        return False
    return out.is_file() and out.stat().st_size > 64


def grab_vnc_frame(ip: str, port: int = 5900, *, timeout: float = 10.0) -> VncShot:
    try:
        png = _rfb_grab(ip, port, timeout=timeout)
    except RfbAuthRequired:
        return VncShot("skipped", error="skipped_auth", auth_required=True)
    except RfbHandshakeError as exc:
        log.debug("VNC %s:%s handshake failed: %s", ip, port, exc)
        return VncShot("failed", error="vnc handshake failed")
    except RfbError as exc:
        # The no-auth handshake worked, so the fallback tool will not be sent a password either.
        log.debug("VNC %s:%s built-in capture failed (%s); trying vncsnapshot", ip, port, exc)
        with tempfile.TemporaryDirectory(prefix="nf-vnc-") as tmp:
            raw = Path(tmp) / "frame.jpg"
            if not _vncsnapshot(ip, port, raw, timeout=timeout):
                return VncShot("failed", error=f"vnc frame failed: {exc}")
            png = raw.read_bytes()
    try:
        return VncShot("captured", data=_to_webp(png))
    except Exception as exc:
        return VncShot("failed", error=str(exc))
