"""RTSP still-frame capture and live MJPEG proxy (ffmpeg). Soft-fails if ffmpeg is missing."""
from __future__ import annotations

import logging
import shutil
import socket
import subprocess
import sys
import threading
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from io import BytesIO
from urllib.parse import urlparse

from .screenshot import ScreenshotResult, _to_webp

log = logging.getLogger(__name__)

MJPEG_BOUNDARY = "ffmpegframe"

# Common anonymous RTSP path layouts (cameras / NVRs). First working path wins.
RTSP_PATH_CANDIDATES: tuple[str, ...] = (
    "/",
    "/stream1",
    "/stream",
    "/live",
    "/h264",
    "/videoMain",
    "/media/video1",
    "/cam/realmonitor?channel=1&subtype=0",
    "/Streaming/Channels/101",
    "/Streaming/Channels/1",
    "/axis-media/media.amp",
)

_MAX_LIVE_STREAMS = 4
_live_lock = threading.Lock()
_live_count = 0


def ffmpeg_available() -> bool:
    return shutil.which("ffmpeg") is not None


def looks_like_rtsp(url: str, *, timeout: float = 4.0) -> tuple[bool, str]:
    """Cheap RTSP OPTIONS check. Rejects HTTP services that nmap mislabels as rtsp."""
    try:
        parsed = urlparse(url)
    except Exception:
        return False, "invalid RTSP URL"
    host = parsed.hostname
    if not host:
        return False, "invalid RTSP URL"
    port = parsed.port or (554 if parsed.scheme != "rtsps" else 322)
    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"
    req = (
        f"OPTIONS {parsed.scheme}://{host}:{port}{path} RTSP/1.0\r\n"
        f"CSeq: 1\r\n"
        f"User-Agent: NetworkFinder/1.0\r\n"
        f"\r\n"
    ).encode("ascii", errors="ignore")
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall(req)
            data = sock.recv(1024)
    except OSError as exc:
        return False, f"RTSP connect failed ({exc})"
    if not data:
        return False, "no RTSP response"
    text = data.decode("latin-1", errors="replace")
    first = text.split("\r\n", 1)[0]
    # Real RTSP daemons answer RTSP/1.0 200/401/404; HTTP apps often echo RTSP/1.0 400 + JSON.
    if not first.upper().startswith("RTSP/"):
        return False, f"not RTSP ({first[:80]})"
    if " 400 " in first or first.endswith(" 400"):
        # Many non-RTSP HTTP services (e.g. Keycloak management) answer RTSP probes with 400 JSON.
        if "application/json" in text.lower() or text.lstrip().startswith("{"):
            return False, "port speaks HTTP (not an RTSP camera stream)"
        return False, f"RTSP rejected OPTIONS ({first[:80]})"
    if any(code in first for code in (" 200 ", " 401 ", " 403 ", " 404 ", " 454 ")):
        return True, first[:80]
    return True, first[:80]


def build_rtsp_url(scheme: str, host: str, port: int, path: str = "/") -> str:
    sch = "rtsps" if scheme == "rtsps" else "rtsp"
    if not path.startswith("/"):
        path = "/" + path
    # Default RTSP port is 554 — omit when standard
    if port == 554:
        return f"{sch}://{host}{path}"
    return f"{sch}://{host}:{port}{path}"


def _popen_kwargs() -> dict:
    kw: dict = {}
    if sys.platform == "win32":
        kw["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    return kw


def _run_ffmpeg(args: list[str], *, timeout: float) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        args,
        capture_output=True,
        timeout=timeout,
        **_popen_kwargs(),
    )


def grab_frame(url: str, *, timeout: float = 12.0) -> ScreenshotResult:
    """Pull a single video frame from an RTSP URL into WEBP bytes."""
    if not ffmpeg_available():
        return ScreenshotResult(status="skipped", error="ffmpeg unavailable")
    ok, reason = looks_like_rtsp(url, timeout=min(timeout, 4.0))
    if not ok:
        return ScreenshotResult(status="failed", error=reason)
    cmd = [
        "ffmpeg",
        "-nostdin",
        "-hide_banner",
        "-loglevel",
        "error",
        "-rtsp_transport",
        "tcp",
        "-i",
        url,
        "-an",
        "-frames:v",
        "1",
        "-f",
        "image2pipe",
        "-vcodec",
        "mjpeg",
        "-",
    ]
    try:
        proc = _run_ffmpeg(cmd, timeout=timeout)
    except subprocess.TimeoutExpired:
        return ScreenshotResult(status="failed", error="RTSP frame timeout")
    except OSError:
        return ScreenshotResult(status="skipped", error="ffmpeg unavailable")
    if proc.returncode != 0 or not proc.stdout:
        err = (proc.stderr or b"").decode("utf-8", errors="replace").strip()[:200]
        return ScreenshotResult(status="failed", error=err or "RTSP frame failed")
    return ScreenshotResult(status="captured", data=_to_webp(proc.stdout))


@dataclass
class RtspProbe:
    url: str
    path: str
    host_used: str
    frame: ScreenshotResult


def probe_rtsp(
    scheme: str,
    hosts: list[str],
    port: int,
    *,
    timeout: float = 12.0,
    paths: tuple[str, ...] = RTSP_PATH_CANDIDATES,
    cancel_check: Callable[[], bool] | None = None,
) -> RtspProbe | None:
    """Try host/path combinations until one yields a frame."""
    for host in hosts:
        for path in paths:
            if cancel_check and cancel_check():
                return None
            url = build_rtsp_url(scheme, host, port, path)
            result = grab_frame(url, timeout=timeout)
            if result.status == "captured" and result.data:
                return RtspProbe(url=url, path=path, host_used=host, frame=result)
            if result.status == "skipped" and result.error == "ffmpeg unavailable":
                return RtspProbe(
                    url=build_rtsp_url(scheme, hosts[0], port, "/"),
                    path="/",
                    host_used=hosts[0],
                    frame=result,
                )
    return None


def acquire_live_slot() -> bool:
    global _live_count
    with _live_lock:
        if _live_count >= _MAX_LIVE_STREAMS:
            return False
        _live_count += 1
        return True


def release_live_slot() -> None:
    global _live_count
    with _live_lock:
        _live_count = max(0, _live_count - 1)


def iter_mjpeg(url: str, *, cancel_check: Callable[[], bool] | None = None) -> Iterator[bytes]:
    """Yield multipart MJPEG parts from an RTSP source (for StreamingResponse).

    Builds multipart boundaries ourselves so browsers always get a valid MJPEG
    stream. Raises RuntimeError if ffmpeg exits before producing a frame.
    """
    if not ffmpeg_available():
        raise RuntimeError("ffmpeg unavailable")
    cmd = [
        "ffmpeg",
        "-nostdin",
        "-hide_banner",
        "-loglevel",
        "error",
        "-rtsp_transport",
        "tcp",
        "-i",
        url,
        "-an",
        "-f",
        "image2pipe",
        "-vcodec",
        "mjpeg",
        "-q:v",
        "7",
        "-",
    ]
    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        **_popen_kwargs(),
    )
    assert proc.stdout is not None
    assert proc.stderr is not None
    frames = 0
    buf = b""
    try:
        while True:
            if cancel_check and cancel_check():
                break
            chunk = proc.stdout.read(4096)
            if not chunk:
                break
            buf += chunk
            # Split on JPEG SOI…EOI markers
            while True:
                start = buf.find(b"\xff\xd8")
                if start < 0:
                    buf = b""
                    break
                end = buf.find(b"\xff\xd9", start + 2)
                if end < 0:
                    buf = buf[start:]
                    break
                jpeg = buf[start : end + 2]
                buf = buf[end + 2 :]
                frames += 1
                yield (
                    f"--{MJPEG_BOUNDARY}\r\n"
                    f"Content-Type: image/jpeg\r\n"
                    f"Content-Length: {len(jpeg)}\r\n"
                    f"\r\n"
                ).encode("ascii") + jpeg + b"\r\n"
        err = (proc.stderr.read() or b"").decode("utf-8", errors="replace").strip()
        if frames == 0:
            raise RuntimeError(err or "ffmpeg produced no video frames")
    finally:
        try:
            proc.kill()
        except OSError:
            pass
        try:
            proc.wait(timeout=3)
        except Exception:
            pass


def placeholder_rtsp_webp() -> bytes:
    """Tiny labeled placeholder used in mock mode (reuses PNG→WEBP path)."""
    from .mock import placeholder_image

    raw = placeholder_image()
    try:
        from PIL import Image, ImageDraw

        img = Image.new("RGB", (640, 360), (20, 32, 48))
        draw = ImageDraw.Draw(img)
        draw.rectangle((40, 40, 600, 320), outline=(80, 160, 220), width=3)
        draw.text((220, 160), "RTSP (mock)", fill=(180, 210, 240))
        out = BytesIO()
        img.save(out, format="WEBP", quality=70)
        return out.getvalue()
    except Exception:
        return _to_webp(raw) if raw[:8] != b"RIFF" else raw
