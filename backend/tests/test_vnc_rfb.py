"""Built-in RFB client: one Raw framebuffer from no-auth VNC servers, never a password.

Each test runs a scripted fake server on 127.0.0.1 (no external VNC tool or real host).
"""
from __future__ import annotations

import socket
import struct
import threading
from collections.abc import Callable
from io import BytesIO

import pytest
from PIL import Image

from app.core.web_capture import vnc


class Peer:
    """Server side of one connection, as seen by a test script."""

    def __init__(self, conn: socket.socket):
        self.conn = conn
        self.received: list[bytes] = []

    def send(self, data: bytes) -> None:
        self.conn.sendall(data)

    def recv(self, n: int) -> bytes:
        buf = b""
        while len(buf) < n:
            chunk = self.conn.recv(n - len(buf))
            if not chunk:
                raise ConnectionError("client closed")
            buf += chunk
        self.received.append(buf)
        return buf

    def leftover(self) -> bytes:
        """Whatever the client sent that the script did not read (until it closes)."""
        self.conn.settimeout(2)
        out = b""
        try:
            while chunk := self.conn.recv(4096):
                out += chunk
        except OSError:
            pass
        return out


@pytest.fixture
def server():
    """Start a one-connection fake server running `script(peer)`; returns (port, peer holder)."""
    listeners: list[socket.socket] = []
    threads: list[threading.Thread] = []

    def start(script: Callable[[Peer], None]):
        lsock = socket.create_server(("127.0.0.1", 0))
        listeners.append(lsock)
        state: dict = {}

        def run():
            conn, _ = lsock.accept()
            with conn:
                peer = Peer(conn)
                state["peer"] = peer
                try:
                    script(peer)
                except (ConnectionError, OSError) as exc:
                    state["error"] = exc
                state["leftover"] = peer.leftover()

        t = threading.Thread(target=run, daemon=True)
        t.start()
        threads.append(t)
        return lsock.getsockname()[1], state, t

    yield start
    for t in threads:
        t.join(timeout=5)
    for s in listeners:
        s.close()


# 3x2 desktop. Pixels on the wire are B, G, R, padding (the client's requested format).
RED, GREEN, BLUE, WHITE, BLACK, GREY = (255, 0, 0), (0, 255, 0), (0, 0, 255), (255, 255, 255), (0, 0, 0), (90, 90, 90)
ROWS = [[RED, GREEN, BLUE], [WHITE, BLACK, GREY]]


def wire(row: list[tuple[int, int, int]]) -> bytes:
    return b"".join(bytes((b, g, r, 0)) for r, g, b in row)


def server_init(width=3, height=2, name=b"desk") -> bytes:
    return struct.pack(">HH", width, height) + bytes(16) + struct.pack(">I", len(name)) + name


def rect(x, y, w, h, encoding=0) -> bytes:
    return struct.pack(">HHHHi", x, y, w, h, encoding)


def update(*rects: bytes, count: int) -> bytes:
    return struct.pack(">BxH", 0, count) + b"".join(rects)


def after_security(peer: Peer, *, width=3, height=2) -> None:
    """ClientInit, ServerInit and the client's format/encoding/update requests."""
    assert peer.recv(1) == b"\x01"  # shared: other viewers stay connected
    peer.send(server_init(width, height))
    assert peer.recv(20) == struct.pack(">B3x", 0) + vnc._PIXEL_FORMAT
    assert peer.recv(8) == struct.pack(">BxHi", 2, 1, 0)  # SetEncodings: Raw only
    assert peer.recv(10) == struct.pack(">BBHHHH", 3, 0, 0, 0, width, height)  # full, non-incremental


def pixels(png: bytes) -> list[list[tuple[int, int, int]]]:
    img = Image.open(BytesIO(png)).convert("RGB")
    return [[img.getpixel((x, y)) for x in range(img.width)] for y in range(img.height)]


def test_rfb_38_no_auth_frame(server):
    def script(peer: Peer):
        peer.send(b"RFB 003.008\n")
        assert peer.recv(12) == b"RFB 003.008\n"
        peer.send(bytes([2, vnc.SEC_VNC, vnc.SEC_NONE]))
        assert peer.recv(1) == bytes([vnc.SEC_NONE])
        peer.send(struct.pack(">I", 0))  # SecurityResult OK
        after_security(peer)
        peer.send(b"\x02")  # Bell
        peer.send(b"\x03\x00\x00\x00" + struct.pack(">I", 5) + b"hello")  # ServerCutText
        peer.send(update(rect(0, 0, 3, 1) + wire(ROWS[0]), rect(0, 1, 3, 1) + wire(ROWS[1]), count=2))

    port, state, t = server(script)
    png = vnc._rfb_grab("127.0.0.1", port, timeout=5)
    t.join(5)
    assert "error" not in state
    assert pixels(png) == ROWS


def test_rfb_33_no_auth_and_partial_updates(server):
    def script(peer: Peer):
        peer.send(b"RFB 003.003\n")
        assert peer.recv(12) == b"RFB 003.003\n"
        peer.send(struct.pack(">I", vnc.SEC_NONE))  # 3.3: the server picks the type
        after_security(peer)
        peer.send(update(rect(0, 0, 3, 1) + wire(ROWS[0]), count=1))  # first half only
        assert peer.recv(10) == struct.pack(">BBHHHH", 3, 0, 0, 0, 3, 2)  # client asks again
        peer.send(update(rect(0, 1, 3, 1) + wire(ROWS[1]), count=1))

    port, state, t = server(script)
    assert pixels(vnc._rfb_grab("127.0.0.1", port, timeout=5)) == ROWS
    t.join(5)
    assert "error" not in state


@pytest.mark.parametrize("banner,reply", [(b"RFB 003.007\n", b"RFB 003.007\n"), (b"RFB 003.889\n", b"RFB 003.008\n")])
def test_rfb_version_negotiation(server, banner, reply):
    def script(peer: Peer):
        peer.send(banner)
        assert peer.recv(12) == reply
        peer.send(bytes([1, vnc.SEC_NONE]))
        peer.recv(1)
        if reply.endswith(b"8\n"):
            peer.send(struct.pack(">I", 0))  # 3.7 has no SecurityResult for None
        after_security(peer)
        peer.send(update(rect(0, 0, 3, 2) + wire(ROWS[0]) + wire(ROWS[1]), count=1))

    port, state, t = server(script)
    assert pixels(vnc._rfb_grab("127.0.0.1", port, timeout=5)) == ROWS
    t.join(5)
    assert "error" not in state


@pytest.mark.parametrize("version,offer", [
    (b"RFB 003.008\n", bytes([1, vnc.SEC_VNC])),
    (b"RFB 003.008\n", bytes([2, 30, 35])),  # Apple Remote Desktop types only
    (b"RFB 003.003\n", struct.pack(">I", vnc.SEC_VNC)),
])
def test_password_servers_are_skipped_without_sending_anything(server, version, offer):
    def script(peer: Peer):
        peer.send(version)
        peer.recv(12)
        peer.send(offer)

    port, state, t = server(script)
    shot = vnc.grab_vnc_frame("127.0.0.1", port, timeout=5)
    t.join(5)
    assert shot.status == "skipped" and shot.auth_required and shot.error == "skipped_auth"
    assert state["leftover"] == b""  # no security type chosen, no password, nothing else


@pytest.mark.parametrize("script_bytes", [
    b"SSH-2.0-OpenSSH_9.6\r\n",  # not RFB
    b"RFB 003.008\n",  # then refuses: zero security types + reason
])
def test_non_rfb_and_refusing_servers_fail_the_handshake(server, script_bytes):
    def script(peer: Peer):
        peer.send(script_bytes)
        if script_bytes.startswith(b"RFB"):
            peer.recv(12)
            peer.send(b"\x00" + struct.pack(">I", 9) + b"too many!")

    port, state, t = server(script)
    shot = vnc.grab_vnc_frame("127.0.0.1", port, timeout=5)
    t.join(5)
    assert shot.status == "failed" and shot.error == "vnc handshake failed" and not shot.auth_required


def test_closed_port_fails_the_handshake():
    with socket.create_server(("127.0.0.1", 0)) as s:
        port = s.getsockname()[1]
    assert vnc.grab_vnc_frame("127.0.0.1", port, timeout=2).error == "vnc handshake failed"


def test_oversized_framebuffer_is_refused_before_pixels(server):
    def script(peer: Peer):
        peer.send(b"RFB 003.008\n")
        peer.recv(12)
        peer.send(bytes([1, vnc.SEC_NONE]))
        peer.recv(1)
        peer.send(struct.pack(">I", 0))
        peer.recv(1)
        peer.send(server_init(5000, 5000))

    port, state, t = server(script)
    with pytest.raises(vnc.RfbError, match="too large"):
        vnc._rfb_grab("127.0.0.1", port, timeout=5)
    t.join(5)
    assert state["leftover"] == b""  # no SetPixelFormat / update request sent


@pytest.mark.parametrize("tail", [
    update(rect(0, 0, 3, 2, encoding=7), count=1),  # Tight: never requested
    update(rect(2, 1, 3, 2), count=1),  # rectangle past the framebuffer edge
    b"\x09",  # unknown message type
    b"",  # silence: the deadline expires
])
def test_frame_errors_fall_back_and_fail_cleanly(server, monkeypatch, tail):
    monkeypatch.setattr(vnc.shutil, "which", lambda _name: None)  # no vncsnapshot installed

    def script(peer: Peer):
        peer.send(b"RFB 003.008\n")
        peer.recv(12)
        peer.send(bytes([1, vnc.SEC_NONE]))
        peer.recv(1)
        peer.send(struct.pack(">I", 0))
        after_security(peer)
        peer.send(tail)

    port, state, t = server(script)
    shot = vnc.grab_vnc_frame("127.0.0.1", port, timeout=1.5)
    t.join(5)
    assert shot.status == "failed" and shot.error.startswith("vnc frame failed: ")


def test_captured_frame_is_returned_as_webp(server):
    def script(peer: Peer):
        peer.send(b"RFB 003.008\n")
        peer.recv(12)
        peer.send(bytes([1, vnc.SEC_NONE]))
        peer.recv(1)
        peer.send(struct.pack(">I", 0))
        after_security(peer)
        peer.send(update(rect(0, 0, 3, 2) + wire(ROWS[0]) + wire(ROWS[1]), count=1))

    port, state, t = server(script)
    shot = vnc.grab_vnc_frame("127.0.0.1", port, timeout=5)
    t.join(5)
    assert shot.status == "captured" and shot.data
    img = Image.open(BytesIO(shot.data))
    assert img.format == "WEBP" and img.size == (3, 2)
