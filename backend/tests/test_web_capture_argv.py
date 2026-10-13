"""Web Capture helper subprocess argv integrity (vncsnapshot, FreeRDP, RTSP/ffmpeg).

Invariants asserted for every external tool invocation:
- argv is a non-empty ``list[str]`` and ``shell=True`` is never passed;
- no token carries shell metacharacters, NUL or newlines beyond what the
  validated IP/port (or an exact, expected RTSP URL token) produce;
- the target IP/port appear only in the expected structured tokens
  (``/v:ip:port``, ``ip::port``, ``-i rtsp://...``) and the
  token holding the target never starts with ``-`` (cannot become an option);
- no token references a password / credentials file, and RDP sends only empty
  ``/u:`` ``/p:`` — no credential guessing, no stdin/arg-file credential sources;
- invalid targets are rejected upstream (``AddressSet.from_specs`` → HTTP 422,
  live RTSP port range → HTTP 400) before any argv can be built.

All tests run offline: ``shutil.which`` / ``subprocess`` are stubbed, no real
vncsnapshot / FreeRDP / ffmpeg binary or network peer is touched.
"""
from __future__ import annotations

import io
import ipaddress
import re
import socket
import subprocess
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.core.web_capture import rdp as rdp_mod
from app.core.web_capture import rtsp as rtsp_mod
from app.core.web_capture import vnc as vnc_mod
from app.main import app
from app.netutils import AddressSet, TargetError
from tests.test_api import csrf, setup_admin

# Documentation ranges only (RFC 5737).
IP = "192.0.2.10"
IP_ALT = "198.51.100.7"

SHELL_META = set(";&|$`<>\n\r\x00'\"(){}*!")
CANONICAL_IPV4 = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


@pytest.fixture
def client(db_env):
    from app.api.auth import limiter

    limiter.reset()
    with TestClient(app) as c:
        yield c


class _RunRecorder:
    """Stand-in for subprocess.run: records (argv, kwargs), never executes anything."""

    def __init__(self, *, returncode: int = 1, stdout: bytes = b"", stderr: bytes = b""):
        self.calls: list[tuple[list, dict]] = []
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr

    def __call__(self, args, **kwargs):
        self.calls.append((args, kwargs))
        return subprocess.CompletedProcess(args, self.returncode, self.stdout, self.stderr)


def _which_only(*names: str):
    """shutil.which stub that 'finds' only the given tool names."""
    return lambda name: f"/opt/tools/bin/{name}" if name in names else None


def _assert_argv_safe(argv, kwargs: dict, *, exempt: tuple[str, ...] = ()) -> None:
    assert isinstance(argv, list) and argv, "argv must be a non-empty list"
    assert all(isinstance(t, str) for t in argv), "every argv token must be str"
    assert kwargs.get("shell") is not True
    for tok in argv:
        if tok in exempt:
            continue
        assert not (set(tok) & SHELL_META), f"shell metacharacter in argv token {tok!r}"


def _assert_no_credential_files(argv: list[str]) -> None:
    for tok in argv:
        low = tok.lower()
        assert "passw" not in low, f"password reference in argv token {tok!r}"
        assert "cred" not in low, f"credential reference in argv token {tok!r}"
        assert not low.endswith((".rdp", ".vnc", ".pass", ".pwd")), f"credential-ish file in {tok!r}"


def _tokens_containing(argv: list[str], needle: str) -> list[str]:
    return [t for t in argv if needle in t]


# --- VNC ---------------------------------------------------------------------

def test_vncsnapshot_argv_is_fixed_list_without_password(monkeypatch, tmp_path):
    rec = _RunRecorder()
    monkeypatch.setattr(vnc_mod.shutil, "which", _which_only("vncsnapshot"))
    monkeypatch.setattr(vnc_mod.subprocess, "run", rec)
    out = tmp_path / "frame.png"

    assert vnc_mod._vncsnapshot(IP, 5901, out, timeout=5.0) is False  # no file written
    assert len(rec.calls) == 1
    argv, kw = rec.calls[0]
    _assert_argv_safe(argv, kw)
    _assert_no_credential_files(argv)
    assert argv == ["/opt/tools/bin/vncsnapshot", "-quality", "5", f"{IP}::5901", str(out)]
    assert not any(t.startswith("-passwd") for t in argv)
    # Target appears only in the host::display token, which cannot be read as an option.
    assert _tokens_containing(argv, IP) == [f"{IP}::5901"]
    assert kw["timeout"] == pytest.approx(8.0)


def _rfb_fails(exc):
    def grab(ip, port, *, timeout):
        raise exc
    return grab


def test_grab_vnc_frame_falls_back_to_vncsnapshot_in_private_tmp(monkeypatch):
    rec = _RunRecorder()
    monkeypatch.setattr(vnc_mod, "_rfb_grab", _rfb_fails(vnc_mod.RfbError("unexpected encoding")))
    monkeypatch.setattr(vnc_mod.shutil, "which", _which_only("vncsnapshot", "ffmpeg"))
    monkeypatch.setattr(vnc_mod.subprocess, "run", rec)

    shot = vnc_mod.grab_vnc_frame(IP_ALT, 5902, timeout=5.0)
    assert shot.status == "failed"
    # Only vncsnapshot runs (ffmpeg has no VNC input); its argv is safe.
    assert [Path(c[0][0]).name for c in rec.calls] == ["vncsnapshot"]
    argv, kw = rec.calls[0]
    _assert_argv_safe(argv, kw)
    _assert_no_credential_files(argv)
    assert _tokens_containing(argv, IP_ALT) == [f"{IP_ALT}::5902"]
    # Output target lives in a per-call temp dir, not a caller-controlled path.
    assert Path(argv[-1]).parent.name.startswith("nf-vnc-")


@pytest.mark.parametrize("exc", [vnc_mod.RfbAuthRequired(), vnc_mod.RfbHandshakeError("not an RFB server")])
def test_grab_vnc_frame_password_or_non_rfb_never_spawns_tools(monkeypatch, exc):
    def boom(*a, **k):
        raise AssertionError("no subprocess may run for a password-protected or non-RFB server")

    monkeypatch.setattr(vnc_mod, "_rfb_grab", _rfb_fails(exc))
    monkeypatch.setattr(vnc_mod.shutil, "which", _which_only("vncsnapshot", "ffmpeg"))
    monkeypatch.setattr(vnc_mod.subprocess, "run", boom)

    shot = vnc_mod.grab_vnc_frame(IP, 5900, timeout=5.0)
    if isinstance(exc, vnc_mod.RfbAuthRequired):
        assert shot.status == "skipped" and shot.auth_required is True
    else:
        assert shot.status == "failed" and not shot.auth_required


# --- FreeRDP -----------------------------------------------------------------

_RDP_FORBIDDEN_PREFIXES = (
    "/pth:", "/from-stdin", "/args-from", "/gu:", "/gp:", "/gd:", "/d:", "/smartcard",
    "/password", "/assistance", "/load-balance-info",
)


def test_freerdp_argv_empty_credentials_and_structured_target(monkeypatch):
    rec = _RunRecorder(returncode=1, stderr=b"ERRCONNECT_LOGON_FAILURE")
    monkeypatch.setattr(rdp_mod.shutil, "which", _which_only("xfreerdp"))
    monkeypatch.setattr(rdp_mod.subprocess, "run", rec)

    shot = rdp_mod.grab_rdp_frame(IP, 3390, timeout=7.0)
    assert shot.status == "skipped" and shot.auth_required is True
    # One attempt per security profile, in order; never a retry with credentials.
    assert len(rec.calls) == len(rdp_mod._SEC_PROFILES) == 3
    profiles = []
    for argv, kw in rec.calls:
        _assert_argv_safe(argv, kw)
        _assert_no_credential_files(argv)
        assert argv[0] == "/opt/tools/bin/xfreerdp"
        assert argv[1] == f"/v:{IP}:3390"
        assert re.fullmatch(r"/v:\d{1,3}(\.\d{1,3}){3}:\d{1,5}", argv[1])
        assert _tokens_containing(argv, IP) == [f"/v:{IP}:3390"]
        assert [t for t in argv if t.startswith("/u:")] == ["/u:"]
        assert [t for t in argv if t.startswith("/p:")] == ["/p:"]
        assert not any(t.startswith(_RDP_FORBIDDEN_PREFIXES) for t in argv)
        assert "/cert:ignore" in argv and "/timeout:7000" in argv
        shots = [t for t in argv if t.startswith("/screenshot:")]
        assert len(shots) == 1
        assert Path(shots[0][len("/screenshot:"):]).parent.name.startswith("nf-rdp-")
        profiles.append(tuple(argv[10:]))
    assert profiles == list(rdp_mod._SEC_PROFILES)


def test_freerdp_timeout_still_uses_only_safe_argv(monkeypatch):
    calls: list[tuple[list, dict]] = []

    def timeout_run(args, **kw):
        calls.append((args, kw))
        raise subprocess.TimeoutExpired(args, kw.get("timeout", 0))

    monkeypatch.setattr(rdp_mod.shutil, "which", _which_only("sdl-freerdp"))
    monkeypatch.setattr(rdp_mod.subprocess, "run", timeout_run)

    shot = rdp_mod.grab_rdp_frame(IP_ALT, 3389, timeout=3.0)
    assert shot.status == "skipped" and shot.error == "skipped_auth"
    assert len(calls) == 3
    for argv, kw in calls:
        _assert_argv_safe(argv, kw)
        _assert_no_credential_files(argv)
        assert argv[1] == f"/v:{IP_ALT}:3389"
        assert kw["timeout"] == pytest.approx(8.0)


def test_freerdp_unavailable_spawns_nothing(monkeypatch):
    def boom(*a, **k):
        raise AssertionError("subprocess must not run without a FreeRDP client")

    monkeypatch.setattr(rdp_mod.shutil, "which", _which_only())
    monkeypatch.setattr(rdp_mod.subprocess, "run", boom)
    assert rdp_mod.grab_rdp_frame(IP, 3389).error == "freerdp unavailable"


# --- RTSP / ffmpeg -----------------------------------------------------------

def _assert_ffmpeg_rtsp_argv(argv: list[str], kw: dict, url: str) -> None:
    _assert_argv_safe(argv, kw, exempt=(url,))
    _assert_no_credential_files(argv)
    assert argv[0] == "ffmpeg"
    assert "-nostdin" in argv
    # URL is exactly one token, directly after -i, and cannot be parsed as an option.
    assert argv.count(url) == 1
    assert argv[argv.index("-i") + 1] == url
    assert url.startswith(("rtsp://", "rtsps://"))
    assert argv.count("-i") == 1
    # Output is stdout only — never a filesystem path.
    assert argv[-1] == "-"
    for tok in argv:
        assert not tok.startswith(("file:", "concat:", "subfile:", "pipe:")), tok
    assert "lavfi" not in argv


def test_grab_frame_ffmpeg_argv(monkeypatch):
    rec = _RunRecorder(returncode=1, stderr=b"401 Unauthorized")
    monkeypatch.setattr(rtsp_mod.shutil, "which", _which_only("ffmpeg"))
    monkeypatch.setattr(rtsp_mod, "looks_like_rtsp", lambda url, timeout: (True, "RTSP/1.0 200 OK"))
    monkeypatch.setattr(rtsp_mod.subprocess, "run", rec)

    url = rtsp_mod.build_rtsp_url("rtsp", IP, 8554, "/stream1")
    assert url == f"rtsp://{IP}:8554/stream1"
    res = rtsp_mod.grab_frame(url, timeout=6.0)
    assert res.status == "failed"
    assert len(rec.calls) == 1
    argv, kw = rec.calls[0]
    _assert_ffmpeg_rtsp_argv(argv, kw, url)
    assert _tokens_containing(argv, IP) == [url]
    assert kw["timeout"] == pytest.approx(6.0)


def test_grab_frame_not_rtsp_spawns_nothing(monkeypatch):
    def boom(*a, **k):
        raise AssertionError("ffmpeg must not run when the RTSP OPTIONS check fails")

    monkeypatch.setattr(rtsp_mod.shutil, "which", _which_only("ffmpeg"))
    monkeypatch.setattr(rtsp_mod, "looks_like_rtsp", lambda url, timeout: (False, "not RTSP"))
    monkeypatch.setattr(rtsp_mod.subprocess, "run", boom)
    assert rtsp_mod.grab_frame(f"rtsp://{IP}/").status == "failed"


def test_probe_rtsp_every_candidate_url_is_one_argv_token(monkeypatch):
    rec = _RunRecorder(returncode=1)
    monkeypatch.setattr(rtsp_mod.shutil, "which", _which_only("ffmpeg"))
    monkeypatch.setattr(rtsp_mod, "looks_like_rtsp", lambda url, timeout: (True, "RTSP/1.0 200 OK"))
    monkeypatch.setattr(rtsp_mod.subprocess, "run", rec)

    # Inventory hostnames (DNS/NetBIOS) are not AddressSet-validated; a hostile one must
    # still be confined to the single URL token after -i and never lead an argv token.
    hosts = ["-o.example", IP]
    assert rtsp_mod.probe_rtsp("rtsp", hosts, 554) is None
    expected = [
        rtsp_mod.build_rtsp_url("rtsp", h, 554, p) for h in hosts for p in rtsp_mod.RTSP_PATH_CANDIDATES
    ]
    assert len(rec.calls) == len(expected)
    for (argv, kw), url in zip(rec.calls, expected, strict=True):
        _assert_ffmpeg_rtsp_argv(argv, kw, url)
        assert not any(t.startswith("-o") for t in argv)


def test_iter_mjpeg_popen_argv(monkeypatch):
    calls: list[tuple[list, dict]] = []

    class FakeProc:
        def __init__(self):
            self.stdout = io.BytesIO(b"\xff\xd8jpegdata\xff\xd9")
            self.stderr = io.BytesIO(b"")

        def kill(self):
            pass

        def wait(self, timeout=None):
            return 0

    def fake_popen(args, **kw):
        calls.append((args, kw))
        return FakeProc()

    monkeypatch.setattr(rtsp_mod.shutil, "which", _which_only("ffmpeg"))
    monkeypatch.setattr(rtsp_mod.subprocess, "Popen", fake_popen)

    url = rtsp_mod.build_rtsp_url("rtsps", IP_ALT, 322, "/live")
    parts = list(rtsp_mod.iter_mjpeg(url))
    assert len(parts) == 1 and b"jpegdata" in parts[0]
    assert len(calls) == 1
    argv, kw = calls[0]
    _assert_ffmpeg_rtsp_argv(argv, kw, url)
    assert _tokens_containing(argv, IP_ALT) == [url]
    assert kw["stdout"] is subprocess.PIPE


# --- Upstream validation (before any argv is built) ---------------------------

_BAD_TARGETS = [
    "192.0.2.1;id",
    "$(id)",
    "`id`",
    "-o",
    "--help",
    "192.0.2.1\nid",
    "192.0.2.1|id",
    "192.0.2.1&&id",
    "192.0.2.1>out",
    "192.0.2.1:3389",
    "192.0.2.256",
    "192.0.2.1/33",
    "2001:db8::1",
    "192.0.2.1\x00",
]


@pytest.fixture
def no_dns(monkeypatch):
    """Hostname-looking fragments (e.g. 'id') must never hit real DNS in tests."""

    def fail(*a, **k):
        raise socket.gaierror("offline test")

    monkeypatch.setattr(socket, "getaddrinfo", fail)


@pytest.mark.parametrize("spec", _BAD_TARGETS)
def test_address_set_rejects_shell_payload_targets(spec, no_dns):
    with pytest.raises(TargetError):
        AddressSet.from_specs(spec, allow_hostname=True)


def test_address_set_only_yields_canonical_ipv4(monkeypatch):
    # Even a resolved hostname is re-serialized via ipaddress before reaching inventory lookup.
    monkeypatch.setattr(
        socket, "getaddrinfo", lambda *a, **k: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (IP_ALT, 0))]
    )
    aset = AddressSet.from_specs("192.0.2.1-3, 198.51.100.0/30; cam01.example", allow_hostname=True)
    addrs = list(aset.addresses())
    assert IP_ALT in addrs and "192.0.2.2" in addrs
    for a in addrs:
        assert CANONICAL_IPV4.fullmatch(a)
        assert str(ipaddress.IPv4Address(a)) == a


@pytest.mark.parametrize("spec", _BAD_TARGETS)
def test_web_capture_api_rejects_shell_payload_targets(spec, client, no_dns):
    setup_admin(client)
    r = client.post("/api/web-captures", json={"targets": spec}, headers=csrf(client))
    assert r.status_code == 422, (spec, r.text)


@pytest.mark.parametrize("bad_port", [0, 70000, -1])
def test_live_rtsp_rejects_out_of_range_port(bad_port, client):
    setup_admin(client)
    r = client.get(f"/api/devices/00000000-0000-0000-0000-000000000000/rtsp/{bad_port}/live")
    assert r.status_code == 400, r.text
