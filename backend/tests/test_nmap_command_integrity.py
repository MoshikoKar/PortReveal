"""Scan-command integrity: the single entrypoint for "can user input change what nmap runs?".

Threat model. Scan targets, settings, network flags and the local interface list all flow into an nmap
command line. An attacker (or a careless admin) controls targets and settings; the interface list comes
from ``nmap --iflist`` output. None of them may add, remove or reinterpret nmap options.

Invariants and where they are locked down:

1. nmap runs from a list argv, never through a shell; targets reach nmap only through an ``-iL`` file.
   -> ``test_run_argv_is_a_list_and_targets_go_through_il_file``, and end to end through
   ``NmapScanner.discover`` / ``scan_ports``: ``test_discover_*``, ``test_scan_ports_*`` (below).
2. Option sets are fixed by code: no ``--script``, ``-A``, ``-iR`` or UDP probes; timing/rate values come
   from closed sets. -> ``assert_safe_argv`` on every composed command (below),
   ``tests/test_scanner.py::test_nmap_arguments_are_fixed_and_safe``,
   ``tests/test_vpn_s2s.py`` (VPN S2S rate caps), ``tests/test_identify_ai.py::test_fixed_port_args_include_ai_candidates``.
3. Targets are parsed into IPv4 addresses before a scan is queued; anything else is 422.
   -> ``test_crafted_targets_never_validate`` (below), ``tests/test_api.py::test_scan_flow_through_api``
   (``"10.0.0.1; reboot"``), ``tests/test_api.py::test_network_and_exclusion_validation`` (CIDR with shell text).
4. Interface bind values (``-e``/``-S``) are a plain interface name and an IPv4 address, checked where
   they become argv, so a hostile ``--iflist`` line cannot inject an option.
   -> ``test_bind_*`` and ``test_run_drops_unsafe_bind_values`` (below).
5. Web-capture helpers (VNC, FreeRDP, ffmpeg/RTSP) follow the same rules.
   -> ``tests/test_web_capture_argv.py``.
6. Scan settings are a closed set: ``timing`` is one of polite/normal/fast, numbers are range-checked and
   unknown fields (raw nmap arguments) are a 422 and never stored.
   -> ``test_scan_settings_*`` (below).
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.api.auth import limiter
from app.db import session_scope
from app.main import app
from app.models import AppSetting
from app.netutils import AddressSet, TargetError
from app.scanner import nmap_scanner
from app.scanner.nmap_iface import BindChoice, bind_args, parse_nmap_iflist
from app.scanner.script_allowlist import MAX_SCRIPT_TIMEOUT_S, MIN_SCRIPT_TIMEOUT_S, SCRIPT_NAMES
from app.scanner.types import PortProfile, ScanContext
from app.settings_store import ScanSettings

FINISHED_XML = '<?xml version="1.0"?><nmaprun><runstats><finished exit="success"/></runstats></nmaprun>'
SHELL_CHARS = set(";&|$`<>\n\r'\"")
# "-O" is not here: it is allowed, but only paired with --osscan-limit --max-os-tries 1
# (asserted separately in assert_safe_argv) as the single narrow UDP exception (one U1 probe).
# "--script" is not a blanket denial either (spec 8.4.6): assert_safe_argv below allows it only
# when every name after it is in SCRIPT_ALLOWLIST. "-sC" (shorthand for --script=default, a whole
# category) stays denied, and so does "--script-args" (never a free-form value reaches nmap).
DENIED_OPTIONS = ("-A", "-iR", "-sU", "-sC", "-PU", "-sY", "-PY")
# Compact nmap forms attach the value to the flag (`-PU53`); still denied.
_DENIED_PREFIXES = ("-PU", "-sU", "-sY", "-PY", "-sC")
CRAFTED_TARGETS = ["10.0.0.1; reboot", "$(id)", "`id`", "10.0.0.2\n-iR 0", "10.0.0.3 && rm -rf /", "--script=evil"]


class PopenSpy:
    """Stands in for subprocess.Popen: records argv/kwargs and the -iL file contents, runs nothing."""

    calls: list[dict] = []

    def __init__(self, cmd, **kwargs):
        target_file = Path(cmd[cmd.index("-iL") + 1])
        PopenSpy.calls.append({"cmd": cmd, "kwargs": kwargs, "targets": target_file.read_text()})
        self.returncode = 0

    def communicate(self, timeout=None):
        return FINISHED_XML, ""

    def kill(self):
        pass


@pytest.fixture
def scanner(tmp_path, monkeypatch):
    PopenSpy.calls = []
    monkeypatch.setattr(nmap_scanner.shutil, "which", lambda _p: "/usr/bin/nmap")
    monkeypatch.setattr(nmap_scanner.subprocess, "Popen", PopenSpy)
    # No `nmap --iflist` run: discover / scan_ports bind to no interface.
    monkeypatch.setattr(nmap_scanner, "resolve_bind", lambda _exe, _t, privileged: BindChoice(None, privileged))
    return nmap_scanner.NmapScanner("nmap", privileged=True, timing="normal", tmp_dir=tmp_path)


def assert_safe_argv(call: dict) -> None:
    """Invariants 1 and 2 for one recorded Popen call."""
    cmd = call["cmd"]
    assert isinstance(cmd, list) and all(isinstance(a, str) for a in cmd)
    assert not call["kwargs"].get("shell")
    assert cmd.count("-iL") == 1 and cmd[-2:] == ["-oX", "-"]
    for i, arg in enumerate(cmd):
        assert not any(arg == d or arg.startswith(d + "=") for d in DENIED_OPTIONS), arg
        assert not any(arg.startswith(p) and len(arg) > len(p) for p in _DENIED_PREFIXES), arg
        assert not arg.startswith("--script-args"), arg
        assert not SHELL_CHARS & set(arg), arg
        if arg == "--script":
            names = cmd[i + 1].split(",")
            assert names and all(n and n in SCRIPT_NAMES for n in names), cmd[i + 1]
            assert "," not in cmd[i + 1] or all(re.fullmatch(r"[a-z0-9][a-z0-9-]*", n) for n in names)
        elif arg.startswith("--script="):
            pytest.fail(f"--script=<category> (whole category) is never allowed: {arg}")
        if arg == "--script-timeout":
            val = cmd[i + 1]
            m = re.fullmatch(r"(\d+)s", val)
            assert m, val
            assert MIN_SCRIPT_TIMEOUT_S <= int(m.group(1)) <= MAX_SCRIPT_TIMEOUT_S, val
    # The one UDP exception (-O's single U1 probe) only ever appears with its two safety flags.
    if "-O" in cmd:
        i = cmd.index("-O")
        assert cmd[i:i + 4] == ["-O", "--osscan-limit", "--max-os-tries", "1"], cmd


def _run(scanner, bind: BindChoice | None, targets=("192.0.2.1", "192.0.2.2")) -> dict:
    scanner._run(["-sn"], list(targets), 30, ScanContext(1), "discovery", bind=bind)
    assert len(PopenSpy.calls) == 1
    return PopenSpy.calls[0]


def test_run_argv_is_a_list_and_targets_go_through_il_file(scanner):
    call = _run(scanner, None)
    cmd = call["cmd"]
    assert isinstance(cmd, list) and all(isinstance(a, str) for a in cmd)
    assert not call["kwargs"].get("shell")
    assert cmd[0] == "/usr/bin/nmap" and cmd[-2:] == ["-oX", "-"] and cmd.count("-iL") == 1
    assert call["targets"] == "192.0.2.1\n192.0.2.2\n"
    assert not any(t in cmd for t in ("192.0.2.1", "192.0.2.2"))  # never on the command line


def test_bind_args_for_a_normal_interface():
    assert bind_args(None) == []
    assert bind_args(BindChoice(device=None, privileged=True)) == []
    assert bind_args(BindChoice(device="eth0", privileged=False)) == ["-e", "eth0"]
    assert bind_args(BindChoice(device="eth0", privileged=True, source="192.0.2.10")) == \
        ["-e", "eth0", "-S", "192.0.2.10"]


@pytest.mark.parametrize("device", [
    "-oN/tmp/out", "--script=evil", "eth0;id", "eth0 -A", "$(id)", "eth0\n-iR", "eth0`id`", "a" * 40, "0eth",
])
def test_bind_rejects_unsafe_device(device):
    assert bind_args(BindChoice(device=device, privileged=True, source="192.0.2.10")) == []


@pytest.mark.parametrize("source", ["192.0.2.10;id", "-S", "--script=x", "192.0.2.256", "2001:db8::1", "eth0"])
def test_bind_drops_unsafe_source_but_keeps_device(source):
    assert bind_args(BindChoice(device="eth0", privileged=True, source=source)) == ["-e", "eth0"]


def test_run_drops_unsafe_bind_values(scanner):
    cmd = _run(scanner, BindChoice(device="-oN/tmp/pwn", privileged=True, source="192.0.2.9;id"))["cmd"]
    assert "-e" not in cmd and "-S" not in cmd
    assert not any("pwn" in a or ";id" in a for a in cmd)
    assert not any(SHELL_CHARS & set(a) for a in cmd)


def test_run_passes_a_valid_bind(scanner):
    cmd = _run(scanner, BindChoice(device="eth1", privileged=True, source="192.0.2.10"))["cmd"]
    i = cmd.index("-e")
    assert cmd[i:i + 4] == ["-e", "eth1", "-S", "192.0.2.10"] and i < cmd.index("-iL")


def test_iflist_parser_skips_hostile_device_names():
    text = "\n".join([
        "************************INTERFACES************************",
        "DEV            (SHORT)   IP/MASK          TYPE     UP MTU   MAC",
        "eth0           (eth0)    192.0.2.10/24    ethernet up 1500  00:00:5E:00:53:01",
        "-oN/tmp/x      (x)       198.51.100.1/24  ethernet up 1500  00:00:5E:00:53:02",
        "eth1;id        (y)       198.51.100.2/24  ethernet up 1500  00:00:5E:00:53:03",
        "**************************ROUTES**************************",
    ])
    assert [i.dev for i in parse_nmap_iflist(text)] == ["eth0"]


# --- end to end through NmapScanner with a Popen spy ------------------------------------------------
@pytest.mark.parametrize("spec", CRAFTED_TARGETS)
def test_crafted_targets_never_validate(spec):
    with pytest.raises(TargetError):
        AddressSet.from_specs(spec)


def test_discover_writes_only_validated_targets_to_the_il_file(scanner):
    targets = AddressSet.from_specs("192.0.2.0/30, 192.0.2.9").chunks(1024)[0]
    scanner.discover(targets, ScanContext(1))
    assert len(PopenSpy.calls) == 1
    call = PopenSpy.calls[0]
    assert_safe_argv(call)
    assert call["targets"].splitlines() == targets == ["192.0.2.0/30", "192.0.2.9"]
    assert not any(t in call["cmd"] for t in targets)


@pytest.mark.parametrize("full,os_detection", [(False, False), (False, True), (True, True)])
def test_scan_ports_every_nmap_run_is_safe(scanner, full, os_detection):
    ips = list(AddressSet.from_specs("192.0.2.1-192.0.2.3").addresses())
    ctx = ScanContext(2)
    ctx.known_truenas_ips = {"192.0.2.2"}  # also exercise the TrueNAS apps run
    profile = PortProfile(full=full, top_ports=1000, timing="fast", os_detection=os_detection)
    scanner.scan_ports(ips, profile, ctx)
    assert len(PopenSpy.calls) >= 2
    for call in PopenSpy.calls:
        assert_safe_argv(call)
        assert set(call["targets"].splitlines()) <= set(ips)
        assert not any(ip in call["cmd"] for ip in ips)
    # os_detection on a privileged scanner requests -O on the primary port-scan run (not the
    # fixed-port TrueNAS-apps follow-up, which never carries OS detection).
    saw_os_detection = any("-O" in call["cmd"] for call in PopenSpy.calls)
    assert saw_os_detection == os_detection


@pytest.mark.parametrize("privileged,os_detection,expect_os", [
    (True, True, True), (True, False, False), (False, True, False), (False, False, False),
])
def test_build_port_args_os_detection_is_privileged_and_narrow(privileged, os_detection, expect_os):
    """-O is only requested when privileged AND enabled, and always with its two safety flags."""
    profile = PortProfile(full=False, top_ports=1000, timing="fast", os_detection=os_detection)
    args = nmap_scanner.build_port_args(privileged, profile)
    assert ("-O" in args) == expect_os
    if expect_os:
        i = args.index("-O")
        assert args[i:i + 4] == ["-O", "--osscan-limit", "--max-os-tries", "1"]
    for bad in ("-sU", "-PU", "-sY", "-PY"):
        assert bad not in args


# --- phase 4: allow-listed vulnerability scripts (spec 8.4.6) ------------------------------------
def test_build_script_args_allows_only_allowlisted_names():
    args = nmap_scanner.build_script_args(True, ["smb-vuln-ms17-010", "smb-os-discovery"], [445], "normal")
    i = args.index("--script")
    assert args[i + 1] == "smb-os-discovery,smb-vuln-ms17-010"  # sorted, deduped
    j = args.index("--script-timeout")
    assert args[j + 1] == "30s"
    assert "-p" in args and "445" in args[args.index("-p") + 1]
    for bad in ("--script-args", "-A", "-iR", "-sU", "-sC"):
        assert bad not in args


def test_build_script_args_rejects_name_outside_allowlist():
    with pytest.raises(ValueError, match="SCRIPT_ALLOWLIST"):
        nmap_scanner.build_script_args(True, ["smb-vuln-ms17-010", "vulners"], [445], "normal")


def test_build_script_args_rejects_whole_category():
    with pytest.raises(ValueError, match="SCRIPT_ALLOWLIST"):
        nmap_scanner.build_script_args(True, ["vuln"], [445], "normal")


def test_build_script_args_rejects_timeout_outside_closed_range():
    with pytest.raises(ValueError, match="timeout"):
        nmap_scanner.build_script_args(True, ["ssh2-enum-algos"], [22], "normal", timeout_s=5)
    with pytest.raises(ValueError, match="timeout"):
        nmap_scanner.build_script_args(True, ["ssh2-enum-algos"], [22], "normal", timeout_s=120)


def test_run_scripts_end_to_end_is_safe(scanner):
    scanner.run_scripts(["192.0.2.1"], ["smb-vuln-ms17-010"], [445], ScanContext(4), 30)
    assert len(PopenSpy.calls) == 1
    assert_safe_argv(PopenSpy.calls[0])


def test_unvalidated_strings_reach_nmap_only_as_il_file_lines(scanner):
    """Defence in depth: even if a crafted string slipped past validation it would be one -iL line,
    never an argv element, so it cannot add an option or reach a shell."""
    scanner.discover(CRAFTED_TARGETS[:3], ScanContext(3))
    call = PopenSpy.calls[0]
    assert_safe_argv(call)
    assert call["targets"].splitlines() == CRAFTED_TARGETS[:3]


# --- PUT /api/settings/scan is a closed set (invariant 6) ---------------------------------------------
@pytest.fixture
def client(db_env):
    limiter.reset()
    with TestClient(app) as c:
        assert c.post("/api/setup/admin", json={"username": "admin", "password": "correct-horse-1"}).status_code == 200
        c.headers["X-CSRF-Token"] = c.cookies.get("nf_csrf", "")
        yield c


def _stored_scan_settings() -> dict:
    with session_scope() as db:
        row = db.get(AppSetting, "scan")
        return dict(row.value) if row else {}


def test_os_detection_defaults_on_for_a_fresh_install(client):
    """Fresh installs and migrated installs both expose os_detection=True (spec 3.2 / 0018)."""
    stored = _stored_scan_settings()
    # 0018 may have written a scan row that enables OS detection; either way the API must report on.
    if stored:
        assert stored.get("os_detection") is True
    assert client.get("/api/settings/scan").json()["os_detection"] is True
    assert ScanSettings().os_detection is True


def test_os_detection_can_be_turned_off_after_migration_enable(client):
    """Spec 3.2 enables OS detection for existing installs once; an admin may still turn it off."""
    before = client.get("/api/settings/scan").json() | {"os_detection": False, "os_detection_enabled_notice": False}
    assert client.put("/api/settings/scan", json=before).status_code == 200
    assert _stored_scan_settings()["os_detection"] is False
    assert client.get("/api/settings/scan").json()["os_detection"] is False


@pytest.mark.parametrize("timing", ["polite", "normal", "fast"])
def test_scan_settings_timing_round_trips(client, timing):
    body = client.get("/api/settings/scan").json() | {"timing": timing}
    r = client.put("/api/settings/scan", json=body)
    assert r.status_code == 200, r.text
    assert r.json()["timing"] == timing
    assert client.get("/api/settings/scan").json()["timing"] == timing
    assert _stored_scan_settings()["timing"] == timing


@pytest.mark.parametrize("patch", [
    {"timing": "--script"}, {"timing": "-T5;id"}, {"timing": "insane"}, {"timing": "-T5"}, {"timing": ""},
    {"top_ports": 99}, {"top_ports": 10001}, {"top_ports": "1000 --script=x"},
    {"parallelism": 0}, {"host_timeout_minutes": 241},
])
def test_scan_settings_reject_values_outside_the_closed_set(client, patch):
    before = client.get("/api/settings/scan").json()
    r = client.put("/api/settings/scan", json=before | patch)
    assert r.status_code == 422, r.text
    assert client.get("/api/settings/scan").json() == before


@pytest.mark.parametrize("extra", [
    {"nmap_args": "--script=vuln"}, {"extra_args": ["-A"]}, {"arguments": "-iR 0"}, {"scripts": "default"},
])
def test_scan_settings_reject_raw_nmap_fields_and_never_store_them(client, extra):
    before = client.get("/api/settings/scan").json()
    r = client.put("/api/settings/scan", json=before | extra)
    assert r.status_code == 422, r.text
    assert r.json()["code"] == "validation_error"
    stored = _stored_scan_settings()
    assert set(stored) <= set(ScanSettings.model_fields)
    assert not any(isinstance(v, str) and v.startswith("-") for v in stored.values())
    assert set(client.get("/api/settings/scan").json()) == set(ScanSettings.model_fields)
