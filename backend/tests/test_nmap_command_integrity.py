"""Scan-command integrity: the single entrypoint for "can user input change what nmap runs?".

Threat model. Scan targets, settings, network flags and the local interface list all flow into an nmap
command line. An attacker (or a careless admin) controls targets and settings; the interface list comes
from ``nmap --iflist`` output. None of them may add, remove or reinterpret nmap options.

Invariants and where they are locked down:

1. nmap runs from a list argv, never through a shell; targets reach nmap only through an ``-iL`` file.
   -> ``test_run_argv_is_a_list_and_targets_go_through_il_file`` (below).
2. Option sets are fixed by code: no ``--script``, ``-A`` or UDP probes; timing/rate values come from
   closed sets. -> ``tests/test_scanner.py::test_nmap_arguments_are_fixed_and_safe``,
   ``tests/test_vpn_s2s.py`` (VPN S2S rate caps), ``tests/test_identify_ai.py::test_fixed_port_args_include_ai_candidates``.
3. Targets are parsed into IPv4 addresses before a scan is queued; anything else is 422.
   -> ``tests/test_api.py::test_scan_flow_through_api`` (``"10.0.0.1; reboot"``),
   ``tests/test_api.py::test_network_and_exclusion_validation`` (CIDR with shell text).
4. Interface bind values (``-e``/``-S``) are a plain interface name and an IPv4 address, checked where
   they become argv, so a hostile ``--iflist`` line cannot inject an option.
   -> ``test_bind_*`` and ``test_run_drops_unsafe_bind_values`` (below).
5. Web-capture helpers (VNC, FreeRDP, ffmpeg/RTSP) follow the same rules.
   -> ``tests/test_web_capture_argv.py``.

Still to add here: a Popen spy over ``NmapScanner.discover`` / ``scan_ports`` with crafted targets and a
deny-list assert on every composed argv, and closed-set tests for ``PUT /api/settings/scan``.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from app.scanner import nmap_scanner
from app.scanner.nmap_iface import BindChoice, bind_args, parse_nmap_iflist
from app.scanner.types import ScanContext

FINISHED_XML = '<?xml version="1.0"?><nmaprun><runstats><finished exit="success"/></runstats></nmaprun>'
SHELL_CHARS = set(";&|$`<>\n\r'\"")


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
    return nmap_scanner.NmapScanner("nmap", privileged=True, timing="normal", tmp_dir=tmp_path)


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
