"""Real scanning through the nmap executable.

Arguments are always built from a fixed allow-list plus validated values and
passed to subprocess as a list (never through a shell). Targets are written to
a temporary file and passed with -iL.
"""
from __future__ import annotations

import ipaddress
import logging
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from ..netutils import PortScope
from .known_ports import AI_LLM_DISCOVERY_TCP_PORTS, STANDARD_EXTRA_TCP_PORTS, merge_port_scope
from .nmap_parser import parse_nmap_xml
from .types import (
    HostObservation,
    PortObservation,
    PortProfile,
    ScanCancelled,
    ScanContext,
    ScanStageError,
    StageResult,
)

log = logging.getLogger(__name__)

_TIMING = {"polite": "-T2", "normal": "-T3", "fast": "-T4"}
# TCP ports used as discovery probes in addition to ICMP/ARP
_DISCOVERY_BASE_TCP = "21,22,23,25,53,80,110,111,135,139,143,389,443,445,993,995,1723,3306,3389,5900,8080,8443"
_DISCOVERY_TCP = merge_port_scope(_DISCOVERY_BASE_TCP, AI_LLM_DISCOVERY_TCP_PORTS) or _DISCOVERY_BASE_TCP
DISCOVERY_TIMEOUT_S = 30 * 60
# Floor for the discovery probe rate. Without it nmap's congestion window never grows on ranges where
# nothing answers (empty subnets behind a router/VPN), so an empty /22 crawls for over an hour and the
# chunk times out, leaving every scan of that network partial (no removals, no baseline).
_DISCOVERY_MIN_RATE = {"polite": 100, "normal": 300, "fast": 600}
_DISCOVERY_RETRIES = 2
EXTRA_PORTS_TIMEOUT_S = 20 * 60


def nmap_is_privileged(setting: str) -> bool:
    if setting == "true":
        return True
    if setting == "false":
        return False
    if sys.platform == "win32":
        return True  # Npcap based installs run with raw socket access
    return hasattr(os, "geteuid") and os.geteuid() == 0


def nmap_version(nmap_path: str) -> str | None:
    exe = shutil.which(nmap_path)
    if not exe:
        return None
    try:
        out = subprocess.run([exe, "--version"], capture_output=True, text=True, timeout=15)
    except (OSError, subprocess.SubprocessError):
        return None
    for line in out.stdout.splitlines():
        if line.startswith("Nmap version"):
            return line.split()[2]
    return "unknown" if out.returncode == 0 else None


def build_discovery_args(privileged: bool, timing: str) -> list[str]:
    # -sn: host discovery only. Reverse DNS stays on (nmap default) for hostnames of live hosts.
    args = ["-sn"]
    if privileged:
        args += ["--privileged", "-PE", "-PP", f"-PS{_DISCOVERY_TCP}", "-PA80,443,3389"]
    else:
        args += ["--unprivileged", f"-PS{_DISCOVERY_TCP}"]
    args += [_TIMING.get(timing, "-T3"), "--max-retries", str(_DISCOVERY_RETRIES),
             "--min-rate", str(discovery_min_rate(timing))]
    return args


def discovery_min_rate(timing: str) -> int:
    return _DISCOVERY_MIN_RATE.get(timing, _DISCOVERY_MIN_RATE["normal"])


def discovery_timeout(targets: list[str], timing: str) -> float:
    """Worst case for a chunk where no address answers (every probe sent with all retries), plus margin."""
    addresses = 0
    for t in targets:
        try:
            addresses += ipaddress.ip_network(t, strict=False).num_addresses
        except ValueError:
            addresses += 1  # hostname
    probes = len(_DISCOVERY_TCP.split(",")) + 5  # TCP SYN list + echo, timestamp and 3 ACK probes
    worst = addresses * probes * (_DISCOVERY_RETRIES + 1) / discovery_min_rate(timing)
    return max(DISCOVERY_TIMEOUT_S, worst * 1.5)


def build_port_args(privileged: bool, profile: PortProfile) -> list[str]:
    args = ["-Pn", "-n", "-sV"]
    args += ["--privileged", "-sS"] if privileged else ["--unprivileged", "-sT"]
    if profile.full:
        args += ["-p", "1-65535"]
    else:
        args += ["--top-ports", str(int(profile.top_ports))]
    args += [
        _TIMING.get(profile.timing, "-T3"),
        "--max-retries", "2",
        "--host-timeout", f"{int(profile.host_timeout_minutes)}m",
        "--min-hostgroup", str(max(1, int(profile.batch_size))),
    ]
    if profile.os_detection and privileged:
        args += ["-O", "--osscan-limit", "--max-os-tries", "1"]
    return args


def build_fixed_port_args(privileged: bool, profile: PortProfile, ports: tuple[int, ...] | list[int]) -> list[str]:
    """Service scan a fixed TCP port list (used for AI/LLM ports outside --top-ports)."""
    spec = PortScope.from_ports(ports)
    assert spec, "fixed port list must not be empty"
    args = ["-Pn", "-n", "-sV"]
    args += ["--privileged", "-sS"] if privileged else ["--unprivileged", "-sT"]
    args += [
        "-p", spec,
        _TIMING.get(profile.timing, "-T3"),
        "--max-retries", "2",
        "--host-timeout", f"{int(profile.host_timeout_minutes)}m",
        "--min-hostgroup", str(max(1, int(profile.batch_size))),
    ]
    return args


def _merge_host_ports(base: HostObservation, extra: HostObservation) -> None:
    """Union open ports from a follow-up scan into the primary host observation."""
    if extra.ports is None:
        if extra.port_scan_failed and base.ports is None:
            base.port_scan_failed = True
        return
    by_key: dict[tuple[str, int], PortObservation] = {
        (p.protocol, p.port): p for p in (base.ports or [])
    }
    for p in extra.ports:
        by_key[(p.protocol, p.port)] = p
    base.ports = sorted(by_key.values(), key=lambda p: (p.protocol, p.port))
    base.port_scan_failed = False
    base.mac = base.mac or extra.mac
    base.vendor = base.vendor or extra.vendor
    base.hostname = base.hostname or extra.hostname
    base.os_name = extra.os_name or base.os_name


class NmapScanner:
    mode = "nmap"

    def __init__(self, nmap_path: str, privileged: bool, timing: str, tmp_dir: Path):
        exe = shutil.which(nmap_path)
        if not exe:
            raise ScanStageError(f"nmap executable not found ({nmap_path}). Install nmap or use SCANNER_MODE=mock.")
        self.exe = exe
        self.privileged = privileged
        self.timing = timing
        self.tmp_dir = tmp_dir
        tmp_dir.mkdir(parents=True, exist_ok=True)

    def discover(self, targets: list[str], ctx: ScanContext) -> StageResult:
        args = build_discovery_args(self.privileged, self.timing)
        run = self._run(args, targets, discovery_timeout(targets, self.timing), ctx, "discovery")
        return StageResult(hosts=run.hosts)

    def scan_ports(self, ips: list[str], profile: PortProfile, ctx: ScanContext) -> StageResult:
        args = build_port_args(self.privileged, profile)
        timeout = profile.host_timeout_minutes * 60 + 15 * 60
        run = self._run(args, ips, timeout, ctx, "full" if profile.full else "ports")
        by_ip = {h.ip: h for h in run.hosts}
        port_scope = run.port_scope or ("1-65535" if profile.full else None)

        # --top-ports misses uncommon local AI/LLM API and web-app dev-server ports; scan them too.
        if not profile.full and STANDARD_EXTRA_TCP_PORTS:
            extra_args = build_fixed_port_args(self.privileged, profile, STANDARD_EXTRA_TCP_PORTS)
            extra_timeout = min(timeout, EXTRA_PORTS_TIMEOUT_S)
            extra = self._run(extra_args, ips, extra_timeout, ctx, "ports-extra")
            for h in extra.hosts:
                if h.ip in by_ip:
                    _merge_host_ports(by_ip[h.ip], h)
                else:
                    by_ip[h.ip] = h
            port_scope = merge_port_scope(port_scope or extra.port_scope, STANDARD_EXTRA_TCP_PORTS)

        hosts = []
        for ip in ips:
            h = by_ip.get(ip)
            if h is None:
                # With -Pn every target should be reported; missing means nmap gave up on it
                h = HostObservation(ip=ip, port_scan_failed=True)
            elif h.ports is None:
                h.port_scan_failed = True
            hosts.append(h)
        return StageResult(hosts=hosts, port_scope=port_scope)
    def _run(self, args: list[str], targets: list[str], timeout: float, ctx: ScanContext, label: str):
        ctx.check_cancelled()
        fd, target_file = tempfile.mkstemp(prefix=f"scan{ctx.scan_id}_", suffix=".txt", dir=self.tmp_dir)
        with os.fdopen(fd, "w") as fh:
            fh.write("\n".join(targets) + "\n")
        cmd = [self.exe, *args, "-iL", target_file, "-oX", "-"]
        log.debug("scan %s: running %s", ctx.scan_id, " ".join(cmd))
        started = time.monotonic()
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            ctx.register(proc)
            try:
                out, err = proc.communicate(timeout=timeout)
            except subprocess.TimeoutExpired as exc:
                proc.kill()
                proc.communicate()
                raise ScanStageError(f"nmap {label} timed out after {int(timeout)}s ({len(targets)} targets)") from exc
            finally:
                ctx.unregister(proc)
        finally:
            try:
                os.unlink(target_file)
            except OSError:
                pass
        if ctx.cancelled:
            raise ScanCancelled()
        if ctx.raw_dir is not None:
            try:
                ctx.raw_dir.mkdir(parents=True, exist_ok=True)
                (ctx.raw_dir / f"{label}_{int(time.time() * 1000)}.xml").write_text(out or "", encoding="utf-8")
            except OSError as exc:
                log.warning("could not keep raw nmap output: %s", exc)
        if proc.returncode != 0:
            msg = (err or "").strip().splitlines()[-3:]
            raise ScanStageError(f"nmap {label} exited with code {proc.returncode}: {' | '.join(msg)}")
        run = parse_nmap_xml(out)
        if not run.finished_ok:
            raise ScanStageError(f"nmap {label}: {run.error}")
        log.debug("scan %s: nmap %s finished in %.1fs, %d hosts", ctx.scan_id, label,
                  time.monotonic() - started, len(run.hosts))
        return run
