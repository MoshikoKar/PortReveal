"""Real scanning through the nmap executable.

Arguments are always built from a fixed allow-list plus validated values and
passed to subprocess as a list (never through a shell). Targets are written to
a temporary file and passed with -iL.
"""
from __future__ import annotations

import functools
import ipaddress
import logging
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from ..netutils import PortScope, ip_sort_key
from .known_ports import AI_LLM_DISCOVERY_TCP_PORTS, STANDARD_EXTRA_TCP_PORTS, merge_port_scope
from .nmap_iface import BindChoice, resolve_bind
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
# Exit codes that mean nmap was stopped from outside, not that the scan itself failed.
_EXIT_REASONS = {
    0xC000013A: "interrupted (Ctrl+C or the console was closed)",  # Windows STATUS_CONTROL_C_EXIT
    0x40010004: "terminated by another process",  # Windows DBG_TERMINATE_PROCESS
}


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


@functools.lru_cache(maxsize=8)
def top_tcp_ports(exe: str, n: int) -> tuple[int, ...]:
    """nmap's own --top-ports N list (open-frequency order from its installed nmap-services).

    Asked from nmap itself with no targets (nothing is scanned), so the list and its tie-breaking
    match --top-ports exactly on every platform.
    """
    try:
        out = subprocess.run([exe, "-sT", "--top-ports", str(int(n)), "-oX", "-"],
                             capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.SubprocessError) as exc:
        raise ScanStageError(f"could not read nmap's top ports: {exc}") from exc
    spec = parse_nmap_xml(out.stdout).port_scope if out.returncode == 0 else None
    if not spec:
        raise ScanStageError(f"could not read nmap's top {n} ports (exit code {out.returncode})")
    ports: list[int] = []
    for part in spec.split(","):
        a, _, b = part.partition("-")
        ports.extend(range(int(a), int(b or a) + 1))
    return tuple(ports)


def standard_port_spec(exe: str, top_n: int, extra: tuple[int, ...] = ()) -> str:
    """Explicit -p list for standard scans: nmap's top-N TCP ports plus the extra web/AI ports
    (and a device profile's ports when given).

    --top-ports and -p cannot be combined into a union, and a second nmap pass for the extras
    would version-scan the overlapping ports twice.
    """
    return PortScope.from_ports({*top_tcp_ports(exe, top_n), *STANDARD_EXTRA_TCP_PORTS, *extra})


def exit_reason(code: int) -> str:
    """Readable nmap exit status (negative = killed by a POSIX signal)."""
    if code < 0:
        return f"killed by signal {-code}"
    known = _EXIT_REASONS.get(code & 0xFFFFFFFF)
    return f"exited with code {code}" + (f" - {known}" if known else "")


def build_port_args(privileged: bool, profile: PortProfile, ports: str, *, versions: bool = True,
                    os_scan: bool = True) -> list[str]:
    args = ["-Pn", "-n"] + (["-sV"] if versions else [])
    args += ["--privileged", "-sS"] if privileged else ["--unprivileged", "-sT"]
    args += [
        "-p", ports,
        _TIMING.get(profile.timing, "-T3"),
        "--max-retries", "2",
        "--host-timeout", f"{int(profile.host_timeout_minutes)}m",
        "--min-hostgroup", str(max(1, int(profile.batch_size))),
    ]
    if os_scan and profile.os_detection and privileged:
        args += ["-O", "--osscan-limit", "--max-os-tries", "1"]
    return args


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
        bind = resolve_bind(self.exe, targets, self.privileged)
        args = build_discovery_args(bind.privileged, self.timing)
        run = self._run(args, targets, discovery_timeout(targets, self.timing), ctx, "discovery",
                        device=bind.device, source=bind.source)
        return StageResult(hosts=run.hosts)

    def scan_ports(self, ips: list[str], profile: PortProfile, ctx: ScanContext) -> StageResult:
        bind = resolve_bind(self.exe, ips, self.privileged)
        extra = () if profile.full else profile.extra_ports
        spec = "1-65535" if profile.full else standard_port_spec(self.exe, profile.top_ports)
        run_spec = standard_port_spec(self.exe, profile.top_ports, extra) if extra else spec
        timeout = profile.host_timeout_minutes * 60 + 15 * 60
        label = "full" if profile.full else "ports"
        cached = {ip: profile.version_cache[ip] for ip in ips if profile.version_cache.get(ip)}
        # Nothing cached for this batch (first scan, cache off or forced): one nmap pass with -sV.
        run = self._run(build_port_args(bind.privileged, profile, run_spec, versions=not cached), ips, timeout,
                        ctx, label, device=bind.device, source=bind.source)
        by_ip = {h.ip: h for h in run.hosts}
        # The scan-wide scope stays the standard one; profile ports are reported separately per batch.
        port_scope = spec if extra else (run.port_scope or spec)
        notes: list[str] = []
        if not cached:
            for h in run.hosts:
                for p in h.ports or []:
                    p.version_checked = True
        elif err := self._detect_versions(by_ip, cached, bind, profile, timeout, ctx, label):
            notes.append(err)

        hosts = []
        for ip in ips:
            h = by_ip.get(ip)
            if h is None:
                # With -Pn every target should be reported; missing means nmap gave up on it
                h = HostObservation(ip=ip, port_scan_failed=True, failure_reason="nmap returned no result for host")
            elif h.ports is None:
                h.port_scan_failed = True
                h.failure_reason = (
                    f"host timed out after {int(profile.host_timeout_minutes)} min (--host-timeout)"
                    if h.failure_reason == "host timed out" else h.failure_reason or "nmap returned no port results"
                )
            hosts.append(h)
        return StageResult(hosts=hosts, port_scope=port_scope, extra_ports=extra, notes=notes)

    def _detect_versions(self, by_ip: dict[str, HostObservation], cached: dict[str, frozenset[int]],
                         bind: BindChoice, profile: PortProfile, timeout: float, ctx: ScanContext,
                         label: str) -> str | None:
        """-sV only the open ports without a fresh cached version (new, reopened or expired ones).

        Cached ports keep nmap's port-table guess here (method=table, unreliable), which change
        detection never lets overwrite the stored product/version. Returns an error text when the
        -sV pass failed (the open ports from the first pass are kept).
        """
        need = {
            ip: ports for ip, h in by_ip.items()
            if (ports := {p.port for p in h.ports or [] if p.protocol == "tcp" and p.port not in cached.get(ip, ())})
        }
        if not need:
            return None
        args = build_port_args(bind.privileged, profile, PortScope.from_ports(set().union(*need.values())),
                               os_scan=False)
        try:
            run = self._run(args, sorted(need, key=ip_sort_key), timeout, ctx, f"{label}-versions",
                            device=bind.device, source=bind.source)
        except ScanStageError as exc:
            # Open ports from the first pass stay valid; unversioned ports are retried next scan.
            log.warning("scan %s: version detection failed, keeping port results: %s", ctx.scan_id, exc)
            return f"version detection failed for {len(need)} host(s), open ports kept: {exc}"
        for vh in run.hosts:
            h = by_ip.get(vh.ip)
            if h is None or h.ports is None or vh.ports is None:
                continue  # host dropped or timed out in the -sV pass: keep the first pass result
            found = {(p.protocol, p.port): p for p in vh.ports}
            for i, p in enumerate(h.ports):
                if (v := found.get((p.protocol, p.port))) is not None:
                    v.version_checked = True
                    h.ports[i] = v
        return None

    def _run(self, args: list[str], targets: list[str], timeout: float, ctx: ScanContext, label: str,
             device: str | None = None, source: str | None = None):
        ctx.check_cancelled()
        fd, target_file = tempfile.mkstemp(prefix=f"scan{ctx.scan_id}_", suffix=".txt", dir=self.tmp_dir)
        with os.fdopen(fd, "w") as fh:
            fh.write("\n".join(targets) + "\n")
        bind = (["-e", device] if device else []) + (["-S", source] if device and source else [])
        if device:
            log.info("scan %s: binding nmap %s to interface %s", ctx.scan_id, label, device)
        cmd = [self.exe, *args, *bind, "-iL", target_file, "-oX", "-"]
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
            detail = f": {' | '.join(msg)}" if msg else ""
            raise ScanStageError(f"nmap {label} {exit_reason(proc.returncode)}{detail}")
        run = parse_nmap_xml(out)
        if not run.finished_ok:
            raise ScanStageError(f"nmap {label}: {run.error}")
        log.debug("scan %s: nmap %s finished in %.1fs, %d hosts", ctx.scan_id, label,
                  time.monotonic() - started, len(run.hosts))
        return run
