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
from .identify_truenas import host_looks_like_truenas
from .known_ports import (
    AI_LLM_DISCOVERY_TCP_PORTS,
    NEVER_PROBE_TCP_PORTS,
    STANDARD_EXTRA_TCP_PORTS,
    TRUENAS_APPS_TCP_PORTS,
    merge_port_scope,
)
from .nmap_iface import BindChoice, bind_args, resolve_bind
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
from .verify_services import verify_hosts

log = logging.getLogger(__name__)

_TIMING = {"polite": "-T2", "normal": "-T3", "fast": "-T4"}
# TCP ports used as discovery probes in addition to ICMP/ARP.
# Includes common LAN/IoT listeners so Docker/NAT scans (no ARP) still find real hosts via syn-ack.
_DISCOVERY_BASE_TCP = (
    "21,22,23,25,53,80,110,111,135,139,143,389,443,445,554,993,995,1723,1883,"
    "3306,3389,5000,5900,8000,8080,8443,8554,9100,32400"
)
_DISCOVERY_TCP = merge_port_scope(_DISCOVERY_BASE_TCP, AI_LLM_DISCOVERY_TCP_PORTS) or _DISCOVERY_BASE_TCP
DISCOVERY_TIMEOUT_S = 12 * 60
# Floor for the discovery probe rate. Without it nmap's congestion window never grows on ranges where
# nothing answers (empty subnets behind a router/VPN), so an empty /22 crawls for over an hour and the
# chunk times out, leaving every scan of that network partial (no removals, no baseline).
# Remote (no ARP) uses higher floors: silent routed ranges must not dominate wall time.
# Local L2 is ARP-only (nmap skips IP probes there); a low floor and a hard ceiling keep the
# broadcast load on the segment light.
_DISCOVERY_MIN_RATE = {"polite": 50, "normal": 100, "fast": 200}
_DISCOVERY_MAX_RATE_LOCAL = {"polite": 150, "normal": 300, "fast": 600}
# Remote (routed/VPN) discovery: floor keeps empty ranges from crawling; ceiling stops nmap from
# bursting unbounded into a site. Without a max-rate, parallel chunks can flood a WAN/VPN path and
# knock over fragile appliances (e.g. Cisco CUCM) even when their IPs are excluded from targets.
_DISCOVERY_MIN_RATE_REMOTE = {"polite": 200, "normal": 500, "fast": 1000}
_DISCOVERY_MAX_RATE_REMOTE = {"polite": 400, "normal": 1000, "fast": 2000}
# RTT caps (initial, max) so probes to silent/filtered addresses are given up quickly instead of
# waiting out nmap's adaptive timeouts; live hosts answer well inside these on routed/VPN paths.
_DISCOVERY_RTT_MS = {"polite": (300, 1200), "normal": (200, 800), "fast": (100, 400)}
_DISCOVERY_RTT_MS_REMOTE = {"polite": (200, 800), "normal": (100, 400), "fast": (50, 250)}
# Site-to-site VPN (admin flag): use the same remote discovery rates/RTT that already finished
# large S2S /16s in ~1h. The flag's job is (1) force the remote profile even if a NIC looks
# local-L2, and (2) drop "fast" so the tunnel never sees the 2000 pps remote-fast ceiling.
_DISCOVERY_RETRIES = 1
_DISCOVERY_MIN_PARALLELISM = 32
EXTRA_PORTS_TIMEOUT_S = 20 * 60
# No scan stage sends UDP: unanswered UDP dominates scan time, and fragile embedded UDP
# services (SNMP/IPMI/CoAP/SSDP/TFTP) can misbehave when probed.
# Telephony signaling ports are never probed (see known_ports.NEVER_PROBE_TCP_PORTS).
_NEVER_PROBE_TCP_PORTS = ",".join(str(p) for p in NEVER_PROBE_TCP_PORTS)
# Without a MAC, only these nmap "up" reasons count as a real device. TCP "reset" /
# "conn-refused" are excluded: Docker Desktop NAT often answers that for every IP.
_TRUSTED_DISCOVERY_REASONS = frozenset({
    "arp-response",
    "iodarp-response",
    "echo-reply",
    "timestamp-reply",
    "address-mask-reply",
    "syn-ack",
    "udp-response",
    "localhost-response",
})


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


def build_discovery_args(privileged: bool, timing: str, *, local_l2: bool = False,
                         vpn_s2s: bool = False) -> list[str]:
    # -sn: host discovery only. Reverse DNS stays on (nmap default) for hostnames of live hosts.
    # TCP probes stay enabled even behind Docker NAT; discovery_host_is_live() drops
    # RST/conn-refused false positives that have no MAC.
    args = ["-sn"]
    if privileged:
        args += ["--privileged", "-PE", "-PP", f"-PS{_DISCOVERY_TCP}", "-PA80,443,3389"]
    else:
        args += ["--unprivileged", f"-PS{_DISCOVERY_TCP}"]
    initial_rtt, max_rtt = discovery_rtt_ms(timing, local_l2=local_l2, vpn_s2s=vpn_s2s)
    args += [
        _TIMING.get(timing, "-T3"),
        "--max-retries", str(_DISCOVERY_RETRIES),
        "--min-rate", str(discovery_min_rate(timing, local_l2=local_l2, vpn_s2s=vpn_s2s)),
        "--initial-rtt-timeout", f"{initial_rtt}ms",
        "--max-rtt-timeout", f"{max_rtt}ms",
    ]
    # VPN always takes the remote (routed) arg shape — never the quieter local-L2 ARP path.
    use_local = local_l2 and not vpn_s2s
    if use_local:
        args += ["--max-rate", str(discovery_max_rate(timing, local_l2=True))]
    else:
        args += [
            "--min-parallelism", str(_DISCOVERY_MIN_PARALLELISM),
            "--max-rate", str(discovery_max_rate(timing, local_l2=False)),
        ]
    return args


def discovery_min_rate(timing: str, *, local_l2: bool = False, vpn_s2s: bool = False) -> int:
    # VPN forces the remote table even when a NIC looks like local L2.
    table = _DISCOVERY_MIN_RATE if (local_l2 and not vpn_s2s) else _DISCOVERY_MIN_RATE_REMOTE
    return table.get(timing, table["normal"])


def discovery_max_rate(timing: str, *, local_l2: bool = False, vpn_s2s: bool = False) -> int:
    table = _DISCOVERY_MAX_RATE_LOCAL if (local_l2 and not vpn_s2s) else _DISCOVERY_MAX_RATE_REMOTE
    maximum = table.get(timing, table["normal"])
    minimum = discovery_min_rate(timing, local_l2=local_l2, vpn_s2s=vpn_s2s)
    assert maximum >= minimum, "discovery max-rate must be >= min-rate"
    return maximum


def discovery_rtt_ms(timing: str, *, local_l2: bool = False, vpn_s2s: bool = False) -> tuple[int, int]:
    table = _DISCOVERY_RTT_MS if (local_l2 and not vpn_s2s) else _DISCOVERY_RTT_MS_REMOTE
    initial, maximum = table.get(timing, table["normal"])
    assert 0 < initial <= maximum, "discovery RTT caps must be positive and ordered"
    return initial, maximum


def discovery_host_is_live(host: HostObservation) -> bool:
    """True when discovery evidence is a real host, not a NAT/firewall false positive."""
    if host.mac:
        return True
    if not host.reason:
        return True  # mock scanner / fixtures without nmap reason codes
    return host.reason in _TRUSTED_DISCOVERY_REASONS


def discovery_timeout(targets: list[str], timing: str, *, local_l2: bool = False,
                      vpn_s2s: bool = False) -> float:
    """Worst case for a chunk where no address answers (every probe sent with all retries), plus margin."""
    addresses = 0
    for t in targets:
        try:
            addresses += ipaddress.ip_network(t, strict=False).num_addresses
        except ValueError:
            addresses += 1  # hostname
    # TCP SYN list + echo/timestamp + 3 ACK
    probes = len(_DISCOVERY_TCP.split(",")) + 5
    worst = addresses * probes * (_DISCOVERY_RETRIES + 1) / discovery_min_rate(
        timing, local_l2=local_l2, vpn_s2s=vpn_s2s)
    return max(DISCOVERY_TIMEOUT_S, worst * 1.5)


def _service_scan_base(privileged: bool) -> list[str]:
    # --version-light: only the most likely probes per port, far fewer malformed payloads.
    args = ["-Pn", "-n", "-sV", "--version-light"]
    args += ["--privileged", "-sS"] if privileged else ["--unprivileged", "-sT"]
    return args


def build_port_args(privileged: bool, profile: PortProfile) -> list[str]:
    args = _service_scan_base(privileged)
    if profile.full:
        args += ["-p", "1-65535"]
    else:
        args += ["--top-ports", str(int(profile.top_ports))]
    args += [
        "--exclude-ports", _NEVER_PROBE_TCP_PORTS,
        _TIMING.get(profile.timing, "-T3"),
        "--max-retries", "2",
        "--host-timeout", f"{int(profile.host_timeout_minutes)}m",
        "--min-hostgroup", str(max(1, int(profile.batch_size))),
    ]
    args += _max_rate_args(profile)
    if profile.os_detection and privileged:
        args += ["-O", "--osscan-limit", "--max-os-tries", "1"]
    return args


def build_fixed_port_args(privileged: bool, profile: PortProfile, ports: tuple[int, ...] | list[int]) -> list[str]:
    """Service scan a fixed TCP port list (used for AI/LLM ports outside --top-ports)."""
    spec = PortScope.from_ports(ports)
    assert spec, "fixed port list must not be empty"
    args = _service_scan_base(privileged)
    args += [
        "-p", spec,
        "--exclude-ports", _NEVER_PROBE_TCP_PORTS,
        _TIMING.get(profile.timing, "-T3"),
        "--max-retries", "2",
        "--host-timeout", f"{int(profile.host_timeout_minutes)}m",
        "--min-hostgroup", str(max(1, int(profile.batch_size))),
    ]
    args += _max_rate_args(profile)
    return args


def _max_rate_args(profile: PortProfile) -> list[str]:
    if profile.max_rate is None:
        return []
    assert profile.max_rate > 0, "port-stage max-rate must be positive"
    return ["--max-rate", str(int(profile.max_rate))]


def _merge_host_ports(base: HostObservation, extra: HostObservation) -> None:
    """Union open ports from a follow-up scan into the primary host observation.

    Follow-ups are additive. Do not clear ``port_scan_failed`` on the primary host —
    a timed-out full ``1-65535`` pass is still incomplete coverage even after extras.
    """
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
        bind = resolve_bind(self.exe, targets, self.privileged)
        local_l2 = bind.device is not None
        vpn = ctx.vpn_s2s
        if vpn:
            log.info(
                "scan %s: VPN S2S discovery profile (min-rate %d, max-rate %d, RTT %s ms)",
                ctx.scan_id,
                discovery_min_rate(self.timing, vpn_s2s=True),
                discovery_max_rate(self.timing, vpn_s2s=True),
                discovery_rtt_ms(self.timing, vpn_s2s=True),
            )
        elif not local_l2:
            log.warning(
                "scan %s: no local ethernet overlaps targets — ARP/MAC unavailable "
                "(typical on Docker Desktop / remote VPS). Using remote discovery "
                "(higher rate, tighter RTT); only hosts that answer ICMP/TCP are reported; "
                "silent phones/IoT need a LAN/host-network scan.",
                ctx.scan_id,
            )
        args = build_discovery_args(bind.privileged, self.timing, local_l2=local_l2, vpn_s2s=vpn)
        run = self._run(
            args, targets, discovery_timeout(targets, self.timing, local_l2=local_l2, vpn_s2s=vpn),
            ctx, "discovery", bind=bind,
        )
        hosts = [h for h in run.hosts if discovery_host_is_live(h)]
        dropped = len(run.hosts) - len(hosts)
        if dropped:
            log.info("scan %s: dropped %d discovery false positive(s) (no MAC / untrusted reason)",
                     ctx.scan_id, dropped)
        return StageResult(hosts=hosts)

    def scan_ports(self, ips: list[str], profile: PortProfile, ctx: ScanContext) -> StageResult:
        bind = resolve_bind(self.exe, ips, self.privileged)
        args = build_port_args(bind.privileged, profile)
        timeout = profile.host_timeout_minutes * 60 + 15 * 60
        run = self._run(args, ips, timeout, ctx, "full" if profile.full else "ports",
                        bind=bind)
        by_ip = {h.ip: h for h in run.hosts}
        port_scope = run.port_scope or ("1-65535" if profile.full else None)

        # --top-ports misses uncommon local AI/LLM API and web-app dev-server ports; scan them too.
        if not profile.full and STANDARD_EXTRA_TCP_PORTS:
            extra_args = build_fixed_port_args(bind.privileged, profile, STANDARD_EXTRA_TCP_PORTS)
            extra_timeout = min(timeout, EXTRA_PORTS_TIMEOUT_S)
            extra = self._run(extra_args, ips, extra_timeout, ctx, "ports-extra", bind=bind)
            for h in extra.hosts:
                if h.ip in by_ip:
                    _merge_host_ports(by_ip[h.ip], h)
                else:
                    by_ip[h.ip] = h
            port_scope = merge_port_scope(port_scope or extra.port_scope, STANDARD_EXTRA_TCP_PORTS)

        # TrueNAS Apps catalog ports (3XXXX) only on hosts identified as TrueNAS / FreeNAS.
        # Also run after full scans: --host-timeout often aborts 1-65535+-sV before high
        # catalog ports are reached. Kept out of scan-wide port_scope.
        if TRUENAS_APPS_TCP_PORTS:
            known = ctx.known_truenas_ips or set()
            truenas_ips = [
                ip for ip in ips
                if ip in known or host_looks_like_truenas(by_ip.get(ip))
            ]
            if truenas_ips:
                tn_args = build_fixed_port_args(bind.privileged, profile, TRUENAS_APPS_TCP_PORTS)
                tn_timeout = min(timeout, EXTRA_PORTS_TIMEOUT_S)
                tn = self._run(tn_args, truenas_ips, tn_timeout, ctx, "ports-truenas", bind=bind)
                for h in tn.hosts:
                    if h.ip in by_ip:
                        _merge_host_ports(by_ip[h.ip], h)
                    else:
                        by_ip[h.ip] = h
                for ip in truenas_ips:
                    host = by_ip.get(ip)
                    if host is not None:
                        host.extra_tcp_ports = TRUENAS_APPS_TCP_PORTS

        hosts = []
        for ip in ips:
            h = by_ip.get(ip)
            if h is None:
                # With -Pn every target should be reported; missing means nmap gave up on it
                h = HostObservation(ip=ip, port_scan_failed=True)
            elif h.ports is None:
                h.port_scan_failed = True
            hosts.append(h)
        # nmap soft-matches (e.g. "rtsp" from an echoed status line) look like real fingerprints.
        verify_hosts(hosts, ctx)
        return StageResult(hosts=hosts, port_scope=port_scope)

    def _run(self, args: list[str], targets: list[str], timeout: float, ctx: ScanContext, label: str,
             bind: BindChoice | None = None):
        ctx.check_cancelled()
        fd, target_file = tempfile.mkstemp(prefix=f"scan{ctx.scan_id}_", suffix=".txt", dir=self.tmp_dir)
        with os.fdopen(fd, "w") as fh:
            fh.write("\n".join(targets) + "\n")
        extra = bind_args(bind)
        if extra:
            log.info("scan %s: binding nmap %s to interface %s (source %s)",
                     ctx.scan_id, label, extra[1], extra[3] if len(extra) > 3 else "auto")
        cmd = [self.exe, *args, *extra, "-iL", target_file, "-oX", "-"]
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
