"""Background vulnerability-check pipeline (spec section 8).

Stage A: local CPE<->CVE match against the cache (no network). Stage B (optional): allow-listed
NSE scripts on the ports that justify them, inside a measured time budget. Stage C: recompute
risk/combined scores. A failure here never changes the main scan's status -- same best-effort
principle as core/intel.py.
"""
from __future__ import annotations

import logging
import time
from collections import defaultdict
from datetime import datetime, timedelta

from sqlalchemy import func, select

from ...config import get_settings
from ...db import session_scope, utcnow
from ...models import (
    SCAN_ACTIVE_STATES,
    VULN_JOB_CANCELLED,
    VULN_JOB_COMPLETED,
    VULN_JOB_FAILED,
    VULN_JOB_PARTIAL,
    VULN_JOB_RUNNING,
    VULN_SOURCE_NMAP_SCRIPT,
    VULN_STATE_CONFIRMED,
    VULN_STATE_DISMISSED,
    Device,
    DevicePort,
    DevicePortVuln,
    Scan,
    Vulnerability,
    VulnFeedState,
    VulnJob,
)
from ...scanner import scanner_status
from ...scanner.nmap_scanner import NmapScanner, nmap_is_privileged
from ...scanner.script_allowlist import SCRIPT_CVE_MAP, scripts_for_port
from ...scanner.types import ScanCancelled, ScanContext, ScanStageError
from ...settings_store import ScanSettings, VulnSettings, get_section
from .match import match_devices
from .score import apply_risk_scores
from .summary import refresh_after_scan_or_sync
from .sync import is_cache_empty

log = logging.getLogger(__name__)

# Spec 8.4.3: scripts never add more than 20% of the port-scan time of the triggering scan, and
# never more than 15 minutes regardless. A manual job (no triggering scan) only has the hard cap.
SCRIPT_BUDGET_FRACTION = 0.20
SCRIPT_BUDGET_MAX_SECONDS = 15 * 60
SCRIPT_HOST_BATCH = 16
SCRIPT_BATCH_TIMEOUT_CAP_S = 120


def _resolve_device_ids(db, job: VulnJob) -> list[int]:
    if job.device_ids:
        return list(job.device_ids)
    if job.network_id is not None:
        return list(db.scalars(select(Device.id).where(Device.network_id == job.network_id)))
    return []


def _update(job_id: int, **fields) -> None:
    with session_scope() as db:
        job = db.get(VulnJob, job_id)
        if job is not None:
            for k, v in fields.items():
                setattr(job, k, v)


def _script_budget_seconds(db, job: VulnJob) -> float:
    """Budget is 20% of the triggering scan's wall time (best available proxy for port-scan
    duration when stages are not timed separately), capped at 15 minutes (spec 8.4.3)."""
    if job.scan_id is not None:
        scan = db.get(Scan, job.scan_id)
        if scan is not None and scan.started_at is not None and scan.finished_at is not None:
            # Prefer port-stage fraction when progress/stage metadata is unavailable: wall time of
            # a standard/full scan is dominated by the port stage after a short discovery.
            scan_seconds = (scan.finished_at - scan.started_at).total_seconds()
            port_proxy = scan_seconds * 0.85 if scan.scan_type in ("standard", "full") else scan_seconds
            return min(SCRIPT_BUDGET_MAX_SECONDS, max(0.0, port_proxy * SCRIPT_BUDGET_FRACTION))
    return float(SCRIPT_BUDGET_MAX_SECONDS)


def _wait_while_scan_busy(ctx: ScanContext, budget_deadline: float) -> bool:
    """Yield the network to a main scan. Returns False if the script budget ran out while waiting."""
    while time.monotonic() < budget_deadline:
        ctx.check_cancelled()
        with session_scope() as db:
            busy = db.scalar(select(Scan.id).where(Scan.status.in_(SCAN_ACTIVE_STATES)).limit(1)) is not None
        if not busy:
            return True
        time.sleep(2)
    return False


def _build_script_scanner(cfg: ScanSettings) -> NmapScanner | None:
    """None in mock/unavailable mode: the script stage is simply skipped, never an error."""
    if scanner_status().effective_mode != "nmap":
        return None
    settings = get_settings()
    return NmapScanner(settings.nmap_path, nmap_is_privileged(settings.nmap_privileged),
                       cfg.timing, settings.data_path / "tmp")


def _script_reports_vulnerable(output: str | None) -> bool:
    """nmap's vulns.lua library reports `State: VULNERABLE` / `State: NOT VULNERABLE` (exact case).
    Matching case-sensitively on "VULNERABLE" avoids a naive substring false-positive on "NOT
    vulnerable" when it is written in lowercase prose instead."""
    text = output or ""
    return "VULNERABLE" in text and "NOT VULNERABLE" not in text


def _apply_host_script_os(db, device: Device, host_scripts: dict[str, str]) -> None:
    """smb-os-discovery / *-ntlm-info → devices.os_name with source ntlm (spec 8.4.4), no flapping."""
    text = " ".join(host_scripts.values())
    os_name = None
    for marker in ("OS: ", "OS Version: ", "Target_Name: "):
        if marker in text:
            # Prefer an explicit OS line from smb-os-discovery / NTLM.
            for line in text.splitlines():
                low = line.strip()
                if low.startswith("OS:") or low.startswith("OS Version:"):
                    os_name = low.split(":", 1)[1].strip()
                    break
            if os_name:
                break
    if not os_name:
        return
    # Respect source ranking: ntlm (40) may replace service, not a fresher nmap_os unless empty.
    rank = {"service": 10, "ssh": 20, "http": 20, "snmp": 20, "ntlm": 40, "nmap_os": 50}
    if device.os_name and rank.get(device.os_source or "", 0) > rank["ntlm"]:
        return
    if device.os_name and device.os_name.lower() == os_name.lower():
        device.os_source = device.os_source or "ntlm"
        device.os_detected_at = utcnow()
        return
    if device.os_name is None or rank.get(device.os_source or "", 0) < rank["ntlm"]:
        device.os_name = os_name[:200]
        device.os_source = "ntlm"
        device.os_detected_at = utcnow()


def _apply_script_inventory(db, device: Device, port_row: DevicePort, p_obs) -> None:
    """Info-script product/version refinements flow through the port row (spec 8.4.4)."""
    if p_obs.product and (not port_row.product or port_row.method != "verified"):
        port_row.product = p_obs.product
        if p_obs.version:
            port_row.version = p_obs.version
    elif p_obs.version and port_row.product and not port_row.version:
        port_row.version = p_obs.version
    if p_obs.scripts:
        _apply_host_script_os(db, device, p_obs.scripts)


def _record_finding(db, device_port_id: int, cve_id: str, now: datetime) -> bool:
    """Record a script-sourced CVE finding. Returns True if newly matched (not just refreshed)."""
    if db.get(Vulnerability, cve_id) is None:
        db.add(Vulnerability(cve_id=cve_id))
        db.flush()  # autoflush is off; device_port_vulns below FK-references this row
    row = db.scalar(
        select(DevicePortVuln).where(DevicePortVuln.device_port_id == device_port_id, DevicePortVuln.cve_id == cve_id)
    )
    if row is not None:
        if row.state != VULN_STATE_DISMISSED:
            row.state, row.source, row.matched_at = VULN_STATE_CONFIRMED, VULN_SOURCE_NMAP_SCRIPT, now
        return False
    db.add(DevicePortVuln(device_port_id=device_port_id, cve_id=cve_id, state=VULN_STATE_CONFIRMED,
                          source=VULN_SOURCE_NMAP_SCRIPT, matched_at=now))
    return True


def _stage_scripts(db, device_ids: list[int], ctx: ScanContext, budget_seconds: float) -> dict:
    stats = {"scripts_run": 0, "cves_found": 0, "budget_exceeded": False}
    scanner = _build_script_scanner(get_section(db, ScanSettings))
    if scanner is None:
        return stats
    ports = db.scalars(
        select(DevicePort).where(DevicePort.device_id.in_(device_ids), DevicePort.is_open.is_(True))
    ).all()
    by_device: dict[int, list[DevicePort]] = defaultdict(list)
    for p in ports:
        by_device[p.device_id].append(p)
    devices = {
        d.id: d for d in db.scalars(select(Device).where(Device.id.in_(by_device.keys())))
    }
    device_list = list(devices.values())

    started = time.monotonic()
    deadline = started + budget_seconds
    for i in range(0, len(device_list), SCRIPT_HOST_BATCH):
        ctx.check_cancelled()
        if time.monotonic() >= deadline:
            stats["budget_exceeded"] = True
            break
        if not _wait_while_scan_busy(ctx, deadline):
            stats["budget_exceeded"] = True
            break
        batch = device_list[i:i + SCRIPT_HOST_BATCH]
        # Spec 8.4.3: each host is probed only on the ports that justify its scripts - never a
        # union of every script with every port across the batch.
        for d in batch:
            ctx.check_cancelled()
            elapsed = time.monotonic() - started
            if elapsed >= budget_seconds:
                stats["budget_exceeded"] = True
                break
            script_names: set[str] = set()
            host_ports: set[int] = set()
            for p in by_device[d.id]:
                names = scripts_for_port(p.port, p.service, p.tunnel)
                if names:
                    script_names.update(names)
                    host_ports.add(p.port)
            if not script_names or not host_ports:
                continue
            timeout = min(budget_seconds - elapsed, SCRIPT_BATCH_TIMEOUT_CAP_S)
            if timeout <= 0:
                stats["budget_exceeded"] = True
                break
            try:
                run = scanner.run_scripts([d.current_ip], sorted(script_names), sorted(host_ports),
                                          ctx, timeout)
            except ScanCancelled:
                raise
            except ScanStageError as exc:
                log.warning("vuln job: script run failed for %s: %s", d.current_ip, exc)
                continue
            stats["scripts_run"] += len(script_names)
            for host in run.hosts:
                for p_obs in host.ports or ():
                    if not p_obs.scripts:
                        continue
                    port_row = next((p for p in by_device[d.id] if p.port == p_obs.port
                                     and p.protocol == p_obs.protocol), None)
                    if port_row is None:
                        continue
                    for script_id, output in p_obs.scripts.items():
                        cve_id = SCRIPT_CVE_MAP.get(script_id)
                        if cve_id and _script_reports_vulnerable(output):
                            if _record_finding(db, port_row.id, cve_id, utcnow()):
                                stats["cves_found"] += 1
                    # Info scripts can refine product/version/OS (spec 8.4.4).
                    _apply_script_inventory(db, d, port_row, p_obs)
                if host.host_scripts:
                    _apply_host_script_os(db, d, host.host_scripts)
            db.flush()
        if stats.get("budget_exceeded"):
            break
    return stats


def run_vuln_job(job_id: int, ctx: ScanContext) -> str:
    """Runs one vuln_jobs row end to end. Returns the final status string."""
    try:
        with session_scope() as db:
            job = db.get(VulnJob, job_id)
            if job is None:
                return VULN_JOB_FAILED
            job.status = VULN_JOB_RUNNING
            job.started_at = utcnow()
            device_ids = _resolve_device_ids(db, job)
            if not device_ids:
                job.status = VULN_JOB_COMPLETED
                job.finished_at = utcnow()
                job.stats = {"ports_checked": 0, "matched": 0, "removed": 0, "scripts_run": 0, "cves_found": 0}
                return VULN_JOB_COMPLETED

        ctx.check_cancelled()
        now = utcnow()
        partial_reason: str | None = None
        stats = {"scripts_run": 0, "cves_found": 0}

        with session_scope() as db:
            cfg = get_section(db, VulnSettings)
            stale_error = db.scalar(
                select(VulnFeedState.last_error).where(VulnFeedState.last_error.isnot(None)).limit(1)
            )
            if is_cache_empty(db):
                partial_reason = "Vulnerability cache is not synced; run a sync or import a snapshot."
            else:
                if stale_error:
                    partial_reason = "Vulnerability cache sync reported an error; matching against a possibly stale cache."
                else:
                    last_sync = db.scalar(select(func.max(VulnFeedState.last_synced_at)))
                    stale_after = timedelta(hours=cfg.sync_interval_hours * 2)
                    if last_sync is not None and (now - last_sync) > stale_after:
                        hours = int(cfg.sync_interval_hours * 2)
                        partial_reason = (
                            f"Vulnerability cache is older than {hours} hours "
                            f"(2× sync interval); matching against a stale cache."
                        )
                _update(job_id, stage="match", progress=0.2)
                stats.update(match_devices(db, device_ids, now=now))

        ctx.check_cancelled()

        with session_scope() as db:
            job = db.get(VulnJob, job_id)
            cfg = get_section(db, VulnSettings)
            if cfg.enabled and cfg.scripts_enabled:
                _update(job_id, stage="scripts", progress=0.5)
                budget = _script_budget_seconds(db, job)
                try:
                    script_stats = _stage_scripts(db, device_ids, ctx, budget)
                    stats["scripts_run"] = script_stats["scripts_run"]
                    stats["cves_found"] = stats.get("cves_found", 0) + script_stats["cves_found"]
                    if script_stats.get("budget_exceeded"):
                        partial_reason = partial_reason or "Script time budget exceeded; partial results saved."
                except ScanCancelled:
                    raise
                except Exception:
                    log.exception("vuln job %s: script stage failed", job_id)
                    partial_reason = partial_reason or "Script stage failed; local cache results were kept."

        ctx.check_cancelled()

        with session_scope() as db:
            _update(job_id, stage="score", progress=0.85)
            apply_risk_scores(db, device_ids, now=now)
        _update(job_id, progress=1.0)

        status = VULN_JOB_PARTIAL if partial_reason else VULN_JOB_COMPLETED
        _update(job_id, status=status, finished_at=utcnow(), stage=None, stats=stats,
               notes=partial_reason, error=partial_reason if status == VULN_JOB_PARTIAL else None)
        with session_scope() as db:
            refresh_after_scan_or_sync(db, now=utcnow())
        return status
    except ScanCancelled:
        _update(job_id, status=VULN_JOB_CANCELLED, finished_at=utcnow(), stage=None,
               notes="Cancelled by user.")
        return VULN_JOB_CANCELLED
    except Exception:
        log.exception("vuln job %s crashed", job_id)
        _update(job_id, status=VULN_JOB_FAILED, finished_at=utcnow(), stage=None,
               error="Internal error (see the application log)")
        return VULN_JOB_FAILED
