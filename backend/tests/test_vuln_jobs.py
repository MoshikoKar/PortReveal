"""Background vulnerability-check pipeline (spec section 8): queue, stages, budget, dedup."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from app.core.vuln import runner as vuln_runner
from app.core.vuln.manager import VulnJobManager, enqueue_vuln_job
from app.core.vuln.runner import run_vuln_job
from app.models import (
    VULN_JOB_CANCELLED,
    VULN_JOB_COMPLETED,
    VULN_JOB_PARTIAL,
    VULN_JOB_QUEUED,
    VULN_JOB_RUNNING,
    VULN_JOB_TRIGGER_AFTER_SCAN,
    VULN_JOB_TRIGGER_MANUAL,
    VULN_STATE_CONFIRMED,
    VULN_STATE_DISMISSED,
    VULN_SOURCE_NMAP_SCRIPT,
    Device,
    DevicePort,
    DevicePortVuln,
    VulnJob,
    Vulnerability,
    VulnCpeMatch,
)
from app.scanner.nmap_parser import ParsedRun
from app.scanner.types import HostObservation, PortObservation, ScanCancelled, ScanContext
from app.settings_store import VulnSettings, put_section

from .helpers import ScriptedScanner, device_by_ip, host, make_network, port, scan

T = datetime(2026, 1, 20, tzinfo=timezone.utc)


# --- enqueue_vuln_job: dedup / priority ------------------------------------------------------------
def test_enqueue_merges_into_an_existing_queued_job_on_overlapping_devices(db):
    j1 = enqueue_vuln_job(db, trigger=VULN_JOB_TRIGGER_AFTER_SCAN, device_ids=[1, 2])
    j2 = enqueue_vuln_job(db, trigger=VULN_JOB_TRIGGER_AFTER_SCAN, device_ids=[2, 3])
    db.commit()
    assert j1.id == j2.id  # merged: device 2 overlaps
    assert sorted(j2.device_ids) == [1, 2, 3]
    assert db.query(VulnJob).count() == 1


def test_enqueue_manual_promotes_priority_on_merge(db):
    j1 = enqueue_vuln_job(db, trigger=VULN_JOB_TRIGGER_AFTER_SCAN, device_ids=[5])
    j2 = enqueue_vuln_job(db, trigger=VULN_JOB_TRIGGER_MANUAL, device_ids=[5])
    db.commit()
    assert j1.id == j2.id
    assert j2.trigger == VULN_JOB_TRIGGER_MANUAL


def test_enqueue_does_not_merge_disjoint_device_sets(db):
    enqueue_vuln_job(db, trigger=VULN_JOB_TRIGGER_AFTER_SCAN, device_ids=[1])
    enqueue_vuln_job(db, trigger=VULN_JOB_TRIGGER_AFTER_SCAN, device_ids=[2])
    db.commit()
    assert db.query(VulnJob).count() == 2


def test_next_queued_prefers_manual_then_fifo(db):
    enqueue_vuln_job(db, trigger=VULN_JOB_TRIGGER_AFTER_SCAN, device_ids=[1])
    manual = enqueue_vuln_job(db, trigger=VULN_JOB_TRIGGER_MANUAL, device_ids=[9])
    db.commit()
    assert VulnJobManager._next_queued() == manual.id


# --- manager: restart recovery ----------------------------------------------------------------------
def test_recover_interrupted_marks_running_jobs_failed(db):
    job = VulnJob(status=VULN_JOB_RUNNING, trigger=VULN_JOB_TRIGGER_MANUAL, device_ids=[1])
    queued = VulnJob(status=VULN_JOB_QUEUED, trigger=VULN_JOB_TRIGGER_MANUAL, device_ids=[2])
    db.add_all([job, queued])
    db.commit()
    VulnJobManager.recover_interrupted()
    db.expire_all()
    assert db.get(VulnJob, job.id).status == "failed"
    assert db.get(VulnJob, job.id).error == "Interrupted by an application restart"
    assert db.get(VulnJob, queued.id).status == VULN_JOB_QUEUED


# --- run_vuln_job: stage A + C --------------------------------------------------------------------
def _device_with_matched_cve(db) -> Device:
    net = make_network(db)
    scan(ScriptedScanner([host("10.0.0.1", [port(22, "ssh", "OpenSSH", "7.4")], mac="00:11:22:33:44:01")]),
         network_id=net.id)
    d = device_by_ip(db, "10.0.0.1")
    p = next(pp for pp in d.ports if pp.port == 22)
    p.cpe = "cpe:/a:openbsd:openssh:7.4"
    db.add(Vulnerability(cve_id="CVE-2024-0001", cvss_base=7.5))
    db.flush()
    db.add(VulnCpeMatch(cve_id="CVE-2024-0001", cpe23="cpe:2.3:a:openbsd:openssh:7.4:*:*:*:*:*:*:*",
                        vendor_product="openbsd:openssh"))
    db.commit()
    return d


def test_run_vuln_job_partial_when_cache_empty(db):
    net = make_network(db)
    scan(ScriptedScanner([host("10.0.0.1", [port(22, "ssh")], mac="00:11:22:33:44:01")]), network_id=net.id)
    d = device_by_ip(db, "10.0.0.1")
    job = enqueue_vuln_job(db, trigger=VULN_JOB_TRIGGER_MANUAL, device_ids=[d.id])
    db.commit()
    status = run_vuln_job(job.id, ScanContext(job.id))
    assert status == VULN_JOB_PARTIAL
    db.expire_all()
    j = db.get(VulnJob, job.id)
    assert "not synced" in (j.notes or j.error or "")


def test_run_vuln_job_matches_and_scores(db):
    d = _device_with_matched_cve(db)
    job = enqueue_vuln_job(db, trigger=VULN_JOB_TRIGGER_MANUAL, device_ids=[d.id])
    db.commit()
    status = run_vuln_job(job.id, ScanContext(job.id))
    assert status == VULN_JOB_COMPLETED
    db.expire_all()
    j = db.get(VulnJob, job.id)
    assert j.stats["matched"] == 1
    d = device_by_ip(db, "10.0.0.1")
    assert d.risk_score > 0 and d.risk_scored_at is not None
    assert db.query(DevicePortVuln).filter_by(cve_id="CVE-2024-0001").one().state == VULN_STATE_CONFIRMED


def test_run_vuln_job_no_devices_completes_trivially(db):
    job = enqueue_vuln_job(db, trigger=VULN_JOB_TRIGGER_MANUAL, device_ids=[999999])
    db.commit()
    # device_ids resolves from the job row itself, not a live device, so this still "runs" stage A
    # against an empty device set only if the id list itself is empty; exercise that path directly.
    job.device_ids = []
    db.commit()
    status = run_vuln_job(job.id, ScanContext(job.id))
    assert status == VULN_JOB_COMPLETED


def test_run_vuln_job_cancelled_mid_pipeline(db, monkeypatch):
    d = _device_with_matched_cve(db)
    job = enqueue_vuln_job(db, trigger=VULN_JOB_TRIGGER_MANUAL, device_ids=[d.id])
    db.commit()
    ctx = ScanContext(job.id)
    ctx.cancel()
    status = run_vuln_job(job.id, ctx)
    assert status == VULN_JOB_CANCELLED


def test_run_vuln_job_respects_dismissed_matches(db):
    d = _device_with_matched_cve(db)
    p = next(pp for pp in d.ports if pp.port == 22)
    db.add(DevicePortVuln(device_port_id=p.id, cve_id="CVE-2024-0001", state=VULN_STATE_DISMISSED, matched_at=T))
    db.commit()
    job = enqueue_vuln_job(db, trigger=VULN_JOB_TRIGGER_MANUAL, device_ids=[d.id])
    db.commit()
    run_vuln_job(job.id, ScanContext(job.id))
    db.expire_all()
    assert db.query(DevicePortVuln).filter_by(cve_id="CVE-2024-0001").one().state == VULN_STATE_DISMISSED
    assert device_by_ip(db, "10.0.0.1").risk_score == 0  # dismissed matches never count toward risk


# --- stage B: scripts (mocked scanner; real nmap mode is not exercised in tests) -------------------
def test_scripts_stage_noop_in_mock_mode(db):
    d = _device_with_matched_cve(db)
    stats = vuln_runner._stage_scripts(db, [d.id], ScanContext(1), budget_seconds=60)
    assert stats == {"scripts_run": 0, "cves_found": 0, "budget_exceeded": False}


class _FakeScanner:
    def __init__(self, parsed: ParsedRun):
        self.parsed = parsed
        self.calls = 0

    def run_scripts(self, ips, names, ports, ctx, timeout):
        self.calls += 1
        return self.parsed


def test_scripts_stage_records_a_confirmed_finding(db, monkeypatch):
    d = _device_with_matched_cve(db)
    p = next(pp for pp in d.ports if pp.port == 22)
    p.port, p.service, p.tunnel = 445, "microsoft-ds", None
    db.commit()

    parsed = ParsedRun(hosts=[
        HostObservation(ip="10.0.0.1", ports=[
            PortObservation(port=445, protocol="tcp",
                            scripts={"smb-vuln-ms17-010": "VULNERABLE: remote code execution"}),
        ]),
    ])
    fake = _FakeScanner(parsed)
    monkeypatch.setattr(vuln_runner, "_build_script_scanner", lambda cfg: fake)
    stats = vuln_runner._stage_scripts(db, [d.id], ScanContext(1), budget_seconds=60)
    db.commit()
    assert fake.calls == 1
    assert stats["cves_found"] == 1
    row = db.query(DevicePortVuln).filter_by(cve_id="CVE-2017-0144").one()
    assert row.state == VULN_STATE_CONFIRMED and row.source == VULN_SOURCE_NMAP_SCRIPT


def test_scripts_stage_ignores_non_vulnerable_output(db, monkeypatch):
    d = _device_with_matched_cve(db)
    p = next(pp for pp in d.ports if pp.port == 22)
    p.port, p.service, p.tunnel = 445, "microsoft-ds", None
    db.commit()
    parsed = ParsedRun(hosts=[
        HostObservation(ip="10.0.0.1", ports=[
            PortObservation(port=445, protocol="tcp",
                            scripts={"smb-vuln-ms17-010": "State: NOT VULNERABLE"}),
        ]),
    ])
    fake = _FakeScanner(parsed)
    monkeypatch.setattr(vuln_runner, "_build_script_scanner", lambda cfg: fake)
    stats = vuln_runner._stage_scripts(db, [d.id], ScanContext(1), budget_seconds=60)
    assert stats["cves_found"] == 0
    assert db.query(DevicePortVuln).filter_by(cve_id="CVE-2017-0144").count() == 0


def test_scripts_stage_skips_devices_with_no_relevant_port(db, monkeypatch):
    d = _device_with_matched_cve(db)
    p = next(pp for pp in d.ports if pp.port == 22)
    p.port, p.service = 9999, "unknown"  # no allow-listed script is triggered by this port/service
    db.commit()
    fake = _FakeScanner(ParsedRun(hosts=[]))
    monkeypatch.setattr(vuln_runner, "_build_script_scanner", lambda cfg: fake)
    stats = vuln_runner._stage_scripts(db, [d.id], ScanContext(1), budget_seconds=60)
    assert fake.calls == 0 and stats["scripts_run"] == 0


def test_scripts_stage_stops_when_budget_is_exhausted(db, monkeypatch):
    d = _device_with_matched_cve(db)
    p = next(pp for pp in d.ports if pp.port == 22)
    p.port, p.service, p.tunnel = 445, "microsoft-ds", None
    db.commit()
    fake = _FakeScanner(ParsedRun(hosts=[]))
    monkeypatch.setattr(vuln_runner, "_build_script_scanner", lambda cfg: fake)
    stats = vuln_runner._stage_scripts(db, [d.id], ScanContext(1), budget_seconds=0)
    assert stats["budget_exceeded"] is True
    assert fake.calls == 0


def test_script_budget_uses_scan_duration_or_hard_cap(db):
    from app.models import SCAN_COMPLETED, Scan

    net = make_network(db)
    s = Scan(scan_type="standard", status=SCAN_COMPLETED, network_id=net.id,
             started_at=T, finished_at=T + timedelta(minutes=10))
    db.add(s)
    db.commit()
    job = VulnJob(status=VULN_JOB_QUEUED, trigger=VULN_JOB_TRIGGER_AFTER_SCAN, scan_id=s.id, device_ids=[1])
    db.add(job)
    db.commit()
    assert vuln_runner._script_budget_seconds(db, job) == 120.0  # 20% of 600s

    manual = VulnJob(status=VULN_JOB_QUEUED, trigger=VULN_JOB_TRIGGER_MANUAL, device_ids=[1])
    db.add(manual)
    db.commit()
    assert vuln_runner._script_budget_seconds(db, manual) == vuln_runner.SCRIPT_BUDGET_MAX_SECONDS


def test_vuln_settings_enabled_gates_scripts_stage(db, monkeypatch):
    d = _device_with_matched_cve(db)
    cfg = VulnSettings(enabled=True, scripts_enabled=False)
    put_section(db, cfg)
    db.commit()
    job = enqueue_vuln_job(db, trigger=VULN_JOB_TRIGGER_MANUAL, device_ids=[d.id])
    db.commit()
    called = []
    monkeypatch.setattr(vuln_runner, "_stage_scripts", lambda *a, **k: called.append(1))
    run_vuln_job(job.id, ScanContext(job.id))
    assert called == []  # scripts_enabled False: stage B is never entered
