"""Background vulnerability-check job queue API (spec section 8.5): status, manual trigger, cancel."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..auth.deps import client_ip, current_user, require_admin
from ..config import get_settings
from ..core.audit import audit
from ..core.vuln.manager import enqueue_vuln_job, vuln_job_manager
from ..core.vuln.runner import run_vuln_job
from ..db import get_db, utcnow
from ..models import VULN_JOB_ACTIVE_STATES, VULN_JOB_QUEUED, VULN_JOB_TRIGGER_MANUAL, Device, VulnJob
from ..scanner.types import ScanContext
from .common import Paging, paged

router = APIRouter(prefix="/api/vuln-jobs", tags=["vuln-jobs"])


def vuln_job_out(j: VulnJob) -> dict:
    return {
        "id": j.id,
        "uuid": j.uuid,
        "status": j.status,
        "trigger": j.trigger,
        "scan_id": j.scan_id,
        "network_id": j.network_id,
        "device_count": len(j.device_ids or []),
        "requested_by": j.requested_by,
        "created_at": j.created_at,
        "started_at": j.started_at,
        "finished_at": j.finished_at,
        "stage": j.stage,
        "progress": j.progress,
        "error": j.error,
        "stats": j.stats,
        "notes": j.notes,
    }


@router.get("")
def list_vuln_jobs(status: str | None = Query(None), paging: Paging = Depends(),
                   db: Session = Depends(get_db), user=Depends(current_user)):
    conds = []
    if status:
        conds.append(VulnJob.status == status)
    total = db.scalar(select(func.count(VulnJob.id)).where(*conds)) or 0
    rows = db.scalars(
        select(VulnJob).where(*conds).order_by(VulnJob.id.desc()).offset(paging.offset).limit(paging.page_size)
    ).all()
    return paged([vuln_job_out(j) for j in rows], total, paging)


@router.get("/active")
def active_vuln_jobs(db: Session = Depends(get_db), user=Depends(current_user)):
    rows = db.scalars(select(VulnJob).where(VulnJob.status.in_(VULN_JOB_ACTIVE_STATES)).order_by(VulnJob.id)).all()
    return {"items": [vuln_job_out(j) for j in rows]}


@router.get("/{job_id}")
def get_vuln_job(job_id: int, db: Session = Depends(get_db), user=Depends(current_user)):
    j = db.get(VulnJob, job_id)
    if j is None:
        raise HTTPException(404, "Vulnerability job not found")
    return vuln_job_out(j)


class VulnJobRequest(BaseModel):
    device_uuids: list[str] = Field(min_length=1, max_length=4096)


@router.post("")
def start_vuln_job(body: VulnJobRequest, request: Request, db: Session = Depends(get_db),
                   user=Depends(require_admin)):
    """Manual "check vulnerabilities" trigger (spec 8.2): device detail button or bulk action."""
    from ..settings_store import VulnSettings, get_section

    if not get_section(db, VulnSettings).enabled:
        raise HTTPException(409, "Vulnerability checks are disabled. Enable them in Settings → Vulnerabilities.")
    ids = list(db.scalars(select(Device.id).where(Device.uuid.in_(body.device_uuids))))
    if not ids:
        raise HTTPException(404, "No matching devices")
    job = enqueue_vuln_job(db, trigger=VULN_JOB_TRIGGER_MANUAL, device_ids=ids, requested_by=user.username)
    audit(db, user.username, "vuln_job.start", None, {"job_id": job.id, "device_count": len(ids)},
          client_ip(request))
    job_id = job.id
    db.commit()
    vuln_job_manager.wake()
    if not get_settings().background_jobs or not vuln_job_manager.running:
        run_vuln_job(job_id, ScanContext(job_id))
    db.expire_all()
    job = db.get(VulnJob, job_id)
    return {"job": vuln_job_out(job)}


@router.post("/{job_id}/cancel")
def cancel_vuln_job(job_id: int, request: Request, db: Session = Depends(get_db), user=Depends(require_admin)):
    job = db.get(VulnJob, job_id)
    if job is None:
        raise HTTPException(404, "Vulnerability job not found")
    if job.status not in VULN_JOB_ACTIVE_STATES:
        raise HTTPException(409, "Job is not active")
    ok = vuln_job_manager.cancel(job_id)
    if not ok and job.status == VULN_JOB_QUEUED:
        from ..models import VULN_JOB_CANCELLED
        job.status = VULN_JOB_CANCELLED
        job.finished_at = utcnow()
        job.notes = "Cancelled before it started."
        ok = True
    if not ok:
        raise HTTPException(409, "Could not cancel job")
    audit(db, user.username, "vuln_job.cancel", None, {"job_id": job_id}, client_ip(request))
    db.commit()
    return {"ok": True}
