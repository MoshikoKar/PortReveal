"""Health and system status (application, database, scanner, scans)."""
from __future__ import annotations

import time

from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .. import __version__
from ..auth.deps import current_user
from ..config import get_settings
from ..core.manager import manager
from ..core.mockdata import mock_hidden, scan_visible
from ..core.scheduler import last_scheduled_date, next_run, scheduler
from ..db import check_db, get_db
from ..models import SCAN_COMPLETED, SCAN_FAILED, SCAN_PARTIAL, SCAN_QUEUED, SCAN_RUNNING, Network, Scan, User
from ..scanner import scanner_status
from ..settings_store import ScheduleSettings, get_section, get_value
from .common import scan_out

router = APIRouter(prefix="/api", tags=["system"])
STARTED = time.time()


@router.get("/health")
def health():
    ok, _ = check_db()
    return {"status": "ok" if ok else "degraded", "database": "ok" if ok else "error", "version": __version__}


def _scan(db: Session, *conds) -> Scan | None:
    return db.scalar(select(Scan).where(*conds).order_by(Scan.id.desc()).limit(1))


def scan_summary(db: Session) -> dict:
    names = {n.id: n.name for n in db.scalars(select(Network)).all()}

    def out(s: Scan | None):
        return scan_out(s, names.get(s.network_id)) if s else None

    sched = get_section(db, ScheduleSettings)
    nxt = next_run(sched, last_run_date=last_scheduled_date())
    shown = scan_visible(db)  # running/queued scans always show: they are live work, not history
    return {
        "current": out(_scan(db, Scan.status == SCAN_RUNNING)),
        "queued": db.scalar(select(func.count(Scan.id)).where(Scan.status == SCAN_QUEUED)) or 0,
        "last_completed": out(_scan(db, Scan.status.in_((SCAN_COMPLETED, SCAN_PARTIAL)), shown)),
        "last_successful": out(_scan(db, Scan.status == SCAN_COMPLETED, shown)),
        "last_failed": out(_scan(db, Scan.status == SCAN_FAILED, shown)),
        "next_scheduled": nxt.isoformat() if nxt else None,
        "schedule": sched.model_dump(),
    }


@router.get("/system/status")
def system_status(db: Session = Depends(get_db), user: User = Depends(current_user)):
    s = get_settings()
    db_ok, db_msg = check_db()
    st = scanner_status()
    return {
        "app": {
            "status": "ok",
            "version": __version__,
            "env": s.app_env,
            "dev_mode": s.is_dev,
            "uptime_seconds": int(time.time() - STARTED),
            "worker_running": manager.running,
            "scheduler_running": scheduler.running,
            "setup_completed": bool(get_value(db, "setup_completed", False)),
            "mock_data_hidden": mock_hidden(db),
        },
        "database": {
            "type": s.db_type,
            "ok": db_ok,
            "message": db_msg if db_ok else "Database unavailable",
            "location": s.sqlalchemy_url.replace("sqlite:///", "") if s.db_type == "sqlite" and s.is_dev else None,
        },
        "scanner": {
            "configured_mode": st.configured_mode,
            "mode": st.effective_mode,
            "mock_active": st.effective_mode == "mock",
            "nmap_detected": st.nmap_detected,
            "nmap_version": st.nmap_version,
            "nmap_path": st.nmap_path,
            "privileged": st.privileged,
            "message": st.message,
        },
        "scans": scan_summary(db),
    }
