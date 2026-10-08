"""FastAPI application entry point (uvicorn app.main:app)."""
from __future__ import annotations

import logging
import shutil
import time
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import select

from . import __version__
from .api import (
    auth,
    dashboard,
    data_transfer,
    devices,
    events,
    exclusions,
    misc,
    networks,
    scans,
    settings,
    setup,
    system,
    users,
    web_captures,
)
from .config import get_settings
from .core.manager import manager
from .core.scheduler import scheduler
from .core.selfid import self_id_worker
from .core.web_capture import web_capture_manager
from .db import init_engine, session_scope
from .logging_setup import setup_logging
from .migrate import upgrade
from .models import Network
from .netutils import TargetError
from .scanner import scanner_status
from .scanner.nmap_iface import off_segment_networks
from .seed import seed_dev

log = logging.getLogger("app")
perf_log = logging.getLogger("app.perf")


@asynccontextmanager
async def lifespan(app: FastAPI):
    s = get_settings()
    setup_logging()
    s.data_path.mkdir(parents=True, exist_ok=True)
    log.info("Network Finder %s starting (env=%s, db=%s)", __version__, s.app_env, s.db_type)
    try:
        upgrade()
    except Exception:
        log.exception("DATABASE MIGRATION FAILED - check DATABASE_URL / database availability. "
                      "For a disposable dev database run: npm run db:reset")
        raise
    init_engine()
    st = scanner_status(refresh=True)
    (log.warning if st.effective_mode != "nmap" else log.info)("Scanner: %s", st.message)
    if not st.nmap_detected:
        log.warning("nmap executable not found (NMAP_PATH=%s). Real network scans cannot run until nmap is "
                    "installed (e.g. apt-get install nmap). The application keeps working.", s.nmap_path)
    if st.effective_mode == "nmap":
        _warn_if_no_mac(s.nmap_path)
    seed_dev()
    if s.background_jobs:
        manager.start()
        web_capture_manager.start()
        self_id_worker.start()
        scheduler.start()
    yield
    scheduler.stop()
    self_id_worker.stop()
    web_capture_manager.stop()
    manager.stop()


def _warn_if_no_mac(nmap_path: str) -> None:
    """Say loudly at startup when no configured network is on a local segment: MAC, vendor and
    MAC-based identity will be missing from every scan (e.g. Docker Desktop bridge networking)."""
    with session_scope() as db:
        cidrs = list(db.scalars(select(Network.cidr)))
    exe = shutil.which(nmap_path)
    if not cidrs or not exe:
        return
    off = off_segment_networks(exe, cidrs)
    if len(off) < len(cidrs):
        return
    hint = (" This process runs in a container: on a Linux Docker host use host networking "
            "(docker-compose.yml); bridge networking (docker-compose.desktop.yml, Docker Desktop) hides MACs."
            if Path("/.dockerenv").exists() else "")
    log.warning("MAC ADDRESSES UNAVAILABLE: none of the configured networks (%s) is on a local network interface, "
                "so scans cannot report MAC, vendor or MAC-based device identity (expected for routed subnets).%s",
                ", ".join(off), hint)


app = FastAPI(title="Network Finder", version=__version__, lifespan=lifespan,
              docs_url="/api/docs", openapi_url="/api/openapi.json", redoc_url=None)

for r in (auth, setup, system, dashboard, devices, events, scans, networks, exclusions, settings, users, misc,
          web_captures, data_transfer):
    app.include_router(r.router)


@app.exception_handler(TargetError)
async def target_error_handler(request: Request, exc: TargetError):
    return JSONResponse(status_code=422, content={"detail": str(exc)})


@app.middleware("http")
async def request_timing(request: Request, call_next):
    """Log API latency so slow endpoints (device list, dashboard, ...) show up in the app log.

    Streaming responses are timed to their first byte, which is what the client waits on.
    """
    if not request.url.path.startswith("/api/"):
        return await call_next(request)
    start = time.perf_counter()
    response = await call_next(request)
    ms = (time.perf_counter() - start) * 1000
    response.headers.setdefault("Server-Timing", f"app;dur={ms:.1f}")
    slow = ms >= get_settings().slow_request_ms
    if slow or perf_log.isEnabledFor(logging.DEBUG):
        target = request.url.path + (f"?{request.url.query}" if request.url.query else "")
        perf_log.log(logging.WARNING if slow else logging.DEBUG, "%s %s -> %s in %.0f ms%s",
                     request.method, target, response.status_code, ms, " (slow)" if slow else "")
    return response


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "same-origin")
    if request.url.path.startswith("/api/"):
        response.headers.setdefault("Cache-Control", "no-store")
    else:
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; "
            "script-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'",
        )
    return response


# --- built frontend (production). In development Vite serves the UI on :5173. ----
_dist: Path = get_settings().frontend_dist_path
if (_dist / "index.html").exists():
    if (_dist / "assets").is_dir():
        app.mount("/assets", StaticFiles(directory=_dist / "assets"), name="assets")

    @app.get("/{path:path}", include_in_schema=False)
    async def spa(path: str):
        if path.startswith("api/"):
            raise HTTPException(404, "Not found")
        candidate = (_dist / path).resolve()
        if path and candidate.is_file() and _dist.resolve() in candidate.parents:
            return FileResponse(candidate)
        return FileResponse(_dist / "index.html")
else:
    @app.get("/", include_in_schema=False)
    async def root():
        return {
            "app": "Network Finder API",
            "version": __version__,
            "ui": "Frontend not built here. In development open http://localhost:5173 (npm run dev).",
            "docs": "/api/docs",
        }
