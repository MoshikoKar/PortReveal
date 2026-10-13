"""FastAPI application entry point (uvicorn app.main:app)."""
from __future__ import annotations

import logging
import time
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.exceptions import HTTPException as StarletteHTTPException

from . import __version__, metrics
from .api import (
    auth,
    dashboard,
    data_transfer,
    devices,
    events,
    exclusions,
    host,
    misc,
    networks,
    reports,
    scans,
    search,
    settings,
    setup,
    system,
    tokens,
    users,
    watches,
    web_captures,
    webhooks,
)
from .api.errors import error_body, validation_message
from .config import check_production_config, get_settings
from .core.manager import manager
from .core.query import QueryError
from .core.scheduler import scheduler
from .core.web_capture import web_capture_manager
from .db import init_engine
from .logging_setup import setup_logging
from .migrate import upgrade
from .netutils import TargetError
from .request_context import REQUEST_ID_HEADER, bind_request_id, request_id_from, unbind_request_id
from .scanner import scanner_status
from .seed import seed_dev
from .stopfile import watcher_from_env

log = logging.getLogger("app")
perf_log = logging.getLogger("app.perf")


@asynccontextmanager
async def lifespan(app: FastAPI):
    s = get_settings()
    setup_logging()
    check_production_config(s)
    s.data_path.mkdir(parents=True, exist_ok=True)
    log.info("PortReveal %s starting (env=%s, db=%s)", __version__, s.app_env, s.db_type)
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
    seed_dev()
    if s.background_jobs:
        manager.start()
        web_capture_manager.start()
        scheduler.start()
    stop_watcher = watcher_from_env()  # set by scripts/run.ps1 (Windows production)
    if stop_watcher:
        stop_watcher.start()
    yield
    if stop_watcher:
        stop_watcher.stop()
    scheduler.stop()
    web_capture_manager.stop()
    manager.stop()
    log.info("PortReveal stopped")


API_VERSION = "1"
API_PREFIX = "/api"
API_VERSIONED_PREFIX = f"/api/v{API_VERSION}"
API_DESCRIPTION = f"""PortReveal REST API (version {API_VERSION}).

**Versioning.** `{API_VERSIONED_PREFIX}/...` is the stable, versioned path for integrations; `/api/...` is the
same API (the bundled UI uses it). Within v{API_VERSION}, changes are additive only: no field is removed, renamed
or retyped and no status code changes meaning. A breaking change ships as `/api/v2` alongside v1.

**Conventions.** `PUT` replaces a whole settings section or resource (send every field), `PATCH` updates only
the fields sent. Creates answer `201`, deletes `204` with no body. Actions are `POST` verbs under their resource
(`/api/scans/{{id}}/cancel`). Lists page with `?page=` and `?page_size=`. Every response carries
`{REQUEST_ID_HEADER}`; quote it when reporting a problem. Full rules: `docs/api/conventions.md`.
"""

_settings = get_settings()
_docs_enabled = _settings.app_env != "production"
app = FastAPI(
    title="PortReveal",
    version=__version__,
    description=API_DESCRIPTION,
    lifespan=lifespan,
    docs_url="/api/docs" if _docs_enabled else None,
    openapi_url="/api/openapi.json" if _docs_enabled else None,
    redoc_url=None,
)

for r in (auth, setup, system, dashboard, devices, events, scans, networks, exclusions, settings, users, misc,
          web_captures, data_transfer, search, watches, reports, tokens, host, webhooks):
    app.include_router(r.router)


# Every error answers with one envelope: {code, message, detail, details?, pos?} (see api/errors.py).
@app.exception_handler(StarletteHTTPException)
async def http_error_handler(request: Request, exc: StarletteHTTPException):
    if isinstance(exc.detail, str):
        body = error_body(exc.status_code, exc.detail, getattr(exc, "code", None))
    else:
        body = error_body(exc.status_code, f"Request failed ({exc.status_code})", getattr(exc, "code", None),
                          detail=exc.detail)
    return JSONResponse(status_code=exc.status_code, content=jsonable_encoder(body), headers=exc.headers)


@app.exception_handler(RequestValidationError)
async def validation_error_handler(request: Request, exc: RequestValidationError):
    errors = exc.errors()
    details = [{"loc": list(e.get("loc", ())), "msg": e.get("msg"), "type": e.get("type")} for e in errors]
    body = error_body(422, validation_message(errors), detail=errors, details=details)
    return JSONResponse(status_code=422, content=jsonable_encoder(body))


@app.exception_handler(TargetError)
async def target_error_handler(request: Request, exc: TargetError):
    return JSONResponse(status_code=422, content=error_body(422, str(exc), "invalid_target"))


@app.exception_handler(QueryError)
async def query_error_handler(request: Request, exc: QueryError):
    return JSONResponse(status_code=400, content=error_body(400, str(exc), "invalid_query", pos=exc.pos))


@app.exception_handler(Exception)
async def unhandled_error_handler(request: Request, exc: Exception):
    # Logged with its traceback by the server; the client gets no exception text.
    return JSONResponse(status_code=500, content=error_body(500, "Internal server error"))


@app.middleware("http")
async def request_timing(request: Request, call_next):
    """Log API latency so slow endpoints (device list, dashboard, ...) show up in the app log, and
    count requests for /api/metrics.

    Streaming responses are timed to their first byte, which is what the client waits on.
    """
    if not request.url.path.startswith("/api/"):
        return await call_next(request)
    start = time.perf_counter()
    response = await call_next(request)
    ms = (time.perf_counter() - start) * 1000
    # The matched route's template (/api/devices/{uuid}) keeps metric labels low-cardinality.
    route = getattr(request.scope.get("route"), "path", None) or "unmatched"
    metrics.observe_request(request.method, route, response.status_code, ms / 1000)
    response.headers.setdefault("Server-Timing", f"app;dur={ms:.1f}")
    slow = ms >= get_settings().slow_request_ms
    if slow or perf_log.isEnabledFor(logging.DEBUG):
        # Parameter names only: values (search text, filters) stay out of the rotating log files.
        names = sorted({k for k, _ in request.query_params.multi_items()})
        target = request.url.path + (f"?{'&'.join(names)}" if names else "")
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


@app.middleware("http")
async def request_context(request: Request, call_next):
    """Correlate a request across UI, response and logs: accept or create X-Request-Id, echo it back."""
    request_id = request_id_from(request.headers.get(REQUEST_ID_HEADER))
    token = bind_request_id(request_id)
    try:
        response = await call_next(request)
    finally:
        unbind_request_id(token)
    response.headers[REQUEST_ID_HEADER] = request_id
    return response


class VersionedPathAlias:
    """Serve ``/api/v1/...`` as ``/api/...``: one set of routes, reachable under the versioned prefix.

    Outermost middleware, so routing, metrics (route templates) and logs see the canonical path.
    """

    def __init__(self, app_):
        self.app = app_

    async def __call__(self, scope, receive, send):
        if scope["type"] in ("http", "websocket"):
            path: str = scope["path"]
            if path == API_VERSIONED_PREFIX or path.startswith(API_VERSIONED_PREFIX + "/"):
                canonical = API_PREFIX + path[len(API_VERSIONED_PREFIX):]
                scope = {**scope, "path": canonical, "raw_path": canonical.encode()}
        await self.app(scope, receive, send)


app.add_middleware(VersionedPathAlias)


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
        body = {
            "app": "PortReveal API",
            "version": __version__,
            "ui": "Frontend not built here. In development open http://localhost:5173 (npm run dev).",
        }
        if _docs_enabled:
            body["docs"] = "/api/docs"
        return body
