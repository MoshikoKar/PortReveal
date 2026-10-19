"""On-demand Web Capture API (inventory enrichment)."""
from __future__ import annotations

import logging
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import FileResponse, StreamingResponse
from pydantic import BaseModel, Field
from sqlalchemy import func, or_, select, true
from sqlalchemy.orm import Session, selectinload

from ..auth.deps import client_ip, current_user, require_admin
from ..core.audit import audit
from ..core.mockdata import archived_hidden_device_ids, device_visible
from ..core.web_capture import delete_web_capture, run_web_capture, web_capture_manager
from ..core.web_capture.classify import BLANK_PAGE_REASON, unusable_page_reason
from ..core.web_capture.rtsp import (
    MJPEG_BOUNDARY,
    acquire_live_slot,
    ffmpeg_available,
    iter_mjpeg,
    looks_like_rtsp,
    probe_rtsp,
    release_live_slot,
)
from ..core.web_capture.runner import CaptureContext
from ..core.web_storage import resolve_screenshot
from ..db import get_db
from ..models import (
    SCREENSHOT_CAPTURED,
    WEB_CAPTURE_ACTIVE_STATES,
    WEB_CAPTURE_QUEUED,
    WEB_PAGE_HOME,
    WEB_PAGE_LOGIN,
    Device,
    User,
    WebCapture,
    WebPage,
)
from ..netutils import AddressSet, TargetError
from ..scanner import scanner_status
from ..settings_store import WebCaptureSettings, get_section
from .common import CaptureStarted, Paging, WebHostsPage, paged

router = APIRouter(tags=["web-captures"])
log = logging.getLogger(__name__)

# Captures whose pages are shown in host previews (running ones fill in live).
HOST_VIEW_STATES = ("running", "completed", "partial", "cancelled")


class WebCaptureRequest(BaseModel):
    targets: str | None = Field(None, max_length=10000)
    device_uuids: list[str] | None = Field(None, max_length=4096)
    # all = every endpoint type; remote = RDP/VNC only; web = HTTP(S)/RTSP only
    scope: Literal["all", "remote", "web"] = "all"
    # With inventory=True, capture every inventory host that has open RDP/VNC (scope forced remote).
    inventory: bool = False


def _is_rtsp_page(p: WebPage) -> bool:
    # Scheme only - RDP/VNC also use kind=stream but are not live RTSP.
    return (p.scheme or "").lower() in ("rtsp", "rtsps")


def _is_desktop_page(p: WebPage) -> bool:
    return (p.scheme or "").lower() in ("rdp", "vnc")


def web_page_out(p: WebPage) -> dict:
    return {
        "id": p.id,
        "uuid": p.uuid,
        "capture_id": p.capture_id,
        "device_id": p.device_id,
        "device_uuid": p.device.uuid if p.device_id and p.device else None,
        "device_port_id": p.device_port_id,
        "ip": p.ip,
        "port": p.port,
        "scheme": p.scheme,
        "host_used": p.host_used,
        "kind": p.kind,
        "url": p.url,
        "final_url": p.final_url,
        "redirect_target": p.redirect_target,
        "external_redirect": p.external_redirect,
        "http_status": p.http_status,
        "title": p.title,
        "content_type": p.content_type,
        "server_header": p.server_header,
        "tls_verified": p.tls_verified,
        "screenshot_status": p.screenshot_status,
        "has_screenshot": _has_shot(p),
        "error_reason": _error_reason(p),
        "capture_error": p.capture_error,
        "auth_scheme": p.auth_scheme,
        "captured_at": p.captured_at,
        "can_live": _is_rtsp_page(p),
    }


def _has_shot(p: WebPage) -> bool:
    """A captured screenshot whose file is really on disk.

    The row alone is not proof: files can be gone (data dir restored/moved without
    web-captures, disk cleanup), and the UI would then render a broken image.
    """
    return bool(
        p.screenshot_relpath and p.screenshot_status == SCREENSHOT_CAPTURED
        and resolve_screenshot(p.screenshot_relpath) is not None
    )


def _classification_capture_error(err: str | None) -> str | None:
    """Return ``err`` when it is a page-classification reason persisted at capture time."""
    if not err:
        return None
    if err == BLANK_PAGE_REASON:
        return err
    for prefix in ("default server page", "error page", "redirect", "no HTTP response"):
        if err == prefix or err.startswith(prefix + " ") or err.startswith(prefix + "("):
            return err
    return None


def _error_reason(p: WebPage) -> str | None:
    """A short reason this page is not a usable application view, or None if it is real content.

    Rematches current classify rules from stored fields on every read, so new default/error
    title patterns apply to existing captures without re-running Web Capture.
    """
    if p.external_redirect:
        return "redirects outside target"
    # RTSP / RDP / VNC have no HTTP status; usable when inventory recorded the endpoint.
    if _is_rtsp_page(p) or _is_desktop_page(p):
        return None
    # Behind an HTTP auth challenge: a login-protected application, not an error page
    if p.auth_scheme and p.http_status in (401, 407):
        return None
    # Prefer a classification reason stored at capture time (body/JS evidence is not on the row)
    classified = _classification_capture_error(p.capture_error)
    if classified:
        return classified
    # Live rematch from title/status (HTML is not retained after capture)
    return unusable_page_reason(p.http_status, p.title, auth_scheme=p.auth_scheme)


def _useful_shot(p: WebPage) -> bool:
    """Has a screenshot of a real page (older captures also screenshotted error pages)."""
    return _has_shot(p) and _error_reason(p) is None


def _page_rank(p: WebPage) -> tuple:
    """Sort key: the most representative page of a host comes first."""
    status = p.http_status or 0
    return (
        not _useful_shot(p),
        _error_reason(p) is not None,
        not (200 <= status < 400),
        p.kind != WEB_PAGE_HOME,
        p.port not in (443, 80),
        p.port,
        p.id,
    )


def _landing_key(p: WebPage) -> str:
    return (p.final_url or p.url or "").rstrip("/").lower()


def _web_services(dev_pages: list[WebPage]) -> list[dict]:
    """The usable web services (scheme + port) of one host, each with its most representative page.

    Error / default / blank / redirect-only services are left out. Services that land on the same
    page (http:80 redirecting to https:443) are shown once, listing every port that leads there.
    """
    by_ep: dict[tuple[str, int], list[WebPage]] = {}
    for p in dev_pages:
        by_ep.setdefault(((p.scheme or "").lower(), p.port), []).append(p)
    endpoints = [sorted(ps, key=_page_rank) for ps in by_ep.values()]
    # Services that answer directly first, so a redirecting one merges into the service it lands on
    endpoints.sort(key=lambda ranked: (_landing_key(ranked[0]) != (ranked[0].url or "").rstrip("/").lower(),
                                       _page_rank(ranked[0])))
    services: list[dict] = []
    by_landing: dict[str, dict] = {}
    for ranked in endpoints:
        best = ranked[0]
        if _error_reason(best) is not None:
            continue
        dup = by_landing.get(_landing_key(best))
        if dup is not None:
            dup["ports"] = sorted({*dup["ports"], best.port})
            continue
        usable = [p for p in ranked if _error_reason(p) is None]
        svc = {
            "scheme": best.scheme,
            "port": best.port,
            "ports": [best.port],
            "page_count": len(usable),
            "has_login": any(p.kind == WEB_PAGE_LOGIN for p in usable),
            "page": web_page_out(best),
        }
        by_landing[_landing_key(best)] = svc
        services.append(svc)
    services.sort(key=lambda s: (not s["page"]["has_screenshot"] or s["page"]["error_reason"] is not None,
                                 s["port"] not in (443, 80), s["port"]))
    return services


def web_capture_out(c: WebCapture, *, include_pages: bool = False) -> dict:
    out = {
        "id": c.id,
        "uuid": c.uuid,
        "status": c.status,
        "targets": c.targets,
        "scope": getattr(c, "scope", None) or "all",
        "target_count": c.target_count,
        "requested_by": c.requested_by,
        "created_at": c.created_at,
        "started_at": c.started_at,
        "finished_at": c.finished_at,
        "stage": c.stage,
        "progress": c.progress,
        "endpoints_found": c.endpoints_found,
        "pages_captured": c.pages_captured,
        "screenshots_captured": c.screenshots_captured,
        "error": c.error,
        "notes": c.notes,
        "mock_mode": c.mock_mode,
    }
    if include_pages:
        out["pages"] = [web_page_out(p) for p in c.pages]
    return out


def _capture_visible(db: Session, *, include_archived: bool = False):
    """Jobs that still have at least one page on a visible device, or no pages yet.

    A finished job whose every page belongs to an archived network is hidden unless
    ``include_archived`` is set - same rule as the Web interfaces gallery.
    """
    if include_archived:
        return true()
    hidden = archived_hidden_device_ids(db)
    if not hidden:
        return true()
    visible_page = select(WebPage.capture_id).where(
        or_(WebPage.device_id.is_(None), WebPage.device_id.not_in(hidden))
    )
    archived_only = select(WebPage.capture_id).where(WebPage.device_id.in_(hidden))
    return or_(WebCapture.id.in_(visible_page), ~WebCapture.id.in_(archived_only))


@router.get("/api/web-captures")
def list_web_captures(
    status: str | None = Query(None),
    include_archived: bool = False,
    paging: Paging = Depends(),
    db: Session = Depends(get_db),
    user: User = Depends(current_user),
):
    conds = [_capture_visible(db, include_archived=include_archived)]
    if status:
        conds.append(WebCapture.status == status)
    total = db.scalar(select(func.count(WebCapture.id)).where(*conds)) or 0
    rows = db.scalars(
        select(WebCapture).where(*conds).order_by(WebCapture.id.desc()).offset(paging.offset).limit(paging.page_size)
    ).all()
    return paged([web_capture_out(c) for c in rows], total, paging)


@router.get("/api/web-captures/active")
def active_web_captures(include_archived: bool = False, db: Session = Depends(get_db),
                        user: User = Depends(current_user)):
    rows = db.scalars(
        select(WebCapture).where(WebCapture.status.in_(WEB_CAPTURE_ACTIVE_STATES),
                                 _capture_visible(db, include_archived=include_archived))
        .order_by(WebCapture.id)
    ).all()
    return {
        "running": [web_capture_out(c) for c in rows if c.status == "running"],
        "queued": [web_capture_out(c) for c in rows if c.status == WEB_CAPTURE_QUEUED],
    }


@router.get("/api/web-captures/{capture_id}")
def get_web_capture(capture_id: int, db: Session = Depends(get_db), user: User = Depends(current_user)):
    c = db.scalar(
        select(WebCapture).where(WebCapture.id == capture_id)
        .options(selectinload(WebCapture.pages).selectinload(WebPage.device))
    )
    if c is None:
        raise HTTPException(404, "Web capture not found")
    return web_capture_out(c, include_pages=True)


@router.post("/api/web-captures", response_model=CaptureStarted)
def start_web_capture(body: WebCaptureRequest, request: Request, db: Session = Depends(get_db),
                      user: User = Depends(require_admin)):
    cfg = get_section(db, WebCaptureSettings)
    if not cfg.enabled:
        raise HTTPException(409, "Web Capture is disabled in settings")
    given = [x for x in (body.targets, body.device_uuids, True if body.inventory else None) if x]
    if len(given) != 1:
        raise HTTPException(422, "Specify exactly one of: targets, device_uuids, inventory")

    scope = body.scope
    if body.inventory:
        scope = "remote"
        from ..core.web_capture.inventory import inventory_remote_ips
        ips = inventory_remote_ips(db)
        if not ips:
            raise HTTPException(404, "No open RDP or VNC ports in current inventory")
        spec = ",".join(ips)
        target_text = spec
    elif body.device_uuids:
        ips = db.scalars(select(Device.current_ip).where(Device.uuid.in_(body.device_uuids))).all()
        if not ips:
            raise HTTPException(404, "No matching devices")
        spec = ",".join(ips)
        target_text = spec
    else:
        spec = body.targets or ""
        target_text = spec.strip()

    try:
        targets = AddressSet.from_specs(spec, allow_hostname=True)
    except TargetError as exc:
        raise HTTPException(422, str(exc)) from exc
    if not targets:
        raise HTTPException(422, "No targets given")
    if len(targets) > cfg.max_addresses:
        raise HTTPException(422, f"Too many addresses ({len(targets)}); maximum is {cfg.max_addresses}")

    # Reject anything that looks like a raw URL submission
    raw = (body.targets or "")
    if "://" in raw or raw.strip().lower().startswith(("http:", "https:")):
        raise HTTPException(422, "Arbitrary URLs are not accepted; provide IP, range, CIDR, or device UUIDs")

    job = WebCapture(
        status=WEB_CAPTURE_QUEUED,
        targets=target_text,
        scope=scope,
        target_count=len(targets),
        requested_by=user.username,
        mock_mode=scanner_status().effective_mode == "mock" or cfg.force_mock,
    )
    db.add(job)
    db.flush()
    audit(db, user.username, "web_capture.start", targets.describe(),
          {"capture_id": job.id, "target_count": len(targets), "scope": scope}, client_ip(request))
    capture_id = job.id
    db.commit()
    web_capture_manager.wake()
    from ..config import get_settings
    # When the background worker is disabled (tests / single-shot), run inline.
    if not get_settings().background_jobs or not web_capture_manager.running:
        run_web_capture(capture_id, CaptureContext(capture_id))
    db.expire_all()
    job = db.get(WebCapture, capture_id)
    return {"capture": web_capture_out(job)}


@router.post("/api/web-captures/{capture_id}/cancel")
def cancel_web_capture(capture_id: int, request: Request, db: Session = Depends(get_db),
                       user: User = Depends(require_admin)):
    job = db.get(WebCapture, capture_id)
    if job is None:
        raise HTTPException(404, "Web capture not found")
    if job.status not in WEB_CAPTURE_ACTIVE_STATES:
        raise HTTPException(409, "Capture is not active")
    ok = web_capture_manager.cancel(capture_id)
    if not ok and job.status == WEB_CAPTURE_QUEUED:
        # worker may be disabled (tests): mark cancelled directly
        from ..db import utcnow
        from ..models import WEB_CAPTURE_CANCELLED
        job.status = WEB_CAPTURE_CANCELLED
        job.finished_at = utcnow()
        job.notes = "Cancelled before it started."
        ok = True
    if not ok:
        raise HTTPException(409, "Could not cancel capture")
    audit(db, user.username, "web_capture.cancel", job.targets, {"capture_id": capture_id}, client_ip(request))
    db.commit()
    return {"ok": True}


@router.delete("/api/web-captures/{capture_id}", status_code=204)
def remove_web_capture(capture_id: int, request: Request, db: Session = Depends(get_db),
                       user: User = Depends(require_admin)):
    job = db.scalar(select(WebCapture).where(WebCapture.id == capture_id).options(selectinload(WebCapture.pages)))
    if job is None:
        raise HTTPException(404, "Web capture not found")
    if job.status in WEB_CAPTURE_ACTIVE_STATES:
        raise HTTPException(409, "Cancel the capture before deleting it")
    audit(db, user.username, "web_capture.delete", job.targets, {"capture_id": capture_id}, client_ip(request))
    delete_web_capture(db, job)
    db.commit()


@router.get("/api/web-pages/{page_id}/screenshot")
def get_screenshot(page_id: int, db: Session = Depends(get_db), user: User = Depends(current_user)):
    page = db.get(WebPage, page_id)
    if page is None:
        raise HTTPException(404, "Web page not found")
    path = resolve_screenshot(page.screenshot_relpath)
    if path is None:
        raise HTTPException(404, "Screenshot not available")
    media = "image/webp" if path.suffix.lower() == ".webp" else "image/png"
    # inline: render in the browser instead of downloading; a page's screenshot never changes
    return FileResponse(path, media_type=media, filename=path.name, content_disposition_type="inline",
                        headers={"Cache-Control": "private, max-age=86400"})


@router.get("/api/web-pages/{page_id}/live")
def live_rtsp_stream(page_id: int, db: Session = Depends(get_db), user: User = Depends(current_user)):
    """Proxy an RTSP source as multipart MJPEG for in-browser live viewing."""
    page = db.get(WebPage, page_id)
    if page is None:
        raise HTTPException(404, "Web page not found")
    if not _is_rtsp_page(page):
        raise HTTPException(400, "Not an RTSP capture page")
    if scanner_status().effective_mode == "mock" or get_section(db, WebCaptureSettings).force_mock:
        raise HTTPException(409, "Live RTSP is not available in mock mode")
    if not ffmpeg_available():
        raise HTTPException(503, "ffmpeg unavailable on the server")
    url = page.final_url or page.url
    if not url or not url.lower().startswith(("rtsp://", "rtsps://")):
        raise HTTPException(404, "No RTSP URL for this page")
    ok, reason = looks_like_rtsp(url)
    if not ok:
        raise HTTPException(502, reason)
    if not acquire_live_slot():
        raise HTTPException(429, "Too many live RTSP streams; try again shortly")

    def _gen():
        try:
            yield from iter_mjpeg(url)
        except Exception as exc:
            log.warning("live RTSP %s failed: %s", url[:120], exc)
        finally:
            release_live_slot()

    return StreamingResponse(
        _gen(),
        media_type=f"multipart/x-mixed-replace; boundary={MJPEG_BOUNDARY}",
        headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"},
    )


@router.get("/api/devices/{device_uuid}/rtsp/{port}/live")
def live_rtsp_by_port(
    device_uuid: str,
    port: int,
    db: Session = Depends(get_db),
    user: User = Depends(current_user),
):
    """Live MJPEG from an inventory RTSP port (discovers a working path if needed)."""
    from ..core.web_capture.inventory import COMMON_RTSP_PORTS, is_rtsp_service

    if port < 1 or port > 65535:
        raise HTTPException(400, "Invalid port")
    dev = db.scalar(select(Device).where(Device.uuid == device_uuid).options(selectinload(Device.ports)))
    if dev is None:
        raise HTTPException(404, "Device not found")
    dport = next((p for p in dev.ports if p.port == port and p.protocol == "tcp" and p.is_open), None)
    if dport is None:
        raise HTTPException(404, "Open TCP port not found on device")
    if not (is_rtsp_service(dport.service) or (not dport.service and port in COMMON_RTSP_PORTS)):
        raise HTTPException(400, "Port is not identified as RTSP in inventory")
    if scanner_status().effective_mode == "mock" or get_section(db, WebCaptureSettings).force_mock:
        raise HTTPException(409, "Live RTSP is not available in mock mode")
    if not ffmpeg_available():
        raise HTTPException(503, "ffmpeg unavailable on the server")

    # Prefer a previously discovered stream URL from web capture
    prior = db.scalar(
        select(WebPage)
        .where(
            WebPage.device_id == dev.id,
            WebPage.port == port,
            WebPage.scheme.in_(("rtsp", "rtsps")),
        )
        .order_by(WebPage.id.desc())
        .limit(1)
    )
    url = None
    if prior and (prior.final_url or prior.url):
        url = prior.final_url or prior.url
        ok, reason = looks_like_rtsp(url)
        if not ok:
            url = None
            # Fall through to path discovery / clearer error
            prior_reason = reason
        else:
            prior_reason = None
    else:
        prior_reason = None

    if url is None:
        scheme = "rtsps" if (dport.service or "").lower().find("ssl") >= 0 else "rtsp"
        hosts = [h for h in (dev.dns_name, dev.hostname, dev.current_ip) if h]
        found = probe_rtsp(scheme, hosts or [dev.current_ip], port, timeout=10.0)
        if found is None:
            raise HTTPException(502, prior_reason or "Could not open any RTSP path on this port")
        url = found.url

    if not acquire_live_slot():
        raise HTTPException(429, "Too many live RTSP streams; try again shortly")

    def _gen():
        try:
            yield from iter_mjpeg(url)
        except Exception as exc:
            log.warning("live RTSP %s failed: %s", url[:120], exc)
        finally:
            release_live_slot()

    return StreamingResponse(
        _gen(),
        media_type=f"multipart/x-mixed-replace; boundary={MJPEG_BOUNDARY}",
        headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"},
    )


@router.get("/api/web-hosts", response_model=WebHostsPage)
def web_hosts(
    kind: Literal["web", "remote"] = Query(
        "web",
        description="web = HTTP(S)/RTSP gallery; remote = RDP/VNC desktops only",
    ),
    include_archived: bool = Query(False, description="also list hosts of archived networks"),
    paging: Paging = Depends(),
    db: Session = Depends(get_db),
    user: User = Depends(current_user),
):
    """Devices with captured pages, summarised from their latest capture, one page at a time.

    ``kind=web`` (default) excludes RDP/VNC; ``kind=remote`` returns only those. Hosts are ordered (with
    screenshots first) before paging, so page 1 always holds the most useful cards. Hosts of archived
    networks (and simulated hosts while they are hidden) are left out like everywhere else.
    """
    latest = (
        select(WebPage.device_id, func.max(WebPage.capture_id).label("cid"))
        .join(WebCapture, WebCapture.id == WebPage.capture_id)
        .join(Device, Device.id == WebPage.device_id)
        .where(WebPage.device_id.is_not(None), WebCapture.status.in_(HOST_VIEW_STATES),
               device_visible(db, include_archived=include_archived))
        .group_by(WebPage.device_id)
        .subquery()
    )
    pages = db.scalars(
        select(WebPage)
        .join(latest, (WebPage.device_id == latest.c.device_id) & (WebPage.capture_id == latest.c.cid))
        .options(selectinload(WebPage.device))
    ).all()
    by_dev: dict[int, list[WebPage]] = {}
    for p in pages:
        desktop = _is_desktop_page(p)
        if kind == "remote" and not desktop:
            continue
        if kind == "web" and desktop:
            continue
        by_dev.setdefault(p.device_id, []).append(p)
    hosts = []
    for dev_pages in by_dev.values():
        dev = dev_pages[0].device
        ranked = sorted(dev_pages, key=_page_rank)
        hero = ranked[0]
        reachable = [p for p in dev_pages if _error_reason(p) is None]
        hosts.append({
            "device_uuid": dev.uuid,
            "hostname": dev.hostname,
            "ip": dev.current_ip,
            "device_status": dev.status,
            "capture_id": hero.capture_id,
            "captured_at": max(p.captured_at for p in dev_pages),
            "ports": sorted({p.port for p in dev_pages}),
            "page_count": len(dev_pages),
            "reachable_count": len(reachable),
            "screenshot_count": sum(1 for p in dev_pages if _useful_shot(p)),
            "has_login": any(p.kind == WEB_PAGE_LOGIN and p.http_status and 200 <= p.http_status < 400
                             for p in dev_pages),
            "auth_required": any(p.http_status in (401, 403) for p in dev_pages),
            "tls_unverified": any(p.tls_verified is False for p in dev_pages),
            "external_redirect": any(p.external_redirect for p in dev_pages),
            "hero": web_page_out(hero),
            "services": _web_services(dev_pages),
        })
    hosts.sort(key=lambda h: (h["screenshot_count"] == 0, h["reachable_count"] == 0, h["hostname"] or h["ip"]))
    return {"hosts": hosts[paging.offset:paging.offset + paging.page_size], "total": len(hosts),
            "page": paging.page, "page_size": paging.page_size}


@router.get("/api/devices/{uuid}/web-interfaces")
def device_web_interfaces(uuid: str, capture_id: int | None = Query(None), db: Session = Depends(get_db),
                          user: User = Depends(current_user)):
    """Captured pages of one device: the requested capture (default: latest) plus its capture history."""
    dev = db.scalar(select(Device).where(Device.uuid == uuid))
    if dev is None:
        raise HTTPException(404, "Device not found")
    runs = db.scalars(
        select(WebCapture)
        .where(WebCapture.status.in_(HOST_VIEW_STATES),
               WebCapture.id.in_(select(WebPage.capture_id).where(WebPage.device_id == dev.id)))
        .order_by(WebCapture.id.desc())
        .limit(50)
    ).all()
    if not runs:
        return {"device_uuid": uuid, "capture_id": None, "captures": [], "pages": []}
    by_run: dict[int, list[WebPage]] = {r.id: [] for r in runs}
    for p in db.scalars(select(WebPage).where(WebPage.device_id == dev.id, WebPage.capture_id.in_(by_run))):
        by_run[p.capture_id].append(p)
    captures = [
        {"id": r.id, "status": r.status, "requested_by": r.requested_by, "finished_at": r.finished_at,
         "page_count": len(by_run[r.id]),
         "screenshot_count": sum(1 for p in by_run[r.id] if _useful_shot(p)),
         "captured_at": max(p.captured_at for p in by_run[r.id])}
        for r in runs
    ]
    if capture_id is not None and capture_id not in by_run:
        raise HTTPException(404, "This device has no pages in that capture")
    chosen = capture_id if capture_id is not None else runs[0].id
    pages = by_run[chosen]
    return {
        "device_uuid": uuid,
        "capture_id": chosen,
        "captures": captures,
        "pages": [web_page_out(p) for p in sorted(pages, key=lambda p: (p.port, p.kind, p.id))],
    }
