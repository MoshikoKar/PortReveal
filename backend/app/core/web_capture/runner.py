"""Execute one Web Capture job: inventory → probe → classify → screenshot."""
from __future__ import annotations

import logging
import threading
import time

from sqlalchemy import select
from sqlalchemy.orm import Session

from ...config import get_settings
from ...db import session_scope, utcnow
from ...models import (
    SCREENSHOT_CAPTURED,
    SCREENSHOT_FAILED,
    SCREENSHOT_NOT_REQUESTED,
    SCREENSHOT_SKIPPED,
    WEB_CAPTURE_CANCELLED,
    WEB_CAPTURE_COMPLETED,
    WEB_CAPTURE_FAILED,
    WEB_CAPTURE_PARTIAL,
    WEB_CAPTURE_RUNNING,
    WEB_PAGE_STREAM,
    DevicePort,
    Exclusion,
    WebCapture,
    WebPage,
    new_uuid,
)
from ...netutils import AddressSet, TargetError
from ...scanner import scanner_status
from ...settings_store import WebCaptureSettings, get_section
from ..web_storage import delete_capture_files, write_screenshot
from .classify import BLANK_PAGE_REASON, unusable_page_reason
from .inventory import find_web_endpoints
from .mock import mock_probe_endpoint, mock_rtsp_endpoint, placeholder_image
from .probe import probe_endpoint
from .rtsp import ffmpeg_available, placeholder_rtsp_webp, probe_rtsp
from .screenshot import playwright_available, take_screenshot
from .wordlist import discovery_paths

log = logging.getLogger(__name__)


class CaptureCancelled(Exception):
    pass


class CaptureContext:
    def __init__(self, capture_id: int):
        self.capture_id = capture_id
        self.cancel_event = threading.Event()

    @property
    def cancelled(self) -> bool:
        return self.cancel_event.is_set()

    def check(self) -> None:
        if self.cancelled:
            raise CaptureCancelled()

    def cancel(self) -> None:
        self.cancel_event.set()


def exclusion_set(db: Session) -> AddressSet:
    out = AddressSet()
    for ex in db.scalars(select(Exclusion).where(Exclusion.enabled.is_(True))).all():
        try:
            out = out.union(AddressSet.from_specs(ex.value, allow_hostname=True))
        except TargetError:
            log.error("Invalid exclusion ignored during web capture: %s", ex.value[:80])
    return out


def _update(capture_id: int, **fields) -> None:
    with session_scope() as db:
        row = db.get(WebCapture, capture_id)
        if row is None:
            return
        for k, v in fields.items():
            setattr(row, k, v)


def _use_mock(cfg: WebCaptureSettings) -> bool:
    if cfg.force_mock:
        return True
    st = scanner_status()
    return st.effective_mode == "mock" or get_settings().app_env == "test"


def run_web_capture(capture_id: int, ctx: CaptureContext) -> str:
    """Run a queued web capture synchronously. Returns final status."""
    started = time.monotonic()
    notes: list[str] = []
    screenshots_done = 0
    pages_done = 0
    had_failures = False
    browser_missing = False

    with session_scope() as db:
        job = db.get(WebCapture, capture_id)
        if job is None:
            return WEB_CAPTURE_FAILED
        if job.status == WEB_CAPTURE_CANCELLED:
            return WEB_CAPTURE_CANCELLED
        cfg = get_section(db, WebCaptureSettings)
        targets_text = job.targets
        mock = _use_mock(cfg)
        job.status = WEB_CAPTURE_RUNNING
        job.started_at = utcnow()
        job.stage = "resolving targets"
        job.progress = 0.02
        job.mock_mode = mock
        db.flush()

    try:
        ctx.check()
        try:
            targets = AddressSet.from_specs(targets_text, allow_hostname=True)
        except TargetError as exc:
            _update(capture_id, status=WEB_CAPTURE_FAILED, finished_at=utcnow(), stage=None,
                    error=str(exc), notes="Invalid targets.")
            return WEB_CAPTURE_FAILED

        with session_scope() as db:
            excl = exclusion_set(db)
            cfg = get_section(db, WebCaptureSettings)

        remaining = targets.subtract(excl)
        for ip in sorted(_ips(targets) - _ips(remaining)):
            notes.append(f"{ip}: skipped (exclusion list).")

        ips = _ips(remaining)
        if len(ips) > cfg.max_addresses:
            _update(capture_id, status=WEB_CAPTURE_FAILED, finished_at=utcnow(), stage=None,
                    error=f"Too many addresses ({len(ips)}); maximum is {cfg.max_addresses}")
            return WEB_CAPTURE_FAILED

        _update(capture_id, stage="selecting endpoints", progress=0.08, target_count=len(ips))
        ctx.check()

        with session_scope() as db:
            cfg = get_section(db, WebCaptureSettings)
            endpoints, inv_notes = find_web_endpoints(db, ips, max_endpoints=cfg.max_endpoints)
            notes.extend(inv_notes)
            # Snapshot endpoint data while session open
            endpoint_data = [
                {
                    "device_id": e.device_id,
                    "device_port_id": e.device_port_id,
                    "ip": e.ip,
                    "port": e.port,
                    "service": e.service,
                    "product": e.product,
                    "scheme": e.scheme,
                    "hosts": e.host_candidates,
                }
                for e in endpoints
            ]
            capture_uuid = db.get(WebCapture, capture_id).uuid
            mock = db.get(WebCapture, capture_id).mock_mode

        _update(capture_id, endpoints_found=len(endpoint_data), stage="probing", progress=0.15)

        if not endpoint_data:
            status = WEB_CAPTURE_COMPLETED
            _update(
                capture_id,
                status=status,
                finished_at=utcnow(),
                stage=None,
                progress=1.0,
                notes="\n".join(notes) or "No known web or RTSP endpoints found in current inventory.",
                pages_captured=0,
                screenshots_captured=0,
            )
            return status

        deadline = started + cfg.max_job_minutes * 60
        shot_budget = cfg.max_screenshots_per_job
        discovery_app_paths = discovery_paths(cfg.discovery_wordlist)
        browser_ok = playwright_available() if not mock else True
        ffmpeg_ok = ffmpeg_available() if not mock else True
        if not browser_ok and not mock:
            browser_missing = True
            notes.append("Chromium unavailable; HTTP metadata captured without screenshots.")
        if not ffmpeg_ok and not mock and any(e["scheme"] in ("rtsp", "rtsps") for e in endpoint_data):
            notes.append("ffmpeg unavailable; RTSP endpoints recorded without frames or live proxy.")

        # (ip, landing URL) -> (status, relpath, error) of a screenshot already taken in this job,
        # so e.g. http:80 redirecting to the https:443 page reuses that image instead of reloading it
        shot_cache: dict[tuple[str, str], tuple[str, str | None, str | None]] = {}
        total = len(endpoint_data)
        for idx, ep in enumerate(endpoint_data):
            if time.monotonic() > deadline:
                notes.append("Job time limit reached; remaining endpoints skipped.")
                had_failures = True
                break
            ctx.check()
            _update(
                capture_id,
                stage=f"probing {ep['ip']}:{ep['port']}",
                progress=0.15 + 0.7 * (idx / max(total, 1)),
            )

            allowed_ips = {ep["ip"]}
            allowed_hosts = set(ep["hosts"]) | {ep["ip"]}

            # --- RTSP / RTSPS: frame grab (and later live MJPEG via API) -----------------
            if ep["scheme"] in ("rtsp", "rtsps"):
                pages_done, screenshots_done, shot_budget, had_failures = _capture_rtsp_endpoint(
                    capture_id=capture_id,
                    capture_uuid=capture_uuid,
                    ep=ep,
                    ctx=ctx,
                    mock=mock,
                    ffmpeg_ok=ffmpeg_ok,
                    shot_budget=shot_budget,
                    timeout=cfg.http_timeout_seconds,
                    pages_done=pages_done,
                    screenshots_done=screenshots_done,
                    had_failures=had_failures,
                    notes=notes,
                )
                continue

            probe = None
            last_err = None
            for host in ep["hosts"]:
                ctx.check()
                try:
                    if mock:
                        probe = mock_probe_endpoint(ep["scheme"], host, ep["port"], ep["ip"])
                    else:
                        probe = probe_endpoint(
                            ep["scheme"],
                            host,
                            ep["port"],
                            allowed_hosts=allowed_hosts,
                            allowed_ips=allowed_ips,
                            timeout=cfg.http_timeout_seconds,
                            max_bytes=cfg.max_response_bytes,
                            max_candidates=cfg.max_candidate_probes,
                            max_pages=cfg.max_pages_per_endpoint,
                            max_discovery=cfg.max_discovery_paths,
                            app_paths=discovery_app_paths,
                            verify_tls=False,
                            cancel_check=lambda: ctx.cancelled,
                        )
                    if probe.pages and any(p.http_status for p in probe.pages):
                        break
                except CaptureCancelled:
                    raise
                except Exception as exc:
                    last_err = str(exc)
                    log.debug("probe %s:%s via %s failed: %s", ep["ip"], ep["port"], host, exc)
                    probe = None
            if probe is None:
                had_failures = True
                notes.append(f"{ep['ip']}:{ep['port']}: probe failed ({last_err or 'no response'}).")
                continue

            # Persist pages + screenshots
            with session_scope() as db:
                job = db.get(WebCapture, capture_id)
                if job is None or job.status == WEB_CAPTURE_CANCELLED:
                    raise CaptureCancelled()
                for pr in probe.pages:
                    page_uuid = new_uuid()
                    shot_status = SCREENSHOT_NOT_REQUESTED
                    shot_path = None
                    shot_err = pr.error
                    want_shot = shot_budget > 0 and not pr.external_redirect and (
                        pr.http_status is not None or pr.html
                    )
                    error_reason = unusable_page_reason(
                        pr.http_status, pr.title, pr.html, getattr(pr, "body_text", None)
                    )
                    if pr.external_redirect:
                        shot_status = SCREENSHOT_NOT_REQUESTED
                        shot_err = shot_err or "redirect outside target"
                    elif error_reason:
                        # error, unresolved redirect, no response, or a default server page:
                        # nothing worth a screenshot
                        shot_status = SCREENSHOT_SKIPPED
                        shot_err = shot_err or error_reason
                    elif want_shot:
                        if mock:
                            write_screenshot(capture_uuid, page_uuid, placeholder_image())
                            shot_status = SCREENSHOT_CAPTURED
                            shot_path = f"{capture_uuid}/{page_uuid}.webp"
                            shot_budget -= 1
                            screenshots_done += 1
                        elif browser_missing:
                            shot_status = SCREENSHOT_SKIPPED
                            shot_err = "Chromium unavailable"
                        else:
                            # Screenshot outside long DB transaction
                            pass  # filled below after commit prep
                    row = WebPage(
                        uuid=page_uuid,
                        capture_id=capture_id,
                        device_id=ep["device_id"],
                        device_port_id=ep["device_port_id"],
                        ip=ep["ip"],
                        port=ep["port"],
                        scheme=probe.scheme,
                        host_used=probe.host_used,
                        kind=pr.kind,
                        url=pr.url,
                        final_url=pr.final_url,
                        redirect_target=pr.redirect_target,
                        external_redirect=pr.external_redirect,
                        http_status=pr.http_status,
                        title=pr.title,
                        content_type=pr.content_type,
                        server_header=pr.server_header,
                        tls_verified=pr.tls_verified,
                        screenshot_status=shot_status,
                        screenshot_relpath=shot_path,
                        capture_error=shot_err,
                    )
                    db.add(row)
                    pages_done += 1
                    if pr.error and pr.http_status is None and not pr.external_redirect:
                        had_failures = True
                # Enrich inventory product when a local LLM API was fingerprinted
                hint = next((p.product_hint for p in probe.pages if getattr(p, "product_hint", None)), None)
                if hint:
                    dport = db.get(DevicePort, ep["device_port_id"])
                    if dport is not None and (not dport.product or dport.product.lower() in ("http", "https", "unknown")):
                        dport.product = hint
                        if not dport.service or "http" not in dport.service.lower():
                            dport.service = dport.service or "http"
                db.flush()
                # Collect pages needing real screenshots
                pending = [
                    p for p in db.scalars(select(WebPage).where(WebPage.capture_id == capture_id)).all()
                    if p.ip == ep["ip"] and p.port == ep["port"] and p.screenshot_status == SCREENSHOT_NOT_REQUESTED
                    and not p.external_redirect and shot_budget > 0 and not mock and not browser_missing
                    and (p.http_status is not None or p.title)
                ]
                # Limit pending by remaining budget and max pages already handled
                pending = pending[:shot_budget]

            if not mock and not browser_missing:
                for page_id_info in pending:
                    ctx.check()
                    if shot_budget <= 0:
                        break
                    with session_scope() as db:
                        page = db.get(WebPage, page_id_info.id)
                        if page is None:
                            continue
                        target_url = page.final_url or page.url
                        page_uuid = page.uuid
                        cap_uuid = capture_uuid
                        hosts = allowed_hosts
                        aips = allowed_ips
                    cache_key = (ep["ip"], target_url.rstrip("/"))
                    cached = shot_cache.get(cache_key)
                    if cached is not None:
                        with session_scope() as db:
                            page = db.get(WebPage, page_id_info.id)
                            if page is not None:
                                page.screenshot_status, page.screenshot_relpath, page.capture_error = cached
                        continue
                    result = take_screenshot(
                        target_url,
                        timeout_ms=int(cfg.browser_timeout_seconds * 1000),
                        allowed_hosts=hosts,
                        allowed_ips=aips,
                        settle_ms=int(cfg.page_settle_seconds * 1000),
                        cancel_check=lambda: ctx.cancelled,
                    )
                    with session_scope() as db:
                        page = db.get(WebPage, page_id_info.id)
                        if page is None:
                            continue
                        if result.status == "captured" and result.data:
                            try:
                                rel = write_screenshot(cap_uuid, page_uuid, result.data)
                                page.screenshot_status = SCREENSHOT_CAPTURED
                                page.screenshot_relpath = rel
                                shot_budget -= 1
                                screenshots_done += 1
                                shot_cache[cache_key] = (SCREENSHOT_CAPTURED, rel, page.capture_error)
                            except Exception:
                                page.screenshot_status = SCREENSHOT_FAILED
                                page.capture_error = "screenshot save failed"
                                had_failures = True
                        elif result.status == "skipped":
                            page.screenshot_status = SCREENSHOT_SKIPPED
                            page.capture_error = result.error
                            # Browser-rendered title can expose SPA soft-404s the probe HTML missed
                            if not page.title and getattr(result, "title", None):
                                page.title = result.title
                            if result.error in (BLANK_PAGE_REASON,) or (
                                result.error
                                and (
                                    result.error.startswith("default server page")
                                    or result.error.startswith("error page")
                                    or result.error == "redirect"
                                    or result.error.startswith("redirect ")
                                )
                            ):
                                shot_cache[cache_key] = (SCREENSHOT_SKIPPED, None, result.error)
                            if result.error == "Chromium unavailable":
                                browser_missing = True
                        else:
                            page.screenshot_status = SCREENSHOT_FAILED
                            page.capture_error = result.error or "screenshot failed"
                            had_failures = True

        ctx.check()
        status = WEB_CAPTURE_PARTIAL if (had_failures or browser_missing) else WEB_CAPTURE_COMPLETED
        if pages_done == 0 and had_failures:
            status = WEB_CAPTURE_PARTIAL
        _update(
            capture_id,
            status=status,
            finished_at=utcnow(),
            stage=None,
            progress=1.0,
            pages_captured=pages_done,
            screenshots_captured=screenshots_done,
            notes="\n".join(notes) or None,
        )
        log.info(
            "web capture %s %s in %.1fs: %d pages, %d screenshots",
            capture_id, status, time.monotonic() - started, pages_done, screenshots_done,
        )
        return status

    except CaptureCancelled:
        _update(
            capture_id,
            status=WEB_CAPTURE_CANCELLED,
            finished_at=utcnow(),
            stage=None,
            pages_captured=pages_done,
            screenshots_captured=screenshots_done,
            notes=("\n".join(notes) + "\nCancelled by user." if notes else "Cancelled by user."),
        )
        return WEB_CAPTURE_CANCELLED
    except Exception as exc:
        log.exception("web capture %s crashed", capture_id)
        _update(
            capture_id,
            status=WEB_CAPTURE_FAILED,
            finished_at=utcnow(),
            stage=None,
            error=f"internal error: {exc}",
            notes="\n".join(notes) or None,
        )
        return WEB_CAPTURE_FAILED


def _ips(aset: AddressSet) -> set[str]:
    return set(aset.addresses())


def _capture_rtsp_endpoint(
    *,
    capture_id: int,
    capture_uuid: str,
    ep: dict,
    ctx: CaptureContext,
    mock: bool,
    ffmpeg_ok: bool,
    shot_budget: int,
    timeout: float,
    pages_done: int,
    screenshots_done: int,
    had_failures: bool,
    notes: list[str],
) -> tuple[int, int, int, bool]:
    """Probe one RTSP endpoint, persist a stream page, optionally store a still frame."""
    scheme = ep["scheme"] if ep["scheme"] in ("rtsp", "rtsps") else "rtsp"
    host = ep["hosts"][0]
    url = f"{scheme}://{host}:{ep['port']}/" if ep["port"] != 554 else f"{scheme}://{host}/"
    shot_status = SCREENSHOT_SKIPPED
    shot_path = None
    shot_err: str | None = None
    page_uuid = new_uuid()
    title = "RTSP stream"
    content_type = "application/rtsp"
    server_header = (ep.get("service") or "rtsp")

    if mock:
        probe = mock_rtsp_endpoint(scheme, host, ep["port"])
        pr = probe.pages[0]
        url = pr.url
        host = probe.host_used
        title = pr.title or title
        content_type = pr.content_type or content_type
        server_header = pr.server_header or server_header
        if shot_budget > 0:
            write_screenshot(capture_uuid, page_uuid, placeholder_rtsp_webp())
            shot_status = SCREENSHOT_CAPTURED
            shot_path = f"{capture_uuid}/{page_uuid}.webp"
            shot_budget -= 1
            screenshots_done += 1
    elif not ffmpeg_ok:
        shot_status = SCREENSHOT_SKIPPED
        shot_err = "ffmpeg unavailable"
        notes.append(f"{ep['ip']}:{ep['port']}: RTSP recorded without frame (ffmpeg unavailable).")
    else:
        found = probe_rtsp(
            scheme,
            ep["hosts"],
            ep["port"],
            timeout=max(timeout, 8.0),
            cancel_check=lambda: ctx.cancelled,
        )
        if found is None:
            had_failures = True
            shot_status = SCREENSHOT_FAILED
            shot_err = "no RTSP stream responded"
            notes.append(f"{ep['ip']}:{ep['port']}: RTSP probe failed (no stream).")
        else:
            url = found.url
            host = found.host_used
            frame = found.frame
            if frame.status == "captured" and frame.data and shot_budget > 0:
                try:
                    shot_path = write_screenshot(capture_uuid, page_uuid, frame.data)
                    shot_status = SCREENSHOT_CAPTURED
                    shot_budget -= 1
                    screenshots_done += 1
                except Exception:
                    shot_status = SCREENSHOT_FAILED
                    shot_err = "screenshot save failed"
                    had_failures = True
            elif frame.status == "skipped":
                shot_status = SCREENSHOT_SKIPPED
                shot_err = frame.error
            else:
                shot_status = SCREENSHOT_FAILED
                shot_err = frame.error or "RTSP frame failed"
                had_failures = True

    with session_scope() as db:
        job = db.get(WebCapture, capture_id)
        if job is None or job.status == WEB_CAPTURE_CANCELLED:
            raise CaptureCancelled()
        db.add(
            WebPage(
                uuid=page_uuid,
                capture_id=capture_id,
                device_id=ep["device_id"],
                device_port_id=ep["device_port_id"],
                ip=ep["ip"],
                port=ep["port"],
                scheme=scheme,
                host_used=host,
                kind=WEB_PAGE_STREAM,
                url=url,
                final_url=url,
                redirect_target=None,
                external_redirect=False,
                http_status=None,
                title=title,
                content_type=content_type,
                server_header=server_header,
                tls_verified=None,
                screenshot_status=shot_status,
                screenshot_relpath=shot_path,
                capture_error=shot_err,
            )
        )
        pages_done += 1
    return pages_done, screenshots_done, shot_budget, had_failures


def delete_web_capture(db: Session, capture: WebCapture) -> None:
    delete_capture_files(capture.uuid)
    db.delete(capture)
