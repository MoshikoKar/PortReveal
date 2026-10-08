"""Passive Playwright screenshots (soft-fail if Chromium is missing)."""
from __future__ import annotations

import logging
import re
import time
from dataclasses import dataclass
from io import BytesIO
from typing import Callable
from urllib.parse import urljoin

from .classify import BLANK_PAGE_REASON, unusable_page_reason

log = logging.getLogger(__name__)

VIEWPORT = {"width": 1280, "height": 720}
# A page must stay put (no main-frame navigation) this long before it is captured, so a JS
# redirect that fires shortly after load is followed instead of photographing the stub page.
QUIET_MS = 1200
NETWORK_IDLE_MS = 4000
META_REFRESH_RE = re.compile(r"^\s*\d*(?:\.\d+)?\s*[;,]?\s*(?:url\s*=\s*)?['\"]?([^'\"]*)", re.I)

# Does the page show anything? Text (incl. shadow DOM), sized media/controls/frames, or a CSS
# background image. Also returns any <meta http-equiv=refresh> so it can be followed at once,
# plus title/body text for soft-error / default-page checks after JS has run (SPA "Not Found").
_MEASURE_JS = """
() => {
  const MEDIA = 'img,svg,canvas,video,object,embed,iframe,frame,input,select,textarea,button';
  const sized = (el, min) => { const r = el.getBoundingClientRect(); return r.width >= min && r.height >= min; };
  const meta = document.querySelector('meta[http-equiv="refresh" i]');
  const refresh = meta ? meta.getAttribute('content') : null;
  const title = (document.title || '').trim().slice(0, 500);
  const text = ((document.body && document.body.innerText) || '').replace(/\\s+/g, ' ').trim().slice(0, 2000);
  const body = document.body;
  if (body && (body.innerText || '').trim()) return { visible: true, refresh, title, text };
  let visible = false;
  const walk = (root) => {
    for (const el of root.querySelectorAll('*')) {
      if (visible) return;
      if (el.shadowRoot) {
        if ((el.shadowRoot.textContent || '').trim()) { visible = true; return; }
        walk(el.shadowRoot);
      }
      if (el.matches(MEDIA) && sized(el, 16)) visible = true;
    }
  };
  walk(document);
  if (!visible) {
    const els = [document.documentElement, ...document.querySelectorAll('*')].slice(0, 500);
    visible = els.some((el) => (getComputedStyle(el).backgroundImage || '').includes('url(') && sized(el, 64));
  }
  return { visible, refresh, title, text };
}
"""


@dataclass
class ScreenshotResult:
    status: str  # captured | skipped | failed
    data: bytes | None = None
    error: str | None = None
    title: str | None = None
    body_text: str | None = None


def playwright_available() -> bool:
    try:
        from playwright.sync_api import sync_playwright  # noqa: F401

        return True
    except Exception:
        return False


def _to_webp(png_bytes: bytes) -> bytes:
    try:
        from PIL import Image

        img = Image.open(BytesIO(png_bytes))
        out = BytesIO()
        img.save(out, format="WEBP", quality=70, method=4)
        return out.getvalue()
    except Exception:
        return png_bytes


def meta_refresh_target(content: str | None, base_url: str) -> str | None:
    """Absolute URL of a ``<meta http-equiv=refresh content="5; url=...">``, or None."""
    if not content:
        return None
    m = META_REFRESH_RE.match(content)
    target = m.group(1).strip() if m else ""
    return urljoin(base_url, target) if target else None


def _settle(page, navs: list[int], budget_ms: int, cancel_check: Callable[[], bool] | None) -> dict:
    """Wait until the page shows content and stopped navigating; return the last measure state.

    Handles slow single-page apps and "loading…" stubs that redirect after a second or two:
    each main-frame navigation restarts the quiet window, a meta refresh is followed at once,
    and a still-blank page keeps waiting until ``budget_ms`` runs out.
    """
    end = time.monotonic() + max(0, budget_ms) / 1000
    followed: set[str] = set()
    last: dict = {"visible": False, "refresh": None, "title": None, "text": None}
    while True:
        if cancel_check and cancel_check():
            return last
        left = int((end - time.monotonic()) * 1000)
        try:
            page.wait_for_load_state("networkidle", timeout=max(1, min(left, NETWORK_IDLE_MS)))
        except Exception:
            pass
        before = navs[0]
        page.wait_for_timeout(max(0, min(QUIET_MS, int((end - time.monotonic()) * 1000))))
        try:
            state = page.evaluate(_MEASURE_JS)
        except Exception:
            state = None  # execution context destroyed: a navigation is in flight
        out_of_time = time.monotonic() >= end
        if navs[0] != before or state is None:
            if out_of_time:
                return last
            continue  # a late redirect started: wait for the page it lands on
        last = state
        visible = bool(state.get("visible"))
        target = meta_refresh_target(state.get("refresh"), page.url)
        if target and target not in followed and target.rstrip("/") != page.url.rstrip("/") and not out_of_time:
            followed.add(target)
            try:
                page.goto(target, wait_until="domcontentloaded", timeout=max(1000, left))
            except Exception:
                pass
            continue
        if visible or out_of_time:
            return last
        page.wait_for_timeout(300)  # still blank: give a late render / redirect more time


def take_screenshot(
    url: str,
    *,
    timeout_ms: int,
    allowed_hosts: set[str],
    allowed_ips: set[str],
    settle_ms: int = 8000,
    cancel_check: Callable[[], bool] | None = None,
) -> ScreenshotResult:
    """Load URL passively and capture a viewport image. Soft-fails if browser missing.

    After the first load the page gets up to ``settle_ms`` to finish rendering and to follow
    late (JS / meta refresh) redirects. A page that still shows nothing is skipped as blank.
    Soft-error / default server pages that only become obvious after JS (e.g. SPA "Not Found")
    are skipped with the classification reason instead of becoming a usable screenshot.
    """
    try:
        from playwright.sync_api import sync_playwright
    except Exception:
        return ScreenshotResult(status="skipped", error="Chromium unavailable")

    if cancel_check and cancel_check():
        return ScreenshotResult(status="skipped", error="cancelled")

    from .classify import is_same_target

    try:
        with sync_playwright() as p:
            try:
                browser = p.chromium.launch(headless=True, args=["--disable-gpu", "--no-sandbox"])
            except Exception:
                return ScreenshotResult(status="skipped", error="Chromium unavailable")
            try:
                context = browser.new_context(
                    viewport=VIEWPORT,
                    ignore_https_errors=True,
                    accept_downloads=False,
                )
                page = context.new_page()
                page.set_default_timeout(timeout_ms)

                # Every HTTPS request is proxied through the API client (which honours
                # ignore_https_errors) instead of letting Chromium's TLS stack reject internal
                # IIS/appliance certs outright (e.g. ERR_SSL_KEY_USAGE_INCOMPATIBLE) — also when an
                # http:// start redirects to https later. If the proxy cannot connect either,
                # Chromium gets a direct try. Redirects are still issued back to the browser, so
                # the same-target guard below still applies.
                def _route_handler(route):
                    req = route.request
                    if req.url.startswith("file:"):
                        return route.abort()
                    nav = req.is_navigation_request() and req.frame == page.main_frame
                    if nav and not is_same_target(url, req.url, allowed_hosts, allowed_ips):
                        return route.abort()
                    if req.url.startswith("https:"):
                        try:
                            return route.fulfill(response=route.fetch(max_redirects=0 if nav else 20))
                        except Exception:
                            pass
                    return route.continue_()

                navs = [0]

                def _on_nav(frame):
                    if frame == page.main_frame:
                        navs[0] += 1

                page.route("**/*", _route_handler)
                page.on("framenavigated", _on_nav)
                try:
                    page.goto(url, wait_until="domcontentloaded", timeout=timeout_ms)
                except Exception:
                    pass
                state = _settle(page, navs, settle_ms, cancel_check)
                if cancel_check and cancel_check():
                    return ScreenshotResult(status="skipped", error="cancelled")
                current = page.url or ""
                if current.startswith("chrome-error:"):
                    return ScreenshotResult(status="failed", error="browser could not load the page")
                try:
                    if current and current != "about:blank" and not is_same_target(
                        url, current, allowed_hosts, allowed_ips
                    ):
                        return ScreenshotResult(status="failed", error="redirect outside target")
                except Exception:
                    pass
                title = (state.get("title") or None) or None
                body_text = (state.get("text") or None) or None
                if not state.get("visible"):
                    return ScreenshotResult(
                        status="skipped", error=BLANK_PAGE_REASON, title=title, body_text=body_text
                    )
                # Probe-time HTML can look like a real SPA shell; after JS the page may only be
                # "Not Found" or a stock Tomcat/IIS welcome — treat those as unusable.
                reason = unusable_page_reason(200, title, body_text=body_text)
                if reason:
                    return ScreenshotResult(
                        status="skipped", error=reason, title=title, body_text=body_text
                    )
                png = page.screenshot(type="png", full_page=False)
                return ScreenshotResult(
                    status="captured", data=_to_webp(png), title=title, body_text=body_text
                )
            finally:
                browser.close()
    except Exception as exc:
        log.warning("screenshot error for %s: %s", url[:120], exc)
        return ScreenshotResult(status="failed", error="screenshot failed")
