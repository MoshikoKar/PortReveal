"""Copy each captured port's landing-page metadata into `port_http`, where search can query it."""
from __future__ import annotations

from collections import defaultdict

from sqlalchemy import select
from sqlalchemy.orm import Session

from ...db import utcnow
from ...models import WEB_PAGE_HOME, WEB_PAGE_LOGIN, DevicePort, PortHttp, WebPage
from .classify import default_page_reason

HTTP_SCHEMES = ("http", "https")
DEFAULT_PAGE_SKIP_PREFIX = "default server page"
_KIND_RANK = {WEB_PAGE_HOME: 0, WEB_PAGE_LOGIN: 1}


def _best_page(pages: list[WebPage]) -> WebPage:
    return min(pages, key=lambda p: (_KIND_RANK.get(p.kind, 2), p.id))


def _is_default_page(p: WebPage) -> bool:
    return bool(default_page_reason(p.title)) or (p.capture_error or "").startswith(DEFAULT_PAGE_SKIP_PREFIX)


def sync_port_http(db: Session, capture_id: int) -> set[int]:
    """Upsert `port_http` for every HTTP(S) port of one capture. Returns the device ids touched."""
    by_port: dict[int, list[WebPage]] = defaultdict(list)
    for page in db.scalars(select(WebPage).where(
        WebPage.capture_id == capture_id, WebPage.device_port_id.isnot(None), WebPage.scheme.in_(HTTP_SCHEMES),
    )):
        by_port[page.device_port_id].append(page)
    if not by_port:
        return set()
    port_ids = list(by_port)
    live = {pid: dev for pid, dev in db.execute(
        select(DevicePort.id, DevicePort.device_id).where(DevicePort.id.in_(port_ids)))}
    existing = {h.device_port_id: h for h in db.scalars(select(PortHttp).where(PortHttp.device_port_id.in_(port_ids)))}
    now = utcnow()
    touched: set[int] = set()
    for port_id, pages in by_port.items():
        device_id = live.get(port_id)
        if device_id is None:
            continue
        best = _best_page(pages)
        row = existing.get(port_id)
        if row is None:
            row = PortHttp(device_port_id=port_id, device_id=device_id, first_seen=now)
            db.add(row)
        row.device_id = device_id
        row.scheme = best.scheme
        row.status = best.http_status
        row.title = best.title
        row.server = best.server_header
        row.content_type = best.content_type
        row.location = best.redirect_target
        row.login = any(p.kind == WEB_PAGE_LOGIN for p in pages)
        row.default_page = _is_default_page(best)
        row.last_seen = now
        touched.add(device_id)
    db.flush()
    return touched
