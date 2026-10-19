"""Copy each captured port's landing-page metadata into `port_http`, where search can query it."""
from __future__ import annotations

import logging
from collections import defaultdict

from sqlalchemy import select
from sqlalchemy.orm import Session

from ...db import utcnow
from ...models import WEB_PAGE_HOME, WEB_PAGE_LOGIN, DevicePort, PortHttp, WebPage
from ..cpe import sync_http_cpes
from ..http_hashes import header_set_hash, html_hash
from .classify import default_page_reason, looks_like_web_vnc

log = logging.getLogger(__name__)

HTTP_SCHEMES = ("http", "https")
DEFAULT_PAGE_SKIP_PREFIX = "default server page"
_KIND_RANK = {WEB_PAGE_HOME: 0, WEB_PAGE_LOGIN: 1}
# PortHttp title/server that would fire the hypervisor tagging rule.
_HYPERVISOR_HTTP = ("vmware esxi", "proxmox")
# nmap product/service/cpe substrings that prove the page is not a hypervisor UI. Used only to
# drop *contradictory* stale captures - never to reject a real ESXi with an empty product field.
_CONFLICTING_PRODUCTS = (
    "fortigate", "fortissh", "fortinet", "cisco", "synology", "samba",
    "nginx", "apache", "httpd", "ollama", "lm studio", "hikvision",
    "jellyfin", "immich", "tomcat", "lighttpd", "hp embedded",
)


def _best_page(pages: list[WebPage]) -> WebPage:
    return min(pages, key=lambda p: (_KIND_RANK.get(p.kind, 2), p.id))


def _is_default_page(p: WebPage) -> bool:
    return bool(default_page_reason(p.title)) or (p.capture_error or "").startswith(DEFAULT_PAGE_SKIP_PREFIX)


def _http_claims_hypervisor(title: str | None, server: str | None) -> bool:
    blob = f"{title or ''} {server or ''}".lower()
    return any(m in blob for m in _HYPERVISOR_HTTP)


def _product_conflicts_hypervisor(product: str | None, service: str | None, cpe: str | None) -> bool:
    blob = f"{product or ''} {service or ''} {cpe or ''}".lower()
    if any(m in blob for m in _HYPERVISOR_HTTP) or "esxi" in blob:
        return False
    return any(m in blob for m in _CONFLICTING_PRODUCTS)


def clear_stale_hypervisor_http(db: Session, device_ids: list[int]) -> set[int]:
    """Delete PortHttp rows that claim ESXi/Proxmox while the port's nmap product says otherwise.

    Stale captures (from an older mock default or a wrong page) otherwise keep pinning
    ``device_type=hypervisor`` under ``auto_only_new_or_changed``, because unchanged hosts
    are never re-captured. Real ESXi with an empty product field is left alone.
    Returns device ids whose HTTP rows were removed (caller should reclassify).
    """
    if not device_ids:
        return set()
    rows = db.execute(
        select(PortHttp, DevicePort)
        .join(DevicePort, DevicePort.id == PortHttp.device_port_id)
        .where(PortHttp.device_id.in_(device_ids))
    ).all()
    touched: set[int] = set()
    for http, port in rows:
        if not _http_claims_hypervisor(http.title, http.server):
            continue
        if not _product_conflicts_hypervisor(port.product, port.service, port.cpe):
            continue
        log.info(
            "dropping stale hypervisor PortHttp on %s (%s) - product %r conflicts with title/server",
            port.port, http.device_id, port.product,
        )
        db.delete(http)
        touched.add(http.device_id)
    if touched:
        db.flush()
    return touched


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
        row.web_vnc = looks_like_web_vnc(None, best.title, best.server_header)
        # Prefer hashes already computed on the page row when present; otherwise hash title+server.
        if not row.html_hash:
            row.html_hash = html_hash(f"{best.title or ''}|{best.server_header or ''}|{best.http_status or ''}")
        if not row.header_set_hash and best.server_header:
            row.header_set_hash = header_set_hash({"server": best.server_header})
        row.last_seen = now
        touched.add(device_id)
        port_row = db.get(DevicePort, port_id)
        if port_row is not None:
            sync_http_cpes(db, port_row, row)
    db.flush()
    return touched
