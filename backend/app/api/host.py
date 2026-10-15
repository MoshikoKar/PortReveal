"""Shodan-shaped host document by IP.

``GET /api/hosts/{ip}`` is the canonical path. ``GET /api/host/{ip}`` is a compatibility alias kept for
Shodan-style clients (singular ``host`` as in Shodan's ``/shodan/host/{ip}``); both return the same body.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from ..auth.deps import current_user
from ..core.mockdata import device_visible
from ..core.query.search import http_out
from ..core.tagging import tags_by_device
from ..core.web_storage import resolve_screenshot
from ..db import get_db
from ..models import (
    SCREENSHOT_CAPTURED,
    Device,
    PortHttp,
    PortSnmp,
    PortTls,
    ServiceBanner,
    User,
    WebPage,
)

router = APIRouter(prefix="/api", tags=["host"])

HOST_DOC = """One host with its open services (NF inventory, Shodan-like shape).

`ports` lists the open services. `data` is a deprecated Shodan-compatible alias holding the same list;
it will be dropped in the next API version, so new clients should read `ports`.
"""


@router.get("/hosts/{ip}", description=HOST_DOC)
@router.get("/host/{ip}", description=HOST_DOC + " Alias of `GET /api/hosts/{ip}`, kept for compatibility.")
def host_document(ip: str, db: Session = Depends(get_db), user: User = Depends(current_user)):
    dev = db.scalar(
        select(Device).where(Device.current_ip == ip, device_visible(db))
        .options(selectinload(Device.ports), selectinload(Device.profile), selectinload(Device.network))
    )
    if dev is None:
        raise HTTPException(404, f"No device with IP {ip}")
    tags = tags_by_device(db, [dev.id]).get(dev.id, [])
    port_ids = [p.id for p in dev.ports if p.is_open]
    http_by = {h.device_port_id: h for h in db.scalars(select(PortHttp).where(PortHttp.device_port_id.in_(port_ids)))} if port_ids else {}
    tls_by = {t.device_port_id: t for t in db.scalars(select(PortTls).where(PortTls.device_port_id.in_(port_ids)))} if port_ids else {}
    snmp_by = {s.device_port_id: s for s in db.scalars(select(PortSnmp).where(PortSnmp.device_port_id.in_(port_ids)))} if port_ids else {}
    banners = {}
    if port_ids:
        for b in db.scalars(select(ServiceBanner).where(ServiceBanner.device_port_id.in_(port_ids))
                            .order_by(ServiceBanner.seen_at.desc())):
            banners.setdefault(b.device_port_id, b.raw_truncated)
    shots = {}
    for page in db.scalars(select(WebPage).where(
        WebPage.device_id == dev.id, WebPage.screenshot_status == SCREENSHOT_CAPTURED,
    ).order_by(WebPage.captured_at.desc())):
        if resolve_screenshot(page.screenshot_relpath) is not None:  # skip rows whose file is gone
            shots.setdefault(page.device_port_id, page)
    data: list[dict] = []
    for p in sorted((x for x in dev.ports if x.is_open), key=lambda x: (x.port, x.protocol)):
        entry: dict = {
            "port": p.port,
            "transport": p.protocol,
            "service": p.service,
            "product": p.product,
            "version": p.version,
            "info": p.extra_info,
            "cpe": (p.cpe or "").split() if p.cpe else [],
            "tunnel": p.tunnel,
            "banner": banners.get(p.id),
            "http": http_out(http_by[p.id]) if p.id in http_by else None,
        }
        if p.id in tls_by:
            t = tls_by[p.id]
            entry["ssl"] = {
                "cert": {
                    "subject": {"cn": t.cn},
                    "issuer": t.issuer,
                    "fingerprint": {"sha256": t.fingerprint_sha256},
                    "expired": t.expired,
                    "expires_soon": t.expires_soon,
                    "self_signed": t.self_signed,
                    "wildcard": t.wildcard,
                    "weak": t.weak,
                    "not_before": t.not_before.isoformat() if t.not_before else None,
                    "not_after": t.not_after.isoformat() if t.not_after else None,
                    "san": t.san,
                }
            }
        if p.id in snmp_by:
            s = snmp_by[p.id]
            entry["snmp"] = {
                "sysDescr": s.sys_descr, "sysName": s.sys_name, "sysObjectID": s.sys_object_id,
                "sysLocation": s.sys_location, "sysContact": s.sys_contact,
                "vendor": s.vendor, "model": s.model,
            }
        if p.id in shots:
            page = shots[p.id]
            entry["screenshot"] = {
                "page_id": page.id, "title": page.title, "captured_at": page.captured_at,
                "phash": page.phash, "ocr_text": page.ocr_text,
            }
        data.append(entry)
    return {
        "ip": dev.current_ip,
        "uuid": dev.uuid,
        "hostname": dev.hostname or dev.dns_name,
        "mac": dev.mac,
        "vendor": dev.vendor,
        "os": dev.os_name,
        "status": dev.status,
        "type": dev.device_type,
        "score": dev.exposure_score,
        "ssh_hostkey_sha256": dev.ssh_hostkey_sha256,
        "tags": [{"tag": t.tag, "source": t.source, "reason": t.reason} for t in tags
                 if t.source != "suppressed"],
        "network": dev.network.name if dev.network else None,
        "zone": dev.network.zone if dev.network else None,
        "first_seen": dev.first_seen,
        "last_seen": dev.last_seen,
        "ports": data,
        "data": data,  # deprecated Shodan alias of "ports"; remove in API v2
    }
