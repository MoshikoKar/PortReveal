"""CPE provenance: keep nmap CPEs plus rule-produced ones with a source."""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db import utcnow
from ..models import (
    CPE_SOURCE_FAVICON,
    CPE_SOURCE_HTTP,
    CPE_SOURCE_NMAP,
    CPE_SOURCE_SNMP,
    DevicePort,
    PortCpe,
    PortHttp,
    PortSnmp,
)

# Favicon mmh3 → CPE (publicly known Shodan hashes for common products)
FAVICON_CPE: dict[int, str] = {
    -670972762: "cpe:/a:fortinet:fortigate",  # common Fortinet hash family; may vary
    116323821: "cpe:/a:grafana:grafana",
    -1067588716: "cpe:/a:synology:diskstation_manager",
}


def _upsert(db: Session, port_id: int, cpe: str, source: str, now: datetime) -> None:
    cpe = cpe.strip()
    if not cpe or len(cpe) > 255:
        return
    row = db.scalar(select(PortCpe).where(
        PortCpe.device_port_id == port_id, PortCpe.cpe == cpe, PortCpe.source == source,
    ))
    if row is None:
        db.add(PortCpe(device_port_id=port_id, cpe=cpe, source=source, first_seen=now, last_seen=now))
    else:
        row.last_seen = now


def sync_nmap_cpes(db: Session, port: DevicePort, *, now: datetime | None = None) -> None:
    now = now or utcnow()
    if not port.cpe or port.id is None:
        return
    for part in port.cpe.split():
        if part.startswith("cpe:"):
            _upsert(db, port.id, part, CPE_SOURCE_NMAP, now)


def sync_http_cpes(db: Session, port: DevicePort, http: PortHttp, *, now: datetime | None = None) -> None:
    now = now or utcnow()
    if port.id is None:
        return
    if http.favicon_hash is not None and http.favicon_hash in FAVICON_CPE:
        _upsert(db, port.id, FAVICON_CPE[http.favicon_hash], CPE_SOURCE_FAVICON, now)
    title = (http.title or "").lower()
    server = (http.server or "").lower()
    blob = f"{title} {server}"
    hints = (
        ("grafana", "cpe:/a:grafana:grafana"),
        ("synology", "cpe:/a:synology:diskstation_manager"),
        ("truenas", "cpe:/a:ixsystems:truenas"),
        ("fortigate", "cpe:/a:fortinet:fortigate"),
        ("guacamole", "cpe:/a:apache:guacamole"),
        ("novnc", "cpe:/a:novnc:novnc"),
    )
    for needle, cpe in hints:
        if needle in blob:
            _upsert(db, port.id, cpe, CPE_SOURCE_HTTP, now)


def sync_snmp_cpes(db: Session, port: DevicePort, snmp: PortSnmp, *, now: datetime | None = None) -> None:
    now = now or utcnow()
    if port.id is None or not snmp.vendor:
        return
    vendor = snmp.vendor.lower().replace(" ", "_")
    cpe = f"cpe:/h:{vendor}:{vendor}"
    _upsert(db, port.id, cpe, CPE_SOURCE_SNMP, now)
