"""Shared API helpers: serialization, pagination, query escaping."""
from __future__ import annotations

from typing import Any

from fastapi import Query
from pydantic import BaseModel

from ..models import Device, DevicePort, Event, Network, Scan, User

# OpenAPI description for PUT routes on entities (PATCH is the partial-update verb; see docs/api/conventions.md).
FULL_REPLACE = (
    "Full replace: send the complete resource body. Optional fields left out are reset to their defaults "
    "(null, false or the documented default); this is not a partial update."
)


def like_pattern(q: str) -> str:
    escaped = q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return f"%{escaped}%"


DEFAULT_PAGE_SIZE = 50
MAX_PAGE_SIZE = 500


class Paging:
    """Offset pagination for list endpoints: ``?page=`` (1-based) and ``?page_size=`` (default 50, max 500).

    Endpoints with costlier pages use ``paging_with`` to lower the default and the ceiling.
    """

    def __init__(self, page: int = Query(1, ge=1),
                 page_size: int = Query(DEFAULT_PAGE_SIZE, ge=1, le=MAX_PAGE_SIZE)):
        self.page = page
        self.page_size = page_size

    @property
    def offset(self) -> int:
        return (self.page - 1) * self.page_size


def paging_with(default: int, max_size: int):
    """A ``Paging`` dependency with its own default and maximum page size."""

    def dependency(page: int = Query(1, ge=1), page_size: int = Query(default, ge=1, le=max_size)) -> Paging:
        return Paging(page, page_size)

    return dependency


def paged(items: list[Any], total: int, paging: Paging) -> dict:
    return {"items": items, "total": total, "page": paging.page, "page_size": paging.page_size}


# --- documented response envelopes (OpenAPI). Rows stay free-form objects; the envelope keys are the contract.
Row = dict[str, Any]

UNPAGED_LIST = (
    "Small admin collection: answers a plain JSON array of every row, not the paged "
    "`{items, total, page, page_size}` envelope. It stays an array within v1 (see docs/api/conventions.md)."
)


class WebHostsPage(BaseModel):
    """`GET /api/web-hosts`: a page of hosts, keyed `hosts` instead of `items`."""

    hosts: list[Row]
    total: int
    page: int
    page_size: int


class ScansStarted(BaseModel):
    """`POST /api/scans`: one queued scan per requested network (or one for ad-hoc targets)."""

    scans: list[Row]


class CaptureStarted(BaseModel):
    """`POST /api/web-captures`: the queued capture job."""

    capture: Row


class ExposedPorts(BaseModel):
    """`GET /api/exposed-ports`: up to `limit` open ports; `truncated` when more exist than were returned."""

    ports: list[Row]
    total: int
    truncated: bool


def user_out(u: User) -> dict:
    return {
        "id": u.id,
        "username": u.username,
        "display_name": u.display_name,
        "role": u.role,
        "source": u.source,
        "is_active": u.is_active,
        "created_at": u.created_at,
        "last_login_at": u.last_login_at,
    }


def network_out(n: Network, device_count: int | None = None, active_count: int | None = None) -> dict:
    return {
        "id": n.id,
        "name": n.name,
        "cidr": n.cidr,
        "description": n.description,
        "enabled": n.enabled,
        "zone": n.zone,
        "vpn_s2s": bool(n.vpn_s2s),
        "baseline_scan_id": n.baseline_scan_id,
        "baseline_at": n.baseline_at,
        "created_at": n.created_at,
        "device_count": device_count,
        "active_count": active_count,
    }


def port_out(p: DevicePort) -> dict:
    return {
        "protocol": p.protocol,
        "port": p.port,
        "is_open": p.is_open,
        "service": p.service,
        "product": p.product,
        "version": p.version,
        "extra_info": p.extra_info,
        "method": p.method,
        "confidence": p.confidence,
        "first_seen": p.first_seen,
        "last_seen": p.last_seen,
        "opened_at": p.opened_at,
        "closed_at": p.closed_at,
    }


def device_summary(d: Device, open_ports: list[DevicePort] | None = None, network_name: str | None = None) -> dict:
    ports = open_ports if open_ports is not None else [p for p in d.ports if p.is_open]
    return {
        "uuid": d.uuid,
        "current_ip": d.current_ip,
        "mac": d.mac,
        "vendor": d.vendor,
        "hostname": d.hostname,
        "os_name": d.os_name,
        "os_accuracy": d.os_accuracy,
        "os_detected_at": d.os_detected_at,
        "os_source": d.os_source,
        "ip_assignment": d.ip_assignment,
        "last_rtt_ms": d.last_rtt_ms,
        "continuous_since": d.continuous_since,
        "discovery_name": d.discovery_name,
        "discovery_source": d.discovery_source,
        "score": d.exposure_score or 0,
        "risk_score": d.risk_score,
        "combined_score": d.combined_score,
        "risk_scored_at": d.risk_scored_at,
        "status": d.status,
        "network_id": d.network_id,
        "network_name": network_name,
        "first_seen": d.first_seen,
        "last_seen": d.last_seen,
        "port_scan_failed": d.port_scan_failed,
        "open_port_count": len(ports),
        "open_ports": [
            {"port": p.port, "protocol": p.protocol, "service": p.service, "product": p.product, "version": p.version}
            for p in sorted(ports, key=lambda x: x.port)
        ],
    }


def event_out(e: Event) -> dict:
    d = e.device
    return {
        "id": e.id,
        "created_at": e.created_at,
        "scan_id": e.scan_id,
        "device_uuid": d.uuid if d else None,
        "device_label": (d.hostname or d.current_ip) if d else e.ip,
        "event_type": e.event_type,
        "severity": e.severity,
        "ip": e.ip,
        "protocol": e.protocol,
        "port": e.port,
        "old_value": e.old_value,
        "new_value": e.new_value,
        "message": e.message,
        "notify": e.notify,
        "notified_at": e.notified_at,
    }


def scan_out(s: Scan, network_name: str | None = None) -> dict:
    return {
        "id": s.id,
        "scan_type": s.scan_type,
        "trigger": s.trigger,
        "status": s.status,
        "scanner_mode": s.scanner_mode,
        "network_id": s.network_id,
        "network_name": network_name,
        "targets": s.targets,
        "target_count": s.target_count,
        "criteria": s.criteria,
        "requested_by": s.requested_by,
        "created_at": s.created_at,
        "started_at": s.started_at,
        "finished_at": s.finished_at,
        "stage": s.stage,
        "progress": round(s.progress or 0.0, 4),
        "hosts_discovered": s.hosts_discovered,
        "hosts_scanned": s.hosts_scanned,
        "hosts_failed": s.hosts_failed,
        "events_count": s.events_count,
        "is_baseline": s.is_baseline,
        "error": s.error,
        "notes": s.notes,
    }
