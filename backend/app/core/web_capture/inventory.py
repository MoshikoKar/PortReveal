"""Identify capture endpoints from existing Nmap inventory (no extra port scan)."""
from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from ...models import Device
from ...scanner.known_ports import AI_LLM_WEB_PORTS

# Service names nmap commonly uses for HTTP(S)
WEB_SERVICE_NAMES = frozenset({
    "http", "https", "http-alt", "https-alt", "http-proxy",
    "ssl/http", "ssl/https", "http-mgmt", "www",
})

COMMON_WEB_PORTS = frozenset({80, 443, 3000, 5000, 8000, 8080, 8443, 8888, 9000}) | AI_LLM_WEB_PORTS

# Classic RTSP listen ports when nmap leaves service empty/unknown.
COMMON_RTSP_PORTS = frozenset({554, 8554})


def is_rtsp_service(service: str | None) -> bool:
    """True when nmap (or inventory) labelled the port as RTSP — any port number."""
    if not service:
        return False
    s = service.strip().lower()
    if s == "rtsp" or s.startswith("rtsp/") or s.startswith("rtsp-"):
        return True
    if s.endswith("/rtsp") or "/rtsp" in s:
        return True
    return "rtsp" in s and "http" not in s


def is_web_service(service: str | None) -> bool:
    if not service:
        return False
    if is_rtsp_service(service):
        return False
    s = service.strip().lower()
    if s in WEB_SERVICE_NAMES:
        return True
    # ssl/http, tcpwrapped-looking names that still contain http
    if "http" in s:
        return True
    return False


def guess_scheme(service: str | None, port: int) -> str:
    if is_rtsp_service(service):
        s = (service or "").lower()
        if "ssl" in s or "rtsps" in s:
            return "rtsps"
        return "rtsp"
    s = (service or "").lower()
    if "https" in s or "ssl" in s or port in (443, 8443, 9443, 10443):
        return "https"
    return "http"


@dataclass
class WebEndpoint:
    device_id: int
    device_port_id: int
    ip: str
    port: int
    protocol: str
    service: str | None
    product: str | None
    hostname: str | None
    dns_name: str | None
    scheme: str

    @property
    def host_candidates(self) -> list[str]:
        """Prefer inventory hostname/DNS, then IP. No extra DNS lookup."""
        out: list[str] = []
        for h in (self.dns_name, self.hostname):
            if h and h.strip() and h.strip() not in out:
                # skip generic / IP-like hostnames that are just the IP
                name = h.strip().rstrip(".")
                if name and name != self.ip and name not in out:
                    out.append(name)
        out.append(self.ip)
        return out


def find_web_endpoints(db: Session, ips: set[str], *, max_endpoints: int) -> tuple[list[WebEndpoint], list[str]]:
    """Return endpoints for the given IPs from current inventory, plus skip notes."""
    notes: list[str] = []
    if not ips:
        return [], notes

    devices = db.scalars(
        select(Device).where(Device.current_ip.in_(ips)).options(selectinload(Device.ports))
    ).all()
    by_ip = {d.current_ip: d for d in devices}

    endpoints: list[WebEndpoint] = []
    for ip in sorted(ips):
        dev = by_ip.get(ip)
        if dev is None:
            notes.append(f"{ip}: no device in inventory.")
            continue
        found = 0
        for p in dev.ports:
            if not p.is_open or p.protocol != "tcp":
                continue
            # Service label wins: RTSP on any port (e.g. 8443) must not fall through to HTTP.
            by_rtsp = is_rtsp_service(p.service) or (
                not is_web_service(p.service) and not p.service and p.port in COMMON_RTSP_PORTS
            )
            by_web = (not by_rtsp) and (is_web_service(p.service) or p.port in COMMON_WEB_PORTS)
            if not (by_rtsp or by_web):
                continue
            if by_rtsp:
                scheme = "rtsps" if (p.service or "").lower().find("ssl") >= 0 else "rtsp"
            else:
                scheme = guess_scheme(p.service, p.port)
            endpoints.append(
                WebEndpoint(
                    device_id=dev.id,
                    device_port_id=p.id,
                    ip=dev.current_ip,
                    port=p.port,
                    protocol=p.protocol,
                    service=p.service,
                    product=p.product,
                    hostname=dev.hostname,
                    dns_name=dev.dns_name,
                    scheme=scheme,
                )
            )
            found += 1
            if len(endpoints) >= max_endpoints:
                notes.append(f"Endpoint limit reached ({max_endpoints}); remaining endpoints skipped.")
                return endpoints, notes
        if found == 0:
            notes.append(f"{ip}: No known web or RTSP endpoints found in current inventory.")
    return endpoints, notes
