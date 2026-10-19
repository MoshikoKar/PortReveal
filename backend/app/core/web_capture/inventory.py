"""Identify capture endpoints from existing Nmap inventory (no extra port scan)."""
from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from ...models import Device
from ...netutils import ip_sort_key
from ...scanner.identify_truenas import looks_like_truenas
from ...scanner.known_ports import AI_LLM_WEB_PORTS, TRUENAS_APPS_TCP_PORTS
from .rdp import is_rdp_service
from .vnc import is_vnc_service

# Service names nmap commonly uses for HTTP(S)
WEB_SERVICE_NAMES = frozenset({
    "http", "https", "http-alt", "https-alt", "http-proxy",
    "ssl/http", "ssl/https", "http-mgmt", "www",
    "webdav", "dav",
})

# Clear non-HTTP listeners - never promote these to HTTP Playwright capture.
# RDP/VNC use a dedicated capture path (see is_rdp_service / is_vnc_service).
NON_WEB_SERVICE_NAMES = frozenset({
    "ssh", "domain", "netbios-ssn", "microsoft-ds", "msrpc", "rpcbind",
    "postgresql", "mysql", "mariadb", "redis", "mongodb", "elasticsearch",
    "smtp", "smtps", "pop3", "pop3s", "imap", "imaps", "ldap", "ldaps",
    "ftp", "ftp-data", "nfs", "smb", "epmap", "ident", "ms-wbt-server",
    "rdp", "vnc", "x11", "snmp", "ntp", "kerberos",
})

COMMON_WEB_PORTS = frozenset({80, 443, 3000, 5000, 8000, 8080, 8443, 8888, 9000}) | AI_LLM_WEB_PORTS
_TRUENAS_APP_PORTS = frozenset(TRUENAS_APPS_TCP_PORTS)
# Custom TrueNAS app host ports often sit here when not in the catalog defaults.
_TRUENAS_UNKNOWN_WEB_PORT_MIN = 20000

# Classic RTSP listen ports when nmap leaves service empty/unknown.
COMMON_RTSP_PORTS = frozenset({554, 8554})


def is_rtsp_service(service: str | None) -> bool:
    """True when nmap (or inventory) labelled the port as RTSP - any port number."""
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
    if "webdav" in s or s.endswith("/dav") or "/dav" in s:
        return True
    return False


def is_probable_web_port(service: str | None, port: int, *, truenas: bool) -> bool:
    """Whether an open TCP port should be probed as HTTP(S) for web capture."""
    if is_web_service(service) or port in COMMON_WEB_PORTS:
        return True
    s = (service or "").strip().lower()
    if s in NON_WEB_SERVICE_NAMES:
        return False
    if not truenas:
        return False
    # TrueNAS Apps catalog ports are almost always HTTP UIs; nmap often leaves them "unknown".
    if port in _TRUENAS_APP_PORTS:
        return True
    if s in ("", "unknown", "tcpwrapped") and port >= _TRUENAS_UNKNOWN_WEB_PORT_MIN:
        return True
    return False


def guess_scheme(service: str | None, port: int, tunnel: str | None = None) -> str:
    """``tunnel`` is nmap's TLS flag: "ssl" when the service was found inside TLS."""
    tls = tunnel == "ssl"
    if is_rtsp_service(service):
        s = (service or "").lower()
        if tls or "ssl" in s or "rtsps" in s:
            return "rtsps"
        return "rtsp"
    if is_rdp_service(service, port):
        return "rdp"
    if is_vnc_service(service, port):
        return "vnc"
    s = (service or "").lower()
    if tls or "https" in s or "ssl" in s or port in (443, 8443, 9443, 10443):
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


def find_web_endpoints(db: Session, ips: set[str], *, max_endpoints: int,
                       deferred: list[str] | None = None) -> tuple[list[WebEndpoint], list[str]]:
    """Return endpoints for the given IPs from current inventory, plus skip notes.

    Hosts are taken in numeric IP order and ``max_endpoints`` is applied at host boundaries:
    the first host that would overflow it, and every host after it, is appended to
    ``deferred`` (when given) so the caller can capture them in a follow-up job instead of
    silently dropping the same tail of a large subnet on every run.
    """
    notes: list[str] = []
    if not ips:
        return [], notes

    devices = db.scalars(
        select(Device).where(Device.current_ip.in_(ips)).options(selectinload(Device.ports))
    ).all()
    by_ip = {d.current_ip: d for d in devices}

    endpoints: list[WebEndpoint] = []
    over = False  # endpoint cap reached: remaining hosts with endpoints go to ``deferred``
    over_hosts: list[str] = []
    for ip in sorted(ips, key=ip_sort_key):
        dev = by_ip.get(ip)
        if dev is None:
            if not over:
                notes.append(f"{ip}: no device in inventory.")
            continue
        host_eps: list[WebEndpoint] = []
        truenas = looks_like_truenas(
            hostname=dev.hostname, dns_name=dev.dns_name, os_name=dev.os_name, vendor=dev.vendor,
        )
        for p in dev.ports:
            if not p.is_open or p.protocol != "tcp":
                continue
            # Service label wins: RTSP on any port (e.g. 8443) must not fall through to HTTP.
            by_rtsp = is_rtsp_service(p.service) or (
                not is_web_service(p.service) and not p.service and p.port in COMMON_RTSP_PORTS
            )
            by_rdp = (not by_rtsp) and is_rdp_service(p.service, p.port)
            by_vnc = (not by_rtsp and not by_rdp) and is_vnc_service(p.service, p.port)
            by_web = (not by_rtsp and not by_rdp and not by_vnc) and is_probable_web_port(
                p.service, p.port, truenas=truenas,
            )
            if not (by_rtsp or by_rdp or by_vnc or by_web):
                continue
            if by_rtsp:
                scheme = "rtsps" if (p.tunnel == "ssl" or "ssl" in (p.service or "").lower()) else "rtsp"
            elif by_rdp:
                scheme = "rdp"
            elif by_vnc:
                scheme = "vnc"
            else:
                scheme = guess_scheme(p.service, p.port, p.tunnel)
            host_eps.append(
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
        if not host_eps:
            if not over:
                notes.append(f"{ip}: No known web/RTSP/RDP/VNC endpoints found in current inventory.")
            continue
        if over or (endpoints and len(endpoints) + len(host_eps) > max_endpoints):
            over = True
            over_hosts.append(ip)  # only hosts that really have endpoints
            continue
        if len(host_eps) > max_endpoints:  # one host alone is larger than a whole job
            notes.append(f"{ip}: {len(host_eps)} endpoints, only the first {max_endpoints} captured.")
            host_eps = host_eps[:max_endpoints]
        endpoints.extend(host_eps)
    if over_hosts:
        if deferred is not None:
            deferred.extend(over_hosts)
        notes.append(f"Endpoint limit reached ({max_endpoints}); {len(over_hosts)} host(s) deferred.")
    return endpoints, notes


def inventory_remote_ips(db: Session) -> list[str]:
    """Current-inventory IPs that expose at least one open RDP or VNC TCP port (archived networks excluded)."""
    from ..mockdata import device_visible
    devices = db.scalars(
        select(Device).where(device_visible(db)).options(selectinload(Device.ports))
    ).all()
    ips: list[str] = []
    for dev in devices:
        ip = (dev.current_ip or "").strip()
        if not ip:
            continue
        for p in dev.ports:
            if not p.is_open or p.protocol != "tcp":
                continue
            if is_rdp_service(p.service, p.port) or is_vnc_service(p.service, p.port):
                ips.append(ip)
                break
    return sorted(set(ips))
