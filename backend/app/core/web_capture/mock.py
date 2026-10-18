"""Mock Web Capture responses for DEV / tests (scenarios A–E). Same pipeline, fake I/O only."""
from __future__ import annotations

from ...models import WEB_PAGE_HOME, WEB_PAGE_LOGIN, WEB_PAGE_OTHER, WEB_PAGE_STREAM
from .probe import EndpointProbe, ProbeResult

# Minimal 1x1 webp-ish placeholder (actually a tiny PNG; storage accepts bytes)
_PLACEHOLDER_PNG = (
    b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x02\x00\x00\x00\x90wS\xde"
    b"\x00\x00\x00\x0cIDATx\x9cc\xf8\x0f\x00\x00\x01\x01\x00\x05\x18\xd8N\x00\x00\x00\x00IEND\xaeB`\x82"
)


def placeholder_image() -> bytes:
    return _PLACEHOLDER_PNG


def mock_rtsp_endpoint(scheme: str, host: str, port: int) -> EndpointProbe:
    """Deterministic RTSP stream page for mock / test captures."""
    sch = "rtsps" if scheme == "rtsps" else "rtsp"
    url = f"{sch}://{host}:{port}/stream1" if port != 554 else f"{sch}://{host}/stream1"
    ep = EndpointProbe(scheme=sch, host_used=host, port=port)
    ep.pages = [
        ProbeResult(
            url=url,
            final_url=url,
            http_status=None,
            title="RTSP stream",
            content_type="application/rtsp",
            server_header="rtspd",
            kind=WEB_PAGE_STREAM,
        )
    ]
    return ep


def mock_probe_endpoint(scheme: str, host: str, port: int, ip: str) -> EndpointProbe:
    """Deterministic scenarios keyed by last octet / port patterns."""
    ep = EndpointProbe(scheme=scheme, host_used=host, port=port)
    base = f"{scheme}://{host}:{port}" if port not in (80, 443) else f"{scheme}://{host}"
    last = 0
    try:
        last = int(ip.rsplit(".", 1)[-1])
    except ValueError:
        last = 0

    # Scenario E: external SSO on :8443 with odd last octet ending 5, or port 9443
    if port in (9443,) or (port == 8443 and last % 10 == 5):
        home = ProbeResult(
            url=f"{base}/",
            final_url=f"{base}/",
            http_status=302,
            title=None,
            content_type="text/html",
            server_header="nginx",
            redirect_target="https://login.microsoftonline.com/common/oauth2",
            external_redirect=True,
            tls_verified=False if scheme == "https" else None,
            error="redirect outside target",
            kind=WEB_PAGE_HOME,
        )
        ep.pages = [home]
        return ep

    # Scenario D: TLS unverified success on https:10443 or last octet % 10 == 4
    if scheme == "https" and (port == 10443 or last % 10 == 4):
        home = ProbeResult(
            url=f"{base}/",
            final_url=f"{base}/",
            http_status=200,
            title="Internal PKI Appliance",
            content_type="text/html",
            server_header="Apache",
            html="<html><title>Internal PKI Appliance</title><body>OK</body></html>",
            tls_verified=False,
            kind=WEB_PAGE_HOME,
        )
        ep.pages = [home]
        return ep

    # Scenario C: HTTP → HTTPS same-target redirect
    if scheme == "http" and (port == 80 and last % 10 == 3):
        https = f"https://{host}/"
        home = ProbeResult(
            url=f"{base}/",
            final_url=https,
            http_status=200,
            title="Redirected Portal",
            content_type="text/html",
            server_header="nginx",
            html="<html><title>Redirected Portal</title><body>Portal</body></html>",
            redirect_target=https,
            external_redirect=False,
            tls_verified=None,
            kind=WEB_PAGE_HOME,
        )
        ep.pages = [home]
        return ep

    # Scenario B: management UI, no login (last % 10 == 2 or port 9090)
    if port == 9090 or last % 10 == 2:
        home = ProbeResult(
            url=f"{base}/",
            final_url=f"{base}/",
            http_status=200,
            title="Switch Management Console",
            content_type="text/html",
            server_header="lighttpd",
            html="<html><title>Switch Management Console</title><body>status</body></html>",
            tls_verified=False if scheme == "https" else None,
            kind=WEB_PAGE_OTHER,
        )
        # Treat root as other/home management
        home.kind = WEB_PAGE_HOME
        ep.pages = [home]
        return ep

    # Scenario A: ESXi hypervisor UI — only for last-octet % 10 == 1 (e.g. 10.0.0.11).
    # Must not be the default: Mock Lab web hosts like srv-web01 (.10) run nginx and were
    # mis-typed as hypervisor after auto web-capture used the old ESXi default.
    if last % 10 == 1:
        home = ProbeResult(
            url=f"{base}/",
            final_url=f"{base}/",
            http_status=200,
            title="VMware ESXi",
            content_type="text/html",
            server_header="VMware ESXi",
            html='<html><title>VMware ESXi</title><a href="/login">Log in</a></html>',
            tls_verified=False if scheme == "https" else None,
            kind=WEB_PAGE_HOME,
        )
        login = ProbeResult(
            url=f"{base}/login",
            final_url=f"{base}/login",
            http_status=200,
            title="ESXi Login",
            content_type="text/html",
            server_header="VMware ESXi",
            html='<html><title>ESXi Login</title><input type="password" /></html>',
            tls_verified=False if scheme == "https" else None,
            kind=WEB_PAGE_LOGIN,
        )
        ep.pages = [home, login]
        return ep

    # Default: generic nginx site (matches Mock Lab srv-web01 / srv-intranet style hosts).
    home = ProbeResult(
        url=f"{base}/",
        final_url=f"{base}/",
        http_status=200,
        title="Welcome to nginx",
        content_type="text/html",
        server_header="nginx",
        html='<html><title>Welcome to nginx</title><body><h1>Welcome to nginx!</h1></body></html>',
        tls_verified=False if scheme == "https" else None,
        kind=WEB_PAGE_HOME,
    )
    ep.pages = [home]
    return ep
