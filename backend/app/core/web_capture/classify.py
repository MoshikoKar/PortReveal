"""Page classification and same-target redirect rules (passive inventory only)."""
from __future__ import annotations

import re
from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse

from ...models import WEB_PAGE_HOME, WEB_PAGE_LOGIN, WEB_PAGE_OTHER, WEB_PAGE_REGISTER

LOGIN_PATHS = (
    "/login",
    "/signin",
    "/sign-in",
    "/auth/login",
    "/account/login",
    "/user/login",
    "/users/sign_in",
    "/session/new",
    "/admin/login",
    "/admin",
)
REGISTER_PATHS = (
    "/register",
    "/signup",
    "/sign-up",
    "/auth/register",
    "/account/register",
    "/users/sign_up",
)
# Tried only when "/" has no application (error or default server page): where apps usually live.
# Ordered most-common first; the discovery cap keeps only the first N. Users can override via a wordlist file.
APP_PATHS = (
    "/home/", "/app/", "/apps/", "/portal/", "/web/", "/ui/", "/dashboard/",
    "/admin/", "/admin", "/admin/login",
    "/console/", "/manage/", "/management/", "/login", "/index.html", "/index.htm",
    "/default.aspx", "/default.asp", "/home.aspx", "/main.aspx", "/portal.aspx",
    "/owa/", "/ecp/", "/RDWeb/", "/certsrv/", "/Reports/", "/ReportServer/", "/aspnet_client/",
    "/Citrix/", "/vpn/", "/remote/", "/sslvpn/", "/dana-na/",
    "/api/", "/api/v1/", "/swagger/", "/swagger-ui/", "/swagger-ui.html", "/openapi.json",
    "/api/tags", "/api/version", "/v1/models", "/v1/embeddings", "/docs", "/redoc",
    "/graphql", "/actuator/", "/health", "/status", "/server-status",
    "/jenkins/", "/grafana/", "/kibana/", "/prometheus/", "/nagios/", "/zabbix/",
    "/phpmyadmin/", "/pma/", "/adminer.php", "/wp-admin/", "/wp-login.php",
    "/solr/", "/nexus/", "/artifactory/", "/gitlab/", "/jira/", "/confluence/",
    "/cgi-bin/", "/webapp/", "/application/", "/site/", "/public/", "/static/",
    "/user/", "/users/", "/account/", "/auth/", "/sso/", "/oauth/",
)

LOGIN_RE = re.compile(r"(?:log[\s_-]?in|sign[\s_-]?in|auth)", re.I)
REGISTER_RE = re.compile(r"(?:register|sign[\s_-]?up|create[\s_-]?account)", re.I)
TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.DOTALL)
# Titles of error pages served with a 2xx status ("soft" errors)
ERROR_TITLE_RE = re.compile(
    r"^\s*(?:[45]\d\d|error)(?!\w)"
    r"|not found|service unavailable|bad request|forbidden|access denied|unauthori[sz]ed"
    r"|internal server error|bad gateway|gateway time-?out|server error|site can.t be reached",
    re.I,
)
# Undertow / JBoss / IIS often answer 200 with a bare "404 - Not Found" body (title may still
# say something useful like "HAL Management Console" when the console is not actually there).
# Also bare "Not Found" from a rendered SPA router with no real app behind it.
SOFT_404_TEXT_RE = re.compile(
    r"^(?:404\s*[\-:]?\s*)?(?:not\s+found|file or directory not found|page not found|page missing)\.?$"
    r"|^404\s*$",
    re.I,
)
# Out-of-the-box server pages: the web server is installed but no application is published at "/"
DEFAULT_PAGE_TITLES = (
    (re.compile(r"^\s*IIS(?:\s*Windows(?:\s*Server)?|\s*\d+(?:\.\d+)?)?\s*$|Internet Information Services", re.I), "IIS"),
    (re.compile(r"Apache2? .*Default Page|Apache HTTP Server Test Page|Test Page for the Apache", re.I), "Apache"),
    (re.compile(
        r"Test Page for the HTTP Server on Red Hat|Red Hat Enterprise Linux(?:\s+\d+(?:\.\d+)*)?\s+Test Page",
        re.I,
    ), "Red Hat"),
    (re.compile(r"Welcome to nginx|Test Page for the Nginx", re.I), "nginx"),
    # Stock Tomcat / TomEE welcome titles: "Apache Tomcat/9.0.52", "Apache Tomcat (TomEE)/9.0.35 (8.0.2)"
    (re.compile(r"^\s*Apache Tomcat(?:\s*\([^)]+\))?(?:/[\d.]+)?(?:\s*\([^)]+\))?\s*$", re.I), "Tomcat"),
    (re.compile(r"^\s*Apache Tomcat\b", re.I), "Tomcat"),
    (re.compile(r"Welcome to (?:JBoss|WildFly)|JBoss EAP|Red Hat JBoss Enterprise Application Platform", re.I), "JBoss"),
    (re.compile(r"Web Server.s Default Page|Default Web Site Page", re.I), "web server"),
)
IT_WORKS_RE = re.compile(r"<h1>\s*It works!\s*</h1>", re.I)
JBOSS_WELCOME_BODY_RE = re.compile(
    r"Your Red Hat JBoss Enterprise Application Platform is running"
    r"|Welcome to JBoss EAP\b"
    r"|To replace this page simply deploy your own war",
    re.I,
)
TOMCAT_WELCOME_BODY_RE = re.compile(
    r"successfully installed Tomcat"
    r"|If you.re seeing this, you.ve successfully installed Tomcat"
    r"|tomcat\.css\b",
    re.I,
)
RHEL_TEST_BODY_RE = re.compile(
    r"Test Page for the HTTP Server on Red Hat"
    r"|Red Hat Enterprise Linux Test Page"
    r"|This page is used to test the proper operation of the (?:HTTP|Apache) server",
    re.I,
)
# Raw HTML that can still produce something on screen even with no visible text
# (scripts render it, media/frames show it, a meta refresh moves on to a real page).
CONTENT_TAG_RE = re.compile(
    r"<(?:script|img|svg|canvas|video|object|embed|iframe|frame|frameset|input|select|textarea|button)\b"
    r"|<meta[^>]+http-equiv\s*=\s*[\"']?refresh"
    r"|background(?:-image)?\s*[:=]",
    re.I,
)
# Set as the page's error reason when nothing is shown (empty body, or nothing rendered in the browser)
BLANK_PAGE_REASON = "blank page"


class _LinkParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.links: list[tuple[str, str]] = []  # (href, text)

    def handle_starttag(self, tag, attrs):
        if tag != "a":
            return
        href = dict(attrs).get("href")
        if href:
            self.links.append((href, ""))

    def handle_data(self, data):
        if self.links and not self.links[-1][1]:
            href, _ = self.links[-1]
            self.links[-1] = (href, data.strip()[:80])


def extract_title(html: str | None) -> str | None:
    if not html:
        return None
    m = TITLE_RE.search(html)
    if not m:
        return None
    title = re.sub(r"\s+", " ", m.group(1)).strip()
    return title[:500] or None


def extract_same_target_auth_links(html: str, base_url: str, allowed_hosts: set[str],
                                   allowed_ips: set[str]) -> list[tuple[str, str]]:
    """Return (absolute_url, kind) for login/register links on the same target only."""
    if not html:
        return []
    parser = _LinkParser()
    try:
        parser.feed(html[:500_000])
    except Exception:
        return []
    out: list[tuple[str, str]] = []
    seen: set[str] = set()
    for href, text in parser.links:
        if href.startswith(("#", "mailto:", "javascript:", "data:")):
            continue
        abs_url = urljoin(base_url, href)
        if not is_same_target(base_url, abs_url, allowed_hosts, allowed_ips):
            continue
        blob = f"{href} {text}"
        kind = None
        if LOGIN_RE.search(blob):
            kind = WEB_PAGE_LOGIN
        elif REGISTER_RE.search(blob):
            kind = WEB_PAGE_REGISTER
        if not kind:
            continue
        if abs_url in seen:
            continue
        seen.add(abs_url)
        out.append((abs_url, kind))
    return out


def classify_from_path(path: str) -> str:
    p = (path or "/").lower()
    for cand in LOGIN_PATHS:
        if p == cand or p.startswith(cand + "/") or p.endswith(cand):
            return WEB_PAGE_LOGIN
    for cand in REGISTER_PATHS:
        if p == cand or p.startswith(cand + "/") or p.endswith(cand):
            return WEB_PAGE_REGISTER
    if p in ("/", "/index.html", "/index.htm", "/home", "/default.html"):
        return WEB_PAGE_HOME
    return WEB_PAGE_OTHER


def _visible_text(html: str | None, body_text: str | None = None) -> str:
    """Rough visible body text for soft-error checks (title/scripts/styles stripped)."""
    parts: list[str] = []
    if body_text:
        parts.append(body_text)
    if html:
        text = re.sub(r"(?is)<title[^>]*>.*?</title>", " ", html)
        text = re.sub(r"(?is)<script[^>]*>.*?</script>", " ", text)
        text = re.sub(r"(?is)<style[^>]*>.*?</style>", " ", text)
        text = re.sub(r"(?is)<noscript[^>]*>.*?</noscript>", " ", text)
        text = re.sub(r"(?is)<!--.*?-->", " ", text)
        text = re.sub(r"(?s)<[^>]+>", " ", text)
        parts.append(text)
    return re.sub(r"\s+", " ", " ".join(parts)).strip()


def auth_challenge_scheme(http_status: int | None, headers) -> str | None:
    """Scheme of an HTTP authentication challenge (``Basic``, ``Digest``, ``NTLM`` …) on 401/407."""
    if http_status not in (401, 407) or headers is None:
        return None
    value = headers.get("www-authenticate") or headers.get("proxy-authenticate") or ""
    scheme = value.strip().split(None, 1)[0].rstrip(",") if value.strip() else ""
    return scheme[:20] or None


def error_page_reason(
    http_status: int | None,
    title: str | None,
    html: str | None = None,
    body_text: str | None = None,
    auth_scheme: str | None = None,
) -> str | None:
    """Why a page is an error page not worth a screenshot, or None for a real page.

    A 401/407 that carries an authentication challenge is a login-protected application
    (browser credential prompt), not an error.
    """
    if http_status is None:
        return "no HTTP response"
    if auth_scheme and http_status in (401, 407):
        return None
    if http_status >= 400:
        return f"error page (HTTP {http_status})"
    if title and ERROR_TITLE_RE.search(title):
        return "error page (title)"
    # Title alone can be a soft 404 (stored pages have no body; SPA shells often set document.title)
    if title and len(title) < 120 and SOFT_404_TEXT_RE.match(title.strip()):
        return "error page (soft 404)"
    visible = _visible_text(html, body_text)
    if visible and len(visible) < 120 and SOFT_404_TEXT_RE.match(visible):
        return "error page (soft 404)"
    return None


def default_page_reason(title: str | None, html: str | None = None, body_text: str | None = None) -> str | None:
    """Detect a web server's out-of-the-box page (no application published there).

    ``title`` alone is enough for rematch on already-captured rows (HTML is not stored).
    """
    for rx, server in DEFAULT_PAGE_TITLES:
        if title and rx.search(title):
            return f"default server page ({server})"
    blob = f"{html or ''}\n{body_text or ''}"[:8000]
    if blob and JBOSS_WELCOME_BODY_RE.search(blob):
        return "default server page (JBoss)"
    if blob and TOMCAT_WELCOME_BODY_RE.search(blob):
        return "default server page (Tomcat)"
    if blob and RHEL_TEST_BODY_RE.search(blob):
        return "default server page (Red Hat)"
    # Distinctive body phrases sometimes land in the stored title on older captures
    if title and TOMCAT_WELCOME_BODY_RE.search(title):
        return "default server page (Tomcat)"
    if title and RHEL_TEST_BODY_RE.search(title):
        return "default server page (Red Hat)"
    if title and JBOSS_WELCOME_BODY_RE.search(title):
        return "default server page (JBoss)"
    if not title and html and IT_WORKS_RE.search(html[:2000]):
        return "default server page (Apache)"
    return None


def blank_page_reason(html: str | None) -> str | None:
    """Detect an HTML response that shows nothing, e.g. ``<html><head></head><body></body></html>``.

    ``html`` is None when the content is unknown (not HTML, or not kept) - never blank then;
    an empty string means a known-empty body.
    """
    if html is None:
        return None
    if CONTENT_TAG_RE.search(html[:200_000]) or _visible_text(html):
        return None
    return BLANK_PAGE_REASON


# capture_error of an endpoint whose probe failed or timed out (no HTTP response at all); the reason
# follows. The page is kept so the gallery shows it as unavailable, and auto-capture retries it.
UNAVAILABLE_PREFIX = "unavailable: "


def unusable_page_reason(
    http_status: int | None,
    title: str | None,
    html: str | None = None,
    body_text: str | None = None,
    auth_scheme: str | None = None,
) -> str | None:
    """Why a page shows no usable application, or None for a real page.

    Covers an unresolved redirect (status stays 3xx because the destination could not be loaded),
    an error response (including soft 404 bodies), no response at all, a web server's
    out-of-the-box default page (IIS / nginx / JBoss welcome, etc.) and an empty page.

    Safe to call on already-stored pages with only ``http_status`` + ``title`` (no HTML): title
    rules rematch on every API read so filters apply without re-running Web Capture.
    """
    if http_status is not None and 300 <= http_status < 400:
        return "redirect"
    if auth_scheme and http_status in (401, 407):
        return None
    return (
        error_page_reason(http_status, title, html, body_text)
        or default_page_reason(title, html, body_text)
        or (blank_page_reason(html) if not body_text else None)
    )


_LOGIN_URL_RE = re.compile(
    r"/(?:oauth2?/authorize|openid-connect/auth|protocol/openid-connect|saml2?/|sso/|adfs/ls|"
    r"login|signin|sign-in|logon|auth/realms)", re.I)


def looks_like_login_url(url: str | None) -> bool:
    """SSO / login endpoints (OAuth authorize, Keycloak, SAML, ADFS, …) by path."""
    return bool(url and _LOGIN_URL_RE.search(url))


def looks_like_login_html(html: str | None, title: str | None) -> bool:
    blob = f"{title or ''} {html or ''}"[:20_000]
    if not blob:
        return False
    if re.search(r'<input[^>]+type=["\']password["\']', blob, re.I):
        return True
    if LOGIN_RE.search(title or ""):
        return True
    return False


_WEB_VNC_MARKERS = (
    "novnc", "noVNC", "guacamole", "websockify", "vnc.html", "vnc_lite",
    "Apache Guacamole", "remote desktop gateway",
)


def looks_like_web_vnc(html: str | None, title: str | None, server: str | None = None) -> bool:
    """True when the HTTP UI is a browser-based VNC/RDP gateway (noVNC, Guacamole, …)."""
    blob = f"{title or ''} {server or ''} {html or ''}"[:30_000].lower()
    if not blob.strip():
        return False
    return any(m.lower() in blob for m in _WEB_VNC_MARKERS)


def _host_of(url: str) -> str:
    try:
        return (urlparse(url).hostname or "").lower().rstrip(".")
    except Exception:
        return ""


def _port_of(url: str) -> int | None:
    try:
        p = urlparse(url)
        if p.port:
            return p.port
        if p.scheme == "https":
            return 443
        if p.scheme == "http":
            return 80
    except Exception:
        return None
    return None


def is_same_target(from_url: str, to_url: str, allowed_hosts: set[str], allowed_ips: set[str]) -> bool:
    """Allow same IP/hostname and HTTP↔HTTPS on the selected target; reject everything else."""
    to = urlparse(to_url)
    if to.scheme not in ("http", "https"):
        return False
    host = (to.hostname or "").lower().rstrip(".")
    if not host:
        return False
    allowed = {h.lower().rstrip(".") for h in allowed_hosts} | {ip.lower() for ip in allowed_ips}
    if host in allowed:
        return True
    # Same host as the from_url (after HTTP→HTTPS scheme change)
    from_host = _host_of(from_url)
    if host and from_host and host == from_host:
        return True
    return False


def redirect_is_external(from_url: str, to_url: str, allowed_hosts: set[str], allowed_ips: set[str]) -> bool:
    return not is_same_target(from_url, to_url, allowed_hosts, allowed_ips)


def candidate_paths_for_endpoint(base: str, html: str | None, allowed_hosts: set[str],
                                 allowed_ips: set[str], max_candidates: int,
                                 discovery: int = 0,
                                 app_paths: tuple[str, ...] | None = None) -> list[tuple[str, str]]:
    """Build (url, suggested_kind) list starting with /, then fixed paths, then same-target links.

    ``discovery`` > 0 (when "/" has no application) first adds that many paths from ``app_paths``
    (default :data:`APP_PATHS`), on top of the ``max_candidates`` budget.
    """
    out: list[tuple[str, str]] = []
    seen: set[str] = set()
    limit = max_candidates + max(0, discovery)
    paths = app_paths if app_paths is not None else APP_PATHS

    def add(url: str, kind: str) -> None:
        if url in seen or len(out) >= limit:
            return
        seen.add(url)
        out.append((url, kind))

    root = base if base.endswith("/") else base + "/"
    add(root, WEB_PAGE_HOME)
    root_origin = urlparse(root)[:2]
    for path in paths[:max(0, discovery)]:
        url = urljoin(root, path.lstrip("/"))
        if urlparse(url)[:2] == root_origin:  # a wordlist entry can never change scheme, host or port
            add(url, classify_from_path(path))
    for path in LOGIN_PATHS + REGISTER_PATHS:
        add(urljoin(root, path.lstrip("/")), classify_from_path(path))
    if html:
        for url, kind in extract_same_target_auth_links(html, root, allowed_hosts, allowed_ips):
            add(url, kind)
            if len(out) >= limit:
                break
    return out[:limit]
