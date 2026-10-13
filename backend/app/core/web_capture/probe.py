"""Passive HTTP(S) probing for Web Capture (GET/HEAD only, size-capped)."""
from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse

import httpx

from ...models import WEB_PAGE_HOME, WEB_PAGE_LOGIN, WEB_PAGE_OTHER, WEB_PAGE_REGISTER
from .classify import (
    candidate_paths_for_endpoint,
    extract_title,
    looks_like_login_html,
    redirect_is_external,
    unusable_page_reason,
)
from .identify_ai import identify_local_ai

# Fingerprint paths tried on every web endpoint. Identity still comes only from
# response content (see identify_ai) — never from the port number alone.
_AI_API_PATHS = ("/api/tags", "/api/version", "/v1/models")

log = logging.getLogger(__name__)


@dataclass
class ProbeResult:
    url: str
    final_url: str | None = None
    http_status: int | None = None
    title: str | None = None
    content_type: str | None = None
    server_header: str | None = None
    html: str | None = None
    body_text: str | None = None  # short non-HTML preview (JSON / plain) for fingerprinting
    product_hint: str | None = None  # e.g. Ollama, LM Studio
    redirect_target: str | None = None
    external_redirect: bool = False
    tls_verified: bool | None = None
    error: str | None = None
    kind: str = WEB_PAGE_OTHER


@dataclass
class EndpointProbe:
    scheme: str
    host_used: str
    port: int
    pages: list[ProbeResult] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


def _build_url(scheme: str, host: str, port: int, path: str = "/") -> str:
    default = 443 if scheme == "https" else 80
    netloc = host if port == default else f"{host}:{port}"
    if not path.startswith("/"):
        path = "/" + path
    return f"{scheme}://{netloc}{path}"


def _read_limited(resp: httpx.Response, max_bytes: int) -> tuple[bytes, bool]:
    """Read body up to max_bytes. Returns (data, truncated)."""
    chunks: list[bytes] = []
    total = 0
    truncated = False
    for chunk in resp.iter_bytes():
        if total + len(chunk) > max_bytes:
            chunks.append(chunk[: max_bytes - total])
            truncated = True
            break
        chunks.append(chunk)
        total += len(chunk)
    return b"".join(chunks), truncated


def probe_url(
    client: httpx.Client,
    url: str,
    *,
    allowed_hosts: set[str],
    allowed_ips: set[str],
    max_bytes: int,
    verify_tls: bool,
) -> ProbeResult:
    """GET a URL following only same-target redirects. Never POSTs."""
    result = ProbeResult(url=url, tls_verified=True if (url.startswith("https") and verify_tls) else (
        False if url.startswith("https") else None
    ))
    current = url
    try:
        for _ in range(5):
            # Manual redirect control so we can stop at external SSO
            with client.stream("GET", current, follow_redirects=False) as resp:
                result.http_status = resp.status_code
                result.content_type = resp.headers.get("content-type")
                result.server_header = resp.headers.get("server")
                if resp.status_code in (301, 302, 303, 307, 308):
                    loc = resp.headers.get("location")
                    if not loc:
                        result.error = "redirect without location"
                        result.final_url = current
                        return result
                    from urllib.parse import urljoin
                    next_url = urljoin(current, loc)
                    result.redirect_target = next_url
                    if redirect_is_external(current, next_url, allowed_hosts, allowed_ips):
                        result.external_redirect = True
                        result.final_url = current
                        result.error = "redirect outside target"
                        # drain
                        try:
                            resp.read()
                        except Exception:
                            pass
                        return result
                    current = next_url
                    continue
                data, truncated = _read_limited(resp, max_bytes)
            result.final_url = current
            ctype = (result.content_type or "").lower()
            text = data.decode("utf-8", errors="replace") if data else ""
            if not data.strip() and 200 <= result.http_status < 300:
                result.html = ""  # known-empty body (None means "not HTML"): nothing to show
            elif "html" in ctype or data[:200].lstrip().startswith((b"<", b"<!")):
                result.html = text or None
                result.title = extract_title(result.html)
            elif text and (
                "json" in ctype
                or "text/" in ctype
                or text.lstrip()[:1] in "{["
            ):
                result.body_text = text[:20_000]
            _apply_ai_identity(result)
            if truncated:
                result.error = "response too large"
            return result
        result.error = "too many redirects"
        result.final_url = current
        return result
    except httpx.TimeoutException:
        result.error = "timeout"
        return result
    except httpx.ConnectError as exc:
        msg = str(exc).lower()
        if "certificate" in msg or "ssl" in msg:
            result.error = "TLS handshake failed"
            result.tls_verified = False
        else:
            result.error = "connection refused"
        return result
    except Exception as exc:
        log.debug("probe failed for %s: %s", url, exc)
        result.error = "request failed"
        return result


def _apply_ai_identity(pr: ProbeResult) -> None:
    path = urlparse(pr.final_url or pr.url).path or "/"
    hint = identify_local_ai(
        path=path,
        title=pr.title,
        server_header=pr.server_header,
        content_type=pr.content_type,
        body=pr.html or pr.body_text,
    )
    if not hint:
        return
    pr.product_hint = hint
    if not pr.title:
        pr.title = hint


def classify_probe(pr: ProbeResult, suggested: str) -> str:
    path = urlparse(pr.final_url or pr.url).path or "/"
    if pr.external_redirect and suggested == WEB_PAGE_HOME:
        return WEB_PAGE_HOME
    if looks_like_login_html(pr.html, pr.title) or suggested == WEB_PAGE_LOGIN:
        if suggested == WEB_PAGE_REGISTER:
            return WEB_PAGE_REGISTER
        return WEB_PAGE_LOGIN
    if suggested == WEB_PAGE_REGISTER:
        return WEB_PAGE_REGISTER
    if suggested == WEB_PAGE_HOME or path in ("/", "/index.html", "/index.htm"):
        return WEB_PAGE_HOME
    if suggested == WEB_PAGE_OTHER:
        return WEB_PAGE_OTHER
    return suggested or WEB_PAGE_OTHER


def probe_endpoint(
    scheme: str,
    host: str,
    port: int,
    *,
    allowed_hosts: set[str],
    allowed_ips: set[str],
    timeout: float,
    max_bytes: int,
    max_candidates: int,
    max_pages: int,
    max_discovery: int = 0,
    app_paths: tuple[str, ...] | None = None,
    verify_tls: bool = False,
    cancel_check: Callable[[], bool] | None = None,
) -> EndpointProbe:
    """Probe homepage + limited auth candidates for one endpoint. GET only."""
    ep = EndpointProbe(scheme=scheme, host_used=host, port=port)
    # Always record tls as unverified when we disable verification for internal capture
    tls_flag = False if scheme == "https" else None

    base = _build_url(scheme, host, port, "/")
    limits = httpx.Limits(max_connections=4, max_keepalive_connections=2)
    with httpx.Client(timeout=timeout, verify=verify_tls, follow_redirects=False,
                      limits=limits, headers={"User-Agent": "PortReveal-WebCapture/1.0"}) as client:
        home = probe_url(client, base, allowed_hosts=allowed_hosts, allowed_ips=allowed_ips,
                         max_bytes=max_bytes, verify_tls=verify_tls)
        home.tls_verified = tls_flag
        home.kind = classify_probe(home, WEB_PAGE_HOME)
        if cancel_check and cancel_check():
            return ep

        # "/" is an unresolved redirect (e.g. HTTP→HTTPS where TLS then fails), an external
        # redirect, or no response at all: there is no page to render and nothing to discover
        # here. Keep the single home result so the UI can show what it answered, and stop — this
        # avoids a wall of identical "redirect" tiles across every port of such a host.
        hs = home.http_status
        if home.external_redirect or hs is None or 300 <= hs < 400:
            ep.pages = [home]
            return ep

        # No application at "/" (error or default server page): also look where apps usually live
        root_unusable = bool(unusable_page_reason(hs, home.title, home.html, home.body_text))
        candidates = candidate_paths_for_endpoint(
            base, home.html, allowed_hosts, allowed_ips, max_candidates,
            discovery=max_discovery if root_unusable else 0,
            app_paths=app_paths,
        )
        # Probe LLM API fingerprint paths on every HTTP endpoint; label only if content matches.
        seen_urls = {u for u, _ in candidates}
        for path in _AI_API_PATHS:
            url = urljoin(base if base.endswith("/") else base + "/", path.lstrip("/"))
            if url not in seen_urls:
                candidates.append((url, WEB_PAGE_OTHER))
                seen_urls.add(url)
        if root_unusable:
            max_pages += 1  # the unusable root page does not take an application's slot
        # Always include home first
        results: dict[str, ProbeResult] = {}
        key = (home.final_url or home.url).rstrip("/") or home.url
        results[key] = home

        for url, suggested in candidates[1:]:
            if cancel_check and cancel_check():
                break
            if len(results) >= max_pages + 5:  # gather then trim
                break
            # Skip if clearly same as home URL we already have
            pr = probe_url(client, url, allowed_hosts=allowed_hosts, allowed_ips=allowed_ips,
                           max_bytes=max_bytes, verify_tls=verify_tls)
            pr.tls_verified = tls_flag
            pr.kind = classify_probe(pr, suggested)
            if pr.error and pr.http_status is None and not pr.external_redirect:
                continue
            # A guessed path that errors (or shows the server's default page) is not a page of this site
            if not pr.external_redirect and unusable_page_reason(
                pr.http_status, pr.title, pr.html, pr.body_text
            ):
                continue
            fkey = (pr.final_url or pr.url).rstrip("/") or pr.url
            if fkey in results:
                # Prefer more specific kind (login over home)
                existing = results[fkey]
                if existing.kind == WEB_PAGE_HOME and pr.kind in (WEB_PAGE_LOGIN, WEB_PAGE_REGISTER):
                    existing.kind = pr.kind
                continue
            results[fkey] = pr

    # Keep one page per kind preference: home, login, register, then other — up to max_pages
    preferred_order = [WEB_PAGE_HOME, WEB_PAGE_LOGIN, WEB_PAGE_REGISTER, WEB_PAGE_OTHER]
    chosen: list[ProbeResult] = []
    used_kinds: set[str] = set()
    by_kind: dict[str, list[ProbeResult]] = {k: [] for k in preferred_order}
    for pr in results.values():
        by_kind.setdefault(pr.kind, []).append(pr)

    for kind in preferred_order:
        for pr in by_kind.get(kind, []):
            if len(chosen) >= max_pages:
                break
            # Deduplicate: if home redirected to login URL already chosen as login, skip second
            fkey = (pr.final_url or pr.url).rstrip("/")
            if any((c.final_url or c.url).rstrip("/") == fkey for c in chosen):
                # Merge kind onto existing if home+login same URL
                for c in chosen:
                    if (c.final_url or c.url).rstrip("/") == fkey:
                        if c.kind == WEB_PAGE_HOME and pr.kind == WEB_PAGE_LOGIN:
                            c.kind = WEB_PAGE_LOGIN
                        break
                continue
            chosen.append(pr)
            used_kinds.add(kind)
            if kind != WEB_PAGE_OTHER:
                break  # one per kind; several discovered applications may be kept

    # If nothing chosen (all failed), still keep home attempt for inventory
    if not chosen and home:
        chosen = [home]

    def _is_unusable(pr: ProbeResult) -> bool:
        if pr.external_redirect:
            return False
        return bool(unusable_page_reason(pr.http_status, pr.title, pr.html, pr.body_text))

    # When a real app was found (e.g. /console/), do not also keep the 404 / JBoss welcome
    # home probe — it clutters the UI next to the live page.
    usable = [pr for pr in chosen if not _is_unusable(pr)]
    ep.pages = usable if usable else chosen
    return ep
