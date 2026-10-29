"""Wordlist library: formats, limits, validation, SSRF-safe URL import, RBAC, audit, legacy-setting migration."""
from __future__ import annotations

import gzip
import io
import json
from pathlib import Path

import httpx
import pytest
from alembic import command
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select, text

from app.api import wordlists as wordlists_api
from app.api.auth import limiter
from app.config import reset_settings_cache
from app.core import wordlists as wl
from app.core.web_capture.classify import APP_PATHS
from app.core.web_capture.wordlist import discovery_paths
from app.main import app
from app.migrate import alembic_config
from app.models import AuditLog, Wordlist
from app.settings_store import WebCaptureSettings, get_section

LIMITS = wl.Limits(max_upload_bytes=256 * 1024, max_decompressed_bytes=1024 * 1024, max_entries=1000, allow_http=False)


def parse(data: bytes, kind: str = "paths", expect_gz: bool | None = False, limits: wl.Limits = LIMITS, chunk: int = 5):
    """Feed in tiny chunks so line, UTF-8 and BOM boundaries fall mid-chunk."""
    out = io.StringIO()
    p = wl._StreamParser(kind, limits, out, expect_gz)
    for i in range(0, len(data), chunk):
        p.feed(data[i:i + chunk])
    result = p.finish()
    return out.getvalue().splitlines(), result


def rejected(data: bytes, **kw) -> wl.WordlistError:
    with pytest.raises(wl.WordlistError) as exc:
        parse(data, **kw)
    return exc.value


# --- formats -------------------------------------------------------------------------------------
def test_plain_text_comments_blank_lines_bom_and_crlf():
    entries, r = parse(b"\xef\xbb\xbf# comment\r\nadmin\r\n\r\n   \n/app/\n  portal  \n#/hidden\n")
    assert entries == ["/admin", "/app/", "/portal"]
    assert (r.accepted, r.skipped) == (3, 0)
    assert len(r.sha256) == 64 and not r.gzip


def test_gzip_including_multi_member():
    data = gzip.compress(b"admin\nlogin\n") + gzip.compress(b"portal\n")
    entries, r = parse(data, expect_gz=True)
    assert entries == ["/admin", "/login", "/portal"] and r.gzip


def test_gzip_detected_by_content_not_extension():
    entries, r = parse(gzip.compress(b"admin\n"), expect_gz=None)
    assert entries == ["/admin"] and r.gzip


def test_gz_extension_with_plain_content_is_rejected():
    assert "not gzip" in str(rejected(b"admin\n", expect_gz=True))


@pytest.mark.parametrize("data", [gzip.compress(b"admin\n" * 50)[:-12], b"\x1f\x8b\x08\x00garbage-not-deflate"])
def test_truncated_or_corrupt_gzip_rejected(data):
    assert "gzip" in str(rejected(data, expect_gz=True))


@pytest.mark.parametrize("filename,gz", [
    ("paths.txt", False), ("a.lst", False), ("a.list", False), ("a.dic", False), ("A.TXT.GZ", True), ("a.dic.gz", True),
])
def test_allowed_extensions(filename, gz):
    assert wl.expects_gzip(filename) is gz


@pytest.mark.parametrize("filename", ["a.zip", "a.tar", "a.tar.gz", "a.exe", "a.gz", "noext", "a.txt.zip"])
def test_disallowed_extensions(filename):
    with pytest.raises(wl.WordlistError):
        wl.expects_gzip(filename)


# --- limits --------------------------------------------------------------------------------------
def test_compressed_size_limit():
    err = rejected(b"#" * (LIMITS.max_upload_bytes + 10), chunk=4096)
    assert err.status == 413 and "MB limit" in str(err)


def test_decompression_bomb_stops_at_decompressed_limit():
    bomb = gzip.compress(b"\n" * (LIMITS.max_decompressed_bytes * 8))  # ~8 MB of newlines -> a few KB gzipped
    assert len(bomb) < LIMITS.max_upload_bytes
    err = rejected(bomb, expect_gz=True, chunk=4096)
    assert err.status == 413 and "decompressed" in str(err)


def test_entry_limit():
    data = "".join(f"p{i}\n" for i in range(LIMITS.max_entries + 1)).encode()
    err = rejected(data, chunk=4096)
    assert err.status == 413 and "entries" in str(err)


def test_overlong_line_is_skipped_without_buffering():
    entries, r = parse(b"/" + b"a" * (wl.MAX_LINE_CHARS * 3) + b"\n/ok\n", chunk=1000)
    assert entries == ["/ok"] and r.reasons["line too long"] == 1


# --- binary rejection ----------------------------------------------------------------------------
@pytest.mark.parametrize("data,expect", [
    (b"admin\n\x00\x01\x02", "NUL"),
    (b"admin\n\xff\xfe broken", "UTF-8"),
    (b"caf\xc3", "UTF-8"),  # truncated multi-byte sequence at EOF
    (b"PK\x03\x04" + b"rest-of-zip-file-header", "zip"),
    (b"MZ\x90\x00" + b"\x03" * 20, "executable"),
    (b"\x7fELF" + b"\x02\x01\x01" + b"x" * 20, "executable"),
])
def test_binary_content_rejected(data, expect):
    err = rejected(data)
    assert expect in str(err) and err.status == 415


def test_zip_inside_gzip_rejected():
    assert "zip" in str(rejected(gzip.compress(b"PK\x03\x04" + b"x" * 40), expect_gz=True))


def test_empty_and_all_invalid_files_rejected():
    assert "empty" in str(rejected(b""))
    err = rejected(b"# only comments\n../x\n")
    assert err.status == 422 and "path traversal" in str(err)


# --- path validation -----------------------------------------------------------------------------
@pytest.mark.parametrize("raw,reason", [
    ("../etc/passwd", "path traversal"),
    ("/a/../../b", "path traversal"),
    ("%2e%2e/secret", "path traversal"),
    ("a\\b", "backslash"),
    ("%5cwindows", "encoded control character or backslash"),
    ("a\rb", "control character"),
    ("a\nb", "control character"),
    ("x\x00y", "control character"),
    ("%0d%0aSet-Cookie:x", "encoded control character or backslash"),
    ("a\u202eb", "control character"),
    ("http://evil.example.test/", "URL scheme"),
    ("file:///etc/passwd", "URL scheme"),
    ("javascript:alert(1)", "URL scheme"),
    ("data:text/html,x", "URL scheme"),
    ("//evil.example.test/x", "protocol-relative URL"),
    ("%2F%2Fevil.example.test", "URL scheme"),
    ("a" * 300, "too long"),
])
def test_path_rejections(raw, reason):
    assert wl.normalize_path(raw) == (None, reason)


@pytest.mark.parametrize("raw,expected", [
    ("admin", "/admin"),
    ("/admin/", "/admin/"),
    ("///admin", None),  # leading // is refused rather than collapsed
    ("  login  ", "/login"),
    ("/a b?c#d", "/a%20b%3Fc%23d"),
    ("/caf\u00e9", "/caf%C3%A9"),
    ("/50%", "/50%25"),
    ("/%41dmin", "/%41dmin"),
    ("/api/v1;x=1", "/api/v1;x=1"),
    ("/<script>", "/%3Cscript%3E"),
])
def test_path_normalization(raw, expected):
    assert wl.normalize_path(raw)[0] == expected


def test_crlf_injection_lines_skipped_in_file():
    entries, r = parse(b"/ok\n/a\rb\n/c\r\n")
    assert entries == ["/ok", "/c"] and r.reasons["control character"] == 1
    assert r.samples == ["line 2: control character"]


def test_dedupe_preserves_order_and_is_reported():
    entries, r = parse(b"b\na\n/b\nB\na\n")
    assert entries == ["/b", "/a", "/B"]
    assert r.reasons["duplicate"] == 2 and r.summary()["skipped"] == 2


def test_wordlist_entry_cannot_change_host():
    from app.core.web_capture.classify import candidate_paths_for_endpoint

    out = candidate_paths_for_endpoint("http://10.0.0.1/", None, set(), set(), 0, discovery=4,
                                       app_paths=("/ok", "//evil.example.test/x", "http://evil.example.test/",
                                                  "https://10.0.0.1:8443/"))
    urls = [u for u, _ in out]
    assert urls[:2] == ["http://10.0.0.1/", "http://10.0.0.1/ok"]
    assert all(u.startswith("http://10.0.0.1/") for u in urls)


# --- subdomain validation ------------------------------------------------------------------------
@pytest.mark.parametrize("raw,expected", [
    ("WWW", "www"),
    ("mail.", "mail"),
    ("dev.api", "dev.api"),
    ("_dmarc", "_dmarc"),
    ("b\u00fccher", "xn--bcher-kva"),
    ("-bad", None),
    ("bad-", None),
    ("a" * 64, None),
    ("a..b", None),
    ("evil.example.test/x", None),
    ("user@host", None),
    ("*.wild", None),
    (".".join(["a" * 60] * 5), None),  # > 253
])
def test_subdomain_normalization(raw, expected):
    assert wl.normalize_subdomain(raw)[0] == expected


def test_subdomain_list_parse():
    entries, r = parse(b"www\nWWW\nmail\nbad_label!\n", kind="subdomains")
    assert entries == ["www", "mail"] and r.reasons == {"duplicate": 1, "invalid characters": 1}


@pytest.mark.parametrize("name,ok", [
    ("Common paths (v2)", True), ("a.b_c-d", True), ("x" * 64, True),
    ("x" * 65, False), ("<script>", False), ("../x", False), ("", False), (" lead", True),
])
def test_name_rules(name, ok):
    if ok:
        assert wl.validate_name(name)
    else:
        with pytest.raises(wl.WordlistError):
            wl.validate_name(name)


# --- SSRF ----------------------------------------------------------------------------------------
@pytest.mark.parametrize("ip", [
    "10.1.2.3", "172.16.0.1", "172.31.255.255", "192.168.1.1", "127.0.0.1", "169.254.169.254", "0.0.0.0",
    "100.64.0.1", "::1", "fc00::1", "fd00:ec2::254", "fe80::1", "::ffff:10.0.0.1", "::ffff:127.0.0.1", "224.0.0.1",
])
def test_blocked_ips(ip):
    assert wl.is_blocked_ip(ip)


@pytest.mark.parametrize("ip", ["1.1.1.1", "8.8.8.8", "2606:4700:4700::1111"])
def test_public_ips_allowed(ip):
    assert not wl.is_blocked_ip(ip)


@pytest.mark.parametrize("url,msg", [
    ("http://lists.example.test/a.txt", "https"),
    ("ftp://lists.example.test/a.txt", "https"),
    ("file:///etc/passwd", "https"),
    ("https://user:pw@lists.example.test/a.txt", "credentials"),
    ("https://token@lists.example.test/a.txt", "credentials"),
    ("https:///a.txt", "host"),
    ("https://lists.example.test/a b.txt", "invalid URL"),
])
def test_url_validation(url, msg):
    with pytest.raises(wl.WordlistError) as exc:
        wl.validate_url(url, allow_http=False)
    assert msg in str(exc.value)


def test_http_allowed_only_when_enabled():
    assert wl.validate_url("http://lists.example.test/a.txt", allow_http=True) == ("http", "lists.example.test", 80)


def ok(body: bytes, **headers):
    # A streamed body: bytes content would be pre-read by httpx, unlike a real transport.
    return lambda: httpx.Response(200, headers=headers, stream=httpx.ByteStream(body))


def redirect(location: str, status: int = 302):
    return lambda: httpx.Response(status, headers={"location": location})


class FakeNet:
    """DNS answers + HTTP responses by (host header, path); records every resolution and request."""

    def __init__(self, dns: dict[str, list[list[str]] | list[str]], routes: dict):
        self.dns = {h: (v if v and isinstance(v[0], list) else [v]) for h, v in dns.items()}
        self.routes = routes
        self.resolved: list[str] = []
        self.requests: list[httpx.Request] = []

    def resolve(self, host: str, port: int) -> list[str]:
        self.resolved.append(host)
        if host not in self.dns:
            return wl.resolve_host(host, port)  # IP literals only; no real DNS in tests
        answers = self.dns[host]
        return answers.pop(0) if len(answers) > 1 else answers[0]

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        return self.routes[(request.headers["host"], request.url.path)]()

    def fetch(self, url: str, limits: wl.Limits = LIMITS) -> bytes:
        return b"".join(wl.fetch_url(url, limits, resolver=self.resolve, transport=httpx.MockTransport(self.handler)))


def test_fetch_pins_connection_to_checked_address():
    net = FakeNet({"lists.example.test": ["1.1.1.1"]},
                  {("lists.example.test", "/paths.txt"): ok(b"admin\n")})
    assert net.fetch("https://lists.example.test/paths.txt") == b"admin\n"
    req = net.requests[0]
    assert req.url.host == "1.1.1.1" and req.url.scheme == "https"
    assert req.headers["host"] == "lists.example.test"
    assert req.extensions["sni_hostname"] == "lists.example.test"
    assert req.headers["accept-encoding"] == "identity"


@pytest.mark.parametrize("answer", [["10.0.0.5"], ["1.1.1.1", "127.0.0.1"], ["169.254.169.254"], ["fe80::1"]])
def test_fetch_blocks_private_resolution(answer):
    net = FakeNet({"lists.example.test": answer}, {})
    with pytest.raises(wl.WordlistError, match="blocked address"):
        net.fetch("https://lists.example.test/paths.txt")
    assert net.requests == []


def test_fetch_blocks_literal_metadata_ip():
    with pytest.raises(wl.WordlistError, match="blocked address"):
        b"".join(wl.fetch_url("https://169.254.169.254/latest/meta-data", LIMITS,
                              transport=httpx.MockTransport(lambda r: httpx.Response(200))))


def test_redirect_to_private_host_blocked():
    net = FakeNet(
        {"lists.example.test": ["1.1.1.1"], "intranet.example.test": ["192.168.1.10"]},
        {("lists.example.test", "/paths.txt"): redirect("https://intranet.example.test/x")},
    )
    with pytest.raises(wl.WordlistError, match="blocked address"):
        net.fetch("https://lists.example.test/paths.txt")
    assert net.resolved == ["lists.example.test", "intranet.example.test"] and len(net.requests) == 1


def test_redirect_re_resolves_every_hop():
    """DNS rebinding: the same host answers public first, private on the next lookup."""
    net = FakeNet(
        {"lists.example.test": [["1.1.1.1"], ["127.0.0.1"]]},
        {("lists.example.test", "/a.txt"): redirect("/b.txt", 301)},
    )
    with pytest.raises(wl.WordlistError, match="blocked address"):
        net.fetch("https://lists.example.test/a.txt")
    assert net.resolved == ["lists.example.test", "lists.example.test"]


def test_redirect_to_http_refused():
    net = FakeNet({"lists.example.test": ["1.1.1.1"]},
                  {("lists.example.test", "/a.txt"): redirect("http://lists.example.test/a.txt")})
    with pytest.raises(wl.WordlistError, match="https"):
        net.fetch("https://lists.example.test/a.txt")


def test_redirect_limit():
    net = FakeNet({"lists.example.test": ["1.1.1.1"]},
                  {("lists.example.test", "/loop"): redirect("/loop")})
    with pytest.raises(wl.WordlistError, match="too many redirects"):
        net.fetch("https://lists.example.test/loop")
    assert len(net.requests) == wl.MAX_REDIRECTS + 1


def test_fetch_size_limit_from_content_length():
    net = FakeNet({"lists.example.test": ["1.1.1.1"]},
                  {("lists.example.test", "/big.txt"): ok(b"a\n", **{"content-length": str(LIMITS.max_upload_bytes + 1)})})
    with pytest.raises(wl.WordlistError, match="MB limit"):
        net.fetch("https://lists.example.test/big.txt")


# --- API: RBAC, audit, selection, in-use delete ---------------------------------------------------
@pytest.fixture
def client(db_env):
    limiter.reset()
    with TestClient(app) as c:
        assert c.post("/api/setup/admin", json={"username": "admin", "password": "correct-horse-1"}).status_code == 200
        yield c


def csrf(c: TestClient) -> dict:
    return {"X-CSRF-Token": c.cookies.get("nf_csrf", "")}


def upload(c: TestClient, data: bytes, filename: str = "paths.txt", **form) -> httpx.Response:
    return c.post("/api/wordlists/upload", files={"file": (filename, data, "text/plain")},
                  data={"kind": "paths", **form}, headers=csrf(c))


def audit_actions(db) -> list[str]:
    db.expire_all()
    return [a.action for a in db.scalars(select(AuditLog).order_by(AuditLog.id))]


def test_upload_select_and_scan_uses_list(client, db):
    r = upload(client, b"# list\nadmin\n../etc\nconsole\nadmin\n", name="Common paths")
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["summary"]["accepted"] == 2 and body["summary"]["skipped"] == 2
    assert body["summary"]["reasons"] == {"path traversal": 1, "duplicate": 1}
    w = body["wordlist"]
    assert (w["name"], w["kind"], w["source"], w["entries"], w["created_by"]) == ("Common paths", "paths", "upload", 2, "admin")

    lib = client.get("/api/wordlists").json()
    assert lib["builtin"]["in_use"] and lib["builtin"]["entries"] == len(APP_PATHS)
    assert lib["limits"]["max_entries"] == 1_000_000 and lib["subdomain_discovery"]

    cfg = client.get("/api/settings/web-capture").json()
    assert cfg["discovery_wordlist_id"] is None and "discovery_wordlist" not in cfg
    r = client.put("/api/settings/web-capture", json={**cfg, "discovery_wordlist_id": w["id"]}, headers=csrf(client))
    assert r.status_code == 200, r.text
    assert client.get("/api/wordlists").json()["items"][0]["in_use"]

    stored = db.get(Wordlist, w["id"])
    assert wl.STORAGE_RE.fullmatch(stored.storage_name)
    assert discovery_paths(db, w["id"]) == ("/admin", "/console")
    assert {"wordlist.upload", "wordlist.select"} <= set(audit_actions(db))


def test_upload_rejects_bad_type_and_binary(client):
    assert upload(client, b"PK\x03\x04xxxx", filename="paths.zip").status_code == 415
    assert upload(client, b"PK\x03\x04" + b"x" * 30, filename="paths.txt").status_code == 415
    assert upload(client, b"ok\n\x00\x00", filename="paths.txt").status_code == 415
    r = client.post("/api/wordlists/upload", files={"file": ("p.txt", b"a\n", "text/plain")},
                    data={"kind": "passwords"}, headers=csrf(client))
    assert r.status_code == 422
    assert client.get("/api/wordlists").json()["items"] == []


def test_upload_gz_and_name_from_file(client):
    r = upload(client, gzip.compress(b"admin\n"), filename="my paths.lst.gz")
    assert r.status_code == 201, r.text
    assert r.json()["wordlist"]["name"] == "my paths"
    assert upload(client, gzip.compress(b"x\n"), filename="my paths.lst.gz").json()["wordlist"]["name"] == "my paths (2)"


def test_select_rejects_unknown_or_subdomain_list(client):
    sub = upload(client, b"www\n", filename="subs.txt", kind="subdomains").json()["wordlist"]
    cfg = client.get("/api/settings/web-capture").json()
    for bad in (sub["id"], 9999):
        r = client.put("/api/settings/web-capture", json={**cfg, "discovery_wordlist_id": bad}, headers=csrf(client))
        assert r.status_code == 422


def test_rename_rules(client, db):
    a = upload(client, b"a\n", filename="a.txt").json()["wordlist"]
    upload(client, b"b\n", filename="b.txt")
    h = csrf(client)
    assert client.patch(f"/api/wordlists/{a['id']}", json={"name": "<b>x</b>"}, headers=h).status_code == 422
    assert client.patch(f"/api/wordlists/{a['id']}", json={"name": "B"}, headers=h).status_code == 409
    r = client.patch(f"/api/wordlists/{a['id']}", json={"name": "Renamed list"}, headers=h)
    assert r.status_code == 200 and r.json()["name"] == "Renamed list"
    assert "wordlist.rename" in audit_actions(db)


def test_delete_in_use_blocked_then_force_falls_back(client, db):
    w = upload(client, b"admin\n").json()["wordlist"]
    cfg = client.get("/api/settings/web-capture").json()
    client.put("/api/settings/web-capture", json={**cfg, "discovery_wordlist_id": w["id"]}, headers=csrf(client))
    path = wl.stored_path(db.get(Wordlist, w["id"]).storage_name)
    assert path.is_file()

    assert client.delete(f"/api/wordlists/{w['id']}", headers=csrf(client)).status_code == 409
    assert client.delete(f"/api/wordlists/{w['id']}?force=true", headers=csrf(client)).status_code == 204
    assert not path.exists()
    assert client.get("/api/settings/web-capture").json()["discovery_wordlist_id"] is None
    assert client.get("/api/wordlists").json()["builtin"]["in_use"]
    db.expire_all()
    assert discovery_paths(db, w["id"]) == APP_PATHS
    assert "wordlist.delete" in audit_actions(db)


def test_viewer_cannot_manage_wordlists(client):
    w = upload(client, b"admin\n").json()["wordlist"]
    h = csrf(client)
    assert client.post("/api/users", json={"username": "viewer1", "password": "viewer-pass-1", "role": "viewer"},
                       headers=h).status_code == 201
    client.post("/api/auth/logout", headers=h)
    client.post("/api/auth/login", json={"username": "viewer1", "password": "viewer-pass-1"})
    h = csrf(client)
    assert client.get("/api/wordlists").status_code == 403
    assert upload(client, b"x\n").status_code == 403
    assert client.post("/api/wordlists/import", json={"url": "https://lists.example.test/a.txt"}, headers=h).status_code == 403
    assert client.patch(f"/api/wordlists/{w['id']}", json={"name": "x"}, headers=h).status_code == 403
    assert client.post(f"/api/wordlists/{w['id']}/reimport", headers=h).status_code == 403
    assert client.delete(f"/api/wordlists/{w['id']}", headers=h).status_code == 403


@pytest.fixture
def fake_net(monkeypatch):
    net = FakeNet({"lists.example.test": ["1.1.1.1"]}, {})

    def fetch(url, limits=None):
        return wl.fetch_url(url, limits, resolver=net.resolve, transport=httpx.MockTransport(net.handler))

    monkeypatch.setattr(wordlists_api, "fetch_url", fetch)
    return net


def test_import_from_url_and_reimport_reports_change(client, db, fake_net):
    fake_net.routes[("lists.example.test", "/common.txt")] = ok(b"admin\nlogin\n")
    r = client.post("/api/wordlists/import", json={"url": "https://lists.example.test/common.txt"}, headers=csrf(client))
    assert r.status_code == 201, r.text
    w = r.json()["wordlist"]
    assert (w["name"], w["source"], w["entries"]) == ("common", "url", 2)
    assert w["source_url"] == "https://lists.example.test/common.txt"
    old_storage = db.get(Wordlist, w["id"]).storage_name

    fake_net.routes[("lists.example.test", "/common.txt")] = ok(b"admin\nlogin\nportal\n")
    r = client.post(f"/api/wordlists/{w['id']}/reimport", headers=csrf(client))
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["previous_entries"] == 2 and body["wordlist"]["entries"] == 3 and body["changed"] is True
    assert body["wordlist"]["sha256"] != w["sha256"]
    assert not wl.stored_path(old_storage).exists()

    r = client.post(f"/api/wordlists/{w['id']}/reimport", headers=csrf(client))
    assert r.json()["changed"] is False
    assert {"wordlist.import", "wordlist.reimport"} <= set(audit_actions(db))


def test_reimport_only_for_url_lists(client):
    w = upload(client, b"admin\n").json()["wordlist"]
    assert client.post(f"/api/wordlists/{w['id']}/reimport", headers=csrf(client)).status_code == 409


@pytest.mark.parametrize("url", [
    "https://127.0.0.1/a.txt", "https://[::1]/a.txt", "https://169.254.169.254/latest", "http://lists.example.test/a.txt",
    "https://admin:pw@lists.example.test/a.txt",
])
def test_import_refused_urls_are_audited(client, db, fake_net, url):
    r = client.post("/api/wordlists/import", json={"url": url}, headers=csrf(client))
    assert r.status_code == 422, r.text
    assert fake_net.requests == []
    assert "wordlist.import_rejected" in audit_actions(db)
    rejected_audit = db.scalars(select(AuditLog).where(AuditLog.action == "wordlist.import_rejected")).one()
    assert "pw@" not in rejected_audit.details  # credentials are never written to the audit log
    assert client.get("/api/wordlists").json()["items"] == []


def test_failed_import_leaves_no_files(client, fake_net):
    fake_net.routes[("lists.example.test", "/bin.txt")] = ok(b"\x00\x01binary")
    r = client.post("/api/wordlists/import", json={"url": "https://lists.example.test/bin.txt"}, headers=csrf(client))
    assert r.status_code == 415
    assert list(wl.wordlists_dir().iterdir()) == []


def test_selection_change_is_audited_with_section_audit(client, db):
    w = upload(client, b"admin\n").json()["wordlist"]
    cfg = client.get("/api/settings/web-capture").json()
    client.put("/api/settings/web-capture", json={**cfg, "discovery_wordlist_id": w["id"]}, headers=csrf(client))
    client.put("/api/settings/web-capture", json={**cfg, "discovery_wordlist_id": None}, headers=csrf(client))
    db.expire_all()
    selects = db.scalars(select(AuditLog).where(AuditLog.action == "wordlist.select").order_by(AuditLog.id)).all()
    assert [json.loads(a.details)["to"] for a in selects] == [w["id"], None]
    assert get_section(db, WebCaptureSettings).discovery_wordlist_id is None


# --- legacy setting migration --------------------------------------------------------------------
@pytest.fixture
def legacy_db(tmp_path, monkeypatch):
    """A database at revision 0033 with the old free-text setting, and a data dir."""
    data = tmp_path / "data"
    data.mkdir()
    monkeypatch.setenv("DATA_DIR", str(data))
    reset_settings_cache()
    url = f"sqlite:///{(tmp_path / 'legacy.db').as_posix()}"
    cfg = alembic_config(url)
    command.upgrade(cfg, "0033")
    engine = create_engine(url)

    def set_legacy(path: str) -> None:
        value = json.dumps({"enabled": True, "max_discovery_paths": 12, "discovery_wordlist": path})
        with engine.begin() as conn:
            conn.execute(text("INSERT INTO app_settings (key, value, updated_at) VALUES ('web_capture', :v, '2026-01-01')"),
                         {"v": value})

    def setting() -> dict:
        with engine.connect() as conn:
            return json.loads(conn.execute(text("SELECT value FROM app_settings WHERE key='web_capture'")).scalar())

    yield {"cfg": cfg, "engine": engine, "data": data, "set_legacy": set_legacy, "setting": setting}
    engine.dispose()
    reset_settings_cache()


def test_legacy_wordlist_file_is_imported_and_selected(legacy_db):
    (legacy_db["data"] / "lists").mkdir()
    (legacy_db["data"] / "lists" / "custom.txt").write_bytes(b"admin\n/portal/\nhttp://evil.example.test/\n")
    legacy_db["set_legacy"]("lists/custom.txt")
    command.upgrade(legacy_db["cfg"], "head")

    value = legacy_db["setting"]()
    assert "discovery_wordlist" not in value and value["max_discovery_paths"] == 12
    with legacy_db["engine"].connect() as conn:
        row = conn.execute(text("SELECT id, name, kind, entries, skipped, storage_name FROM wordlists")).one()
    assert value["discovery_wordlist_id"] == row.id
    assert (row.name, row.kind, row.entries, row.skipped) == ("custom", "paths", 2, 1)
    stored = legacy_db["data"] / "wordlists" / row.storage_name
    assert stored.read_text(encoding="utf-8") == "/admin\n/portal/\n"

    command.downgrade(legacy_db["cfg"], "0033")
    value = legacy_db["setting"]()
    assert "discovery_wordlist_id" not in value
    assert Path(value["discovery_wordlist"]) == stored


@pytest.mark.parametrize("legacy", ["missing/nothing.txt", ""])
def test_legacy_missing_file_falls_back_to_builtin(legacy_db, legacy):
    legacy_db["set_legacy"](legacy)
    command.upgrade(legacy_db["cfg"], "head")
    value = legacy_db["setting"]()
    assert value["discovery_wordlist_id"] is None and "discovery_wordlist" not in value
    with legacy_db["engine"].connect() as conn:
        assert conn.execute(text("SELECT COUNT(*) FROM wordlists")).scalar() == 0
