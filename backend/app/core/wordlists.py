"""Wordlist library: managed, validated wordlists for Web capture discovery.

Uploads and URL imports are parsed while streaming (size, decompression-bomb and entry limits are
enforced as bytes arrive). Every line is validated and sanitized; only accepted entries are stored,
one per line, in a server-named file under <data dir>/wordlists. Entries never reach a shell: scans
join them onto a base URL whose scheme, host and port the capture job fixes.
"""
from __future__ import annotations

import codecs
import hashlib
import ipaddress
import os
import re
import socket
import time
import uuid
import zlib
from collections import Counter
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import TextIO
from urllib.parse import quote, unquote, urljoin, urlsplit, urlunsplit

import httpx

from ..config import get_settings

KIND_PATHS = "paths"
KIND_SUBDOMAINS = "subdomains"
KINDS = (KIND_PATHS, KIND_SUBDOMAINS)
SOURCE_UPLOAD = "upload"
SOURCE_URL = "url"
SOURCE_BUILTIN = "builtin"

TEXT_EXTS = (".txt", ".lst", ".list", ".dic")
MAX_PATH_LEN = 255
MAX_HOST_LEN = 253
MAX_LABEL_LEN = 63
MAX_NAME_LEN = 64
# A line longer than this is skipped without being buffered (a 50 MB single "line" stays cheap).
MAX_LINE_CHARS = 4096
MAX_REDIRECTS = 3
CONNECT_TIMEOUT_S = 5.0
READ_TIMEOUT_S = 20.0
FETCH_DEADLINE_S = 120.0
MAX_SAMPLES = 5
_CHUNK = 64 * 1024

NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9 ._()-]{0,63}")
STORAGE_RE = re.compile(r"[0-9a-f]{32}\.txt")
# C0/C1 controls, DEL, line/paragraph separators and bidi overrides (display spoofing).
_CTRL = re.compile("[\x00-\x1f\x7f-\x9f\u2028\u2029\u202a-\u202e\u2066-\u2069]")
_SCHEME = re.compile(r"^[A-Za-z][A-Za-z0-9+.\-]*:")
_BAD_PCT = re.compile(r"%(?![0-9A-Fa-f]{2})")
# RFC 3986 path characters (pchar + "/"); "%" is kept because stray ones were already escaped.
_PATH_SAFE = "/:@!$&'()*+,;=-._~%"
_LABEL = re.compile(r"[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?")

# Archive / executable signatures refused outright (anything else binary fails the NUL/UTF-8 check).
_BINARY_MAGIC = (
    (b"PK\x03\x04", "zip archive"),
    (b"PK\x05\x06", "zip archive"),
    (b"7z\xbc\xaf\x27\x1c", "7z archive"),
    (b"Rar!\x1a\x07", "rar archive"),
    (b"\xfd7zXZ\x00", "xz archive"),
    (b"BZh91AY&SY", "bzip2 archive"),
    (b"\x7fELF", "executable"),
    (b"MZ\x90\x00", "executable"),
    (b"\xca\xfe\xba\xbe", "executable"),
    (b"\xcf\xfa\xed\xfe", "executable"),
    (b"%PDF-", "PDF document"),
)

# Explicit SSRF block list; anything else that is not globally routable is refused as well.
BLOCKED_NETWORKS = tuple(ipaddress.ip_network(n) for n in (
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12",
    "192.168.0.0/16", "::1/128", "::/128", "fc00::/7", "fe80::/10",
))


class WordlistError(ValueError):
    """User-facing rejection (bad file, limit exceeded, blocked URL)."""

    def __init__(self, message: str, status: int = 400):
        super().__init__(message)
        self.status = status


@dataclass(frozen=True)
class Limits:
    max_upload_bytes: int
    max_decompressed_bytes: int
    max_entries: int
    allow_http: bool

    @classmethod
    def from_settings(cls) -> Limits:
        s = get_settings()
        return cls(
            max_upload_bytes=s.wordlist_max_upload_mb * 1024 * 1024,
            max_decompressed_bytes=s.wordlist_max_decompressed_mb * 1024 * 1024,
            max_entries=s.wordlist_max_entries,
            allow_http=s.wordlist_allow_http,
        )

    def as_dict(self) -> dict:
        return {
            "max_upload_bytes": self.max_upload_bytes,
            "max_decompressed_bytes": self.max_decompressed_bytes,
            "max_entries": self.max_entries,
            "allow_http": self.allow_http,
            "extensions": [*TEXT_EXTS, *(e + ".gz" for e in TEXT_EXTS)],
        }


@dataclass
class ParseResult:
    accepted: int = 0
    skipped: int = 0
    reasons: Counter = field(default_factory=Counter)
    samples: list[str] = field(default_factory=list)  # "line 7: path traversal"
    sha256: str = ""
    size_bytes: int = 0
    gzip: bool = False

    def summary(self) -> dict:
        return {
            "accepted": self.accepted,
            "skipped": self.skipped,
            "reasons": dict(self.reasons.most_common()),
            "samples": self.samples,
        }


# --- validation -------------------------------------------------------------------------------
def validate_name(name: str) -> str:
    n = " ".join((name or "").split())
    if not NAME_RE.fullmatch(n):
        raise WordlistError(
            f"name must be 1-{MAX_NAME_LEN} characters: letters, digits, space, '.', '_', '-', '(', ')'", 422)
    return n


def name_from_filename(filename: str) -> str:
    stem = Path(filename or "").name
    for ext in (".gz", *TEXT_EXTS):
        if stem.lower().endswith(ext):
            stem = stem[: -len(ext)]
    stem = re.sub(r"[^A-Za-z0-9 ._()-]+", "-", stem).strip(" .-_()")[:MAX_NAME_LEN]
    return stem or "wordlist"


def normalize_path(raw: str) -> tuple[str | None, str | None]:
    """(normalized path, None) or (None, skip reason)."""
    s = raw.strip(" \t")
    if not s:
        return None, "empty"
    if _CTRL.search(s):
        return None, "control character"
    if "\\" in s:
        return None, "backslash"
    if s.startswith("//"):
        return None, "protocol-relative URL"
    if _SCHEME.match(s) or "://" in s:
        return None, "URL scheme"
    decoded = unquote(s)
    if _CTRL.search(decoded) or "\\" in decoded:
        return None, "encoded control character or backslash"
    if ".." in s or ".." in decoded:
        return None, "path traversal"
    if _SCHEME.match(decoded) or "://" in decoded or decoded.startswith("//"):
        return None, "URL scheme"
    s = "/" + s.lstrip("/")
    out = quote(_BAD_PCT.sub("%25", s), safe=_PATH_SAFE)
    if len(out) > MAX_PATH_LEN:
        return None, "too long"
    return out, None


def normalize_subdomain(raw: str) -> tuple[str | None, str | None]:
    s = raw.strip(" \t").lower().rstrip(".")
    if not s:
        return None, "empty"
    if _CTRL.search(s):
        return None, "control character"
    if any(c in s for c in "/\\:@ %"):
        return None, "not a host name"
    if not s.isascii():
        try:
            s = s.encode("idna").decode("ascii")
        except UnicodeError:
            return None, "invalid IDN"
    if len(s) > MAX_HOST_LEN:
        return None, "too long"
    for label in s.split("."):
        if not label:
            return None, "empty label"
        if len(label) > MAX_LABEL_LEN:
            return None, "label too long"
        if not _LABEL.fullmatch(label):
            return None, "invalid characters"
    return s, None


NORMALIZERS: dict[str, Callable[[str], tuple[str | None, str | None]]] = {
    KIND_PATHS: normalize_path,
    KIND_SUBDOMAINS: normalize_subdomain,
}


def expects_gzip(filename: str, *, require_ext: bool = True) -> bool | None:
    """True for *.gz, False for plain text extensions; None when unknown and ``require_ext`` is off."""
    n = (filename or "").lower()
    gz = n.endswith(".gz")
    base = n[:-3] if gz else n
    if base.endswith(TEXT_EXTS):
        return gz
    if not require_ext and "." not in base.rsplit("/", 1)[-1]:
        return None
    raise WordlistError("unsupported file type: use .txt, .lst, .list or .dic (optionally .gz)", 415)


# --- streaming parser -----------------------------------------------------------------------
class _StreamParser:
    def __init__(self, kind: str, limits: Limits, out: TextIO, expect_gz: bool | None):
        self._normalize = NORMALIZERS[kind]
        self._limits = limits
        self._out = out
        self._expect_gz = expect_gz
        self._hash = hashlib.sha256()
        self._received = 0
        self._decompressed = 0
        self._head = b""
        self._mode: str | None = None  # "gz" | "plain", decided from the first bytes
        self._gz = None
        self._dec = codecs.getincrementaldecoder("utf-8")("strict")
        self._started_text = False
        self._buf = ""
        self._overlong = False
        self._line_no = 0
        self._candidates = 0
        self._seen: set[str] = set()
        self.result = ParseResult()

    def feed(self, chunk: bytes) -> None:
        if not chunk:
            return
        self._received += len(chunk)
        if self._received > self._limits.max_upload_bytes:
            raise WordlistError(f"file exceeds the {self._limits.max_upload_bytes // (1024 * 1024)} MB limit", 413)
        self._hash.update(chunk)
        if self._mode is None:
            self._head += chunk
            if len(self._head) < 16:  # enough for every signature in _BINARY_MAGIC
                return
            chunk, self._head = self._head, b""
            self._decide(chunk)
        self._feed_raw(chunk)

    def finish(self) -> ParseResult:
        if self._mode is None:
            if not self._head:
                raise WordlistError("file is empty")
            head, self._head = self._head, b""
            self._decide(head)
            self._feed_raw(head)
        if self._mode == "gz" and self._gz is not None:
            raise WordlistError("truncated gzip data")
        try:
            tail = self._dec.decode(b"", final=True)
        except UnicodeDecodeError:
            raise WordlistError("file is not valid UTF-8 text", 415) from None
        self._feed_text(tail)
        if self._overlong or self._buf:
            self._line(self._buf, overlong=self._overlong)
        r = self.result
        r.sha256 = self._hash.hexdigest()
        r.size_bytes = self._received
        r.gzip = self._mode == "gz"
        if not r.accepted:
            why = ", ".join(f"{k} ({v})" for k, v in r.reasons.most_common(3))
            raise WordlistError(f"no valid entries{f' - skipped: {why}' if why else ''}", 422)
        return r

    def _decide(self, head: bytes) -> None:
        self._mode = "gz" if head[:2] == b"\x1f\x8b" else "plain"
        if self._expect_gz and self._mode != "gz":
            raise WordlistError("file has a .gz extension but is not gzip data", 415)
        if self._mode == "plain":
            _reject_magic(head)

    def _feed_raw(self, data: bytes) -> None:
        if self._mode == "plain":
            self._feed_bytes(data)
            return
        while True:  # bounded output per step; multi-member gzip supported
            if self._gz is None:
                if not data:
                    return
                self._gz = zlib.decompressobj(16 + zlib.MAX_WBITS)
            try:
                out = self._gz.decompress(data, _CHUNK)
            except zlib.error:
                raise WordlistError("corrupt gzip data", 415) from None
            self._feed_bytes(out)
            if self._gz.eof:
                data = self._gz.unused_data
                self._gz = None
                continue
            data = self._gz.unconsumed_tail
            if not data and len(out) < _CHUNK:
                return

    def _feed_bytes(self, data: bytes) -> None:
        if not data:
            return
        if not self._started_text and self._mode == "gz" and self._decompressed == 0:
            _reject_magic(data)
        self._decompressed += len(data)
        if self._decompressed > self._limits.max_decompressed_bytes:
            raise WordlistError(
                f"decompressed size exceeds the {self._limits.max_decompressed_bytes // (1024 * 1024)} MB limit", 413)
        if b"\x00" in data:
            raise WordlistError("binary content (NUL byte) is not allowed", 415)
        try:
            text = self._dec.decode(data)
        except UnicodeDecodeError:
            raise WordlistError("file is not valid UTF-8 text", 415) from None
        self._feed_text(text)

    def _feed_text(self, text: str) -> None:
        if not text:
            return
        if not self._started_text:
            self._started_text = True
            if text.startswith("\ufeff"):
                text = text[1:]
        start = 0
        while True:
            nl = text.find("\n", start)
            if nl < 0:
                if not self._overlong:
                    self._buf += text[start:]
                    if len(self._buf) > MAX_LINE_CHARS:
                        self._overlong, self._buf = True, ""
                return
            if self._overlong:
                self._line("", overlong=True)
            else:
                line = self._buf + text[start:nl]
                self._line(line, overlong=len(line) > MAX_LINE_CHARS)
            self._buf, self._overlong = "", False
            start = nl + 1

    def _line(self, raw: str, *, overlong: bool = False) -> None:
        self._line_no += 1
        if raw.endswith("\r"):
            raw = raw[:-1]
        stripped = raw.strip(" \t")
        if not overlong and (not stripped or stripped.startswith("#")):
            return
        self._candidates += 1
        if self._candidates > self._limits.max_entries:
            raise WordlistError(f"more than {self._limits.max_entries:,} entries", 413)
        value, reason = (None, "line too long") if overlong else self._normalize(raw)
        if value is not None and value in self._seen:
            value, reason = None, "duplicate"
        r = self.result
        if value is None:
            r.skipped += 1
            r.reasons[reason or "invalid"] += 1
            if len(r.samples) < MAX_SAMPLES:
                r.samples.append(f"line {self._line_no}: {reason}")
            return
        self._seen.add(value)
        self._out.write(value + "\n")
        r.accepted += 1


def _reject_magic(head: bytes) -> None:
    for magic, what in _BINARY_MAGIC:
        if head.startswith(magic):
            raise WordlistError(f"{what} files are not accepted; upload a plain text wordlist", 415)


# --- storage ----------------------------------------------------------------------------------
def wordlists_dir() -> Path:
    d = get_settings().data_path / "wordlists"
    d.mkdir(parents=True, exist_ok=True)
    return d


def stored_path(storage_name: str) -> Path:
    """Path of a stored list; the name is always server-generated, never a user path."""
    if not STORAGE_RE.fullmatch(storage_name or ""):
        raise WordlistError("invalid storage name", 500)
    return wordlists_dir() / storage_name


def remove_stored(storage_name: str) -> None:
    try:
        stored_path(storage_name).unlink(missing_ok=True)
    except (OSError, WordlistError):
        pass


def ingest(chunks: Iterable[bytes], *, kind: str, expect_gz: bool | None,
           limits: Limits | None = None) -> tuple[str, ParseResult]:
    """Parse a byte stream into a new stored file. Returns (storage name, result); nothing is kept on error."""
    if kind not in KINDS:
        raise WordlistError(f"type must be one of {', '.join(KINDS)}", 422)
    limits = limits or Limits.from_settings()
    d = wordlists_dir()
    tmp = d / f".{uuid.uuid4().hex}.part"
    try:
        with tmp.open("w", encoding="utf-8", newline="\n") as out:
            parser = _StreamParser(kind, limits, out, expect_gz)
            for chunk in chunks:
                parser.feed(chunk)
            result = parser.finish()
        name = f"{uuid.uuid4().hex}.txt"
        os.replace(tmp, d / name)
        return name, result
    finally:
        tmp.unlink(missing_ok=True)
        close = getattr(chunks, "close", None)
        if close:
            close()


def iter_file(fh, chunk: int = _CHUNK) -> Iterator[bytes]:
    while data := fh.read(chunk):
        yield data


# --- SSRF-safe URL import ---------------------------------------------------------------------
def validate_url(url: str, allow_http: bool) -> tuple[str, str, int]:
    """(scheme, host, port) of an acceptable import URL, else WordlistError."""
    u = (url or "").strip()
    if not u or len(u) > 2048 or _CTRL.search(u) or " " in u:
        raise WordlistError("invalid URL", 422)
    parts = urlsplit(u)
    allowed = ("https", "http") if allow_http else ("https",)
    if parts.scheme.lower() not in allowed:
        raise WordlistError("only https:// URLs are allowed" if not allow_http else "only http(s):// URLs are allowed", 422)
    if "@" in parts.netloc:
        raise WordlistError("credentials in the URL are not allowed", 422)
    host = (parts.hostname or "").strip()
    if not host:
        raise WordlistError("URL must include a host", 422)
    try:
        port = parts.port or (443 if parts.scheme.lower() == "https" else 80)
    except ValueError:
        raise WordlistError("invalid port in URL", 422) from None
    return parts.scheme.lower(), host, port


def resolve_host(host: str, port: int) -> list[str]:
    try:
        return [str(ipaddress.ip_address(host))]
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    except (OSError, UnicodeError):
        raise WordlistError(f"cannot resolve host {host}") from None
    out: list[str] = []
    for info in infos:
        ip = str(info[4][0]).split("%", 1)[0]
        if ip not in out:
            out.append(ip)
    if not out:
        raise WordlistError(f"cannot resolve host {host}")
    return out


def is_blocked_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return True
    if addr.version == 6 and addr.ipv4_mapped:
        addr = addr.ipv4_mapped
    if any(addr in net for net in BLOCKED_NETWORKS if net.version == addr.version):
        return True
    return not addr.is_global or addr.is_multicast or addr.is_reserved or addr.is_unspecified


def _checked_ip(host: str, port: int, resolver: Callable[[str, int], list[str]]) -> str:
    ips = resolver(host, port)
    bad = [ip for ip in ips if is_blocked_ip(ip)]
    if bad or not ips:
        raise WordlistError(f"{host} resolves to a blocked address ({bad[0] if bad else 'none'}); "
                            "private, loopback, link-local and metadata ranges are refused", 422)
    return ips[0]


def fetch_url(url: str, limits: Limits | None = None, *,
              resolver: Callable[[str, int], list[str]] = resolve_host,
              transport: httpx.BaseTransport | None = None) -> Iterator[bytes]:
    """Stream the body of ``url``. Every hop is validated and resolved, and the connection is pinned to
    the checked address (no second DNS lookup), so a rebinding or redirect cannot reach a blocked range."""
    limits = limits or Limits.from_settings()
    deadline = time.monotonic() + FETCH_DEADLINE_S
    current = url.strip()
    with httpx.Client(transport=transport, timeout=httpx.Timeout(READ_TIMEOUT_S, connect=CONNECT_TIMEOUT_S),
                      follow_redirects=False, trust_env=False) as client:
        for _hop in range(MAX_REDIRECTS + 1):
            scheme, host, port = validate_url(current, limits.allow_http)
            ip = _checked_ip(host, port, resolver)
            parts = urlsplit(current)
            ip_host = f"[{ip}]" if ":" in ip else ip
            target = urlunsplit((scheme, f"{ip_host}:{port}", parts.path or "/", parts.query, ""))
            headers = {"Host": parts.netloc, "Accept-Encoding": "identity", "User-Agent": "PortReveal-Wordlists/1.0"}
            extensions = {"sni_hostname": host} if scheme == "https" else {}
            try:
                resp = client.send(client.build_request("GET", target, headers=headers, extensions=extensions),
                                   stream=True)
            except httpx.TimeoutException:
                raise WordlistError("the server did not answer in time", 504) from None
            except httpx.HTTPError as exc:
                raise WordlistError(f"download failed: {exc.__class__.__name__}", 502) from None
            try:
                if resp.status_code in (301, 302, 303, 307, 308):
                    location = resp.headers.get("location")
                    if not location:
                        raise WordlistError("redirect without a Location header", 502)
                    current = urljoin(current, location)
                    continue
                if resp.status_code != 200:
                    raise WordlistError(f"the server answered HTTP {resp.status_code}", 502)
                declared = resp.headers.get("content-length")
                if declared and declared.isdigit() and int(declared) > limits.max_upload_bytes:
                    raise WordlistError(f"file exceeds the {limits.max_upload_bytes // (1024 * 1024)} MB limit", 413)
                try:
                    for chunk in resp.iter_raw(_CHUNK):
                        if time.monotonic() > deadline:
                            raise WordlistError("download took too long", 504)
                        yield chunk
                except httpx.TimeoutException:
                    raise WordlistError("the server did not answer in time", 504) from None
                except httpx.HTTPError as exc:
                    raise WordlistError(f"download failed: {exc.__class__.__name__}", 502) from None
                return
            finally:
                resp.close()
        raise WordlistError(f"too many redirects (max {MAX_REDIRECTS})", 502)


def redact_url(url: str) -> str:
    """The URL without user:password, for logs and audit (refused URLs may carry credentials)."""
    try:
        parts = urlsplit(url)
        return urlunsplit(parts._replace(netloc=parts.netloc.rsplit("@", 1)[-1]))
    except ValueError:
        return "<invalid URL>"


def url_filename(url: str) -> str:
    return urlsplit(url).path.rsplit("/", 1)[-1]


# --- legacy "Discovery wordlist file" setting -------------------------------------------------
def import_legacy_file(raw_path: str) -> tuple[str, ParseResult, str] | None:
    """Import the old free-text setting's file: (storage name, result, display name), or None if unusable."""
    raw_path = (raw_path or "").strip()
    if not raw_path:
        return None
    path = Path(raw_path)
    if not path.is_absolute():
        path = get_settings().data_path / path
    if not path.is_file():
        return None
    try:
        expect_gz = expects_gzip(path.name, require_ext=False)
    except WordlistError:
        expect_gz = None  # the old setting accepted any name; content checks still apply
    try:
        with path.open("rb") as fh:
            name, result = ingest(iter_file(fh), kind=KIND_PATHS, expect_gz=expect_gz)
    except (OSError, WordlistError):
        return None
    return name, result, name_from_filename(path.name)
