"""Strict domain / host-name validation (LDH labels, IDNA punycode) and resolver-list checks.

Every name that reaches a tool command line, a temp input file or a DNS query passes through here.
"""
from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable

MAX_NAME_LEN = 253
MAX_LABEL_LEN = 63
MAX_RESOLVERS = 8
MAX_CUSTOM_WORDS = 5000

_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
# Discovered names (AXFR, passive sources) may carry service labels such as _sip; configured domains may not.
_LABEL_UNDERSCORE = re.compile(r"[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?")
_TLD = re.compile(r"[a-z]{2,63}|xn--[a-z0-9-]{1,59}")
_FORBIDDEN = set("/\\:@ %*?#&=+,;!\"'<>()[]{}|^`~$\t\r\n\x00")


class DomainError(ValueError):
    """A domain / host name / resolver that must not be used."""


def _to_ascii(s: str) -> str:
    if s.isascii():
        return s
    try:
        return s.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise DomainError("invalid internationalized name") from exc


def normalize_hostname(raw: str, *, allow_underscore: bool = False) -> str:
    """Lower-case, punycode, no trailing dot. Raises DomainError for anything that is not a
    multi-label DNS host name (IP literals, wildcards, URLs, empty labels, overlong names)."""
    if not isinstance(raw, str):
        raise DomainError("name must be text")
    if len(raw) > 1000:
        raise DomainError("name is too long")
    s = raw.strip().lower().rstrip(".")
    if not s:
        raise DomainError("name is empty")
    if any(c in _FORBIDDEN for c in s) or any(ord(c) < 32 or ord(c) == 127 for c in s):
        raise DomainError("not a host name (only letters, digits, '-' and '.')")
    s = _to_ascii(s)
    if len(s) > MAX_NAME_LEN:
        raise DomainError(f"name is longer than {MAX_NAME_LEN} characters")
    labels = s.split(".")
    if len(labels) < 2:
        raise DomainError("name needs at least two labels (for example example.com)")
    rx = _LABEL_UNDERSCORE if allow_underscore else _LABEL
    for label in labels[:-1]:
        if not label:
            raise DomainError("name has an empty label")
        if len(label) > MAX_LABEL_LEN:
            raise DomainError(f"label longer than {MAX_LABEL_LEN} characters")
        if not rx.fullmatch(label):
            raise DomainError(f"invalid label '{label}'")
    if not _TLD.fullmatch(labels[-1]):
        # Also rejects IP literals (all-numeric last label).
        raise DomainError(f"invalid top-level label '{labels[-1]}'")
    return s


def normalize_domain(raw: str) -> str:
    return normalize_hostname(raw)


def in_domain(name: str, domain: str) -> bool:
    """True when `name` is the domain itself or a name below it (label boundary, not a suffix match)."""
    return name == domain or name.endswith("." + domain)


def discovered_name(raw: object, domain: str) -> str | None:
    """A tool / AXFR result as a clean name inside `domain`, or None (dropped, never trusted)."""
    if not isinstance(raw, str):
        return None
    raw = raw.strip()
    if raw.startswith("*."):  # wildcard owner from AXFR or certificate names
        return None
    try:
        name = normalize_hostname(raw, allow_underscore=True)
    except DomainError:
        return None
    return name if in_domain(name, domain) else None


def normalize_word(raw: str) -> str | None:
    """One wordlist entry / typed label: 'dev' or 'dev.api' (relative to the domain)."""
    s = (raw or "").strip().lower().strip(".")
    if not s or any(c in _FORBIDDEN for c in s):
        return None
    try:
        s = _to_ascii(s)
    except DomainError:
        return None
    labels = s.split(".")
    if any(not lb or len(lb) > MAX_LABEL_LEN or not _LABEL_UNDERSCORE.fullmatch(lb) for lb in labels):
        return None
    return s


def normalize_words(values: Iterable[str]) -> list[str]:
    out: dict[str, None] = {}
    for v in values:
        w = normalize_word(v)
        if w is None:
            raise DomainError(f"invalid subdomain label '{str(v)[:60]}'")
        out[w] = None
    if len(out) > MAX_CUSTOM_WORDS:
        raise DomainError(f"at most {MAX_CUSTOM_WORDS} typed subdomains")
    return list(out)


def normalize_resolvers(values: Iterable[str] | None, *, field: str = "resolvers") -> list[str]:
    """IP literals only (IPv4 / IPv6), de-duplicated, at most MAX_RESOLVERS."""
    out: dict[str, None] = {}
    for raw in values or []:
        v = (raw or "").strip()
        if not v:
            continue
        try:
            out[str(ipaddress.ip_address(v))] = None
        except ValueError as exc:
            raise DomainError(f"{field}: '{v[:60]}' is not an IP address") from exc
    if len(out) > MAX_RESOLVERS:
        raise DomainError(f"{field}: at most {MAX_RESOLVERS} servers")
    return list(out)


def candidates(domain: str, words: Iterable[str], limit: int) -> list[str]:
    """Wordlist entries as names below `domain` (valid names only, at most `limit`)."""
    out: dict[str, None] = {}
    for w in words:
        word = normalize_word(w)
        if word is None:
            continue
        name = f"{word}.{domain}"
        if len(name) > MAX_NAME_LEN:
            continue
        out[name] = None
        if len(out) >= limit:
            break
    return list(out)
