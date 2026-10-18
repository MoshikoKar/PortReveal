"""Fixed allow-list of safe/discovery NSE scripts for the background vulnerability pipeline
(spec section 8.4). Hard-coded, never read from user settings, so a dangerous script can never be
smuggled in through the settings API: every name here was checked against four rules before being
added (8.4.1) --

1. category is `safe` or `default`/`discovery`, never `intrusive`/`brute`/`dos`/`exploit`/`external`.
2. never calls out to an external service (no `vulners`, no `exploitdb`, no external `http.request`).
3. only runs against the port/service that justifies it (e.g. `smb-*` only when 445 is open).
4. light: few packets, no password guessing, no range scanning.

`ssl-enum-ciphers` is deliberately excluded (`intrusive`, slow). `vulners` is excluded (calls out).
Whole-category scripts (`--script=vuln`, `--script=safe`) are never used -- only explicit names.
"""
from __future__ import annotations

from dataclasses import dataclass

# Trigger kinds: "port" (specific TCP ports or service names), "tls" (tunnel=ssl or an
# ssl/https-flavoured service), "http" (any HTTP(S) service; the script itself no-ops without NTLM).
PORT_TRIGGER = "port"
TLS_TRIGGER = "tls"
HTTP_TRIGGER = "http"


@dataclass(frozen=True)
class AllowedScript:
    name: str
    trigger: str
    ports: tuple[int, ...] = ()
    services: tuple[str, ...] = ()
    note: str = ""


SCRIPT_ALLOWLIST: tuple[AllowedScript, ...] = (
    AllowedScript("smb-vuln-ms17-010", PORT_TRIGGER, ports=(445,), note="EternalBlue, local check only"),
    AllowedScript("smb-double-pulsar-backdoor", PORT_TRIGGER, ports=(445,), note="known backdoor detection"),
    AllowedScript("ssl-heartbleed", TLS_TRIGGER, note="Heartbleed"),
    AllowedScript("ssl-ccs-injection", TLS_TRIGGER, note="CCS injection"),
    AllowedScript("ssl-poodle", TLS_TRIGGER, note="POODLE"),
    AllowedScript("ssl-dh-params", TLS_TRIGGER, note="weak Diffie-Hellman parameters"),
    AllowedScript("sslv2", TLS_TRIGGER, note="legacy SSLv2 protocol"),
    AllowedScript("tls-ticketbleed", TLS_TRIGGER, note="Ticketbleed"),
    AllowedScript("ssh2-enum-algos", PORT_TRIGGER, ports=(22,), services=("ssh",), note="weak SSH algorithms"),
    AllowedScript("smb2-security-mode", PORT_TRIGGER, ports=(445,), note="is SMB signing required"),
    AllowedScript("smb-protocols", PORT_TRIGGER, ports=(445,), note="supported SMB versions"),
    AllowedScript("smb2-capabilities", PORT_TRIGGER, ports=(445,), note="SMB2 capabilities"),
    AllowedScript("smb-os-discovery", PORT_TRIGGER, ports=(445,), note="precise Windows OS (feeds section 3)"),
    AllowedScript("rdp-ntlm-info", PORT_TRIGGER, ports=(3389,), note="NTLM / Windows version"),
    AllowedScript("http-ntlm-info", HTTP_TRIGGER, note="NTLM details"),
    AllowedScript("rdp-enum-encryption", PORT_TRIGGER, ports=(3389,), note="RDP encryption level"),
    AllowedScript("ftp-anon", PORT_TRIGGER, ports=(21,), note="anonymous FTP access"),
    AllowedScript("mysql-info", PORT_TRIGGER, ports=(3306,), services=("mysql",)),
    AllowedScript("ms-sql-info", PORT_TRIGGER, ports=(1433,), services=("ms-sql-s",)),
    AllowedScript("redis-info", PORT_TRIGGER, ports=(6379,), services=("redis",)),
    AllowedScript("mongodb-info", PORT_TRIGGER, ports=(27017,), services=("mongodb",)),
    AllowedScript("vnc-info", PORT_TRIGGER, ports=(5900,), services=("vnc",)),
)

SCRIPT_NAMES: frozenset[str] = frozenset(s.name for s in SCRIPT_ALLOWLIST)

MIN_SCRIPT_TIMEOUT_S = 10
MAX_SCRIPT_TIMEOUT_S = 60
DEFAULT_SCRIPT_TIMEOUT_S = 30

# A small, explicit subset of the allow-list maps directly to one well-known CVE when the script's
# own output reports a positive finding. Everything else in the allow-list is discovery-only
# (strengthens a CPE match or feeds OS detection) and never creates a vulnerability finding by itself.
SCRIPT_CVE_MAP: dict[str, str] = {
    "smb-vuln-ms17-010": "CVE-2017-0144",
    "ssl-heartbleed": "CVE-2014-0160",
    "ssl-poodle": "CVE-2014-3566",
    "ssl-ccs-injection": "CVE-2014-0224",
    "tls-ticketbleed": "CVE-2016-9244",
}

_TLS_SERVICE_HINTS = ("ssl", "https", "tls")


def scripts_for_port(port: int, service: str | None, tunnel: str | None) -> list[str]:
    """Allow-listed script names applicable to one open port, from its port/service/tunnel alone."""
    svc = (service or "").lower()
    is_tls = tunnel == "ssl" or any(h in svc for h in _TLS_SERVICE_HINTS)
    is_http = svc in ("http", "https", "http-proxy", "http-alt")
    names = []
    for s in SCRIPT_ALLOWLIST:
        if s.trigger == PORT_TRIGGER and (port in s.ports or svc in s.services):
            names.append(s.name)
        elif s.trigger == TLS_TRIGGER and is_tls:
            names.append(s.name)
        elif s.trigger == HTTP_TRIGGER and is_http:
            names.append(s.name)
    return names
