"""Short, factual summaries of the kept NSE output (one line per port) and fact flags.

Every phrase here restates something the device returned to a read-only script; nothing is scored
or guessed. The raw script output stays available in the port's details for the on-click view.
"""
from __future__ import annotations

import base64
import hashlib
import re
from datetime import datetime, timezone

from .services import shown_service

_NBSTAT_NAME = re.compile(r"NetBIOS name:\s*([^,\s]+)")


def _data(scripts: dict | None, sid: str):
    return ((scripts or {}).get(sid) or {}).get("data")


def _output(scripts: dict | None, sid: str) -> str:
    return ((scripts or {}).get(sid) or {}).get("output") or ""


def _sha256_fp(key_b64: str) -> str | None:
    try:
        digest = hashlib.sha256(base64.b64decode(key_b64)).digest()
    except (ValueError, TypeError):
        return None
    return "SHA256:" + base64.b64encode(digest).decode().rstrip("=")


def _ssh_key(scripts: dict | None) -> str | None:
    keys = _data(scripts, "ssh-hostkey")
    if not isinstance(keys, list):
        return None
    order = ("ssh-ed25519", "ecdsa-sha2-nistp256", "ssh-rsa")
    keys = sorted((k for k in keys if isinstance(k, dict) and k.get("key")),
                  key=lambda k: order.index(k.get("type")) if k.get("type") in order else len(order))
    if not keys:
        return None
    fp = _sha256_fp(keys[0]["key"])
    kind = (keys[0].get("type") or "").removeprefix("ssh-").split("-")[0].upper()
    return f"key {kind} {fp[:19]}…" if fp else None


def _cert(scripts: dict | None) -> dict | None:
    data = _data(scripts, "ssl-cert")
    return data if isinstance(data, dict) else None


def _not_after(cert: dict) -> datetime | None:
    raw = ((cert.get("validity") or {}).get("notAfter") or "").strip()
    try:
        dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def cert_facts(scripts: dict | None, now: datetime | None = None) -> tuple[str | None, list[str]]:
    cert = _cert(scripts)
    if cert is None:
        return None, []
    now = now or datetime.now(timezone.utc)
    flags = []
    subject, issuer = cert.get("subject") or {}, cert.get("issuer") or {}
    if subject and subject == issuer:
        flags.append("TLS self-signed")
    end = _not_after(cert)
    if end is not None and end < now:
        flags.append("TLS expired")
    cn = subject.get("commonName") or subject.get("organizationName")
    text = "cert: " + (cn or "no subject name")
    if end is not None:
        text += (" · expired " if end < now else " · expires ") + end.strftime("%Y-%m")
    if "TLS self-signed" in flags:
        text += " · self-signed"
    return text, flags


def tls_subject_text(scripts: dict | None) -> str | None:
    cert = _cert(scripts)
    subject = (cert or {}).get("subject")
    return " ".join(str(v) for v in subject.values()) if isinstance(subject, dict) else None


def _smb(host_scripts: dict | None) -> tuple[list[str], list[str]]:
    parts, flags = [], []
    dialects = _data(host_scripts, "smb-protocols")
    dialects = dialects.get("dialects") if isinstance(dialects, dict) else None
    if isinstance(dialects, list):
        v1 = any("SMBv1" in d or "NT LM 0.12" in d for d in dialects)
        parts.append("SMBv1 on" if v1 else "SMBv1 off")
        if v1:
            flags.append("SMBv1 enabled")
    mode = _data(host_scripts, "smb2-security-mode")
    modes = [str(v).lower() for v in mode.values()] if isinstance(mode, dict) else []
    if modes:
        if any("not required" in m for m in modes):
            parts.append("signing not required")
            flags.append("SMB signing not required")
        elif any("required" in m for m in modes):
            parts.append("signing required")
    return parts, flags


def script_identity(host_scripts: dict | None, port_scripts: list[dict] | tuple = ()) -> dict[str, tuple[str, str]]:
    """Name / OS a device reported to the SMB, NetBIOS or RDP scripts: field -> (value, source)."""
    found: dict[str, tuple[str, str]] = {}

    def put(field, value, source):
        if field not in found and isinstance(value, str) and value.strip():
            found[field] = (value.strip().rstrip("\x00"), source)

    if m := _NBSTAT_NAME.search(_output(host_scripts, "nbstat")):
        put("name", m.group(1), "NetBIOS")
    smb = _data(host_scripts, "smb-os-discovery")
    if isinstance(smb, dict):
        put("name", smb.get("server"), "SMB")
        put("os", smb.get("os"), "SMB")
    for scripts in port_scripts:
        rdp = _data(scripts, "rdp-ntlm-info")
        if isinstance(rdp, dict):
            put("name", rdp.get("DNS_Computer_Name") or rdp.get("NetBIOS_Computer_Name"), "RDP")
            if rdp.get("Product_Version"):
                put("os", f"Windows build {rdp['Product_Version']}", "RDP")
    return found


def port_summary(port: int, service: str | None, method: str | None, details: dict | None,
                 host_scripts: dict | None = None) -> tuple[str | None, list[str]]:
    """(one short line, fact flags) for one open port."""
    scripts = (details or {}).get("scripts")
    parts: list[str] = []
    flags: list[str] = []
    if key := _ssh_key(scripts):
        parts.append(key)
    if port in (139, 445):
        ident = script_identity(host_scripts)
        if "name" in ident:
            parts.append(ident["name"][0])
        smb_parts, smb_flags = _smb(host_scripts)
        parts += smb_parts
        flags += smb_flags
    rdp = _data(scripts, "rdp-ntlm-info")
    if isinstance(rdp, dict):
        parts += [v for v in (rdp.get("DNS_Computer_Name"), rdp.get("Product_Version") and
                              f"build {rdp['Product_Version']}") if v]
    text, cflags = cert_facts(scripts)
    if text:
        parts.append(text)
        flags += cflags
    socks = _output(scripts, "socks-auth-info")
    if socks:
        no_auth = "no authentication" in socks.lower()
        parts.append("auth: none" if no_auth else "auth required")
        if no_auth:
            flags.append("SOCKS without auth")
    vnc = _data(scripts, "vnc-info")
    if isinstance(vnc, dict):
        sec = vnc.get("Security types")
        names = [str(k) for k in sec] if isinstance(sec, (dict, list)) else []
        no_auth = any(n.split(" (")[0].strip().lower() == "none" for n in names)
        parts.append("VNC " + str(vnc.get("Protocol version") or "").strip() + (" · auth: none" if no_auth else ""))
        if no_auth:
            flags.append("VNC without auth")
    rtsp = (details or {}).get("rtsp") or {}
    if rtsp.get("auth") == "required":
        parts.append("requires password")
    elif rtsp.get("auth") == "none":
        parts.append("stream without password")
        flags.append("RTSP without password")
    if shown_service(service, method) == "telnet":
        flags.append("Telnet open")
    return (" · ".join(p.strip() for p in parts if p and p.strip()) or None), flags


def device_flags(ports, host_scripts: dict | None) -> list[str]:
    flags: list[str] = []
    for p in ports:
        for f in port_summary(p.port, p.service, p.method, p.details, host_scripts)[1]:
            if f not in flags:
                flags.append(f)
    return flags


def is_private_mac(mac: str | None) -> bool:
    """Locally administered address (randomized / private Wi-Fi MAC): its OUI names no vendor."""
    if not mac or len(mac) < 2:
        return False
    try:
        return bool(int(mac[:2], 16) & 0x02)
    except ValueError:
        return False


def device_identity(details: dict | None, ports) -> dict[str, dict]:
    """Self-reported identity (core/selfid.py) completed by names/OS from the SMB, NetBIOS and RDP
    scripts: field -> {"value", "source"}."""
    ident = dict((details or {}).get("identity") or {})
    port_scripts = [(p.details or {}).get("scripts") for p in ports if p.details]
    for field, (value, source) in script_identity((details or {}).get("host_scripts"), port_scripts).items():
        ident.setdefault(field, {"value": value, "source": source})
    return ident
