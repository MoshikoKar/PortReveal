"""Pull TLS certificates from already-open TLS-capable ports (no auth, one handshake)."""
from __future__ import annotations

import hashlib
import logging
import socket
import ssl
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import dsa, ec, rsa
from cryptography.x509.oid import ExtensionOID, NameOID
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db import utcnow
from ..models import DevicePort, PortTls

log = logging.getLogger(__name__)

# Ports that commonly speak TLS even when nmap did not set tunnel=ssl.
TLS_PORTS = frozenset({
    443, 636, 993, 995, 465, 8443, 9443, 10443, 5986, 3389, 5061, 853, 990, 992,
})
EXPIRES_SOON_DAYS = 30
CONNECT_TIMEOUT = 4.0
BANNER_PROBE_PORTS = frozenset({3389})  # RDP also stores cert CN as identity signal


@dataclass
class CertInfo:
    cn: str | None
    san: str | None
    issuer: str | None
    not_before: datetime | None
    not_after: datetime | None
    fingerprint_sha256: str
    self_signed: bool
    expired: bool
    expires_soon: bool
    wildcard: bool
    weak: bool


def _name_cn(name: x509.Name) -> str | None:
    try:
        return name.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value  # type: ignore[return-value]
    except (IndexError, ValueError):
        return None


def _sans(cert: x509.Certificate) -> str | None:
    try:
        ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
    except x509.ExtensionNotFound:
        return None
    names = []
    for n in ext.value:  # type: ignore[attr-defined]
        names.append(str(n.value) if hasattr(n, "value") else str(n))
    return ", ".join(names) if names else None


def _weak_key(cert: x509.Certificate) -> bool:
    if cert.signature_hash_algorithm and cert.signature_hash_algorithm.name in ("sha1", "md5"):
        return True
    pub = cert.public_key()
    if isinstance(pub, rsa.RSAPublicKey) and pub.key_size < 2048:
        return True
    if isinstance(pub, dsa.DSAPublicKey) and pub.key_size < 2048:
        return True
    if isinstance(pub, ec.EllipticCurvePublicKey) and pub.curve.key_size < 224:
        return True
    return False


def parse_der(der: bytes, *, now: datetime | None = None) -> CertInfo:
    now = now or datetime.now(timezone.utc)
    cert = x509.load_der_x509_certificate(der)
    nb = cert.not_valid_before_utc if hasattr(cert, "not_valid_before_utc") else cert.not_valid_before.replace(tzinfo=timezone.utc)
    na = cert.not_valid_after_utc if hasattr(cert, "not_valid_after_utc") else cert.not_valid_after.replace(tzinfo=timezone.utc)
    cn = _name_cn(cert.subject)
    san = _sans(cert)
    issuer_cn = _name_cn(cert.issuer)
    issuer = issuer_cn or cert.issuer.rfc4514_string()
    fp = hashlib.sha256(der).hexdigest()
    self_signed = cert.subject == cert.issuer
    expired = na < now
    expires_soon = (not expired) and na < now + timedelta(days=EXPIRES_SOON_DAYS)
    names = " ".join(filter(None, [cn, san or ""]))
    wildcard = "*" in names
    return CertInfo(
        cn=cn, san=san, issuer=issuer, not_before=nb, not_after=na,
        fingerprint_sha256=fp, self_signed=self_signed, expired=expired,
        expires_soon=expires_soon, wildcard=wildcard, weak=_weak_key(cert),
    )


def fetch_cert(ip: str, port: int, *, timeout: float = CONNECT_TIMEOUT) -> CertInfo | None:
    """One TLS handshake; returns None on timeout/refusal/non-TLS."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=ip) as ssock:
                der = ssock.getpeercert(binary_form=True)
                if not der:
                    return None
                return parse_der(der)
    except (OSError, ssl.SSLError, TimeoutError, ValueError):
        return None


def port_looks_tls(p: DevicePort) -> bool:
    if not p.is_open or p.protocol != "tcp":
        return False
    if (p.tunnel or "").lower() == "ssl":
        return True
    if p.port in TLS_PORTS:
        return True
    svc = (p.service or "").lower()
    return any(x in svc for x in ("https", "ssl", "tls", "rdp", "ms-wbt", "imaps", "pop3s", "smtps", "ldaps"))


def upsert_tls(db: Session, port: DevicePort, info: CertInfo, *, now: datetime | None = None) -> PortTls:
    now = now or utcnow()
    row = db.scalar(select(PortTls).where(PortTls.device_port_id == port.id))
    if row is None:
        row = PortTls(device_port_id=port.id, device_id=port.device_id, first_seen=now)
        db.add(row)
    row.device_id = port.device_id
    row.cn = info.cn
    row.san = info.san
    row.issuer = info.issuer
    row.not_before = info.not_before
    row.not_after = info.not_after
    row.fingerprint_sha256 = info.fingerprint_sha256
    row.self_signed = info.self_signed
    row.expired = info.expired
    row.expires_soon = info.expires_soon
    row.wildcard = info.wildcard
    row.weak = info.weak
    row.last_seen = now
    return row


def enrich_device_tls(db: Session, device_id: int, ip: str, *, now: datetime | None = None) -> int:
    """Probe open TLS-looking ports on one device. Returns certs stored."""
    now = now or utcnow()
    ports = db.scalars(select(DevicePort).where(
        DevicePort.device_id == device_id, DevicePort.is_open.is_(True),
    )).all()
    n = 0
    for p in ports:
        if not port_looks_tls(p):
            continue
        info = fetch_cert(ip, p.port)
        if info is None:
            continue
        upsert_tls(db, p, info, now=now)
        n += 1
    return n
