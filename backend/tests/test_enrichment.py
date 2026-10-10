"""Shodan-style enrichment: banners, TLS parse, hashes, RDP/VNC inventory, query fields."""
from __future__ import annotations

from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from app.core.banners import banner_hash, truncate_banner
from app.core.http_hashes import favicon_hash, html_hash
from app.core.query.fields import resolve
from app.core.query.search import extract_before, prepare
from app.core.tls_probe import parse_der
from app.core.web_capture.classify import looks_like_web_vnc
from app.core.web_capture.inventory import guess_scheme, is_rdp_service, is_vnc_service
from app.core.web_capture.rdp import is_rdp_service as rdp_svc
from app.core.web_capture.vnc import is_vnc_service as vnc_svc


def test_banner_truncate_and_hash():
    assert truncate_banner(None) is None
    assert truncate_banner("  hi  ") == "hi"
    long = "x" * 5000
    t = truncate_banner(long)
    assert t is not None and len(t) <= 4096 and t.endswith("…")
    assert banner_hash("a") == banner_hash("a")
    assert banner_hash("a") != banner_hash("b")


def test_favicon_mmh3_signed():
    # Empty favicon still produces a deterministic signed int
    h = favicon_hash(b"\x00\x01\x02\x03")
    assert isinstance(h, int)
    assert -2**31 <= h < 2**31
    assert html_hash("<html/>") is not None


def test_tls_parse_self_signed():
    from datetime import timedelta

    from cryptography.hazmat.primitives.serialization import Encoding

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "*.lab.local")])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=365))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("*.lab.local")]), critical=False)
        .sign(key, hashes.SHA256())
    )
    info = parse_der(cert.public_bytes(Encoding.DER))
    assert info.cn == "*.lab.local"
    assert info.self_signed is True
    assert info.wildcard is True
    assert info.fingerprint_sha256


def test_rdp_vnc_inventory_schemes():
    assert is_rdp_service("ms-wbt-server", 3389)
    assert is_vnc_service("vnc", 5900)
    assert rdp_svc("rdp", 3389)
    assert vnc_svc(None, 5901)
    assert guess_scheme("ms-wbt-server", 3389) == "rdp"
    assert guess_scheme("vnc", 5900) == "vnc"


def test_web_vnc_classify():
    assert looks_like_web_vnc("<html>noVNC</html>", "Console", None)
    assert looks_like_web_vnc(None, "Apache Guacamole", None)
    assert not looks_like_web_vnc("<html>hello</html>", "Home", None)


def test_query_fields_ssl_tls_snmp_before():
    assert resolve("ssl.cert.subject.cn") is not None
    assert resolve("has") is not None
    assert resolve("before") is not None
    assert resolve("http.favicon") is not None
    node = prepare('port:443 has:tls')
    assert node is not None
    remaining, before = extract_before(prepare("port:22 before:2026-09-01"))
    assert before is not None
    assert str(before) == "2026-08-31"
