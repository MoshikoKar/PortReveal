"""Expected-country geo mismatch: name harvest, cache, events, settings API."""
from __future__ import annotations

import gzip

import pytest
from fastapi.testclient import TestClient

from app.api.auth import limiter
from app.core.geo import (
    CDN_MISMATCH_LABEL,
    GeoRecord,
    check_devices_geo,
    harvest_published_names,
    is_public_ip,
    normalize_expected,
)
from app.core.geo_sync import COUNTRY_SOURCE, sync_geo_feeds
from app.main import app
from app.models import (
    EV_GEO_MISMATCH,
    SCAN_COMPLETED,
    SCAN_STANDARD,
    Device,
    Event,
    GeoLookupCache,
    Network,
    PortHttp,
    PortTls,
    Scan,
)

from .helpers import ScriptedScanner, device_by_ip, host, make_network, scan


@pytest.fixture
def client(db_env):
    limiter.reset()
    with TestClient(app) as c:
        yield c


def csrf(c: TestClient) -> dict:
    return {"X-CSRF-Token": c.cookies.get("nf_csrf", "")}


@pytest.fixture
def admin(client):
    assert client.post("/api/setup/admin", json={"username": "admin", "password": "correct-horse-1"}).status_code == 200
    return client


def _armed(db, net: Network) -> Network:
    """Expected countries plus a real baseline scan row so geo events notify."""
    scan_row = Scan(scan_type=SCAN_STANDARD, status=SCAN_COMPLETED, network_id=net.id)
    db.add(scan_row)
    db.flush()
    net.expected_countries = ["AA"]
    net.baseline_scan_id = scan_row.id
    db.commit()
    return net


def _device(db, net, ip="10.0.0.5", hostname="host.example.test"):
    d = Device(current_ip=ip, hostname=hostname, dns_name=hostname, network_id=net.id)
    db.add(d)
    db.commit()
    return device_by_ip(db, ip)


def test_private_and_cgnat_are_not_geolocatable():
    assert is_public_ip("10.0.0.5") is False
    assert is_public_ip("192.168.1.1") is False
    assert is_public_ip("172.16.9.9") is False
    assert is_public_ip("100.64.0.1") is False
    assert is_public_ip("127.0.0.1") is False
    assert is_public_ip("203.0.113.10") is True  # documentation range: stand-in for a public address


def test_harvest_uses_published_names_not_local_suffixes():
    d = Device(current_ip="10.0.0.5", hostname="printer.local", dns_name="host.example.test")
    http = PortHttp(location="https://app.example.test/login", title="https://title.example.test/")
    tls = PortTls(cn="web.example.test", san="DNS:api.example.test, DNS:*.cdn.example.test")
    names = harvest_published_names(d, [http], [tls])
    assert "host.example.test" in names
    assert "app.example.test" in names
    assert "web.example.test" in names
    assert "api.example.test" in names
    assert "cdn.example.test" in names
    assert "printer.local" not in names


def test_published_name_mismatch_raises_high_severity_event(db):
    net = _armed(db, make_network(db))
    d = _device(db, net)
    calls = {"dns": 0, "geo": 0}

    def resolver(name):
        calls["dns"] += 1
        assert name == "host.example.test"
        return ["203.0.113.10"]

    def lookup(ip):
        calls["geo"] += 1
        return GeoRecord(country="BB", asn=64496, as_org="Example Net")

    events = check_devices_geo(db, [d.id], resolver=resolver, lookup=lookup, ensure_dbs=False)
    db.commit()
    db.refresh(d)
    assert len(events) == 1
    assert events[0].event_type == EV_GEO_MISMATCH
    assert events[0].severity == "high"
    assert events[0].notify is True
    assert d.geo_status == "mismatch"
    assert d.geo_mismatch is True
    assert d.geo_country == "BB"
    assert d.geo_ip == "203.0.113.10"
    assert d.geo_asn == 64496
    assert d.geo_cdn is False
    assert calls["dns"] == 1

    again = check_devices_geo(db, [d.id], resolver=resolver, lookup=lookup, ensure_dbs=False)
    assert again == []
    assert calls["dns"] == 1  # cache hit


def test_cdn_mismatch_is_lower_severity_and_still_flagged(db):
    net = _armed(db, make_network(db, name="CDN Net"))
    d = _device(db, net, ip="10.0.0.6")

    def resolver(_name):
        return ["203.0.113.20"]

    def lookup(_ip):
        return GeoRecord(country="BB", asn=13335, as_org="Example CDN")

    events = check_devices_geo(db, [d.id], resolver=resolver, lookup=lookup, ensure_dbs=False)
    db.commit()
    db.refresh(d)
    assert events[0].severity == "medium"
    assert CDN_MISMATCH_LABEL in events[0].message
    assert d.geo_status == "mismatch_cdn"
    assert d.geo_mismatch is True
    assert d.geo_cdn is True


def test_allowlist_match_is_ok(db):
    net = _armed(db, make_network(db, name="Allow"))
    net.expected_countries = ["AA", "BB"]
    db.commit()
    d = _device(db, net, ip="10.0.0.7")

    events = check_devices_geo(
        db, [d.id], ensure_dbs=False,
        resolver=lambda _n: ["203.0.113.30"],
        lookup=lambda _ip: GeoRecord(country="BB"),
    )
    db.commit()
    db.refresh(d)
    assert events == []
    assert d.geo_status == "ok"
    assert d.geo_mismatch is False


def test_no_public_candidate_is_not_checked(db):
    net = _armed(db, make_network(db, name="Private only"))
    d = _device(db, net, ip="10.0.0.8", hostname=None)
    d.dns_name = None
    db.commit()
    events = check_devices_geo(
        db, [d.id], ensure_dbs=False,
        resolver=lambda _n: [],
        lookup=lambda _ip: GeoRecord(country="BB"),
    )
    db.commit()
    db.refresh(d)
    assert events == []
    assert d.geo_status == "not_checked"
    assert d.geo_mismatch is False


def test_public_device_ip_mismatch(db):
    net = _armed(db, make_network(db, name="Public IP"))
    d = _device(db, net, ip="203.0.113.40", hostname=None)
    d.dns_name = None
    db.commit()
    events = check_devices_geo(
        db, [d.id], ensure_dbs=False,
        resolver=lambda _n: [],
        lookup=lambda ip: GeoRecord(country="BB") if ip == "203.0.113.40" else None,
    )
    db.commit()
    db.refresh(d)
    assert events[0].event_type == EV_GEO_MISMATCH
    assert d.geo_source == "device_ip"
    assert d.geo_ip == "203.0.113.40"


def test_missing_db_marks_unavailable_without_crash(db):
    net = make_network(db, name="No DB")
    net.expected_countries = ["AA"]
    db.commit()
    d = _device(db, net, ip="10.0.0.9")
    events = check_devices_geo(db, [d.id], ensure_dbs=False)
    db.commit()
    db.refresh(d)
    assert events == []
    assert d.geo_status == "unavailable"


def test_silent_before_baseline(db):
    net = make_network(db, name="No baseline")
    net.expected_countries = ["AA"]
    db.commit()
    d = _device(db, net, ip="10.0.0.10")
    events = check_devices_geo(
        db, [d.id], ensure_dbs=False,
        resolver=lambda _n: ["203.0.113.50"],
        lookup=lambda _ip: GeoRecord(country="BB"),
    )
    assert events[0].notify is False


def test_network_without_expected_countries_is_skipped(db):
    net = make_network(db, name="No countries")
    db.commit()
    d = _device(db, net, ip="10.0.0.11")
    events = check_devices_geo(
        db, [d.id], ensure_dbs=False,
        resolver=lambda _n: ["203.0.113.60"],
        lookup=lambda _ip: GeoRecord(country="BB"),
    )
    db.commit()
    db.refresh(d)
    assert events == []
    assert d.geo_status is None


def test_cache_expires_and_re_resolves(db):
    from datetime import timedelta

    from app.db import utcnow

    net = _armed(db, make_network(db, name="TTL"))
    d = _device(db, net, ip="10.0.0.12")
    now = utcnow()
    calls = {"n": 0}

    def resolver(_name):
        calls["n"] += 1
        return ["203.0.113.70"]

    check_devices_geo(db, [d.id], now=now, ensure_dbs=False, resolver=resolver,
                      lookup=lambda _ip: GeoRecord(country="AA"))
    check_devices_geo(db, [d.id], now=now + timedelta(hours=1), ensure_dbs=False,
                      resolver=resolver, lookup=lambda _ip: GeoRecord(country="AA"))
    assert calls["n"] == 1
    check_devices_geo(db, [d.id], now=now + timedelta(hours=25), ensure_dbs=False,
                      resolver=resolver, lookup=lambda _ip: GeoRecord(country="AA"))
    assert calls["n"] == 2
    assert db.get(GeoLookupCache, "dns:host.example.test") is not None


def test_scan_pipeline_tags_geo_mismatch(db):
    net = _armed(db, make_network(db, name="Scan geo"))
    scanner = ScriptedScanner([host("10.0.0.13", hostname="host.example.test")])

    def resolver(_name):
        return ["203.0.113.80"]

    def lookup(_ip):
        return GeoRecord(country="BB")

    from app.core import geo as geo_mod
    orig = geo_mod.check_devices_geo

    def wrapped(db, ids, **kwargs):
        kwargs.setdefault("resolver", resolver)
        kwargs.setdefault("lookup", lookup)
        kwargs["ensure_dbs"] = False
        return orig(db, ids, **kwargs)

    geo_mod.check_devices_geo = wrapped  # type: ignore[method-assign]
    try:
        s = scan(scanner, network_id=net.id)
    finally:
        geo_mod.check_devices_geo = orig  # type: ignore[method-assign]
    from sqlalchemy import select
    types = {e.event_type for e in db.scalars(select(Event).where(Event.scan_id == s.id)).unique()}
    d = device_by_ip(db, "10.0.0.13")
    assert d.geo_mismatch is True
    assert EV_GEO_MISMATCH in types
    assert "geo-mismatch" in {t.tag for t in d.tags}


def test_geo_mismatch_search_field(db):
    from app.core.query.search import prepare, search_hosts

    net = _armed(db, make_network(db, name="Search geo"))
    d = _device(db, net, ip="10.0.0.14")
    check_devices_geo(
        db, [d.id], ensure_dbs=False,
        resolver=lambda _n: ["203.0.113.90"],
        lookup=lambda _ip: GeoRecord(country="BB"),
    )
    db.commit()
    hits = search_hosts(db, prepare("geo.mismatch:true"), page_size=100)
    assert any(h["ip"] == "10.0.0.14" for h in hits.items)


def test_normalize_expected_codes():
    assert normalize_expected(["aa", "BB", "aa", "1"]) == ["AA", "BB"]
    assert normalize_expected(None) == []


def test_geo_feed_sync_writes_files(db, tmp_path, monkeypatch):
    from app.core import geo_sync

    monkeypatch.setattr(geo_sync, "geo_dir", lambda: tmp_path)

    def fetch(url: str) -> bytes:
        assert "dbip-country-lite" in url or "dbip-asn-lite" in url
        return gzip.compress(b"M" * 70_000)

    stats = sync_geo_feeds(db, fetch=fetch)
    db.commit()
    assert COUNTRY_SOURCE in stats
    assert (tmp_path / "dbip-country-lite.mmdb").is_file()
    assert (tmp_path / "dbip-asn-lite.mmdb").is_file()


def test_network_expected_countries_roundtrip(admin):
    h = csrf(admin)
    r = admin.post("/api/networks", json={"name": "Office", "cidr": "10.20.0.0/24",
                                          "expected_countries": ["aa", "BB"]}, headers=h)
    assert r.status_code == 201
    assert r.json()["expected_countries"] == ["AA", "BB"]
    nid = r.json()["id"]
    listed = next(n for n in admin.get("/api/networks").json() if n["id"] == nid)
    assert listed["expected_countries"] == ["AA", "BB"]
    r = admin.put(f"/api/networks/{nid}", json={"name": "Office", "cidr": "10.20.0.0/24",
                                                "expected_countries": ["AA"]}, headers=h)
    assert r.json()["expected_countries"] == ["AA"]


def test_geo_settings_attribution_and_roundtrip(admin):
    body = admin.get("/api/settings/geo").json()
    assert "DB-IP" in body["attribution"]
    assert body["license"] == "CC BY 4.0"
    assert body["cache_ttl_hours"] == 24
    body["cache_ttl_hours"] = 12
    body["offline_mode"] = True
    r = admin.put("/api/settings/geo", json={
        "cache_ttl_hours": 12, "offline_mode": True,
        "maxmind_country_path": "", "cdn_asns": body["cdn_asns"],
    }, headers=csrf(admin))
    assert r.status_code == 200
    assert r.json()["cache_ttl_hours"] == 12
    assert r.json()["offline_mode"] is True
    assert admin.post("/api/settings/geo/sync", headers=csrf(admin)).status_code == 409
