"""Subdomain inventory: server-side paging / sort / filters, the counters endpoint, the subdomain detail page
(records history, events, linked devices), the device page's domain names and the private vs
configured-network finding split. No network access: rows are written directly."""
from __future__ import annotations

from datetime import timedelta

import pytest

from app.core.domains.classify import compute_flags, exposed_publicly, is_private_ip
from app.db import utcnow
from app.models import (
    Device,
    DevicePort,
    DomainScan,
    Event,
    Subdomain,
    SubdomainObservation,
)
from app.netutils import AddressSet
from tests.test_domains import client, csrf, make_domain  # noqa: F401  (client is a pytest fixture)


def _seed(db, n: int = 7):
    d = make_domain(db)
    now = utcnow()
    rows = []
    for i in range(n):
        exposure = ("external", "internal", "both")[i % 3]
        rows.append(Subdomain(
            domain_id=d.id, name=f"h{i:02d}.example.com", exposure=exposure, sources=["passive"],
            wildcard=i == 4, flags=["private_ip_public"] if i == 2 else [], status="gone" if i == 6 else "active",
            ips=[f"198.51.100.{i + 1}"], hosting=[], records={}, first_seen=now, last_seen=now - timedelta(hours=i),
        ))
    db.add_all(rows)
    db.commit()
    return d, rows


def test_subdomains_paged_sorted_and_filtered_server_side(client, db):  # noqa: F811
    d, _ = _seed(db)
    url = f"/api/domains/{d.id}/subdomains"

    page1 = client.get(url, params={"page_size": 2, "page": 1}).json()
    page3 = client.get(url, params={"page_size": 2, "page": 3}).json()
    assert page1["total"] == 6  # gone row excluded by the default status filter
    assert [s["name"] for s in page1["items"]] == ["h00.example.com", "h01.example.com"]
    assert [s["name"] for s in page3["items"]] == ["h04.example.com", "h05.example.com"]

    newest_last = client.get(url, params={"sort": "last_seen", "page_size": 3}).json()["items"]
    assert [s["name"] for s in newest_last] == ["h05.example.com", "h04.example.com", "h03.example.com"]

    external = client.get(url, params={"exposure": "external"}).json()
    assert external["total"] == 2 and {s["exposure"] for s in external["items"]} == {"external"}
    assert [s["name"] for s in client.get(url, params={"flag": "private_ip_public"}).json()["items"]] == ["h02.example.com"]
    assert client.get(url, params={"flag": "internal_ip_public"}).json()["total"] == 0
    assert [s["name"] for s in client.get(url, params={"wildcard": "true"}).json()["items"]] == ["h04.example.com"]
    assert [s["name"] for s in client.get(url, params={"q": "198.51.100.4"}).json()["items"]] == ["h03.example.com"]
    assert client.get(url, params={"status": "all"}).json()["total"] == 7
    assert client.get(url, params={"flag": "bogus"}).status_code == 422


def test_counts_endpoint_is_independent_of_the_page(client, db):  # noqa: F811
    d, _ = _seed(db)
    counts = client.get(f"/api/domains/{d.id}/subdomains/counts").json()
    # Active rows only: h00..h05 -> external 0,3 / internal 1,4 / both 2,5; one wildcard (h04)
    assert counts == {"active": 6, "external": 2, "internal": 2, "both": 2, "unresolved": 0, "wildcard": 1}
    assert client.get(f"/api/domains/{d.id}").json()["counts"] == counts
    assert client.get("/api/domains/999/subdomains/counts").status_code == 404


def test_subdomain_detail_history_and_events(client, db):  # noqa: F811
    d, rows = _seed(db, n=2)
    s = rows[0]
    j1 = DomainScan(domain_id=d.id, status="completed", finished_at=utcnow() - timedelta(days=1))
    j2 = DomainScan(domain_id=d.id, status="completed", finished_at=utcnow())
    db.add_all([j1, j2])
    db.flush()
    db.add_all([
        SubdomainObservation(domain_scan_id=j1.id, subdomain_id=s.id, name=s.name, exposure="external",
                             records={"public": {"a": ["198.51.100.9"], "aaaa": [], "cname": []}}, ips=["198.51.100.9"]),
        SubdomainObservation(domain_scan_id=j2.id, subdomain_id=s.id, name=s.name, exposure="external",
                             records={"public": {"a": ["198.51.100.1"], "aaaa": [], "cname": []}}, ips=["198.51.100.1"]),
        Event(event_type="subdomain_ip_changed", severity="medium", message="ip changed", domain_id=d.id,
              domain_scan_id=j2.id, hostname=s.name, old_value="198.51.100.9", new_value="198.51.100.1"),
        Event(event_type="subdomain_new", severity="info", message="other", domain_id=d.id, hostname=rows[1].name),
    ])
    s.last_scan_id = j2.id
    db.commit()
    base = f"/api/domains/{d.id}/subdomains/{s.id}"

    detail = client.get(base).json()
    assert detail["name"] == s.name and detail["domain_name"] == "example.com"
    assert detail["first_seen"] and detail["last_verified_at"]
    assert detail["devices"] == [] and detail["web_pages"] == []
    assert detail["last_scan"]["id"] == j2.id

    hist = client.get(f"{base}/history").json()
    assert hist["total"] == 2
    assert [h["scan_id"] for h in hist["items"]] == [j2.id, j1.id]
    assert hist["items"][1]["records"]["public"]["a"] == ["198.51.100.9"]

    ev = client.get(f"{base}/events").json()
    assert [e["event_type"] for e in ev["items"]] == ["subdomain_ip_changed"]

    # A subdomain id is only found under its own domain
    other = make_domain(db, name="example.org")
    assert client.get(f"/api/domains/{other.id}/subdomains/{s.id}").status_code == 404


def test_device_link_and_device_domain_names(client, db):  # noqa: F811
    d, rows = _seed(db, n=2)
    s = rows[0]
    s.ips = ["192.0.2.10", "198.51.100.1"]
    s.hosting = [{"ip": "192.0.2.10", "kind": "network", "network": "Lab", "device_uuid": None, "device_label": None,
                  "asn": None, "as_org": None}]
    dev = Device(current_ip="192.0.2.10", hostname="web01.example.com")
    db.add(dev)
    db.flush()
    db.add(DevicePort(device_id=dev.id, protocol="tcp", port=443, is_open=True, service="https"))
    db.add(DevicePort(device_id=dev.id, protocol="tcp", port=23, is_open=False, service="telnet"))
    db.commit()

    detail = client.get(f"/api/domains/{d.id}/subdomains/{s.id}").json()
    assert detail["device_uuid"] == dev.uuid
    assert detail["hosting"][0]["device_uuid"] == dev.uuid  # linked live, though the scan stored none
    [linked] = detail["devices"]
    assert (linked["uuid"], linked["label"], linked["ip"]) == (dev.uuid, "web01.example.com", "192.0.2.10")
    assert linked["open_ports_count"] == 1 and linked["vulnerabilities"] == 0
    assert [(p["port"], p["is_open"]) for p in detail["ports"]] == [(23, False), (443, True)]
    listed = client.get(f"/api/domains/{d.id}/subdomains").json()["items"]
    assert next(x for x in listed if x["id"] == s.id)["hosting"][0]["device_uuid"] == dev.uuid

    names = client.get(f"/api/devices/{dev.uuid}/domain-names").json()
    assert [(n["name"], n["domain_name"], n["domain_id"]) for n in names] == [(s.name, "example.com", d.id)]
    assert client.get("/api/devices/no-such-device/domain-names").status_code == 404


def test_finding_split_private_vs_configured_network_public_ip():
    in_lab = AddressSet.from_specs("203.0.113.0/24").__contains__
    # RFC1918 in the public answer: private IP in public DNS only
    assert compute_flags(["passive"], "external", [], ["10.1.2.3"], in_lab) == ["private_ip_public"]
    # Public address inside a configured network: internal network IP only
    assert compute_flags(["passive"], "external", [], ["203.0.113.7"], in_lab) == ["internal_ip_public"]
    # Both kinds in one answer
    assert compute_flags(["passive"], "external", [], ["10.1.2.3", "203.0.113.7"], in_lab) == [
        "private_ip_public", "internal_ip_public"]
    # A public address outside every configured network: nothing
    assert compute_flags(["passive"], "external", [], ["198.51.100.7"], in_lab) == []
    # Both still count as exposed (alerts unchanged)
    assert exposed_publicly(["internal_ip_public"]) and exposed_publicly(["private_ip_public"])
    # AXFR name answered publicly with a configured-network address -> internal name exposed too
    assert compute_flags(["axfr", "passive"], "both", ["203.0.113.7"], ["203.0.113.7"], in_lab) == [
        "internal_ip_public", "internal_name_exposed"]


@pytest.mark.parametrize("ip,private", [
    ("::ffff:10.1.2.3", True),        # IPv4-mapped IPv6: judged by the IPv4 part
    ("::ffff:192.168.0.10", True),
    ("::ffff:127.0.0.1", True),
    ("::ffff:198.51.100.7", False),
    ("100.64.0.1", True),             # CGNAT
    ("100.127.255.254", True),
    ("100.128.0.1", False),           # just outside CGNAT
    ("fd12:3456::1", True),           # ULA
    ("fc00::1", True),
    ("127.0.0.1", True),              # loopback
    ("::1", True),
    ("169.254.10.1", True),           # link-local / multicast stay private (not reachable as a public service)
    ("fe80::1", True),
    ("224.0.0.251", True),
    ("198.51.100.7", False),          # public (documentation ranges stand in for public addresses)
    ("2001:db8::1", False),
    ("not-an-ip", False),
])
def test_private_ip_classification(ip, private):
    assert is_private_ip(ip) is private
    # The finding follows the same rule
    assert (compute_flags(["passive"], "external", [], [ip], None) == ["private_ip_public"]) is private
