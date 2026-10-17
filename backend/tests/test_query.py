"""Inventory query language: parser, SQL semantics (same-service AND, negation), facets, history."""
from __future__ import annotations

import pytest
from sqlalchemy import select

from app.core.query.history import host_match
from app.core.query.parser import And, Not, Or, QueryError, Term, parse
from app.core.query.search import count, facets, parse_facets, prepare, search_hosts, search_services
from app.models import DeviceProfile, DeviceTag, PortHttp

from .helpers import ScriptedScanner, device_by_ip, host, make_network, port, scan


# --- parser --------------------------------------------------------------------------------------
def test_parser_precedence_and_negation():
    node = parse('port:443 product:nginx OR -tag:lab "web portal"')
    assert isinstance(node, Or)
    left, right = node.children
    assert isinstance(left, And) and [t.field for t in left.children] == ["port", "product"]
    assert isinstance(right, And)
    assert isinstance(right.children[0], Not)
    assert right.children[1] == Term(None, "web portal", True, right.children[1].pos)


def test_parser_operators_and_quotes():
    t = parse('product:="Apache httpd"')
    assert t.op == "=" and t.value == "Apache httpd" and t.quoted
    t = parse("score:>=60")
    assert t.op == ">=" and t.value == "60"
    assert parse("") is None and parse("   ") is None


@pytest.mark.parametrize("bad", ['title:"open', "port:", "(port:22", "port:22)", "()", "-"])
def test_parser_errors(bad):
    if bad == "-":  # a lone dash is free text, not an error
        assert parse(bad) == Term(None, "-", False, 0)
        return
    with pytest.raises(QueryError):
        parse(bad)


def test_validation_rejects_unknown_fields_and_values():
    with pytest.raises(QueryError, match="unknown field"):
        prepare("nosuch:1")
    with pytest.raises(QueryError, match="number"):
        prepare("port:abc")
    with pytest.raises(QueryError, match="duration"):
        prepare("first_seen:soon")
    with pytest.raises(QueryError, match="has: value"):
        prepare("has:wings")
    with pytest.raises(QueryError, match="too long"):
        prepare("a" * 2000)


# --- SQL semantics ---------------------------------------------------------------------------------
@pytest.fixture
def inventory(db):
    net = make_network(db)
    scanner = ScriptedScanner([
        host("10.0.0.10", [port(22, "ssh", "OpenSSH", "8.9p1"), port(443, "https", "nginx", "1.24.0")],
             mac="02:00:00:00:00:10", hostname="web01"),
        host("10.0.0.11", [port(443, "https", "Apache httpd", "2.4.57"), port(8080, "http", "nginx", "1.22")],
             mac="02:00:00:00:00:11", hostname="web02"),
        host("10.0.0.12", [port(3389, "ms-wbt-server", "Microsoft Terminal Services")],
             mac="02:00:00:00:00:12", hostname="ws-finance"),
        host("10.0.0.13", [], mac="02:00:00:00:00:13", hostname="printer"),
    ])
    scan(scanner, network_id=net.id)
    db.expire_all()
    web01, web02 = device_by_ip(db, "10.0.0.10"), device_by_ip(db, "10.0.0.11")
    p443 = next(p for p in web01.ports if p.port == 443)
    db.add(PortHttp(device_port_id=p443.id, device_id=web01.id, scheme="https", status=302,
                    location="https://web01/login", server="nginx"))
    p8080 = next(p for p in web02.ports if p.port == 8080)
    db.add(PortHttp(device_port_id=p8080.id, device_id=web02.id, scheme="http", status=200, title="Grafana",
                    login=True))
    db.add(DeviceTag(device_id=web02.id, tag="lab", source="manual"))
    printer = device_by_ip(db, "10.0.0.13")
    # the post-scan step already tagged it from its hostname and created its profile
    assert printer.device_type == "printer" and {t.tag for t in printer.tags} == {"printer"}
    profile = db.scalar(select(DeviceProfile).where(DeviceProfile.device_id == printer.id))
    profile.owner, profile.notes = "alice", "HP LaserJet M507"
    printer.exposure_score = 5
    web01.exposure_score = 70
    db.commit()
    return net


def ips(db, q: str, **kw) -> list[str]:
    return sorted(h["ip"] for h in search_hosts(db, prepare(q), page_size=100, **kw).items)


def test_port_terms_must_match_the_same_service(db, inventory):
    # web02 has 443 (Apache) and 8080 (nginx): no single service is nginx on 443
    assert ips(db, "port:443 product:nginx") == ["10.0.0.10"]
    assert ips(db, "port:443 product:apache") == ["10.0.0.11"]
    assert ips(db, "(port:443 OR port:8080) product:nginx") == ["10.0.0.10", "10.0.0.11"]


def test_negation_semantics(db, inventory):
    # a lone negated port term means "host without"
    assert ips(db, "-port:443") == ["10.0.0.12", "10.0.0.13"]
    # with a positive port partner it narrows that same service
    assert ips(db, "port:443 -product:nginx") == ["10.0.0.11"]
    assert ips(db, "-tag:lab port:443") == ["10.0.0.10"]
    # NULL columns never make a row "unknown": hosts without an owner are not hidden by -owner:x
    assert "10.0.0.10" in ips(db, "-owner:alice")


def test_host_fields_lists_ranges_and_wildcards(db, inventory):
    assert ips(db, "port:22,3389") == ["10.0.0.10", "10.0.0.12"]
    assert ips(db, "port:4000-9000") == ["10.0.0.11"]
    assert ips(db, "hostname:web*") == ["10.0.0.10", "10.0.0.11"]
    assert ips(db, "net:10.0.0.8/30") == ["10.0.0.10", "10.0.0.11"]
    assert ips(db, "ip:10.0.0.1?") == ["10.0.0.10", "10.0.0.11", "10.0.0.12", "10.0.0.13"]
    assert ips(db, "score:>=60") == ["10.0.0.10"]
    assert ips(db, "network:\"Test Net\" type:printer") == ["10.0.0.13"]
    assert ips(db, "notes:laserjet owner:alice") == ["10.0.0.13"]
    assert ips(db, "new:1d") == ["10.0.0.10", "10.0.0.11", "10.0.0.12", "10.0.0.13"]
    assert ips(db, "first_seen:>30d") == []


def test_ip_assignment_and_rtt_fields(db, inventory):
    web01, web02 = device_by_ip(db, "10.0.0.10"), device_by_ip(db, "10.0.0.11")
    web01.ip_assignment, web01.last_rtt_ms = "static", 2.5
    web02.ip_assignment, web02.last_rtt_ms = "dynamic", 40.0
    db.commit()
    assert ips(db, "ip_assignment:static") == ["10.0.0.10"]
    assert ips(db, "ip_assignment:dynamic") == ["10.0.0.11"]
    assert ips(db, "rtt:<10") == ["10.0.0.10"]
    assert ips(db, "rtt:>=10") == ["10.0.0.11"]
    with pytest.raises(QueryError, match="number"):
        prepare("rtt:fast")


def test_http_and_has_fields(db, inventory):
    assert ips(db, "http.title:grafana http.login:true") == ["10.0.0.11"]
    assert ips(db, "http.status:300-399 http.location:/login") == ["10.0.0.10"]
    assert ips(db, "has:http") == ["10.0.0.10", "10.0.0.11"]
    assert ips(db, "has:owner") == ["10.0.0.13"]
    assert ips(db, "has:login") == ["10.0.0.11"]
    assert ips(db, "-has:port") == ["10.0.0.13"]
    assert ips(db, "port:*") == ["10.0.0.10", "10.0.0.11", "10.0.0.12"]


def test_free_text_matches_hosts_and_services(db, inventory):
    assert ips(db, "finance") == ["10.0.0.12"]
    assert ips(db, "grafana") == ["10.0.0.11"]
    assert ips(db, "3389") == ["10.0.0.12"]
    assert ips(db, "02:00:00:00:00:13") == ["10.0.0.13"]


def test_results_show_matching_services_and_sort(db, inventory):
    page = search_hosts(db, prepare("port:443"), page_size=10, sort="score")
    assert page.total == 2
    assert page.items[0]["ip"] == "10.0.0.10"  # highest score first
    assert [s["port"] for s in page.items[0]["services"]] == [443]
    assert page.items[0]["services"][0]["http"]["status"] == 302
    svc = search_services(db, prepare("product:nginx"), page_size=10)
    assert svc.total == 2 and {s["port"] for s in svc.items} == {443, 8080}


def test_facets_and_count(db, inventory):
    node = prepare("port:443")
    out = facets(db, node, parse_facets("port,product,tag,http.server,net"))
    assert out["port"] == [{"value": "443/tcp", "count": 2, "term": "port:443"}]
    assert {f["value"] for f in out["product"]} == {"nginx", "Apache httpd"}
    assert out["product"][0]["term"].startswith("product:=")
    assert out["http.server"][0]["value"] == "nginx"
    assert out["net"] == [{"value": "10.0.0.0/24", "count": 2, "term": "net:10.0.0.0/24"}]
    # facet terms are valid queries that narrow the result
    assert ips(db, f"port:443 {out['product'][0]['term']}") in (["10.0.0.10"], ["10.0.0.11"])
    assert count(db, node) == {"hosts": 2, "services": 2}
    with pytest.raises(QueryError):
        parse_facets("nosuch")


def test_history_evaluator_mirrors_sql_semantics():
    h = {"ip": "10.0.0.11", "mac": None, "hostname": "web02", "status": "active", "network": "Net",
         "tags": ["lab"], "type": None, "score": 3,
         "ports": [{"port": 443, "proto": "tcp", "service": "https", "product": "Apache httpd", "version": "2.4"},
                   {"port": 8080, "proto": "tcp", "service": "http", "product": "nginx", "version": "1.22"}]}
    assert not host_match(parse("port:443 product:nginx"), h)
    assert host_match(parse("port:443 -product:nginx"), h)
    assert not host_match(parse("-port:443"), h)
    assert host_match(parse("tag:lab net:10.0.0.0/24"), h)
    assert host_match(parse("nginx"), h)
