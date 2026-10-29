"""Subdomain exposure from the linked devices' existing scan data: max scores, open ports union,
vulnerability sum / worst severity, web preview; list filters / sort on those aggregates, the domain
cards' risk summary, "Port scan now", and a fixed query count on the list endpoint. No network access."""
from __future__ import annotations

from sqlalchemy import event as sa_event
from sqlalchemy import select

from app.db import session_scope, utcnow
from app.models import (
    AuditLog,
    Device,
    DevicePort,
    DevicePortVuln,
    Scan,
    Subdomain,
    Vulnerability,
    WebCapture,
    WebPage,
)
from tests.test_domains import client, csrf, make_domain  # noqa: F401  (client is a pytest fixture)


def _sub(db, d, name: str, ips: list[str]) -> Subdomain:
    s = Subdomain(domain_id=d.id, name=name, exposure="external", sources=["passive"], ips=ips, hosting=[],
                  records={}, flags=[], status="active", first_seen=utcnow(), last_seen=utcnow())
    db.add(s)
    db.flush()
    return s


def _device(db, ip: str, *, exposure: int, risk: int | None = None, combined: int | None = None,
            open_ports=(), closed_ports=()) -> Device:
    dev = Device(current_ip=ip, hostname=f"host-{ip.rsplit('.', 1)[1]}.example.com", exposure_score=exposure,
                 risk_score=risk or 0, combined_score=combined or 0,
                 risk_scored_at=utcnow() if risk is not None else None)
    db.add(dev)
    db.flush()
    for port in open_ports:
        db.add(DevicePort(device_id=dev.id, protocol="tcp", port=port, is_open=True, service="http",
                          product="nginx", version="1.0"))
    for port in closed_ports:
        db.add(DevicePort(device_id=dev.id, protocol="tcp", port=port, is_open=False, service="telnet"))
    db.flush()
    return dev


def _vuln(db, dev: Device, port: int, cve: str, severity: str, cvss: float, state: str = "confirmed") -> None:
    if db.get(Vulnerability, cve) is None:
        db.add(Vulnerability(cve_id=cve, severity=severity, cvss_base=cvss))
    dp = db.scalar(select(DevicePort).where(DevicePort.device_id == dev.id, DevicePort.port == port))
    db.add(DevicePortVuln(device_port_id=dp.id, cve_id=cve, state=state))
    db.flush()


def _page(db, dev: Device | None, ip: str, port: int, host: str) -> None:
    cap = WebCapture(targets=ip, status="completed")
    db.add(cap)
    db.flush()
    db.add(WebPage(capture_id=cap.id, device_id=dev.id if dev else None, ip=ip, port=port, scheme="https",
                   host_used=host, url=f"https://{host}:{port}/", http_status=200, title="Example"))
    db.flush()


def _by_name(items: list[dict]) -> dict[str, dict]:
    return {s["name"]: s for s in items}


def test_aggregates_for_zero_one_and_many_linked_devices(client, db):  # noqa: F811
    d = make_domain(db)
    _sub(db, d, "none.example.com", ["198.51.100.99"])  # nothing in inventory on that address
    one = _device(db, "198.51.100.1", exposure=40, risk=70, combined=65, open_ports=[443, 8443], closed_ports=[23])
    _vuln(db, one, 443, "CVE-2026-0001", "HIGH", 8.1)
    _vuln(db, one, 443, "CVE-2026-0002", "LOW", 2.0, state="dismissed")  # dismissed: not counted
    _sub(db, d, "one.example.com", ["198.51.100.1"])
    a = _device(db, "198.51.100.2", exposure=80, open_ports=[22])  # not risk-scored yet
    b = _device(db, "198.51.100.3", exposure=20, risk=30, combined=25, open_ports=[80, 443])
    _vuln(db, a, 22, "CVE-2026-0003", "CRITICAL", 9.8)
    _vuln(db, b, 80, "CVE-2026-0004", "MEDIUM", 5.0)
    _page(db, b, "198.51.100.3", 443, "198.51.100.3")
    many = _sub(db, d, "many.example.com", ["198.51.100.2", "198.51.100.3"])
    db.commit()

    items = _by_name(client.get(f"/api/domains/{d.id}/subdomains").json()["items"])
    none = items["none.example.com"]
    assert none["linked_devices"] == 0
    assert [none[k] for k in ("exposure_score", "risk_score", "combined_score", "open_ports_count", "vulns_count",
                              "worst_severity")] == [None] * 6
    assert none["has_web_preview"] is False

    o = items["one.example.com"]
    assert (o["exposure_score"], o["risk_score"], o["combined_score"]) == (40, 70, 65)
    assert (o["open_ports_count"], o["vulns_count"], o["worst_severity"]) == (2, 1, "high")
    assert o["has_web_preview"] is False

    m = items["many.example.com"]
    assert (m["exposure_score"], m["risk_score"], m["combined_score"]) == (80, 30, 25)  # max; risk only from b
    assert (m["open_ports_count"], m["vulns_count"], m["worst_severity"]) == (3, 2, "critical")
    assert m["has_web_preview"] is True and m["web_device_uuid"] == b.uuid

    detail = client.get(f"/api/domains/{d.id}/subdomains/{many.id}").json()
    assert detail["combined_score"] == 25 and detail["open_ports_count"] == 3
    assert [(x["ip"], x["exposure_score"], x["open_ports_count"]) for x in detail["devices"]] == [
        ("198.51.100.2", 80, 1), ("198.51.100.3", 20, 2)]
    assert [(p["port"], p["ip"]) for p in detail["ports"]] == [(22, "198.51.100.2"), (80, "198.51.100.3"),
                                                              (443, "198.51.100.3")]
    p443 = next(p for p in detail["ports"] if p["port"] == 443)
    assert p443["has_preview"] is True and p443["url"] == "https://many.example.com/"
    assert next(p for p in detail["ports"] if p["port"] == 22)["has_preview"] is False
    assert detail["vulns"]["total"] == 2
    assert detail["vulns"]["by_severity"] == {"critical": 1, "high": 0, "medium": 1, "low": 0, "unknown": 0}
    assert [v["cve_id"] for v in detail["vulns"]["top"]] == ["CVE-2026-0003", "CVE-2026-0004"]
    assert len(detail["web_pages"]) == 1 and detail["web_pages"][0]["device_uuid"] == b.uuid

    empty = client.get(f"/api/domains/{d.id}/subdomains/{_by_name([none])['none.example.com']['id']}").json()
    assert empty["devices"] == [] and empty["ports"] == [] and empty["web_pages"] == []
    assert empty["vulns"]["total"] == 0 and empty["combined_score"] is None


def test_host_name_page_without_device_counts_as_web_preview(client, db):  # noqa: F811
    d = make_domain(db)
    _sub(db, d, "www.example.com", ["198.51.100.20"])
    _page(db, None, "198.51.100.20", 443, "www.example.com")
    db.commit()
    [row] = client.get(f"/api/domains/{d.id}/subdomains").json()["items"]
    assert row["has_web_preview"] is True and row["web_device_uuid"] is None and row["combined_score"] is None


def test_list_filters_and_sort_on_aggregates(client, db):  # noqa: F811
    d = make_domain(db)
    _device(db, "198.51.100.1", exposure=10, risk=80, combined=75, open_ports=[443])
    _device(db, "198.51.100.2", exposure=90, risk=40, combined=45, open_ports=[22, 80, 443])
    lo = _device(db, "198.51.100.3", exposure=5, risk=5, combined=5)
    _page(db, lo, "198.51.100.3", 443, "198.51.100.3")
    _sub(db, d, "high.example.com", ["198.51.100.1"])
    _sub(db, d, "medium.example.com", ["198.51.100.2"])
    _sub(db, d, "low.example.com", ["198.51.100.3"])
    _sub(db, d, "bare.example.com", ["198.51.100.50"])
    db.commit()
    url = f"/api/domains/{d.id}/subdomains"

    def names(**params) -> list[str]:
        return [s["name"] for s in client.get(url, params=params).json()["items"]]

    assert names(score="high") == ["high.example.com"]
    assert names(score="medium") == ["medium.example.com"]
    assert names(score="low") == ["low.example.com"]
    assert names(score="unscored") == ["bare.example.com"]
    assert names(has_ports="true") == ["high.example.com", "medium.example.com"]
    assert names(has_ports="false") == ["bare.example.com", "low.example.com"]
    assert names(has_web="true") == ["low.example.com"]
    # Sort: valued rows ordered, unscored always last
    assert names(sort="-combined_score") == ["high.example.com", "medium.example.com", "low.example.com",
                                             "bare.example.com"]
    assert names(sort="combined_score") == ["low.example.com", "medium.example.com", "high.example.com",
                                            "bare.example.com"]
    assert names(sort="-exposure_score")[:3] == ["medium.example.com", "high.example.com", "low.example.com"]
    assert names(sort="-open_ports_count") == ["medium.example.com", "high.example.com", "low.example.com",
                                               "bare.example.com"]
    # Paging and total apply after the aggregate filter
    page = client.get(url, params={"sort": "-combined_score", "page_size": 2, "page": 2}).json()
    assert page["total"] == 4 and [s["name"] for s in page["items"]] == ["low.example.com", "bare.example.com"]
    assert client.get(url, params={"score": "huge"}).status_code == 422

    risk = client.get(f"/api/domains/{d.id}").json()["risk"]
    assert risk == {"max_combined_score": 75, "high_risk": 1, "with_open_ports": 2}
    assert client.get("/api/domains").json()[0]["risk"] == risk


def test_list_endpoint_query_count_does_not_grow_with_rows(client, db):  # noqa: F811
    d = make_domain(db)
    url = f"/api/domains/{d.id}/subdomains"

    def add(i: int) -> None:
        dev = _device(db, f"198.51.100.{i}", exposure=50, risk=50, combined=50, open_ports=[443])
        _vuln(db, dev, 443, f"CVE-2026-1{i:03d}", "HIGH", 7.5)
        _page(db, dev, dev.current_ip, 443, f"n{i}.example.com")
        _sub(db, d, f"n{i}.example.com", [dev.current_ip])
        db.commit()

    def selects(params: dict) -> int:
        seen: list[str] = []

        def record(_conn, _cursor, statement, *_args):
            if statement.lstrip().upper().startswith("SELECT"):
                seen.append(statement)

        bind = db.get_bind()
        sa_event.listen(bind, "before_cursor_execute", record)
        try:
            assert client.get(url, params=params).status_code == 200
        finally:
            sa_event.remove(bind, "before_cursor_execute", record)
        return len(seen)

    add(1)
    few = {k: selects(p) for k, p in {"plain": {}, "agg": {"sort": "-combined_score", "has_web": "true"}}.items()}
    for i in range(2, 9):
        add(i)
    many = {k: selects(p) for k, p in {"plain": {}, "agg": {"sort": "-combined_score", "has_web": "true"}}.items()}
    assert many == few


def test_port_scan_now_queues_the_existing_scan(client, db):  # noqa: F811
    d = make_domain(db)
    s = _sub(db, d, "app.example.com", ["198.51.100.30"])
    gone = _sub(db, d, "nowhere.example.com", [])
    db.commit()
    base = f"/api/domains/{d.id}/subdomains"

    r = client.post(f"{base}/{s.id}/port-scan", headers=csrf(client))
    assert r.status_code == 200, r.text
    assert r.json()["targets"] == ["198.51.100.30"]
    with session_scope() as x:
        scan = x.get(Scan, r.json()["scan_id"])
        assert scan is not None and scan.status == "queued" and "app.example.com" in (scan.criteria or "")
        assert "domain.subdomain_port_scan" in {a.action for a in x.scalars(select(AuditLog))}
    assert client.post(f"{base}/{gone.id}/port-scan", headers=csrf(client)).status_code == 409
    assert client.post(f"{base}/999999/port-scan", headers=csrf(client)).status_code == 404
