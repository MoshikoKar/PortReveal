"""Daily digest email layout: tables, Attention, links, counts, networks, subject."""

from __future__ import annotations

from app.core.notify import format_daily_digest, format_sample_digest
from app.db import utcnow
from app.models import (
    EV_CVE_WATCH_MATCH,
    EV_DEVICE_DISCOVERED,
    EV_PORT_OPENED,
    EV_SERVICE_DETECTED,
    EV_VERSION_CHANGED,
    Device,
    Event,
)

BASE = "https://portreveal.example.com"
_ids = iter(range(1, 10_000))


def _ev(etype: str, device: Device | None, ip: str, **kw) -> Event:
    return Event(id=next(_ids), created_at=utcnow(), event_type=etype, ip=ip, message=kw.pop("message", "x"), device=device, **kw)


def _ports(dev: Device, ip: str, ports: list[int]) -> list[Event]:
    return [_ev(EV_PORT_OPENED, dev, ip, protocol="tcp", port=p) for p in ports]


def test_sections_render_as_tables_in_wider_card():
    dev = Device(hostname="host-a", network_id=1)
    evs = [
        _ev(
            EV_VERSION_CHANGED,
            dev,
            "10.0.0.1",
            protocol="tcp",
            port=80,
            old_value="Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)",
            new_value="Microsoft Internet Information Services httpd 10.0.17763 build",
        )
    ]
    _, plain, html = format_daily_digest(evs)
    assert "max-width:660px" in html
    assert "<th" in html and ">From</th>" in html and ">To</th>" in html
    assert "<li" not in html
    # Long labels keep their version numbers.
    assert "2.0" in plain and "10.0.17763" in plain


def test_links_need_base_url():
    dev = Device(hostname="host-a", network_id=1)
    evs = _ports(dev, "10.0.0.1", list(range(9000, 9010)))
    evs += [
        _ev(
            EV_SERVICE_DETECTED,
            Device(hostname=f"h{i}", network_id=1),
            f"10.0.1.{i}",
            protocol="tcp",
            port=22,
            new_value="OpenSSH 9.6",
        )
        for i in range(12)
    ]
    _, plain, html = format_daily_digest(evs, base_url=BASE + "/")
    assert f'href="{BASE}/changes?range=24h"' in html and "Open Changes" in html
    assert f"{BASE}/changes?type=service_detected&amp;range=24h" in html  # "…and N more"
    assert "…and 4 more" in html
    assert f"{BASE}/changes?type=port_opened&amp;q=10.0.0.1&amp;range=24h" in html  # "+N more" ports
    assert f"Open Changes: {BASE}/changes?range=24h" in plain

    _, plain, html = format_daily_digest(evs)
    assert "href=" not in html
    assert "public app URL" in html


def test_attention_block_lists_high_signal_first_and_is_omitted_when_empty():
    a = Device(hostname="host-a", network_id=1)
    evs = _ports(a, "10.0.0.1", [8080, 8081, 3389])
    evs.append(_ev(EV_DEVICE_DISCOVERED, Device(hostname="newbie", network_id=1), "10.0.0.9"))
    evs.append(_ev(EV_CVE_WATCH_MATCH, a, "10.0.0.1", new_value="CVE-2026-0001"))
    _, plain, html = format_daily_digest(evs)
    assert plain.index("Attention") < plain.index("Ports (")
    attention = plain[plain.index("Attention") : plain.index("Watches (")]
    assert "CVE watchlist" in attention and "New device | newbie" in attention
    assert "Sensitive port opened | host-a | TCP/3389" in attention
    assert "TCP/8080" not in attention

    _, plain, html = format_daily_digest(_ports(a, "10.0.0.1", [8080]))
    assert "Attention" not in plain and "Attention" not in html


def test_port_section_shows_hosts_and_ports_and_sensitive_first():
    a = Device(hostname="host-a", network_id=1)
    b = Device(hostname="host-b", network_id=1)
    evs = _ports(a, "10.0.0.1", [1098, 1099, 1100, 1101, 1102, 1103, 445, 3389]) + _ports(b, "10.0.0.2", [80])
    _, plain, _ = format_daily_digest(evs)
    assert "Ports opened (2 hosts · 9 ports)" in plain
    row = next(
        line for line in plain.splitlines() if "host-a | 10.0.0.1" in line and "Attention" not in line and "TCP/1098" in line
    )
    assert row.index("TCP/445") < row.index("TCP/3389") < row.index("TCP/1098")
    assert "+3 more" in row and "TCP/1103" not in row


def test_network_column_only_when_multiple_networks():
    a = Device(hostname="host-a", network_id=1)
    b = Device(hostname="host-b", network_id=2)
    names = {1: "HQ", 2: "Lab"}
    _, plain, html = format_daily_digest(_ports(a, "10.0.0.1", [80]) + _ports(b, "10.0.0.2", [80]), names)
    assert ">Network</th>" in html and "| HQ" in plain and "| Lab" in plain
    _, plain, html = format_daily_digest(_ports(a, "10.0.0.1", [80, 81]), names)
    assert ">Network</th>" not in html and "HQ" not in plain


def test_service_and_version_churn_collapsed_under_other_changes():
    a = Device(hostname="host-a", network_id=1)
    churn = [
        _ev(EV_VERSION_CHANGED, a, "10.0.0.1", protocol="tcp", port=p, old_value="x 1.0", new_value="x 1.1") for p in range(20)
    ]
    evs = (
        churn
        + _ports(a, "10.0.0.1", [3389])
        + [_ev(EV_SERVICE_DETECTED, a, "10.0.0.1", protocol="tcp", port=22, new_value="OpenSSH 9.6")]
    )
    _, plain, _ = format_daily_digest(evs)
    assert plain.index("Ports (") < plain.index("Services (") < plain.index("Other changes (20)")
    other = plain[plain.index("Other changes") :]
    assert other.count("x 1.0 | x 1.1") == 3
    assert "…and 17 more" in other
    assert "Services identified (1)" in plain[: plain.index("Other changes")]


def test_subject_has_title_signals_and_date_and_matches_header():
    a = Device(hostname="host-a", network_id=1)
    evs = [_ev(EV_DEVICE_DISCOVERED, a, "10.0.0.1")] + _ports(a, "10.0.0.1", list(range(1, 28)))
    subject, plain, html = format_daily_digest(evs, group_name="Email digest")
    day = utcnow().astimezone().strftime("%Y-%m-%d")
    assert subject.startswith("[PortReveal] Daily summary · 1 new")
    assert "27 ports" in subject and subject.endswith(day)
    assert len(subject) <= 78
    assert "Email digest" not in subject
    assert ">Daily summary</div>" in html and "Email digest" in html
    assert plain.startswith("PortReveal Daily summary")


def test_sample_digest_uses_production_layout():
    subject, plain, html = format_sample_digest(BASE)
    assert subject.startswith("[PortReveal] [test] Daily summary")
    assert "Attention" in plain and "max-width:660px" in html and f"{BASE}/changes" in html
