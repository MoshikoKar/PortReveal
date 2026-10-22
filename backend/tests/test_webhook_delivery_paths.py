"""Tag / watch / presence events reach webhooks; batching and master switch behaviour."""

from __future__ import annotations

import json
import time as time_mod

import httpx
import pytest
from sqlalchemy import select

from app.core import webhooks
from app.core.intel import run_watches
from app.core.presence import evaluate_absence
from app.models import (
    EV_DEVICE_DISAPPEARED,
    EV_WATCH_MATCH,
    Event,
    SavedSearch,
    WebhookEndpoint,
)
from app.settings_store import NotificationSettings, put_section

from .helpers import ScriptedScanner, host, make_network, port, scan


@pytest.fixture(autouse=True)
def _webhooks_on(db):
    put_section(db, NotificationSettings(webhooks_enabled=True))
    db.commit()


def test_deliver_batches_per_hook(db, monkeypatch):
    db.add(WebhookEndpoint(name="siem", url="https://hooks.example.com/batch", enabled=True))
    evs = [Event(event_type="port_opened", severity="high", ip="192.0.2.1", message=f"e{i}", notify=True) for i in range(3)]
    db.add_all(evs)
    db.commit()
    bodies = []

    def post(url, *, content=None, **_k):
        bodies.append(json.loads(content))
        return httpx.Response(204)

    monkeypatch.setattr(webhooks.httpx, "post", post)
    webhooks.deliver_event_ids([e.id for e in evs])
    assert len(bodies) == 1
    assert bodies[0]["batch"] is True and bodies[0]["count"] == 3


def test_tag_events_deliver_via_webhooks(db, monkeypatch):
    """Tag add/remove from a second scan deliver as alert events (notify=True)."""
    net = make_network(db)
    hosts = [host("10.0.0.1", [port(22, "ssh"), port(80, "http")], mac="02:00:00:00:00:01")]
    scan(ScriptedScanner(hosts), network_id=net.id)  # baseline: silent classification
    hosts[0].ports = [port(80, "http"), port(3306, "mysql")]
    s2 = scan(ScriptedScanner(hosts), network_id=net.id)
    ids = list(
        db.scalars(
            select(Event.id).where(
                Event.scan_id == s2.id,
                Event.event_type.in_(("tag_added", "tag_removed")),
            )
        )
    )
    assert ids
    assert all(db.get(Event, i).notify for i in ids)
    db.add(WebhookEndpoint(name="tags", url="https://hooks.example.com/tags", enabled=True))
    db.commit()
    posted = []

    def post(url, **_k):
        posted.append(url)
        return httpx.Response(204)

    monkeypatch.setattr(webhooks.httpx, "post", post)
    webhooks.deliver_event_ids(ids)
    assert posted == ["https://hooks.example.com/tags"]


def test_watch_events_deliver_via_webhooks(db, monkeypatch):
    net = make_network(db)
    scan(
        ScriptedScanner([host("10.0.0.1", [port(3389, "ms-wbt-server")], mac="02:00:00:00:00:01")]),
        network_id=net.id,
    )
    db.add(SavedSearch(name="RDP", query="port:3389"))
    db.commit()
    assert run_watches() == []  # baseline
    scan(
        ScriptedScanner(
            [
                host("10.0.0.1", [port(3389, "ms-wbt-server")], mac="02:00:00:00:00:01"),
                host("10.0.0.2", [port(3389, "ms-wbt-server")], mac="02:00:00:00:00:02"),
            ]
        ),
        network_id=net.id,
    )
    ids = list(db.scalars(select(Event.id).where(Event.event_type == EV_WATCH_MATCH)))
    assert ids
    db.add(WebhookEndpoint(name="w", url="https://hooks.example.com/watch", enabled=True))
    db.commit()
    posted = []

    def post(url, **_k):
        posted.append(url)
        return httpx.Response(204)

    monkeypatch.setattr(webhooks.httpx, "post", post)
    webhooks.deliver_event_ids(ids)
    assert posted == ["https://hooks.example.com/watch"]


def test_presence_events_deliver_via_webhooks(db, monkeypatch):
    """Presence disappearance events (list[int] from evaluate_absence) deliver like other sources."""
    assert evaluate_absence.__annotations__.get("return") in (list[int], "list[int]")
    ev = Event(
        event_type=EV_DEVICE_DISAPPEARED,
        severity="high",
        ip="192.0.2.50",
        message="absence alert",
        notify=True,
    )
    db.add(ev)
    db.add(WebhookEndpoint(name="p", url="https://hooks.example.com/presence", enabled=True))
    db.commit()
    posted = []

    def post(url, **_k):
        posted.append(url)
        return httpx.Response(204)

    monkeypatch.setattr(webhooks.httpx, "post", post)
    webhooks.deliver_event_ids([ev.id])
    assert posted == ["https://hooks.example.com/presence"]


def test_general_webhooks_switch_gates_delivery(db, monkeypatch):
    put_section(db, NotificationSettings(webhooks_enabled=True))
    db.add(WebhookEndpoint(name="on", url="https://hooks.example.com/on", enabled=True))
    ev = Event(event_type="port_opened", severity="high", ip="192.0.2.20", message="x", notify=True)
    db.add(ev)
    db.commit()
    posted = []

    def post(url, **_k):
        posted.append(url)
        return httpx.Response(204)

    monkeypatch.setattr(webhooks.httpx, "post", post)
    webhooks.deliver_event_ids([ev.id])
    assert posted == ["https://hooks.example.com/on"]

    put_section(db, NotificationSettings(webhooks_enabled=False))
    db.commit()
    posted.clear()
    webhooks.deliver_event_ids([ev.id])
    assert posted == []


def test_round_timeout_skips_slow_hook(db, monkeypatch):
    """A hanging hook is marked timed out without blocking the round forever."""
    put_section(db, NotificationSettings(webhooks_enabled=True))
    db.add(WebhookEndpoint(name="slow", url="https://hooks.example.com/slow", enabled=True))
    db.add(WebhookEndpoint(name="fast", url="https://hooks.example.com/fast", enabled=True))
    ev = Event(event_type="port_opened", severity="high", ip="192.0.2.21", message="x", notify=True)
    db.add(ev)
    db.commit()

    def post(url, **_k):
        if "slow" in url:
            time_mod.sleep(30)
        return httpx.Response(204)

    monkeypatch.setattr(webhooks, "ROUND_TIMEOUT", 0.5)
    monkeypatch.setattr(webhooks.httpx, "post", post)
    webhooks.deliver_event_ids([ev.id])

    rows = {h.name: h for h in db.scalars(select(WebhookEndpoint)).all()}
    db.refresh(rows["slow"])
    db.refresh(rows["fast"])
    assert rows["fast"].last_success_at is not None
    assert rows["slow"].last_error and "timeout" in rows["slow"].last_error
