"""Webhook CRUD extensions: PATCH, secret rotation, test POST, notify-flag delivery."""

from __future__ import annotations

import httpx
import pytest
from fastapi.testclient import TestClient

from app.api.auth import limiter
from app.core import webhooks
from app.main import app
from app.models import Event, WebhookEndpoint
from app.settings_store import NotificationSettings, put_section


@pytest.fixture
def client(db_env):
    limiter.reset()
    with TestClient(app) as c:
        assert c.post("/api/setup/admin", json={"username": "admin", "password": "correct-horse-1"}).status_code == 200
        yield c


def csrf(c: TestClient) -> dict:
    return {"X-CSRF-Token": c.cookies.get("nf_csrf", "")}


def test_webhook_patch_and_rotate_secret(client):
    h = csrf(client)
    r = client.post(
        "/api/webhooks",
        json={
            "name": "SIEM",
            "url": "https://hooks.example.com/events",
            "enabled": True,
            "event_types": ["port_opened"],
            "rotate_secret": True,
        },
        headers=h,
    )
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["has_secret"] is True and body["secret"] and body["include_record_events"] is False
    secret_once = body["secret"]
    wid = body["id"]

    listed = client.get("/api/webhooks", headers=h).json()
    assert listed[0]["id"] == wid and "secret" not in listed[0]

    r = client.patch(
        f"/api/webhooks/{wid}",
        json={
            "name": "SIEM-prod",
            "enabled": False,
            "include_record_events": True,
            "event_types": ["port_opened", "watch_match"],
        },
        headers=h,
    )
    assert r.status_code == 200, r.text
    assert r.json()["name"] == "SIEM-prod"
    assert r.json()["enabled"] is False
    assert r.json()["include_record_events"] is True
    assert r.json()["event_types"] == ["port_opened", "watch_match"]
    assert "secret" not in r.json()

    r = client.patch(f"/api/webhooks/{wid}", json={"rotate_secret": True}, headers=h)
    assert r.status_code == 200 and r.json()["secret"] and r.json()["secret"] != secret_once


def test_webhook_test_posts_signed_event(client, monkeypatch):
    h = csrf(client)
    r = client.post(
        "/api/webhooks",
        json={
            "name": "test-hook",
            "url": "https://hooks.example.com/test",
            "secret": "shared-secret",
        },
        headers=h,
    )
    wid = r.json()["id"]

    seen = {}

    def post(url, *, content=None, headers=None, timeout=None):
        seen["url"] = url
        seen["headers"] = headers
        seen["body"] = content
        return httpx.Response(204)

    monkeypatch.setattr(webhooks.httpx, "post", post)
    r = client.post(f"/api/webhooks/{wid}/test", headers=h)
    assert r.status_code == 200, r.text
    assert r.json()["ok"] is True and r.json()["status_code"] == 204
    assert seen["url"] == "https://hooks.example.com/test"
    assert seen["headers"].get("X-NF-Signature")
    assert b"webhook_test" in seen["body"]

    row = client.get("/api/webhooks", headers=h).json()[0]
    assert row["last_success_at"] and row["last_error"] is None


def test_webhook_notify_flag_skips_record_unless_opt_in(db, monkeypatch):
    """Default: only notify=True events. Opt-in via include_record_events for record events."""
    put_section(db, NotificationSettings(webhooks_enabled=True))
    db.add(WebhookEndpoint(name="alerts", url="https://hooks.example.com/alert", enabled=True))
    db.add(
        WebhookEndpoint(
            name="records",
            url="https://hooks.example.com/record",
            enabled=True,
            include_record_events=True,
        )
    )
    alert_ev = Event(
        event_type="port_opened", severity="high", ip="192.0.2.10", port=22, protocol="tcp", message="opened", notify=True
    )
    record_ev = Event(
        event_type="port_opened", severity="low", ip="192.0.2.11", port=80, protocol="tcp", message="recorded", notify=False
    )
    db.add_all([alert_ev, record_ev])
    db.commit()

    posted: list[str] = []

    def post(url, **_k):
        posted.append(url)
        return httpx.Response(204)

    monkeypatch.setattr(webhooks.httpx, "post", post)
    webhooks.deliver_event_ids([alert_ev.id, record_ev.id])

    assert posted.count("https://hooks.example.com/alert") == 1  # alert only
    assert posted.count("https://hooks.example.com/record") == 2  # alert + record


def test_webhook_master_switch_disables_delivery(db, monkeypatch):
    put_section(db, NotificationSettings(webhooks_enabled=False))
    db.add(WebhookEndpoint(name="off", url="https://hooks.example.com/off", enabled=True))
    ev = Event(event_type="port_opened", severity="high", ip="192.0.2.12", message="opened", notify=True)
    db.add(ev)
    db.commit()
    posted = []

    def post(url, **_k):
        posted.append(url)
        return httpx.Response(204)

    monkeypatch.setattr(webhooks.httpx, "post", post)
    webhooks.deliver_event_ids([ev.id])
    assert posted == []


def test_notifications_partial_put_preserves_omitted(client):
    h = csrf(client)
    full = {
        "enabled": False,
        "smtp_host": "smtp.example.com",
        "smtp_port": 25,
        "security": "none",
        "username": "",
        "sender": "nm@example.com",
        "recipients": ["ops@example.com"],
        "event_types": ["port_opened"],
        "digest_time": "09:00",
        "webhooks_enabled": False,
        "watchlist_email_enabled": False,
        "watchlist_webhooks_enabled": False,
    }
    assert client.put("/api/settings/notifications", json=full, headers=h).status_code == 200
    r = client.put("/api/settings/notifications", json={"webhooks_enabled": True}, headers=h)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["webhooks_enabled"] is True
    assert body["smtp_host"] == "smtp.example.com"
    assert body["watchlist_email_enabled"] is False
    assert body["digest_time"] == "09:00"
    assert "always_notify_types" in body
    assert "watch_match" in body["always_notify_types"]
