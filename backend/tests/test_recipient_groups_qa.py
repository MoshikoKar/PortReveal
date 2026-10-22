"""QA fixes for recipient groups: Postgres migration, digests, locks, CVE, batching, retries."""

from __future__ import annotations

import json
import logging
import time
from pathlib import Path

import pytest
from alembic import command
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select, text

from app.api.auth import limiter
from app.core import channels, webhooks
from app.core.channels import (
    deliver_channel_event_ids,
    flush_due_holds,
)
from app.core.vuln.watchlist import schedule_watchlist_delivery
from app.logging_setup import setup_logging
from app.main import app
from app.migrate import alembic_config
from app.models import (
    DELIVERY_DAILY,
    DELIVERY_IMMEDIATE,
    DEST_EMAIL,
    DEST_SLACK,
    DEST_WEBHOOK,
    EV_CVE_WATCH_MATCH,
    RecipientDestination,
    RecipientHold,
    WebhookEndpoint,
)
from app.settings_store import NotificationSettings, put_section
from tests.test_recipient_groups import _event, _group, csrf


@pytest.fixture
def client(db_env):
    limiter.reset()
    with TestClient(app) as c:
        assert c.post("/api/setup/admin", json={"username": "admin", "password": "correct-horse-1"}).status_code == 200
        yield c


def test_migration_boolean_binds_and_enabled_copy(tmp_path: Path):
    """0031 must use typed booleans (Postgres) and copy notifications.enabled onto the default group."""
    url = f"sqlite:///{(tmp_path / 'mig.db').as_posix()}"
    cfg = alembic_config(url)
    command.upgrade(cfg, "0030")
    eng = create_engine(url)
    payload = {
        "enabled": True,
        "digest_time": "03:00",
        "recipients": ["ops@example.com"],
        "event_types": ["port_opened"],
    }
    with eng.begin() as conn:
        conn.execute(
            text("INSERT INTO app_settings (key, value, updated_at) VALUES ('notifications', :value, CURRENT_TIMESTAMP)"),
            {"value": json.dumps(payload)},
        )
    command.upgrade(cfg, "0031")
    with eng.connect() as conn:
        row = conn.execute(text("SELECT enabled, is_default, digest_time FROM recipient_groups WHERE is_default = 1")).fetchone()
        assert row is not None
        assert bool(row[0]) is True and bool(row[1]) is True
        assert row[2] == "03:00"
        cols = {r[1] for r in conn.execute(text("PRAGMA table_info(recipient_holds)")).fetchall()}
        assert "attempts" in cols and "next_attempt_at" in cols


def test_legacy_digest_retired_single_html_email(db, monkeypatch):
    """After upgrade path: only the default group emails; uses HTML digest format; no double send."""
    g = _group(db, name="Email digest", is_default=True, delivery_mode=DELIVERY_DAILY, digest_time="00:00")
    db.add(RecipientDestination(group_id=g.id, kind=DEST_EMAIL, enabled=True, target="ops@example.com"))
    ev = _event(db, message="port opened")
    db.commit()
    put_section(db, NotificationSettings(enabled=True, smtp_host="smtp.example.com", recipients=["ops@example.com"]))
    db.commit()

    sent: list[tuple] = []

    def fake_email(cfg, subject, plain, html=None):
        sent.append((list(cfg.recipients), subject, plain, html))

    monkeypatch.setattr(channels, "send_email", fake_email)
    deliver_channel_event_ids([ev.id])
    # Held for daily — flush as due (digest_time 00:00, now is after).
    flush_due_holds(hourly=False)
    assert len(sent) == 1
    assert sent[0][0] == ["ops@example.com"]
    assert sent[0][3] is not None  # HTML body from format_daily_digest
    assert "Daily summary" in sent[0][3] or "PortReveal" in sent[0][3]


def test_per_group_daily_time_independent_of_email(db, monkeypatch):
    from app.security import encrypt_secret

    g = _group(db, name="Slack SOC", delivery_mode=DELIVERY_DAILY, digest_time="00:00", enabled=True)
    db.add(
        RecipientDestination(
            group_id=g.id,
            kind=DEST_SLACK,
            enabled=True,
            url_enc=encrypt_secret("https://hooks.slack.example/services/T/B/x"),
        )
    )
    ev = _event(db)
    put_section(db, NotificationSettings(enabled=False, smtp_host=""))  # email master OFF
    db.commit()

    posts: list[str] = []

    def fake_post(url, payload, *, secret, raw=None):
        posts.append(url)
        return None

    monkeypatch.setattr(channels, "_post_json", fake_post)
    deliver_channel_event_ids([ev.id])
    flush_due_holds(hourly=False)
    assert posts and "hooks.slack.example" in posts[0]


def test_no_db_lock_during_slow_delivery(db, monkeypatch):
    """PUT settings must not wait on a slow Slack receiver during channel delivery."""
    from app.security import encrypt_secret

    g = _group(db, delivery_mode=DELIVERY_IMMEDIATE, dedupe_seconds=0, max_per_hour=50)
    db.add(
        RecipientDestination(
            group_id=g.id,
            kind=DEST_SLACK,
            enabled=True,
            url_enc=encrypt_secret("https://hooks.slack.example/slow"),
        )
    )
    events = [_event(db, message=f"m{i}") for i in range(3)]
    db.commit()

    def slow_post(url, payload, *, secret, raw=None):
        time.sleep(0.35)
        return None

    monkeypatch.setattr(channels, "_post_json", slow_post)

    started = time.monotonic()
    # Run delivery on a side thread; main thread does a DB write (settings) mid-flight.
    import threading

    done = threading.Event()

    def _run():
        try:
            deliver_channel_event_ids([e.id for e in events])
        finally:
            done.set()

    threading.Thread(target=_run, daemon=True).start()
    time.sleep(0.05)
    t0 = time.monotonic()
    put_section(db, NotificationSettings(enabled=True, smtp_host="relay.example.com"))
    db.commit()
    write_elapsed = time.monotonic() - t0
    assert write_elapsed < 0.5, f"settings write blocked for {write_elapsed:.2f}s"
    assert done.wait(5)
    assert time.monotonic() - started >= 0.3


def test_httpx_loggers_silenced_to_warning():
    setup_logging()
    assert logging.getLogger("httpx").level >= logging.WARNING
    assert logging.getLogger("httpcore").level >= logging.WARNING


def test_cve_routes_to_groups_without_duplicate_webhook(db, monkeypatch):
    from app.security import encrypt_secret

    hook = WebhookEndpoint(
        name="siem",
        url="https://hooks.example.com/siem",
        enabled=True,
        secret_enc=encrypt_secret("s"),
    )
    db.add(hook)
    db.flush()
    g = _group(db, delivery_mode=DELIVERY_IMMEDIATE, dedupe_seconds=0, event_types=[EV_CVE_WATCH_MATCH])
    db.add(RecipientDestination(group_id=g.id, kind=DEST_WEBHOOK, enabled=True, webhook_id=hook.id))
    ev = _event(db, event_type=EV_CVE_WATCH_MATCH, severity="high", message="CVE-2024-1")
    put_section(
        db,
        NotificationSettings(
            enabled=True,
            webhooks_enabled=True,
            watchlist_webhooks_enabled=True,
            watchlist_email_enabled=False,
            smtp_host="x",
            recipients=[],
        ),
    )
    db.commit()

    posts: list[str] = []

    def capture_post(url, body, headers, *, deadline=8.0):
        posts.append(url)
        return 204

    monkeypatch.setattr(webhooks, "_http_post", capture_post)
    monkeypatch.setattr(channels, "_http_post", capture_post)

    schedule_watchlist_delivery([ev.id], wait=True)
    # Group-managed webhook should receive once via channels, not again via watchlist/global.
    assert len(posts) == 1


def test_immediate_batches_one_message_per_destination(db, monkeypatch):
    from app.security import encrypt_secret

    g = _group(db, delivery_mode=DELIVERY_IMMEDIATE, dedupe_seconds=0, max_per_hour=50)
    db.add(
        RecipientDestination(
            group_id=g.id,
            kind=DEST_SLACK,
            enabled=True,
            url_enc=encrypt_secret("https://hooks.slack.example/b"),
        )
    )
    events = [_event(db, message=f"e{i}") for i in range(3)]
    db.commit()
    payloads: list[dict] = []

    def fake_post(url, payload, *, secret, raw=None):
        payloads.append(payload)
        return None

    monkeypatch.setattr(channels, "_post_json", fake_post)
    deliver_channel_event_ids([e.id for e in events])
    assert len(payloads) == 1
    assert "3 event" in payloads[0]["attachments"][0]["text"]


def test_failed_flush_keeps_holds_for_retry(db, monkeypatch):
    from app.security import encrypt_secret

    g = _group(db, delivery_mode=DELIVERY_DAILY, digest_time="00:00")
    db.add(
        RecipientDestination(
            group_id=g.id,
            kind=DEST_SLACK,
            enabled=True,
            url_enc=encrypt_secret("https://hooks.slack.example/fail"),
        )
    )
    ev = _event(db)
    db.commit()
    deliver_channel_event_ids([ev.id])
    assert db.scalar(select(RecipientHold).where(RecipientHold.event_id == ev.id)) is not None

    def boom(url, payload, *, secret, raw=None):
        raise RuntimeError("HTTP 500 from hooks.slack.example")

    monkeypatch.setattr(channels, "_post_json", boom)
    flush_due_holds(hourly=False)
    hold = db.scalar(select(RecipientHold).where(RecipientHold.event_id == ev.id))
    assert hold is not None
    assert (hold.attempts or 0) >= 1
    assert hold.next_attempt_at is not None


def test_group_managed_webhook_skipped_by_global(db, monkeypatch):

    hook = WebhookEndpoint(name="g", url="https://hooks.example.com/g", enabled=True)
    db.add(hook)
    db.flush()
    g = _group(db, delivery_mode=DELIVERY_IMMEDIATE, dedupe_seconds=0)
    db.add(RecipientDestination(group_id=g.id, kind=DEST_WEBHOOK, enabled=True, webhook_id=hook.id))
    ev = _event(db)
    put_section(db, NotificationSettings(webhooks_enabled=True))
    db.commit()

    posts: list[int] = []

    def capture(url, body, headers, *, deadline=8.0):
        posts.append(1)
        return 204

    monkeypatch.setattr(webhooks, "_http_post", capture)
    monkeypatch.setattr(channels, "_http_post", capture)
    webhooks.deliver_event_ids([ev.id])  # global only
    assert posts == []  # skipped — group-managed
    deliver_channel_event_ids([ev.id])
    assert len(posts) == 1


def test_api_rejects_unknown_network_and_empty_destinations(client):
    h = csrf(client)
    r = client.post(
        "/api/recipient-groups",
        json={"name": "X", "destinations": [], "network_ids": [99999]},
        headers=h,
    )
    assert r.status_code == 422
    r = client.post(
        "/api/recipient-groups",
        json={"name": "Y", "destinations": [{"kind": "email", "target": "a@example.com"}], "network_ids": [99999]},
        headers=h,
    )
    assert r.status_code == 422
    assert "network" in r.text.lower()
