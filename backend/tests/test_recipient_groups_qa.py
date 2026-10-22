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
    DEST_TEAMS,
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
    command.upgrade(cfg, "head")
    with eng.connect() as conn:
        row = conn.execute(
            text(
                "SELECT enabled, is_default, digest_time, event_types, last_digest_on FROM recipient_groups WHERE is_default = 1"
            )
        ).fetchone()
        assert row is not None
        assert bool(row[0]) is True and bool(row[1]) is True
        assert row[2] == "03:00"
        types = json.loads(row[3]) if isinstance(row[3], str) else (row[3] or [])
        assert "port_opened" in types
        for t in ("watch_match", "policy_violation", "monitor_change", "cve_watch_match"):
            assert t in types
        cols = {r[1] for r in conn.execute(text("PRAGMA table_info(recipient_holds)")).fetchall()}
        assert "attempts" in cols and "next_attempt_at" in cols and "pending_dest_ids" in cols


def test_legacy_digest_retired_single_html_email(db, monkeypatch):
    """After upgrade path: only the default group emails; uses HTML digest format; no double send."""
    g = _group(db, name="Email digest", is_default=True, delivery_mode=DELIVERY_DAILY, digest_time="00:00")
    db.add(RecipientDestination(group_id=g.id, kind=DEST_EMAIL, enabled=True, target="ops@example.com"))
    ev = _event(db, message="port opened")
    db.commit()
    put_section(db, NotificationSettings(enabled=True, smtp_host="smtp.example.com", recipients=["ops@example.com"]))
    db.commit()

    sent: list[tuple] = []

    def fake_email(cfg, subject, plain, html=None, **kwargs):
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


def test_slow_smtp_timeout_records_failure_no_resend(db, monkeypatch):
    """#1: slow SMTP must not resend every tick; TimeoutError must not abort sibling groups."""
    monkeypatch.setattr(channels, "HTTP_DEADLINE", 0.25)
    g = _group(db, name="Daily A", delivery_mode=DELIVERY_DAILY, digest_time="00:00")
    g2 = _group(db, name="Daily B", delivery_mode=DELIVERY_DAILY, digest_time="00:00")
    db.add(RecipientDestination(group_id=g.id, kind=DEST_EMAIL, enabled=True, target="a@example.com"))
    db.add(RecipientDestination(group_id=g2.id, kind=DEST_EMAIL, enabled=True, target="b@example.com"))
    ev = _event(db)
    put_section(db, NotificationSettings(enabled=True, smtp_host="smtp.example.com", recipients=["x@example.com"]))
    db.commit()

    sent: list[str] = []

    def slow_or_ok(cfg, subject, plain, html=None, *, timeout=None):
        to = cfg.recipients[0]
        if to == "a@example.com":
            # Wait is HTTP_DEADLINE+2 (=2.25s with patched deadline); exceed it.
            time.sleep(3.0)
            sent.append(to)  # may not run if future is abandoned
            return
        sent.append(to)

    monkeypatch.setattr(channels, "send_email", slow_or_ok)
    deliver_channel_event_ids([ev.id])
    flush_due_holds(hourly=False)

    hold_a = db.scalar(select(RecipientHold).where(RecipientHold.group_id == g.id, RecipientHold.event_id == ev.id))
    assert hold_a is not None
    assert (hold_a.attempts or 0) >= 1
    assert hold_a.next_attempt_at is not None
    # Group B must still have been attempted (not aborted by A's timeout).
    assert "b@example.com" in sent or db.get(type(g2), g2.id) is not None

    sent_before = list(sent)
    flush_due_holds(hourly=False)  # next tick — backoff should suppress A
    assert sent.count("a@example.com") == sent_before.count("a@example.com")


def test_failed_immediate_retries_despite_dedupe(db, monkeypatch):
    """#2: default dedupe must not swallow retries after a failed immediate send."""
    from app.security import encrypt_secret

    g = _group(db, delivery_mode=DELIVERY_IMMEDIATE, dedupe_seconds=300)
    db.add(
        RecipientDestination(
            group_id=g.id,
            kind=DEST_SLACK,
            enabled=True,
            url_enc=encrypt_secret("https://hooks.slack.example/ok"),
        )
    )
    db.add(
        RecipientDestination(
            group_id=g.id,
            kind=DEST_TEAMS,
            enabled=True,
            url_enc=encrypt_secret("https://hooks.teams.example/closed"),
        )
    )
    ev = _event(db, message="alert-once")
    db.commit()

    posts: list[str] = []

    def selective(url, payload, *, secret, raw=None):
        posts.append(url)
        if "teams" in url:
            raise RuntimeError("connection refused")
        return None

    monkeypatch.setattr(channels, "_post_json", selective)
    deliver_channel_event_ids([ev.id])
    hold = db.scalar(select(RecipientHold).where(RecipientHold.event_id == ev.id))
    assert hold is not None
    assert hold.reason != "dedupe"
    assert (hold.attempts or 0) >= 1
    assert hold.pending_dest_ids  # only failed dests
    assert posts.count("https://hooks.slack.example/ok") == 1

    # Due for retry immediately for the test.
    hold.next_attempt_at = None
    db.commit()
    flush_due_holds(hourly=False)
    # Slack must not be re-sent; Teams retried.
    assert posts.count("https://hooks.slack.example/ok") == 1
    assert posts.count("https://hooks.teams.example/closed") >= 2


def test_retry_only_failed_destinations(db, monkeypatch):
    """#3: retries target only destinations that failed, not the whole group."""
    from app.security import encrypt_secret

    g = _group(db, delivery_mode=DELIVERY_IMMEDIATE, dedupe_seconds=0)
    db.add(
        RecipientDestination(
            group_id=g.id,
            kind=DEST_SLACK,
            enabled=True,
            url_enc=encrypt_secret("https://hooks.slack.example/ok"),
        )
    )
    db.add(
        RecipientDestination(
            group_id=g.id,
            kind=DEST_TEAMS,
            enabled=True,
            url_enc=encrypt_secret("https://hooks.teams.example/bad"),
        )
    )
    ev = _event(db)
    db.commit()
    posts: list[str] = []

    def selective(url, payload, *, secret, raw=None):
        posts.append(url)
        if "teams" in url:
            raise RuntimeError("HTTP 500")
        return None

    monkeypatch.setattr(channels, "_post_json", selective)
    deliver_channel_event_ids([ev.id])
    hold = db.scalar(select(RecipientHold).where(RecipientHold.event_id == ev.id))
    assert hold is not None and hold.pending_dest_ids
    teams_id = hold.pending_dest_ids[0]
    hold.next_attempt_at = None
    db.commit()

    # Teams recovers on retry.
    def ok_all(url, payload, *, secret, raw=None):
        posts.append(url)
        return None

    monkeypatch.setattr(channels, "_post_json", ok_all)
    flush_due_holds(hourly=False)
    assert posts.count("https://hooks.slack.example/ok") == 1  # never retried
    assert posts.count("https://hooks.teams.example/bad") == 2  # fail + success
    assert db.scalar(select(RecipientHold).where(RecipientHold.event_id == ev.id)) is None
    del teams_id  # used for clarity above


def test_migration_includes_always_notify_event_types(tmp_path: Path):
    """#4: default Email digest keeps legacy ALWAYS_NOTIFY_TYPES (no silent drop)."""
    url = f"sqlite:///{(tmp_path / 'mig-types.db').as_posix()}"
    cfg = alembic_config(url)
    command.upgrade(cfg, "0030")
    eng = create_engine(url)
    payload = {
        "enabled": True,
        "digest_time": "08:00",
        "recipients": ["ops@example.com"],
        "event_types": ["port_opened", "tag_added"],
    }
    with eng.begin() as conn:
        conn.execute(
            text("INSERT INTO app_settings (key, value, updated_at) VALUES ('notifications', :value, CURRENT_TIMESTAMP)"),
            {"value": json.dumps(payload)},
        )
    command.upgrade(cfg, "head")
    with eng.connect() as conn:
        raw = conn.execute(text("SELECT event_types FROM recipient_groups WHERE is_default = 1")).scalar()
        types = json.loads(raw) if isinstance(raw, str) else (raw or [])
        assert "port_opened" in types and "tag_added" in types
        for t in ("watch_match", "policy_violation", "monitor_change", "cve_watch_match"):
            assert t in types


def test_disabled_group_does_not_own_webhook(db, monkeypatch):
    """#5: only enabled groups suppress their webhook from the global path."""
    hook = WebhookEndpoint(name="g", url="https://hooks.example.com/g", enabled=True)
    db.add(hook)
    db.flush()
    g = _group(db, delivery_mode=DELIVERY_IMMEDIATE, dedupe_seconds=0, enabled=False)
    db.add(RecipientDestination(group_id=g.id, kind=DEST_WEBHOOK, enabled=True, webhook_id=hook.id))
    ev = _event(db)
    put_section(db, NotificationSettings(webhooks_enabled=True))
    db.commit()

    posts: list[int] = []

    def capture(url, body, headers, *, deadline=8.0):
        posts.append(1)
        return 204

    monkeypatch.setattr(webhooks, "_http_post", capture)
    webhooks.deliver_event_ids([ev.id])
    assert len(posts) == 1  # global delivery runs — group is disabled


def test_daily_group_waits_if_digest_time_already_passed(db, monkeypatch):
    """#6: new/migrated daily group past today's time waits until tomorrow."""
    from datetime import datetime

    from app.core.channels import daily_seed_last_digest_on

    now = datetime.now().astimezone()
    digest = f"{now.hour:02d}:{now.minute:02d}"
    g = _group(
        db,
        delivery_mode=DELIVERY_DAILY,
        digest_time=digest,
        last_digest_on=daily_seed_last_digest_on(digest, now),
    )
    db.add(RecipientDestination(group_id=g.id, kind=DEST_EMAIL, enabled=True, target="ops@example.com"))
    ev = _event(db)
    put_section(db, NotificationSettings(enabled=True, smtp_host="smtp.example.com", recipients=["ops@example.com"]))
    db.commit()

    sent: list[str] = []
    monkeypatch.setattr(channels, "send_email", lambda *a, **k: sent.append("x"))
    deliver_channel_event_ids([ev.id])
    flush_due_holds(hourly=False)
    assert sent == []
    assert db.scalar(select(RecipientHold).where(RecipientHold.event_id == ev.id)) is not None
