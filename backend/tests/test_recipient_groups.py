"""Recipient groups: routing filters, batching, rate-cap overflow, dedupe, quiet hours,
migration of legacy email settings, Slack/Teams payload shape, and API CRUD."""

from __future__ import annotations

import json
from datetime import datetime, timedelta
from pathlib import Path

import pytest
from alembic import command
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select, text

from app.api.auth import limiter
from app.core import channels
from app.core.channels import (
    HOLD_DIGEST,
    HOLD_HOURLY,
    HOLD_QUIET,
    HOLD_RATE,
    _slack_payload,
    _teams_payload,
    deliver_channel_event_ids,
    flush_due_holds,
    group_matches_event,
)
from app.db import utcnow
from app.main import app
from app.migrate import alembic_config
from app.models import (
    DELIVERY_DAILY,
    DELIVERY_HOURLY,
    DELIVERY_IMMEDIATE,
    DEST_EMAIL,
    Device,
    Event,
    RecipientDestination,
    RecipientGroup,
    RecipientHold,
)
from tests.helpers import make_network


@pytest.fixture
def client(db_env):
    limiter.reset()
    with TestClient(app) as c:
        assert c.post("/api/setup/admin", json={"username": "admin", "password": "correct-horse-1"}).status_code == 200
        yield c


def csrf(c: TestClient) -> dict:
    return {"X-CSRF-Token": c.cookies.get("nf_csrf", "")}


def _event(db, **kwargs) -> Event:
    defaults = dict(
        event_type="port_opened",
        severity="info",
        message="tcp/443 opened on 10.0.0.10",
        ip="10.0.0.10",
        port=443,
        protocol="tcp",
        notify=True,
        created_at=utcnow(),
    )
    defaults.update(kwargs)
    ev = Event(**defaults)
    db.add(ev)
    db.flush()
    return ev


def _group(db, **kwargs) -> RecipientGroup:
    defaults = dict(
        name="SOC",
        enabled=True,
        is_default=False,
        min_severity="info",
        delivery_mode=DELIVERY_IMMEDIATE,
        max_per_hour=20,
        dedupe_seconds=300,
        quiet_bypass_critical=True,
        rate_sent=0,
        created_at=utcnow(),
        updated_at=utcnow(),
    )
    defaults.update(kwargs)
    g = RecipientGroup(**defaults)
    db.add(g)
    db.flush()
    return g


# --- Matching / routing -------------------------------------------------------


def test_group_matches_severity_network_and_types(db):
    net_a = make_network(db, cidr="10.0.0.0/24", name="Alpha")
    net_b = make_network(db, cidr="10.1.0.0/24", name="Beta")

    dev_a = Device(
        network_id=net_a.id,
        current_ip="10.0.0.10",
        status="active",
        first_seen=utcnow(),
        last_seen=utcnow(),
    )
    db.add(dev_a)
    db.flush()

    g = _group(db, min_severity="medium", event_types=["port_opened"], network_ids=[net_a.id])
    hi = _event(db, severity="high", event_type="port_opened", device_id=dev_a.id)
    lo = _event(db, severity="low", event_type="port_opened", device_id=dev_a.id)
    wrong_type = _event(db, severity="high", event_type="port_closed", device_id=dev_a.id)
    assert group_matches_event(g, hi) is True
    assert group_matches_event(g, lo) is False
    assert group_matches_event(g, wrong_type) is False

    # Network scope: device on other network is excluded
    g.network_ids = [net_b.id]
    db.flush()
    db.refresh(hi)
    assert group_matches_event(g, hi) is False

    # notify=False never matches
    silent = _event(db, severity="high", notify=False, device_id=dev_a.id)
    g.network_ids = None
    assert group_matches_event(g, silent) is False


def test_daily_and_hourly_batching_hold_events(db, monkeypatch):
    g_daily = _group(db, name="Daily", delivery_mode=DELIVERY_DAILY, digest_time="08:00")
    g_hourly = _group(db, name="Hourly", delivery_mode=DELIVERY_HOURLY)
    db.add(RecipientDestination(group_id=g_daily.id, kind=DEST_EMAIL, enabled=True, target="daily@example.com"))
    db.add(RecipientDestination(group_id=g_hourly.id, kind=DEST_EMAIL, enabled=True, target="hourly@example.com"))
    ev = _event(db)
    db.commit()

    sent: list[str] = []

    def fake_email(cfg, subject, plain, html=None, **kwargs):
        sent.append(cfg.recipients[0])

    monkeypatch.setattr(channels, "send_email", fake_email)
    deliver_channel_event_ids([ev.id])

    db.expire_all()
    holds = list(db.scalars(select(RecipientHold)).all())
    reasons = {(h.group_id, h.reason) for h in holds}
    assert (g_daily.id, HOLD_DIGEST) in reasons
    assert (g_hourly.id, HOLD_HOURLY) in reasons
    assert sent == []  # not delivered yet


def test_rate_cap_overflow_rolls_into_digest(db, monkeypatch):
    g = _group(db, delivery_mode=DELIVERY_IMMEDIATE, max_per_hour=1, dedupe_seconds=0)
    db.add(RecipientDestination(group_id=g.id, kind=DEST_EMAIL, enabled=True, target="cap@example.com"))
    e1 = _event(db, message="one")
    e2 = _event(db, message="two")
    db.commit()

    sent: list[str] = []

    def fake_email(cfg, subject, plain, html=None, **kwargs):
        sent.append(plain)

    monkeypatch.setattr(channels, "send_email", fake_email)
    deliver_channel_event_ids([e1.id])
    deliver_channel_event_ids([e2.id])

    db.expire_all()
    g = db.get(RecipientGroup, g.id)
    assert g.rate_sent == 1
    hold = db.scalar(select(RecipientHold).where(RecipientHold.event_id == e2.id))
    assert hold is not None and hold.reason == HOLD_RATE
    assert len(sent) == 1

    # Hourly flush releases rate-cap overflow (digest may summarize without raw message text)
    flush_due_holds(hourly=True)
    assert len(sent) == 2
    db.expire_all()
    assert db.scalar(select(RecipientHold).where(RecipientHold.event_id == e2.id)) is None


def test_dedupe_window_skips_identical_events(db, monkeypatch):
    g = _group(db, delivery_mode=DELIVERY_DAILY, dedupe_seconds=600)
    db.add(RecipientDestination(group_id=g.id, kind=DEST_EMAIL, enabled=True, target="d@example.com"))
    e1 = _event(db, message="same")
    e2 = _event(db, message="same")  # identical fingerprint
    db.commit()
    deliver_channel_event_ids([e1.id, e2.id])
    holds = list(db.scalars(select(RecipientHold).where(RecipientHold.group_id == g.id)).all())
    # First held for digest; second skipped by dedupe (or held as dedupe marker only for first)
    digest_holds = [h for h in holds if h.reason == HOLD_DIGEST]
    assert len(digest_holds) == 1


def test_quiet_hours_hold_non_critical(db, monkeypatch):
    now = datetime.now().astimezone()
    start = (now - timedelta(minutes=30)).strftime("%H:%M")
    end = (now + timedelta(minutes=30)).strftime("%H:%M")
    g = _group(
        db,
        delivery_mode=DELIVERY_IMMEDIATE,
        quiet_start=start,
        quiet_end=end,
        quiet_bypass_critical=True,
        dedupe_seconds=0,
    )
    db.add(RecipientDestination(group_id=g.id, kind=DEST_EMAIL, enabled=True, target="q@example.com"))
    info = _event(db, severity="info", message="noise")
    crit = _event(db, severity="high", message="critical")
    db.commit()

    sent: list[tuple] = []
    monkeypatch.setattr(
        channels,
        "send_email",
        lambda cfg, subject, plain, html=None, **kwargs: sent.append((subject, plain or "", html or "")),
    )
    deliver_channel_event_ids([info.id, crit.id])

    db.expire_all()
    quiet = db.scalar(select(RecipientHold).where(RecipientHold.event_id == info.id))
    assert quiet is not None and quiet.reason == HOLD_QUIET
    blob = " ".join(x for t in sent for x in t)
    assert "critical" in blob.lower() or len(sent) == 1
    assert "noise" not in blob.lower()
    assert len(sent) == 1  # critical bypassed quiet; noise held


def test_slack_and_teams_payload_shape():
    cards = [
        {"type": "port_opened", "severity": "high", "ip": "10.0.0.10", "port": 443, "message": "opened", "protocol": "tcp"},
        {"type": "watch_match", "severity": "medium", "ip": "10.0.0.11", "port": None, "message": "match"},
    ]
    slack = _slack_payload(cards, "SOC")
    assert "attachments" in slack
    assert slack["attachments"][0]["footer"] == "PortReveal"
    assert "SOC" in slack["attachments"][0]["text"]
    assert "port_opened" in slack["attachments"][0]["text"]

    teams = _teams_payload(cards, "SOC")
    assert teams["@type"] == "MessageCard"
    assert teams["title"].startswith("PortReveal")
    assert len(teams["sections"][0]["facts"]) == 2


def test_migration_copies_email_recipients_into_default_group(tmp_path: Path):
    """Hand-written 0031 upgrade creates a default group from app_settings notifications JSON."""
    url = f"sqlite:///{(tmp_path / 'mig.db').as_posix()}"
    cfg = alembic_config(url)
    command.upgrade(cfg, "0030")
    eng = create_engine(url)
    payload = {
        "enabled": True,
        "digest_time": "09:30",
        "recipients": ["ops@example.com", "soc@example.com"],
        "event_types": ["port_opened", "watch_match"],
    }
    with eng.begin() as conn:
        conn.execute(
            text("INSERT INTO app_settings (key, value, updated_at) VALUES ('notifications', :value, CURRENT_TIMESTAMP)"),
            {"value": json.dumps(payload)},
        )
    command.upgrade(cfg, "0031")
    with eng.connect() as conn:
        row = conn.execute(
            text("SELECT name, is_default, delivery_mode, digest_time, event_types FROM recipient_groups")
        ).fetchone()
        assert row is not None
        assert row[0] == "Email digest" and row[1] == 1 and row[2] == "daily"
        assert row[3] == "09:30"
        types = json.loads(row[4]) if isinstance(row[4], str) else (row[4] or [])
        assert "port_opened" in types
        # Legacy digest always included ALWAYS_NOTIFY_TYPES.
        for t in ("watch_match", "policy_violation", "monitor_change", "cve_watch_match"):
            assert t in types
        dests = conn.execute(text("SELECT kind, target FROM recipient_destinations ORDER BY target")).fetchall()
        assert [(d[0], d[1]) for d in dests] == [
            ("email", "ops@example.com"),
            ("email", "soc@example.com"),
        ]
        cols = {r[1] for r in conn.execute(text("PRAGMA table_info(webhook_endpoints)")).fetchall()}
        assert "last_error_at" in cols

    command.downgrade(cfg, "0030")
    with eng.connect() as conn:
        tables = {r[0] for r in conn.execute(text("SELECT name FROM sqlite_master WHERE type='table'")).fetchall()}
        assert "recipient_groups" not in tables
        cols = {r[1] for r in conn.execute(text("PRAGMA table_info(webhook_endpoints)")).fetchall()}
        assert "last_error_at" not in cols


# --- API ----------------------------------------------------------------------


def test_recipient_group_crud_masks_slack_url(client, monkeypatch):
    h = csrf(client)
    # Migration may have created a default group already
    listed = client.get("/api/recipient-groups", headers=h).json()
    assert isinstance(listed, list)

    r = client.post(
        "/api/recipient-groups",
        json={
            "name": "SOC",
            "delivery_mode": "daily",
            "digest_time": "07:00",
            "min_severity": "high",
            "destinations": [
                {"kind": "email", "target": "soc@example.com"},
                {"kind": "slack", "url": "https://hooks.slack.example/services/T00/B00/secretXXX"},
            ],
        },
        headers=h,
    )
    assert r.status_code == 201, r.text
    body = r.json()
    assert "Critical+High" in body["summary"]
    assert "All networks" in body["summary"]
    # Mode lives on the badge; summary is severity · networks only.
    assert "Daily" not in body["summary"] and "07:00" not in body["summary"]
    assert not body["summary"].startswith("SOC")
    assert body["delivery_mode"] == "daily"
    assert any(k.startswith("Email · soc@example.com") for k in body["destination_kinds"])
    assert "Slack" in body["destination_kinds"]
    dests = {d["kind"]: d for d in body["destinations"]}
    assert dests["email"]["target"] == "soc@example.com"
    assert dests["slack"]["has_url"] is True
    assert dests["slack"]["url_hint"] and "secretXXX" not in (dests["slack"]["url_hint"] or "")
    assert "url" not in dests["slack"] or dests["slack"].get("url") in (None, "")

    gid = body["id"]
    r = client.patch(f"/api/recipient-groups/{gid}", json={"enabled": False}, headers=h)
    assert r.status_code == 200 and r.json()["enabled"] is False

    # Slack URL must never appear in list output
    listed = client.get("/api/recipient-groups", headers=h).json()
    blob = json.dumps(listed)
    assert "secretXXX" not in blob

    r = client.delete(f"/api/recipient-groups/{gid}", headers=h)
    assert r.status_code == 204


def test_default_group_cannot_be_deleted(client, db):
    # Ensure a default group exists (migration may have created one; create if missing)
    g = db.scalar(select(RecipientGroup).where(RecipientGroup.is_default.is_(True)))
    if g is None:
        g = _group(db, name="Email digest", is_default=True, delivery_mode=DELIVERY_DAILY, digest_time="08:00")
        db.commit()
    r = client.delete(f"/api/recipient-groups/{g.id}", headers=csrf(client))
    assert r.status_code == 400


def test_group_test_uses_destinations_without_logging_url(client, monkeypatch):
    h = csrf(client)
    posted: list[tuple[str, dict | None]] = []

    def fake_post(url, payload, *, secret, raw=None):
        posted.append((url, payload))
        return None

    monkeypatch.setattr(channels, "_post_json", fake_post)
    r = client.post(
        "/api/recipient-groups",
        json={
            "name": "Teams ops",
            "delivery_mode": "immediate",
            "destinations": [
                {"kind": "teams", "url": "https://outlook.office.example/webhook/SECRETTOKEN"},
            ],
        },
        headers=h,
    )
    assert r.status_code == 201, r.text
    gid = r.json()["id"]
    r = client.post(f"/api/recipient-groups/{gid}/test", headers=h)
    assert r.status_code == 200 and r.json()["ok"] is True
    assert posted and posted[0][0].endswith("SECRETTOKEN")
    assert posted[0][1]["@type"] == "MessageCard"
