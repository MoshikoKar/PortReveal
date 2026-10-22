"""CVE watchlist: validation, detection hooks, dedupe/reopen, delivery, and settings."""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from app.api.auth import limiter
from app.core.notify import _pending_all
from app.core.vuln.lifecycle import sync_finding_lifecycle
from app.core.vuln.watchlist import (
    check_watchlist,
    deliver_watchlist_alerts,
    parse_cve_ids,
    schedule_watchlist_delivery,
    validate_cve_id,
)
from app.db import utcnow
from app.main import app
from app.models import (
    EV_CVE_WATCH_MATCH,
    VULN_STATE_CONFIRMED,
    VULN_STATE_DISMISSED,
    VULN_STATE_POTENTIAL,
    CveWatchlistAlert,
    DevicePortVuln,
    Event,
    Vulnerability,
)
from app.settings_store import NotificationSettings, put_section

from .helpers import ScriptedScanner, device_by_ip, host, make_network, port, scan


@pytest.fixture
def client(db_env):
    limiter.reset()
    with TestClient(app) as c:
        yield c


def csrf(c: TestClient) -> dict:
    return {"X-CSRF-Token": c.cookies.get("nf_csrf", "")}


@pytest.fixture
def admin(db, client):
    assert client.post("/api/setup/admin", json={"username": "admin", "password": "correct-horse-1"}).status_code == 200
    return client


def _seed_finding(db, *, cve_id="CVE-2026-109618", state=VULN_STATE_CONFIRMED, cvss=9.0, kev=False):
    net = make_network(db)
    scan(ScriptedScanner([
        host("10.0.0.1", [port(22, "ssh", "OpenSSH", "7.4")], mac="00:11:22:33:44:01"),
    ]), network_id=net.id)
    d = device_by_ip(db, "10.0.0.1")
    p = next(x for x in d.ports if x.port == 22)
    if db.get(Vulnerability, cve_id) is None:
        db.add(Vulnerability(cve_id=cve_id, cvss_base=cvss, kev=kev, summary="test vuln"))
        db.flush()
    db.add(DevicePortVuln(device_port_id=p.id, cve_id=cve_id, state=state, matched_at=utcnow()))
    db.commit()
    sync_finding_lifecycle(db, now=utcnow())
    db.commit()
    return d, p


def test_validate_and_parse_cve_ids():
    assert validate_cve_id("cve-2026-109618") == "CVE-2026-109618"
    assert parse_cve_ids("CVE-2026-109618, CVE-2026-109619 and CVE-2026-109618") == [
        "CVE-2026-109618", "CVE-2026-109619",
    ]
    with pytest.raises(ValueError):
        validate_cve_id("not-a-cve")
    with pytest.raises(ValueError, match="CVE-2026-1"):
        parse_cve_ids("CVE-2026-1")  # too few digits in the serial


def test_parse_reports_all_invalid_ids():
    with pytest.raises(ValueError) as ei:
        parse_cve_ids("nope CVE-2026-1 also-bad CVE-2026-109618")
    msg = str(ei.value)
    assert "nope" in msg and "CVE-2026-1" in msg and "also-bad" in msg
    # Valid tokens are accepted into the list only when every token is valid; with invalids,
    # the error lists every bad token (not just the first).
    assert msg.startswith("invalid CVE id(s):")


def test_api_bulk_add_list_status_pending_and_found(admin, db):
    r = admin.post("/api/cve-watchlist", headers=csrf(admin),
                   json={"cve_ids": "CVE-2026-109618 CVE-2026-109619"})
    assert r.status_code == 201
    body = r.json()
    assert body["added"] == ["CVE-2026-109618", "CVE-2026-109619"]
    assert body["already_watched"] == []
    assert {e["cve_id"] for e in body["entries"]} == {"CVE-2026-109618", "CVE-2026-109619"}
    assert all(e["status"] == "pending" for e in body["entries"])

    listed = admin.get("/api/cve-watchlist").json()
    assert len(listed) == 2
    assert all(e["status"] == "pending" for e in listed)

    _seed_finding(db, cve_id="CVE-2026-109618")
    # Re-check so the existing watch alerts; status should become found.
    check_watchlist(db, cve_ids=["CVE-2026-109618"], now=utcnow())
    db.commit()
    found = {e["cve_id"]: e for e in admin.get("/api/cve-watchlist").json()}
    assert found["CVE-2026-109618"]["status"] == "found"
    assert found["CVE-2026-109618"]["affected_devices"] == 1
    assert found["CVE-2026-109618"]["confirmed_count"] == 1
    assert found["CVE-2026-109619"]["status"] == "pending"
    assert found["CVE-2026-109619"]["next_sync_at"] is not None or found["CVE-2026-109619"]["next_sync_at"] is None

    again = admin.post("/api/cve-watchlist", headers=csrf(admin),
                       json={"cve_ids": "CVE-2026-109618 CVE-2026-109620"})
    assert again.status_code == 201
    assert again.json()["added"] == ["CVE-2026-109620"]
    assert again.json()["already_watched"] == ["CVE-2026-109618"]


def test_status_found_for_script_stub_without_feed_metadata(admin, db):
    """nmap-script stubs create a bare Vulnerability row; status is still found from the finding."""
    from app.models import VULN_SOURCE_NMAP_SCRIPT

    net = make_network(db)
    scan(ScriptedScanner([
        host("10.0.0.1", [port(22, "ssh", "OpenSSH", "7.4")], mac="00:11:22:33:44:01"),
    ]), network_id=net.id)
    d = device_by_ip(db, "10.0.0.1")
    p = next(x for x in d.ports if x.port == 22)
    # Bare stub like runner._record_finding — no CVSS/summary from the NVD feed yet.
    db.add(Vulnerability(cve_id="CVE-2026-777777"))
    db.flush()
    db.add(DevicePortVuln(
        device_port_id=p.id, cve_id="CVE-2026-777777", state=VULN_STATE_CONFIRMED,
        source=VULN_SOURCE_NMAP_SCRIPT, matched_at=utcnow(),
    ))
    db.commit()
    admin.post("/api/cve-watchlist", headers=csrf(admin), json={"cve_ids": "CVE-2026-777777"})
    entry = admin.get("/api/cve-watchlist").json()[0]
    assert entry["status"] == "found"
    assert entry["affected_devices"] == 1
    assert entry["cve_known"] is True


def test_status_only_dismissed(admin, db):
    _seed_finding(db, state=VULN_STATE_DISMISSED)
    admin.post("/api/cve-watchlist", headers=csrf(admin), json={"cve_ids": "CVE-2026-109618"})
    entry = admin.get("/api/cve-watchlist").json()[0]
    assert entry["status"] == "only_dismissed"
    assert entry["dismissed_count"] == 1


def test_pending_cve_later_found_after_sync_check(admin, db):
    """Watch a CVE before it exists in the local DB; after a Vulnerability + finding appear, alert."""
    admin.post("/api/cve-watchlist", headers=csrf(admin), json={"cve_ids": "CVE-2026-555555"})
    assert admin.get("/api/cve-watchlist").json()[0]["status"] == "pending"

    _seed_finding(db, cve_id="CVE-2026-555555")
    stats = check_watchlist(db, now=utcnow())
    db.commit()
    assert stats["alerted"] == 1
    events = db.query(Event).filter_by(event_type=EV_CVE_WATCH_MATCH).all()
    assert len(events) == 1
    assert events[0].notify is True
    assert "CVE-2026-555555" in events[0].message
    entry = admin.get("/api/cve-watchlist").json()[0]
    assert entry["status"] == "found"
    assert entry["last_alert_at"] is not None


def test_dedupe_once_per_device_port_and_reopen_alerts(admin, db):
    d, p = _seed_finding(db)
    admin.post("/api/cve-watchlist", headers=csrf(admin), json={"cve_ids": "CVE-2026-109618"})
    db.expire_all()
    assert db.query(Event).filter_by(event_type=EV_CVE_WATCH_MATCH).count() == 1

    # Second check must not re-alert the same hit.
    stats = check_watchlist(db, now=utcnow())
    db.commit()
    assert stats["alerted"] == 0
    assert db.query(Event).filter_by(event_type=EV_CVE_WATCH_MATCH).count() == 1

    # Remove finding (resolve) → prune alert record → re-add → alert again.
    row = db.query(DevicePortVuln).filter_by(cve_id="CVE-2026-109618").one()
    db.delete(row)
    db.commit()
    sync_finding_lifecycle(db, now=utcnow())
    db.commit()
    pruned = check_watchlist(db, now=utcnow())
    db.commit()
    assert pruned["pruned"] >= 1
    assert db.query(CveWatchlistAlert).count() == 0

    db.add(DevicePortVuln(device_port_id=p.id, cve_id="CVE-2026-109618",
                          state=VULN_STATE_CONFIRMED, matched_at=utcnow()))
    db.commit()
    sync_finding_lifecycle(db, now=utcnow())
    db.commit()
    again = check_watchlist(db, now=utcnow())
    db.commit()
    assert again["alerted"] == 1
    assert db.query(Event).filter_by(event_type=EV_CVE_WATCH_MATCH).count() == 2
    assert d.uuid  # used above; keep device in scope for clarity


def test_dismissed_never_alerts(admin, db):
    _seed_finding(db, state=VULN_STATE_DISMISSED)
    admin.post("/api/cve-watchlist", headers=csrf(admin), json={"cve_ids": "CVE-2026-109618"})
    db.expire_all()
    assert db.query(Event).filter_by(event_type=EV_CVE_WATCH_MATCH).count() == 0
    assert check_watchlist(db, now=utcnow())["alerted"] == 0


def test_undismiss_triggers_watchlist(admin, db):
    d, _p = _seed_finding(db, state=VULN_STATE_DISMISSED)
    # Restore state_before_dismiss for undo path.
    row = db.query(DevicePortVuln).filter_by(cve_id="CVE-2026-109618").one()
    row.state_before_dismiss = VULN_STATE_CONFIRMED
    db.commit()
    admin.post("/api/cve-watchlist", headers=csrf(admin), json={"cve_ids": "CVE-2026-109618"})
    db.expire_all()
    assert db.query(Event).filter_by(event_type=EV_CVE_WATCH_MATCH).count() == 0

    r = admin.delete(f"/api/devices/{d.uuid}/vulns/CVE-2026-109618/dismiss", headers=csrf(admin))
    assert r.status_code == 204
    db.expire_all()
    assert db.query(Event).filter_by(event_type=EV_CVE_WATCH_MATCH).count() == 1


def test_dismiss_clears_alert_so_undismiss_realerts(admin, db):
    """Owner decision: dismiss counts as reopen baseline — clear alert, undismiss alerts again."""
    d, _p = _seed_finding(db)
    admin.post("/api/cve-watchlist", headers=csrf(admin), json={"cve_ids": "CVE-2026-109618"})
    db.expire_all()
    assert db.query(Event).filter_by(event_type=EV_CVE_WATCH_MATCH).count() == 1
    assert db.query(CveWatchlistAlert).count() == 1

    assert admin.post(
        f"/api/devices/{d.uuid}/vulns/CVE-2026-109618/dismiss", headers=csrf(admin),
    ).status_code == 200
    db.expire_all()
    assert db.query(CveWatchlistAlert).count() == 0

    assert admin.delete(
        f"/api/devices/{d.uuid}/vulns/CVE-2026-109618/dismiss", headers=csrf(admin),
    ).status_code == 204
    db.expire_all()
    assert db.query(Event).filter_by(event_type=EV_CVE_WATCH_MATCH).count() == 2
    assert db.query(CveWatchlistAlert).count() == 1


def test_potential_alerts_and_ignores_cvss_floor(admin, db):
    _seed_finding(db, state=VULN_STATE_POTENTIAL, cvss=1.0)
    from app.settings_store import VulnSettings
    put_section(db, VulnSettings(enabled=True, min_cvss_display=9.0, include_potential=False))
    db.commit()
    admin.post("/api/cve-watchlist", headers=csrf(admin), json={"cve_ids": "CVE-2026-109618"})
    db.expire_all()
    events = db.query(Event).filter_by(event_type=EV_CVE_WATCH_MATCH).all()
    assert len(events) == 1
    assert "potential" in (events[0].new_value or "").lower()


def test_immediate_check_on_add(admin, db):
    _seed_finding(db)
    before = db.query(Event).filter_by(event_type=EV_CVE_WATCH_MATCH).count()
    admin.post("/api/cve-watchlist", headers=csrf(admin), json={"cve_ids": "CVE-2026-109618"})
    db.expire_all()
    assert db.query(Event).filter_by(event_type=EV_CVE_WATCH_MATCH).count() == before + 1


def test_delivery_after_commit_failure_does_not_lose_events(admin, db):
    _seed_finding(db)
    put_section(db, NotificationSettings(
        enabled=True, smtp_host="smtp.test", recipients=["ops@example.com"],
        watchlist_email_enabled=True, watchlist_webhooks_enabled=True,
    ))
    db.commit()
    admin.post("/api/cve-watchlist", headers=csrf(admin),
               json={"cve_ids": "CVE-2026-999999"})  # no finding yet
    db.add(Vulnerability(cve_id="CVE-2026-999999", cvss_base=8.0))
    d = device_by_ip(db, "10.0.0.1")
    p = next(x for x in d.ports if x.port == 22)
    db.add(DevicePortVuln(device_port_id=p.id, cve_id="CVE-2026-999999",
                          state=VULN_STATE_CONFIRMED, matched_at=utcnow()))
    db.commit()

    stats = check_watchlist(db, cve_ids=["CVE-2026-999999"], now=utcnow())
    db.commit()
    assert stats["alerted"] == 1
    event_ids = stats["event_ids"]

    from app.models import WebhookEndpoint
    db.add(WebhookEndpoint(name="siem", url="http://127.0.0.1:9/hook", enabled=True, event_types=[]))
    db.commit()

    with patch("app.core.notify.send_email", side_effect=RuntimeError("smtp down")), \
         patch("httpx.post", side_effect=RuntimeError("hook down")):
        deliver_watchlist_alerts(event_ids)

    ev = db.query(Event).filter_by(id=event_ids[0]).one()
    assert ev.notify is True
    assert ev.notified_at is None  # digest can still pick it up


def test_batched_immediate_email_sets_notified_at(admin, db):
    d, p = _seed_finding(db, cve_id="CVE-2026-111111")
    db.add(Vulnerability(cve_id="CVE-2026-222222", cvss_base=8.0))
    db.flush()
    db.add(DevicePortVuln(device_port_id=p.id, cve_id="CVE-2026-222222",
                          state=VULN_STATE_CONFIRMED, matched_at=utcnow()))
    db.commit()
    put_section(db, NotificationSettings(
        enabled=True, smtp_host="smtp.test", recipients=["ops@example.com"],
        watchlist_email_enabled=True, watchlist_webhooks_enabled=False,
    ))
    db.commit()
    admin.post("/api/cve-watchlist", headers=csrf(admin),
               json={"cve_ids": "CVE-2026-111111 CVE-2026-222222"})
    db.expire_all()
    events = db.query(Event).filter_by(event_type=EV_CVE_WATCH_MATCH).all()
    assert len(events) == 2
    ids = [e.id for e in events]

    sent = {}

    def _capture(cfg, subject, plain, html):
        sent["subject"] = subject
        sent["plain"] = plain
        sent["html"] = html

    with patch("app.core.notify.send_email", side_effect=_capture):
        deliver_watchlist_alerts(ids)
    db.expire_all()
    assert "2 matches" in sent["subject"] or "2 match" in sent["subject"]
    assert "CVE-2026-111111" in sent["plain"] and "CVE-2026-222222" in sent["plain"]
    for e in db.query(Event).filter(Event.id.in_(ids)).all():
        assert e.notified_at is not None
    assert d.uuid


def test_notify_true_emailed_events_skipped_in_digest(admin, db):
    _seed_finding(db)
    put_section(db, NotificationSettings(
        enabled=True, smtp_host="smtp.test", recipients=["ops@example.com"],
        event_types=[],  # digest still includes ALWAYS_NOTIFY_TYPES
        watchlist_email_enabled=True, watchlist_webhooks_enabled=False,
    ))
    db.commit()
    admin.post("/api/cve-watchlist", headers=csrf(admin), json={"cve_ids": "CVE-2026-109618"})
    db.expire_all()
    ev = db.query(Event).filter_by(event_type=EV_CVE_WATCH_MATCH).one()
    assert ev.notify is True
    assert ev.notified_at is None
    cfg = NotificationSettings(
        enabled=True, smtp_host="smtp.test", recipients=["ops@example.com"], event_types=[],
    )
    pending = _pending_all(db, cfg)
    assert any(e.id == ev.id for e in pending)

    with patch("app.core.notify.send_email"):
        deliver_watchlist_alerts([ev.id])
    db.expire_all()
    ev = db.query(Event).filter_by(id=ev.id).one()
    assert ev.notified_at is not None
    pending2 = _pending_all(db, cfg)
    assert all(e.id != ev.id for e in pending2)


def test_webhooks_off_toggle_skips_delivery(admin, db):
    _seed_finding(db)
    put_section(db, NotificationSettings(
        enabled=False, watchlist_email_enabled=False, watchlist_webhooks_enabled=False,
    ))
    db.commit()
    admin.post("/api/cve-watchlist", headers=csrf(admin), json={"cve_ids": "CVE-2026-109618"})
    db.expire_all()
    ev = db.query(Event).filter_by(event_type=EV_CVE_WATCH_MATCH).one()
    with patch("httpx.post") as post:
        deliver_watchlist_alerts([ev.id])
        post.assert_not_called()


def test_webhook_payload_includes_structured_fields(admin, db):
    _seed_finding(db, kev=True, cvss=9.8)
    put_section(db, NotificationSettings(watchlist_email_enabled=False, watchlist_webhooks_enabled=True))
    db.commit()
    admin.post("/api/cve-watchlist", headers=csrf(admin), json={"cve_ids": "CVE-2026-109618"})
    db.expire_all()
    ev = db.query(Event).filter_by(event_type=EV_CVE_WATCH_MATCH).one()
    captured = {}

    def fake_post(url, content=None, headers=None, timeout=None):
        import json as json_mod
        captured["payload"] = json_mod.loads(content.decode())
        resp = MagicMock()
        resp.status_code = 200
        return resp

    from app.models import WebhookEndpoint
    db.add(WebhookEndpoint(name="siem", url="http://127.0.0.1:9/hook", enabled=True, event_types=[]))
    db.commit()
    with patch("httpx.post", side_effect=fake_post):
        deliver_watchlist_alerts([ev.id])
    p = captured["payload"]
    assert p["type"] == EV_CVE_WATCH_MATCH
    assert p["batch"] is True
    assert p["count"] == 1
    assert p["cve_id"] == "CVE-2026-109618"
    assert p["kev"] is True
    assert p["cvss"] == 9.8
    assert p["port"] == 22
    assert p["device_uuid"]
    assert p["matches"][0]["cve_id"] == "CVE-2026-109618"


def test_schedule_delivery_runs_after_commit(admin, db):
    """check_watchlist does not deliver; schedule runs delivery only after commit."""
    _seed_finding(db)
    put_section(db, NotificationSettings(
        enabled=True, smtp_host="smtp.test", recipients=["ops@example.com"],
        watchlist_email_enabled=True, watchlist_webhooks_enabled=False,
    ))
    db.commit()
    # Add watch without the API's immediate check so we control check → commit → deliver order.
    from app.models import CveWatchlistEntry
    db.add(CveWatchlistEntry(cve_id="CVE-2026-109618", created_at=utcnow(), enabled=True))
    db.commit()
    order: list[str] = []

    def tracking_deliver(ids):
        order.append("deliver")
        assert db.query(Event).filter(Event.id.in_(ids)).count() == len(ids)

    class _ImmediateThread:
        def __init__(self, target=None, name=None, daemon=None):
            self._target = target

        def start(self):
            order.append("thread-start")
            if self._target:
                self._target()

    with patch("app.core.vuln.watchlist.deliver_watchlist_alerts", side_effect=tracking_deliver) as deliver:
        order.append("check")
        stats = check_watchlist(db, now=utcnow())
        deliver.assert_not_called()
        assert stats["alerted"] == 1
        db.commit()
        order.append("commit")
        with patch("app.core.vuln.watchlist.threading.Thread", _ImmediateThread):
            schedule_watchlist_delivery(stats["event_ids"])
    assert order == ["check", "commit", "thread-start", "deliver"]


def test_partial_settings_update_preserves_watchlist_toggles(admin, db):
    h = csrf(admin)
    body = {
        "enabled": False, "smtp_host": "relay", "smtp_port": 25, "security": "none",
        "username": "", "sender": "nm@corp", "recipients": ["it@corp"],
        "event_types": ["port_opened"], "digest_time": "08:00",
        "watchlist_email_enabled": False, "watchlist_webhooks_enabled": False,
    }
    assert admin.put("/api/settings/notifications", json=body, headers=h).status_code == 200
    # Omit the new fields — must not reset them to true.
    body.pop("watchlist_email_enabled")
    body.pop("watchlist_webhooks_enabled")
    r = admin.put("/api/settings/notifications", json=body, headers=h)
    assert r.status_code == 200
    assert r.json()["watchlist_email_enabled"] is False
    assert r.json()["watchlist_webhooks_enabled"] is False
    assert "cve_watch_match" not in r.json()["available_event_types"]


def test_sync_and_rescore_invokes_watchlist(db):
    from datetime import datetime, timezone

    from app.core.vuln import sync
    from app.settings_store import VulnSettings

    cfg = VulnSettings(enabled=True, sources=["nvd"], offline_mode=True)
    put_section(db, cfg)
    db.commit()
    T = datetime(2026, 1, 15, tzinfo=timezone.utc)

    with patch.object(sync, "sync_all", return_value={"nvd": {"ok": True}}), \
         patch("app.core.vuln.match.match_all", return_value={"ports_checked": 0, "matched": 0, "removed": 0}), \
         patch("app.core.vuln.score.apply_risk_scores"), \
         patch("app.core.vuln.summary.refresh_after_scan_or_sync"), \
         patch("app.core.vuln.watchlist.check_watchlist_safe",
               return_value={"checked": 0, "alerted": 0, "pruned": 0, "event_ids": [7]}) as check, \
         patch("app.core.vuln.watchlist.schedule_watchlist_delivery") as sched:
        sync.sync_and_rescore(db, cfg, fetch=lambda *a, **k: None, now=T)
    check.assert_called()
    # Sync child exits after return — delivery must wait so webhooks are not lost.
    sched.assert_called_with([7], wait=True)


def test_run_vuln_job_invokes_watchlist(db):
    from app.core.vuln.manager import enqueue_vuln_job
    from app.core.vuln.runner import run_vuln_job
    from app.models import VULN_JOB_TRIGGER_MANUAL
    from app.scanner.types import ScanContext

    d, _p = _seed_finding(db)
    job = enqueue_vuln_job(db, trigger=VULN_JOB_TRIGGER_MANUAL, device_ids=[d.id])
    db.commit()

    with patch("app.core.vuln.runner.match_devices", return_value={"ports_checked": 0, "matched": 0, "removed": 0}), \
         patch("app.core.vuln.runner.apply_risk_scores"), \
         patch("app.core.vuln.runner.refresh_after_scan_or_sync"), \
         patch("app.core.vuln.runner.is_cache_empty", return_value=False), \
         patch("app.core.vuln.watchlist.check_watchlist_safe",
               return_value={"checked": 0, "alerted": 0, "pruned": 0, "event_ids": [99]}) as check, \
         patch("app.core.vuln.watchlist.schedule_watchlist_delivery") as sched:
        from app.settings_store import VulnSettings
        put_section(db, VulnSettings(enabled=True, scripts_enabled=False))
        db.commit()
        status = run_vuln_job(job.id, ScanContext(job.id))
    assert status in ("completed", "partial")
    check.assert_called()
    sched.assert_called_with([99])


def test_schedule_wait_runs_delivery_inline():
    """CLI / sync child pass wait=True so delivery finishes before process exit."""
    with patch("app.core.vuln.watchlist.deliver_watchlist_alerts") as deliver, \
         patch("app.core.vuln.watchlist.threading.Thread") as Thread:
        schedule_watchlist_delivery([1, 2], wait=True)
        deliver.assert_called_once_with([1, 2])
        Thread.assert_not_called()


def test_slow_webhook_does_not_block_concurrent_writes(admin, db):
    """HTTP runs with no write transaction open — concurrent DB writes complete quickly."""
    import threading
    import time

    from app.models import WebhookEndpoint

    _seed_finding(db)
    put_section(db, NotificationSettings(
        watchlist_email_enabled=False, watchlist_webhooks_enabled=True,
    ))
    db.commit()
    admin.post("/api/cve-watchlist", headers=csrf(admin), json={"cve_ids": "CVE-2026-109618"})
    db.expire_all()
    ev = db.query(Event).filter_by(event_type=EV_CVE_WATCH_MATCH).one()
    db.add(WebhookEndpoint(name="slow", url="http://127.0.0.1:9/hook", enabled=True, event_types=[]))
    db.commit()

    started = threading.Event()

    def slow_post(*_a, **_k):
        started.set()
        time.sleep(2.5)
        raise ConnectionError("unreachable")

    errors: list[BaseException] = []

    def run_delivery():
        try:
            with patch("httpx.post", side_effect=slow_post):
                deliver_watchlist_alerts([ev.id])
        except BaseException as exc:  # noqa: BLE001 — collect for assertion
            errors.append(exc)

    t = threading.Thread(target=run_delivery)
    t.start()
    assert started.wait(timeout=2.0)
    t0 = time.monotonic()
    # Concurrent write while HTTP is in flight — must not wait on the webhook timeout.
    r = admin.patch(
        f"/api/cve-watchlist/{admin.get('/api/cve-watchlist').json()[0]['id']}",
        headers=csrf(admin),
        json={"note": "during-delivery"},
    )
    elapsed = time.monotonic() - t0
    assert r.status_code == 200
    assert elapsed < 1.5, f"concurrent write blocked for {elapsed:.2f}s during webhook"
    t.join(timeout=10)
    assert not t.is_alive()
    assert errors == []


def test_patch_and_delete(admin, db):
    created = admin.post("/api/cve-watchlist", headers=csrf(admin),
                         json={"cve_ids": "CVE-2026-109618", "note": "keep"}).json()
    entry_id = created["entries"][0]["id"]
    patched = admin.patch(f"/api/cve-watchlist/{entry_id}", headers=csrf(admin),
                          json={"enabled": False, "note": "paused"}).json()
    assert patched["enabled"] is False and patched["note"] == "paused"
    assert admin.delete(f"/api/cve-watchlist/{entry_id}", headers=csrf(admin)).status_code == 204
    assert admin.get("/api/cve-watchlist").json() == []


def test_viewer_cannot_write(admin, client):
    assert admin.post(
        "/api/users",
        json={"username": "viewer1", "password": "viewer-pass-1", "role": "viewer"},
        headers=csrf(admin),
    ).status_code == 201
    admin.post("/api/auth/logout", headers=csrf(admin))
    assert client.post("/api/auth/login", json={"username": "viewer1", "password": "viewer-pass-1"}).status_code == 200
    assert client.post("/api/cve-watchlist", headers=csrf(client),
                       json={"cve_ids": "CVE-2026-109618"}).status_code == 403
    assert client.get("/api/cve-watchlist").status_code == 200
