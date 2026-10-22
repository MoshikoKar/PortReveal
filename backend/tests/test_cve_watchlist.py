"""CVE watchlist: validation, detection hooks, dedupe/reopen, and best-effort delivery."""
from __future__ import annotations

from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from app.api.auth import limiter
from app.core.vuln.lifecycle import sync_finding_lifecycle
from app.core.vuln.watchlist import (
    check_watchlist,
    parse_cve_ids,
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
    with pytest.raises(ValueError):
        parse_cve_ids("CVE-2026-1")  # too few digits in the serial


def test_api_bulk_add_list_status_pending_and_found(admin, db):
    r = admin.post("/api/cve-watchlist", headers=csrf(admin),
                   json={"cve_ids": "CVE-2026-109618 CVE-2026-109619"})
    assert r.status_code == 201
    body = r.json()
    assert {e["cve_id"] for e in body} == {"CVE-2026-109618", "CVE-2026-109619"}
    assert all(e["status"] == "pending" for e in body)

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
    assert found["CVE-2026-109619"]["status"] == "pending"


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


def test_email_and_webhook_failure_does_not_break_check(admin, db):
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

    with patch("app.core.notify.send_email", side_effect=RuntimeError("smtp down")), \
         patch("app.core.webhooks.deliver_event", side_effect=RuntimeError("hook down")):
        stats = check_watchlist(db, cve_ids=["CVE-2026-999999"], now=utcnow())
        db.commit()
    assert stats["alerted"] == 1
    assert db.query(Event).filter_by(event_type=EV_CVE_WATCH_MATCH).count() >= 1


def test_patch_and_delete(admin, db):
    created = admin.post("/api/cve-watchlist", headers=csrf(admin),
                         json={"cve_ids": "CVE-2026-109618", "note": "keep"}).json()
    entry_id = created[0]["id"]
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
