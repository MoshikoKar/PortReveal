"""User dashboard preferences: round-trip and validation."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.api.auth import limiter
from app.dashboard_prefs import MAX_PREFERENCES_BYTES
from app.main import app


@pytest.fixture
def client(db_env):
    limiter.reset()
    with TestClient(app) as c:
        yield c


def csrf(c: TestClient) -> dict:
    return {"X-CSRF-Token": c.cookies.get("nf_csrf", "")}


def setup_admin(c: TestClient):
    r = c.post("/api/setup/admin", json={"username": "admin", "password": "correct-horse-1"})
    assert r.status_code == 200, r.text
    assert c.post("/api/setup/complete", headers=csrf(c)).status_code == 200
    return r.json()["user"]


def _valid_dashboard(**overrides):
    dash = {
        "v": 2,
        "layouts": {
            "lg": [{"i": "kpis", "x": 0, "y": 0, "w": 24, "h": 8}],
            "md": [{"i": "kpis", "x": 0, "y": 0, "w": 20, "h": 8}],
            "sm": [{"i": "kpis", "x": 0, "y": 0, "w": 1, "h": 8}],
        },
        "hidden": ["networks"],
        "kpiVisible": ["known_hosts", "active"],
    }
    dash.update(overrides)
    return {"dashboard": dash}


def test_preferences_round_trip(client):
    setup_admin(client)
    me = client.get("/api/auth/me").json()["user"]
    assert me["preferences"] is None

    body = _valid_dashboard()
    r = client.put("/api/auth/me/preferences", json=body, headers=csrf(client))
    assert r.status_code == 200, r.text
    saved = r.json()["user"]["preferences"]
    assert saved["dashboard"]["v"] == 2
    assert saved["dashboard"]["hidden"] == ["networks"]
    assert saved["dashboard"]["kpiVisible"] == ["known_hosts", "active"]
    assert saved["dashboard"]["layouts"]["lg"][0]["i"] == "kpis"

    me2 = client.get("/api/auth/me").json()["user"]
    assert me2["preferences"] == saved


def test_rejects_unknown_widget_id(client):
    setup_admin(client)
    body = _valid_dashboard()
    body["dashboard"]["layouts"]["lg"].append({"i": "not_a_widget", "x": 0, "y": 8, "w": 8, "h": 10})
    r = client.put("/api/auth/me/preferences", json=body, headers=csrf(client))
    assert r.status_code == 422
    assert "widget" in r.json()["detail"].lower() or "unknown" in r.json()["detail"].lower()


def test_rejects_duplicate_ids(client):
    setup_admin(client)
    body = _valid_dashboard()
    body["dashboard"]["layouts"]["lg"] = [
        {"i": "kpis", "x": 0, "y": 0, "w": 24, "h": 8},
        {"i": "kpis", "x": 0, "y": 8, "w": 12, "h": 8},
    ]
    r = client.put("/api/auth/me/preferences", json=body, headers=csrf(client))
    assert r.status_code == 422
    assert "duplicate" in r.json()["detail"].lower()


def test_rejects_out_of_bounds(client):
    setup_admin(client)
    body = _valid_dashboard()
    body["dashboard"]["layouts"]["lg"] = [{"i": "kpis", "x": 20, "y": 0, "w": 24, "h": 8}]
    r = client.put("/api/auth/me/preferences", json=body, headers=csrf(client))
    assert r.status_code == 422


def test_rejects_v1_schema(client):
    setup_admin(client)
    r = client.put("/api/auth/me/preferences", json=_valid_dashboard(v=1), headers=csrf(client))
    assert r.status_code == 422
    assert "version" in r.json()["detail"].lower()


def test_rejects_unknown_keys(client):
    setup_admin(client)
    body = _valid_dashboard()
    body["extra"] = True
    r = client.put("/api/auth/me/preferences", json=body, headers=csrf(client))
    assert r.status_code == 422
    assert "unknown" in r.json()["detail"].lower()


def test_rejects_empty_kpi_visible(client):
    setup_admin(client)
    body = _valid_dashboard(kpiVisible=[])
    r = client.put("/api/auth/me/preferences", json=body, headers=csrf(client))
    assert r.status_code == 422


def test_rejects_oversized_payload(client):
    setup_admin(client)
    body = _valid_dashboard()
    # Pad via a huge hidden list is blocked by allowlist; use raw oversized by monkeypatching size check path.
    # Build a valid-looking payload that exceeds the byte limit after encoding.
    body["dashboard"]["layouts"]["lg"] = [
        {"i": "recent_changes", "x": 0, "y": 0, "w": 12, "h": 10},
    ]
    # Force size via many repeated layout items isn't allowed (duplicates). Patch limit instead.
    from app import dashboard_prefs as dp

    original = dp.MAX_PREFERENCES_BYTES
    try:
        # Temporarily shrink limit so a normal payload fails size check when we pass huge raw_bytes.
        # Call validator directly for the size case; API uses encoded length.
        with pytest.raises(dp.PreferencesValidationError, match="too large"):
            dp.validate_preferences_payload(body, raw_bytes=MAX_PREFERENCES_BYTES + 1)
    finally:
        assert dp.MAX_PREFERENCES_BYTES == original
