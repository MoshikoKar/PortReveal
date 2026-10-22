"""Network name charset: create/rename reject non-English characters; legacy names stay editable."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.api.auth import limiter
from app.main import app
from app.models import Network
from app.netutils import (
    NETWORK_NAME_CHARS_MSG,
    NETWORK_NAME_EMPTY_MSG,
    NETWORK_NAME_MAX,
    NETWORK_NAME_MAX_MSG,
    trim_network_name,
    validate_network_name,
)


@pytest.fixture
def client(db_env):
    limiter.reset()
    with TestClient(app) as c:
        yield c


def csrf(c: TestClient) -> dict:
    return {"X-CSRF-Token": c.cookies.get("nf_csrf", "")}


def setup_admin(c: TestClient):
    assert c.post("/api/setup/admin", json={"username": "admin", "password": "correct-horse-1"}).status_code == 200


def assert_plain_422(r, message: str) -> None:
    """Charset / empty / length errors use HTTPException plain message, not pydantic loc lists."""
    assert r.status_code == 422, r.text
    body = r.json()
    assert body["code"] == "validation_error"
    assert body["message"] == message
    assert body["detail"] == message
    assert not isinstance(body["detail"], list)


@pytest.mark.parametrize(
    "name",
    ["Office LAN", "Lab-1", "Site_A", "HQ (VPN)", "net.v2", "Trimmed"],
)
def test_validate_network_name_accepts_allowed_chars(name):
    assert validate_network_name(f"  {name}  ") == name
    assert validate_network_name(f"\ufeff{name}\ufeff") == name


@pytest.mark.parametrize(
    "name",
    ["רשת", "Lab 🌐", "Lab@Home", "Lab#1", "café", "net/1"],
)
def test_validate_network_name_rejects_disallowed(name):
    with pytest.raises(ValueError, match="English letters"):
        validate_network_name(name)


def test_trim_network_name_strips_bom_and_whitespace():
    assert trim_network_name("\ufeff  Lab  \ufeff") == "Lab"
    assert trim_network_name("\ufeff") == ""


def test_create_accepts_valid_name(client):
    setup_admin(client)
    h = csrf(client)
    r = client.post("/api/networks", json={"name": "Office LAN", "cidr": "10.10.0.0/24"}, headers=h)
    assert r.status_code == 201, r.text
    assert r.json()["name"] == "Office LAN"


def test_create_accepts_bom_prefixed_name(client):
    setup_admin(client)
    h = csrf(client)
    r = client.post("/api/networks", json={"name": "\ufeffOffice BOM", "cidr": "10.10.1.0/24"}, headers=h)
    assert r.status_code == 201, r.text
    assert r.json()["name"] == "Office BOM"


@pytest.mark.parametrize(
    "name",
    ["רשת משרד", "Lab 🌐", "Lab@Home", "Site#1"],
)
def test_create_rejects_hebrew_emoji_and_symbols(client, name):
    setup_admin(client)
    h = csrf(client)
    r = client.post("/api/networks", json={"name": name, "cidr": "10.11.0.0/24"}, headers=h)
    assert_plain_422(r, NETWORK_NAME_CHARS_MSG)


@pytest.mark.parametrize("name", ["", "   ", "\ufeff", "\ufeff  \ufeff"])
def test_create_rejects_empty_with_plain_422(client, name):
    setup_admin(client)
    h = csrf(client)
    r = client.post("/api/networks", json={"name": name, "cidr": "10.11.1.0/24"}, headers=h)
    assert_plain_422(r, NETWORK_NAME_EMPTY_MSG)


def test_create_rejects_too_long_after_trim_with_plain_422(client):
    setup_admin(client)
    h = csrf(client)
    too_long = "  " + ("a" * (NETWORK_NAME_MAX + 1)) + "  "
    r = client.post("/api/networks", json={"name": too_long, "cidr": "10.11.2.0/24"}, headers=h)
    assert_plain_422(r, NETWORK_NAME_MAX_MSG)
    ok = "  " + ("b" * NETWORK_NAME_MAX) + "  "
    r = client.post("/api/networks", json={"name": ok, "cidr": "10.11.3.0/24"}, headers=h)
    assert r.status_code == 201, r.text
    assert r.json()["name"] == "b" * NETWORK_NAME_MAX


def test_rename_to_invalid_name_is_rejected(client, db):
    setup_admin(client)
    h = csrf(client)
    net = client.post("/api/networks", json={"name": "Lab", "cidr": "10.12.0.0/24"}, headers=h).json()
    r = client.put(
        f"/api/networks/{net['id']}",
        json={"name": "רשת", "cidr": "10.12.0.0/24", "enabled": True},
        headers=h,
    )
    assert_plain_422(r, NETWORK_NAME_CHARS_MSG)
    db.expire_all()
    assert db.get(Network, net["id"]).name == "Lab"


def test_edit_other_fields_keeps_legacy_name(client, db):
    """Existing networks with non-ASCII names remain readable and updatable when the name is unchanged."""
    setup_admin(client)
    h = csrf(client)
    legacy = Network(name="רשת ישנה", cidr="10.13.0.0/24", description="legacy", enabled=True)
    db.add(legacy)
    db.commit()
    nid = legacy.id

    listed = {n["name"]: n for n in client.get("/api/networks").json()}
    assert "רשת ישנה" in listed

    r = client.put(
        f"/api/networks/{nid}",
        json={"name": "רשת ישנה", "cidr": "10.13.0.0/24", "description": "updated note", "enabled": False},
        headers=h,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["name"] == "רשת ישנה"
    assert body["description"] == "updated note"
    assert body["enabled"] is False

    r = client.put(
        f"/api/networks/{nid}",
        json={"name": "רשת חדשה", "cidr": "10.13.0.0/24", "enabled": True},
        headers=h,
    )
    assert_plain_422(r, NETWORK_NAME_CHARS_MSG)
    db.expire_all()
    assert db.get(Network, nid).name == "רשת ישנה"


def test_edit_other_fields_with_legacy_trailing_space(client, db):
    """Form trims the name; server must treat trimmed incoming == stored.strip() as unchanged."""
    setup_admin(client)
    h = csrf(client)
    legacy = Network(name="רשת ישנה ", cidr="10.14.0.0/24", description="padded", enabled=True)
    db.add(legacy)
    db.commit()
    nid = legacy.id

    r = client.put(
        f"/api/networks/{nid}",
        json={"name": "רשת ישנה", "cidr": "10.14.0.0/24", "description": "still legacy", "enabled": False},
        headers=h,
    )
    assert r.status_code == 200, r.text
    assert r.json()["name"] == "רשת ישנה "
    assert r.json()["description"] == "still legacy"
    assert r.json()["enabled"] is False
    db.expire_all()
    assert db.get(Network, nid).name == "רשת ישנה "
