"""Round-trip inventory export/import."""
from __future__ import annotations

import io

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select, update

from app.api.auth import limiter
from app.core.data_transfer import DataTransferError, export_inventory, import_inventory
from app.main import app
from app.models import Device, DevicePort, Event, Exclusion, Network, Scan, Snapshot, User
from app.settings_store import NotificationSettings, get_section, put_section

from .helpers import ScriptedScanner, host, make_network, port, scan


def csrf(c: TestClient) -> dict:
    return {"X-CSRF-Token": c.cookies.get("nf_csrf", "")}


def setup_admin(c: TestClient, username="admin", password="correct-horse-1"):
    r = c.post("/api/setup/admin", json={"username": username, "password": password})
    assert r.status_code == 200, r.text
    return r.json()


@pytest.fixture
def client(db_env):
    limiter.reset()
    with TestClient(app) as c:
        yield c


def _seed_inventory(db):
    db.add(Exclusion(value="10.0.0.99", description="skip", enabled=True))
    db.commit()
    net = make_network(db, cidr="10.0.0.0/24", name="Lab")
    hosts = [
        host("10.0.0.1", [port(22, "ssh", "OpenSSH", "8.0")], mac="00:11:22:33:44:01", hostname="gw"),
        host("10.0.0.2", [port(80, "http")], mac="00:11:22:33:44:02", hostname="web"),
    ]
    s1 = scan(ScriptedScanner(hosts), network_id=net.id)
    # Second scan opens a new port so change events exist in history
    s2 = scan(
        ScriptedScanner([
            host("10.0.0.1", [port(22, "ssh", "OpenSSH", "8.0"), port(443, "https")],
                 mac="00:11:22:33:44:01", hostname="gw"),
            host("10.0.0.2", [port(80, "http")], mac="00:11:22:33:44:02", hostname="web"),
        ]),
        network_id=net.id,
    )
    db.expire_all()
    return net, s1, s2


def test_export_import_round_trip_preserves_ids_and_skips_users_settings(db, tmp_path):
    put_section(db, NotificationSettings(enabled=False, smtp_host="keep.example", recipients=["a@x.local"]))
    db.add(User(username="prod-admin", password_hash="x", role="admin", source="local"))
    db.commit()

    net, s1, s2 = _seed_inventory(db)
    device_count = db.scalar(select(func.count(Device.id)))
    port_count = db.scalar(select(func.count(DevicePort.id)))
    event_count = db.scalar(select(func.count(Event.id)))
    snap_count = db.scalar(select(func.count(Snapshot.id)))
    assert device_count == 2 and port_count >= 2 and event_count >= 1 and snap_count == 1

    device_ids = sorted(db.scalars(select(Device.id)).all())
    device_uuids = {d.id: d.uuid for d in db.scalars(select(Device)).all()}
    baseline = db.get(Network, net.id).baseline_scan_id
    assert baseline == s1.id

    zip_path = tmp_path / "inv.zip"
    export_inventory(db, zip_path)
    assert zip_path.is_file() and zip_path.stat().st_size > 0

    db.execute(update(Device).values(hostname="mutated"))
    db.commit()

    result = import_inventory(db, zip_path, confirm=True)
    db.commit()
    db.expire_all()

    assert result["imported"]["devices"] == 2
    assert result["imported"]["scans"] >= 2
    assert result["imported"]["networks"] == 1
    assert result["imported"]["exclusions"] == 1

    assert sorted(db.scalars(select(Device.id)).all()) == device_ids
    for d in db.scalars(select(Device)).all():
        assert d.uuid == device_uuids[d.id]
        assert d.hostname != "mutated"
    restored_net = db.scalar(select(Network).where(Network.name == "Lab"))
    assert restored_net is not None
    assert restored_net.baseline_scan_id == s1.id
    assert db.scalar(select(func.count(Snapshot.id))) == 1
    assert db.scalar(select(func.count(Event.id))) == event_count
    assert db.get(Scan, s2.id) is not None

    assert db.scalar(select(User).where(User.username == "prod-admin")) is not None
    assert get_section(db, NotificationSettings).smtp_host == "keep.example"


def test_import_requires_confirm(db, tmp_path):
    _seed_inventory(db)
    path = tmp_path / "inv.zip"
    export_inventory(db, path)
    with pytest.raises(DataTransferError, match="confirm"):
        import_inventory(db, path, confirm=False)


def test_import_refuses_active_scan(db, tmp_path):
    _seed_inventory(db)
    path = tmp_path / "inv.zip"
    export_inventory(db, path)
    db.add(Scan(scan_type="standard", status="running", network_id=None))
    db.commit()
    with pytest.raises(DataTransferError, match="queued or running"):
        import_inventory(db, path, confirm=True)


def test_api_export_import(client, db):
    setup_admin(client)
    _seed_inventory(db)

    er = client.get("/api/data/export")
    assert er.status_code == 200
    assert er.headers["content-type"].startswith("application/zip")
    assert er.content[:2] == b"PK"

    bad = client.post(
        "/api/data/import",
        files={"file": ("inv.zip", io.BytesIO(er.content), "application/zip")},
        headers=csrf(client),
    )
    assert bad.status_code == 400

    ok = client.post(
        "/api/data/import",
        data={"confirm": "true"},
        files={"file": ("inv.zip", io.BytesIO(er.content), "application/zip")},
        headers=csrf(client),
    )
    assert ok.status_code == 200, ok.text
    body = ok.json()
    assert body["imported"]["networks"] >= 1
    assert body["imported"]["devices"] == 2
