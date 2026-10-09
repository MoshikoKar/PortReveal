"""Operations: production boot checks, restart recovery, and the metrics endpoint."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app import metrics
from app.api.auth import limiter
from app.config import SECRET_KEY_PLACEHOLDER, ConfigError, Settings, check_production_config
from app.core.manager import manager
from app.core.web_capture import web_capture_manager
from app.main import app
from app.models import Scan, WebCapture

from .helpers import ScriptedScanner, host, make_network, port, scan


# --- production boot checks ------------------------------------------------------------------------
@pytest.mark.parametrize("secret", ["", "   ", SECRET_KEY_PLACEHOLDER])
def test_production_refuses_to_boot_without_a_secret_key(tmp_path, secret):
    s = Settings(_env_file=None, app_env="production", app_secret_key=secret, data_dir=str(tmp_path))
    with pytest.raises(ConfigError, match="openssl rand -hex 32"):
        check_production_config(s)


def test_production_boot_error_points_at_the_generated_key_file(tmp_path):
    (tmp_path / ".secret_key").write_text("abc")
    s = Settings(_env_file=None, app_env="production", app_secret_key="", data_dir=str(tmp_path))
    with pytest.raises(ConfigError, match=r"\.secret_key: set APP_SECRET_KEY to its contents"):
        check_production_config(s)


def test_secret_key_check_passes_with_a_key_or_outside_production(tmp_path):
    check_production_config(Settings(_env_file=None, app_env="production", app_secret_key="k" * 64,
                                     data_dir=str(tmp_path)))
    check_production_config(Settings(_env_file=None, app_env="development", app_secret_key="", data_dir=str(tmp_path)))


# --- restart recovery (single process: a crash or kill mid-scan is recovered on the next start) --------
def test_restart_fails_in_flight_jobs_and_keeps_the_queue(db):
    net = make_network(db)
    db.add_all([
        Scan(scan_type="standard", status="running", network_id=net.id, stage="service scan", progress=0.4),
        Scan(scan_type="discovery", status="queued", network_id=net.id),
        WebCapture(targets="10.0.0.1", status="running"),
        WebCapture(targets="10.0.0.2", status="queued"),
    ])
    db.commit()

    manager.recover_interrupted()
    web_capture_manager.recover_interrupted()

    db.expire_all()
    running, queued = db.scalars(select(Scan).order_by(Scan.id)).all()
    assert (running.status, running.stage, running.error) == ("failed", None, "Interrupted by an application restart")
    assert running.finished_at is not None
    assert queued.status == "queued"  # still picked up by the worker after the restart
    assert manager._next_queued() == queued.id
    cap_running, cap_queued = db.scalars(select(WebCapture).order_by(WebCapture.id)).all()
    assert (cap_running.status, cap_running.error) == ("failed", "Interrupted by an application restart")
    assert cap_queued.status == "queued"


def test_inventory_survives_an_interrupted_scan(db):
    net = make_network(db)
    scan(ScriptedScanner([host("10.0.0.1", [port(22, "ssh")])]), network_id=net.id)
    db.add(Scan(scan_type="standard", status="running", network_id=net.id))
    db.commit()
    manager.recover_interrupted()
    # the next scan compares against the inventory from before the interruption
    s = scan(ScriptedScanner([host("10.0.0.1", [port(22, "ssh")])]), network_id=net.id)
    assert s.status == "completed" and s.events_count == 0


# --- metrics -----------------------------------------------------------------------------------------
@pytest.fixture
def client(db_env):
    limiter.reset()
    metrics.reset()
    with TestClient(app) as c:
        yield c


def test_metrics_require_auth_and_export_counters_and_gauges(client, db):
    assert client.get("/api/metrics").status_code == 401
    net = make_network(db)
    scan(ScriptedScanner([host("10.0.0.1", [port(22, "ssh")])]), network_id=net.id)
    db.add(Scan(scan_type="discovery", status="queued", network_id=net.id))
    db.commit()
    assert client.post("/api/setup/admin", json={"username": "admin", "password": "correct-horse-1"}).status_code == 200

    r = client.get("/api/metrics")
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/plain")
    lines = r.text.splitlines()
    assert 'nf_scans_finished_total{type="standard",status="completed"} 1' in lines
    assert "nf_scan_duration_seconds_count{type=\"standard\"} 1" in lines
    assert 'nf_scan_queue{state="queued"} 1' in lines
    assert 'nf_devices{status="active"} 1' in lines
    assert 'nf_http_requests_total{method="GET",status="401"} 1' in lines
    assert "# TYPE nf_http_requests_total counter" in lines


# --- graceful stop file (Windows run.ps1 -Stop) ------------------------------------------------------
def test_stop_file_raises_sigint_once_and_ignores_a_stale_request(tmp_path, monkeypatch):
    import signal
    import time

    from app import stopfile

    raised: list[int] = []
    monkeypatch.setattr(stopfile.signal, "raise_signal", raised.append)
    path = tmp_path / "network-finder.stop"
    path.write_text("left over from an earlier run")
    watcher = stopfile.StopFileWatcher(path, poll_seconds=0.02)
    watcher.start()
    try:
        assert not path.exists()  # stale request cleared at start
        time.sleep(0.1)
        assert raised == []
        path.write_text("stop")
        deadline = time.monotonic() + 2
        while not raised and time.monotonic() < deadline:
            time.sleep(0.02)
        assert raised == [signal.SIGINT]
        assert not path.exists()
    finally:
        watcher.stop()
