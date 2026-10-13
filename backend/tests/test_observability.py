"""Observability: request ids, liveness, structured log fields, safe diagnostics and enrichment signals."""
from __future__ import annotations

import json
import logging
import smtplib
import ssl

import pytest
from fastapi.testclient import TestClient

from app import metrics
from app.api.auth import limiter
from app.config import reset_settings_cache
from app.core.notify import SmtpConfigError, smtp_failure_reason
from app.logging_setup import JsonFormatter, RequestContextFilter
from app.main import app
from app.request_context import bind_request_id, request_id_from, unbind_request_id


@pytest.fixture
def client(db_env):
    limiter.reset()
    with TestClient(app) as c:
        yield c


def admin(c: TestClient) -> dict:
    assert c.post("/api/setup/admin", json={"username": "admin", "password": "correct-horse-1"}).status_code == 200
    return {"X-CSRF-Token": c.cookies.get("nf_csrf", "")}


# --- request id ------------------------------------------------------------------------------------
def test_request_id_is_generated_and_echoed(client):
    r = client.get("/api/live")
    rid = r.headers["X-Request-Id"]
    assert len(rid) == 32 and int(rid, 16) >= 0
    assert client.get("/api/live").headers["X-Request-Id"] != rid  # one per request

    r = client.get("/api/health", headers={"X-Request-Id": "ui-1234.abcd"})
    assert r.headers["X-Request-Id"] == "ui-1234.abcd"
    assert client.get("/api/nosuch", headers={"X-Request-Id": "ui-err"}).headers["X-Request-Id"] == "ui-err"


@pytest.mark.parametrize("bad", ["has space", "x" * 65, "line\nbreak", "quote\"", ""])
def test_unsafe_client_request_ids_are_replaced(bad):
    rid = request_id_from(bad)
    assert rid != bad and len(rid) == 32


def test_request_id_reaches_log_records_inside_a_request(client):
    seen: list[str | None] = []
    real = JsonFormatter()

    class Capture(logging.Handler):
        def emit(self, record):
            seen.append(json.loads(real.format(record)).get("request_id"))

    handler = Capture()
    handler.addFilter(RequestContextFilter())
    logger = logging.getLogger("app.perf")
    logger.addHandler(handler)
    level = logger.level
    logger.setLevel(logging.DEBUG)  # every API request then logs its timing on app.perf
    try:
        client.get("/api/live", headers={"X-Request-Id": "trace-42"})
    finally:
        logger.setLevel(level)
        logger.removeHandler(handler)
    assert "trace-42" in seen


# --- liveness vs readiness ----------------------------------------------------------------------------
def test_live_does_not_touch_the_database(client, monkeypatch):
    def boom():
        raise AssertionError("liveness must not check the database")

    monkeypatch.setattr("app.api.system.check_db", boom)
    r = client.get("/api/live")
    assert r.status_code == 200 and r.json()["status"] == "ok" and r.json()["version"]


def test_health_stays_db_coupled_readiness(client, monkeypatch):
    monkeypatch.setattr("app.api.system.check_db", lambda: (False, "down"))
    assert client.get("/api/health").status_code == 503
    assert client.get("/api/live").status_code == 200


# --- structured logs ---------------------------------------------------------------------------------
def _record(**extra) -> logging.LogRecord:
    record = logging.LogRecord("app.test", logging.INFO, __file__, 1, "hello", (), None)
    record.__dict__.update(extra)
    return record


def test_json_logs_carry_identity_and_allowlisted_extras():
    payload = json.loads(JsonFormatter().format(_record(user="admin", scan_id=7, password="hunter2")))
    assert payload["service"] == "portreveal" and payload["version"] and payload["host"] and payload["pid"]
    assert payload["user"] == "admin" and payload["scan_id"] == 7
    assert "password" not in payload  # only allowlisted extras are emitted


def test_context_filter_stamps_current_request_id():
    record = _record()
    token = bind_request_id("abc123")
    try:
        RequestContextFilter().filter(record)
    finally:
        unbind_request_id(token)
    assert json.loads(JsonFormatter().format(record))["request_id"] == "abc123"

    outside = _record()
    RequestContextFilter().filter(outside)
    assert "request_id" not in json.loads(JsonFormatter().format(outside))


def test_slow_request_log_omits_query_values(client, monkeypatch, caplog):
    monkeypatch.setenv("SLOW_REQUEST_MS", "0")
    reset_settings_cache()
    with caplog.at_level(logging.WARNING, logger="app.perf"):
        client.get("/api/live", params={"q": "hostname:secret-box", "page": "2"})
    messages = [r.getMessage() for r in caplog.records if r.name == "app.perf"]
    assert messages and all("secret-box" not in m for m in messages)
    assert any("/api/live?page&q " in m for m in messages)


# --- metrics -------------------------------------------------------------------------------------------
def test_http_metrics_use_route_templates_not_raw_urls(client):
    metrics.reset()
    h = admin(client)
    client.get("/api/devices/does-not-exist")
    client.get("/api/v1/devices/also-missing")
    client.get("/api/definitely/not/a/route")
    text = client.get("/api/metrics", headers=h).text
    assert 'nf_http_requests_total{method="GET",route="/api/devices/{uuid}",status="404"} 2' in text
    assert "does-not-exist" not in text and "also-missing" not in text
    assert 'route="unmatched"' in text or 'route="/{path:path}"' in text


def test_enrichment_failures_are_counted_and_warned(db, monkeypatch, caplog):
    from types import SimpleNamespace

    from app.core import intel
    from app.models import Device

    for i in range(6):
        db.add(Device(current_ip=f"192.0.2.{i + 1}", status="active"))
    db.flush()
    ids = [d.id for d in db.query(Device).all()]

    def failing(*_a):
        raise OSError("probe failed")

    monkeypatch.setattr("app.scanner.scanner_status", lambda *a, **k: SimpleNamespace(effective_mode="nmap"))
    monkeypatch.setattr("app.core.tls_probe.enrich_device_tls", failing)
    monkeypatch.setattr("app.core.ssh_keys.enrich_device_ssh", lambda *_a: None)
    metrics.reset()
    with caplog.at_level(logging.WARNING, logger="app.core.intel"):
        intel._enrich_open_services(db, ids, scan_id=99)
    warnings = [r.getMessage() for r in caplog.records if r.levelno == logging.WARNING]
    assert warnings == ["scan 99: TLS enrichment failed for 6 of 6 devices (enable DEBUG for details)"]
    assert 'nf_enrich_failures_total{probe="tls"} 6' in metrics.render(db)


def test_image_soft_fail_is_counted(db):
    from app.core.image_intel import average_hash

    metrics.reset()
    assert average_hash(b"not an image") is None
    assert 'nf_enrich_failures_total{probe="image_hash"} 1' in metrics.render(db)


# --- admin diagnostics return classified messages --------------------------------------------------------
@pytest.mark.parametrize("exc,expected", [
    (SmtpConfigError("No recipients configured"), "No recipients configured"),
    (smtplib.SMTPAuthenticationError(535, b"5.7.8 bad credentials for alice@corp.example"), "authentication failed"),
    (smtplib.SMTPRecipientsRefused({"ops@corp.example": (550, b"no such user")}), "refused the recipient"),
    (ssl.SSLCertVerificationError("certificate verify failed: mail.corp.example"), "TLS"),
    (TimeoutError("timed out"), "timed out"),
    (ConnectionRefusedError(10061, "refused"), "refused the connection"),
    (OSError("network unreachable"), "could not connect"),
    (ValueError("internal detail"), "unexpected error"),
])
def test_smtp_failures_are_classified(exc, expected):
    reason = smtp_failure_reason(exc)
    assert expected in reason
    assert "corp.example" not in reason and "internal detail" not in reason


def test_smtp_test_endpoint_hides_raw_error_from_ui_and_audit(client, monkeypatch):
    h = admin(client)
    cfg = {"enabled": False, "smtp_host": "smtp.example.test", "recipients": ["ops@example.test"]}
    assert client.put("/api/settings/notifications", json=cfg, headers=h).status_code == 200

    def refuse(*_a, **_k):
        raise smtplib.SMTPAuthenticationError(535, b"5.7.8 credentials invalid for svc-mailer@corp.example")

    monkeypatch.setattr("app.api.settings.send_email", refuse)
    body = client.post("/api/settings/notifications/test", json={}, headers=h).json()
    assert body == {"ok": False, "message": "Sending failed: authentication failed (check username and password)."}
    entry = client.get("/api/audit", params={"q": "smtp_test"}).json()["items"][0]
    assert json.loads(entry["details"]) == {"ok": False, "error": "authentication failed (check username and password)",
                                "error_type": "SMTPAuthenticationError"}
    assert "corp.example" not in json.dumps(entry)
