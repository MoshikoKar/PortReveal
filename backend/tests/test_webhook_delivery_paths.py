"""Tag / watch / presence events reach webhooks; batching, queue, hard HTTP deadline."""

from __future__ import annotations

import json
import queue
import threading
import time as time_mod
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest
from sqlalchemy import select

from app.core import webhooks
from app.core.intel import run_watches
from app.core.presence import evaluate_absence
from app.models import (
    EV_DEVICE_DISAPPEARED,
    EV_WATCH_MATCH,
    Event,
    SavedSearch,
    WebhookEndpoint,
)
from app.settings_store import NotificationSettings, put_section

from .helpers import ScriptedScanner, host, make_network, port, scan


@pytest.fixture(autouse=True)
def _webhooks_on(db, monkeypatch, request):
    put_section(db, NotificationSettings(webhooks_enabled=True))
    db.commit()
    # Drain any leftover queue jobs from prior tests so a delayed worker cannot race.
    q = webhooks._delivery_queue
    if q is not None:
        while True:
            try:
                q.get_nowait()
                q.task_done()
            except queue.Empty:
                break
    # Scans call schedule_event_delivery; keep that off unless the test is about the queue.
    if request.node.name not in {
        "test_schedule_returns_fast_with_trickling_endpoint",
        "test_queued_scan_work_not_delayed_by_slow_webhook",
        "test_healthy_hook_not_blocked_by_stuck_hook",
        "test_queue_full_surfaces_on_hook_status",
    }:
        monkeypatch.setattr(webhooks, "schedule_event_delivery", lambda *a, **k: None)


def _patch_http(monkeypatch, impl):
    """Route delivery through ``_http_post`` (url, body, headers, *, deadline) → status."""
    monkeypatch.setattr(webhooks, "_http_post", impl)


def test_deliver_batches_per_hook(db, monkeypatch):
    db.add(WebhookEndpoint(name="siem", url="https://hooks.example.com/batch", enabled=True))
    evs = [Event(event_type="port_opened", severity="high", ip="192.0.2.1", message=f"e{i}", notify=True) for i in range(3)]
    db.add_all(evs)
    db.commit()
    bodies = []

    def post(url, body, headers, *, deadline=8.0):
        bodies.append(json.loads(body))
        return 204

    _patch_http(monkeypatch, post)
    webhooks.deliver_event_ids([e.id for e in evs])
    assert len(bodies) == 1
    assert bodies[0]["batch"] is True and bodies[0]["count"] == 3 and len(bodies[0]["events"]) == 3


def test_deliver_splits_batches_over_cap(db, monkeypatch):
    db.add(WebhookEndpoint(name="siem", url="https://hooks.example.com/split", enabled=True))
    n = webhooks.MAX_BATCH_EVENTS + 7
    evs = [Event(event_type="port_opened", severity="high", ip="192.0.2.1", message=f"e{i}", notify=True) for i in range(n)]
    db.add_all(evs)
    db.commit()
    counts = []

    def post(url, body, headers, *, deadline=8.0):
        payload = json.loads(body)
        counts.append(payload.get("count") or 1)
        return 204

    _patch_http(monkeypatch, post)
    webhooks.deliver_event_ids([e.id for e in evs])
    assert counts == [webhooks.MAX_BATCH_EVENTS, 7]


def test_tag_events_deliver_via_webhooks(db, monkeypatch):
    """Tag add/remove from a second scan deliver as alert events (notify=True)."""
    net = make_network(db)
    hosts = [host("10.0.0.1", [port(22, "ssh"), port(80, "http")], mac="02:00:00:00:00:01")]
    scan(ScriptedScanner(hosts), network_id=net.id)  # baseline: silent classification
    hosts[0].ports = [port(80, "http"), port(3306, "mysql")]
    s2 = scan(ScriptedScanner(hosts), network_id=net.id)
    ids = list(
        db.scalars(
            select(Event.id).where(
                Event.scan_id == s2.id,
                Event.event_type.in_(("tag_added", "tag_removed")),
            )
        )
    )
    assert ids
    assert all(db.get(Event, i).notify for i in ids)
    db.add(WebhookEndpoint(name="tags", url="https://hooks.example.com/tags", enabled=True))
    db.commit()
    posted = []

    def post(url, body, headers, *, deadline=8.0):
        posted.append(url)
        return 204

    _patch_http(monkeypatch, post)
    webhooks.deliver_event_ids(ids)
    assert posted == ["https://hooks.example.com/tags"]


def test_watch_events_deliver_via_webhooks(db, monkeypatch):
    net = make_network(db)
    scan(
        ScriptedScanner([host("10.0.0.1", [port(3389, "ms-wbt-server")], mac="02:00:00:00:00:01")]),
        network_id=net.id,
    )
    db.add(SavedSearch(name="RDP", query="port:3389"))
    db.commit()
    assert run_watches() == []  # baseline
    scan(
        ScriptedScanner(
            [
                host("10.0.0.1", [port(3389, "ms-wbt-server")], mac="02:00:00:00:00:01"),
                host("10.0.0.2", [port(3389, "ms-wbt-server")], mac="02:00:00:00:00:02"),
            ]
        ),
        network_id=net.id,
    )
    ids = list(db.scalars(select(Event.id).where(Event.event_type == EV_WATCH_MATCH)))
    assert ids
    db.add(WebhookEndpoint(name="w", url="https://hooks.example.com/watch", enabled=True))
    db.commit()
    posted = []

    def post(url, body, headers, *, deadline=8.0):
        posted.append(url)
        return 204

    _patch_http(monkeypatch, post)
    webhooks.deliver_event_ids(ids)
    assert posted == ["https://hooks.example.com/watch"]


def test_presence_events_deliver_via_webhooks(db, monkeypatch):
    """Presence disappearance events (list[int] from evaluate_absence) deliver like other sources."""
    assert evaluate_absence.__annotations__.get("return") in (list[int], "list[int]")
    ev = Event(
        event_type=EV_DEVICE_DISAPPEARED,
        severity="high",
        ip="192.0.2.50",
        message="absence alert",
        notify=True,
    )
    db.add(ev)
    db.add(WebhookEndpoint(name="p", url="https://hooks.example.com/presence", enabled=True))
    db.commit()
    posted = []

    def post(url, body, headers, *, deadline=8.0):
        posted.append(url)
        return 204

    _patch_http(monkeypatch, post)
    webhooks.deliver_event_ids([ev.id])
    assert posted == ["https://hooks.example.com/presence"]


def test_general_webhooks_switch_gates_delivery(db, monkeypatch):
    put_section(db, NotificationSettings(webhooks_enabled=True))
    db.add(WebhookEndpoint(name="on", url="https://hooks.example.com/on", enabled=True))
    ev = Event(event_type="port_opened", severity="high", ip="192.0.2.20", message="x", notify=True)
    db.add(ev)
    db.commit()
    posted = []

    def post(url, body, headers, *, deadline=8.0):
        posted.append(url)
        return 204

    _patch_http(monkeypatch, post)
    webhooks.deliver_event_ids([ev.id])
    assert posted == ["https://hooks.example.com/on"]

    put_section(db, NotificationSettings(webhooks_enabled=False))
    db.commit()
    posted.clear()
    webhooks.deliver_event_ids([ev.id])
    assert posted == []


def test_schedule_returns_fast_with_trickling_endpoint(db, monkeypatch):
    """schedule_event_delivery must return immediately even if the hook trickles for tens of seconds."""
    put_section(db, NotificationSettings(webhooks_enabled=True))
    db.add(WebhookEndpoint(name="slow", url="https://hooks.example.com/trickle", enabled=True))
    ev = Event(event_type="port_opened", severity="high", ip="192.0.2.21", message="x", notify=True)
    db.add(ev)
    db.commit()

    release = threading.Event()
    started = threading.Event()

    def slow_post(url, body, headers, *, deadline=8.0):
        started.set()
        # Simulate a trickling server that would outlive any "wait then abandon" budget.
        if not release.wait(timeout=30):
            raise TimeoutError(f"timeout after {int(deadline)}s")
        raise TimeoutError(f"timeout after {int(deadline)}s")

    _patch_http(monkeypatch, slow_post)
    webhooks.start_delivery_worker()
    t0 = time_mod.monotonic()
    webhooks.schedule_event_delivery([ev.id])
    assert time_mod.monotonic() - t0 < 1.0
    assert started.wait(timeout=5)
    release.set()
    assert webhooks.wait_delivery_idle(timeout=10)
    db.refresh(db.scalars(select(WebhookEndpoint)).first())
    row = db.scalars(select(WebhookEndpoint)).first()
    assert row.last_error and "timeout after" in row.last_error
    assert "round budget" not in row.last_error


def test_queued_scan_work_not_delayed_by_slow_webhook(db, monkeypatch):
    """After scheduling delivery (as the scan worker does), the caller can start the next job immediately."""
    put_section(db, NotificationSettings(webhooks_enabled=True))
    db.add(WebhookEndpoint(name="slow", url="https://hooks.example.com/slow", enabled=True))
    ev = Event(event_type="port_opened", severity="high", ip="192.0.2.22", message="x", notify=True)
    db.add(ev)
    db.commit()

    hold = threading.Event()
    order: list[str] = []

    def slow_post(url, body, headers, *, deadline=8.0):
        order.append("http_start")
        hold.wait(timeout=30)
        order.append("http_done")
        return 204

    _patch_http(monkeypatch, slow_post)
    webhooks.start_delivery_worker()

    # Mimic runner.py: schedule webhooks, then proceed to the next queued scan.
    t0 = time_mod.monotonic()
    webhooks.schedule_event_delivery([ev.id])
    order.append("next_scan_start")
    elapsed = time_mod.monotonic() - t0
    assert elapsed < 1.0
    assert order[0] == "next_scan_start" or (
        "next_scan_start" in order and order.index("next_scan_start") < order.index("http_done") if "http_done" in order else True
    )
    # Next-scan marker must appear before HTTP finishes.
    assert "next_scan_start" in order
    hold.set()
    assert webhooks.wait_delivery_idle(timeout=10)
    assert "http_done" in order
    assert order.index("next_scan_start") < order.index("http_done")


def _serve(handler_cls):
    httpd = HTTPServer(("127.0.0.1", 0), handler_cls)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd, httpd.server_address[1]


def test_header_trickle_cut_at_deadline_with_truthful_elapsed(db, monkeypatch):
    """A server that trickles response headers must be cut by the wall-clock deadline (~8s)."""
    put_section(db, NotificationSettings(webhooks_enabled=True))
    db.add(WebhookEndpoint(name="trickle", url="http://127.0.0.1:9/unused", enabled=True))
    ev = Event(event_type="port_opened", severity="high", ip="192.0.2.23", message="x", notify=True)
    db.add(ev)
    db.commit()

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            # Trickle status/header bytes so body-loop deadlines never run.
            self.wfile.write(b"HTTP/1.1 ")
            self.wfile.flush()
            for ch in b"200 OK\r\nContent-Length: 0\r\n\r\n":
                time_mod.sleep(1.0)
                self.wfile.write(bytes([ch]))
                self.wfile.flush()

        def log_message(self, *_args):
            return

    httpd, port_n = _serve(Handler)
    try:
        row = db.scalars(select(WebhookEndpoint)).first()
        row.url = f"http://127.0.0.1:{port_n}/hook"
        db.commit()
        monkeypatch.setattr(webhooks, "HTTP_DEADLINE", 1.5)
        monkeypatch.setattr(webhooks, "HTTP_CONNECT_TIMEOUT", 1.0)
        t0 = time_mod.monotonic()
        webhooks.deliver_event_ids([ev.id])
        elapsed = time_mod.monotonic() - t0
        assert 1.2 <= elapsed < 3.5, f"elapsed={elapsed:.2f}s"
        db.refresh(row)
        assert row.last_error and row.last_error.startswith("timeout after")
        # Real elapsed in the message (not a fixed nominal "8s" / "round budget").
        assert "round budget" not in row.last_error
        assert any(row.last_error.startswith(f"timeout after {n}") for n in ("1.", "2.", "3."))
    finally:
        httpd.shutdown()


def test_delayed_receiver_within_deadline_succeeds(db, monkeypatch):
    """A receiver that answers after ~3s must succeed within the 8s whole-request budget."""
    put_section(db, NotificationSettings(webhooks_enabled=True))
    db.add(WebhookEndpoint(name="slow-ok", url="http://127.0.0.1:9/unused", enabled=True))
    ev = Event(event_type="port_opened", severity="high", ip="192.0.2.24", message="x", notify=True)
    db.add(ev)
    db.commit()

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            length = int(self.headers.get("Content-Length") or 0)
            self.rfile.read(length)
            time_mod.sleep(3.0)
            self.send_response(204)
            self.end_headers()

        def log_message(self, *_args):
            return

    httpd, port_n = _serve(Handler)
    try:
        row = db.scalars(select(WebhookEndpoint)).first()
        row.url = f"http://127.0.0.1:{port_n}/hook"
        db.commit()
        t0 = time_mod.monotonic()
        webhooks.deliver_event_ids([ev.id])
        elapsed = time_mod.monotonic() - t0
        assert 2.5 <= elapsed < 7.0, f"elapsed={elapsed:.2f}s"
        db.refresh(row)
        assert row.last_success_at is not None
        assert row.last_error is None
    finally:
        httpd.shutdown()


def test_healthy_hook_not_blocked_by_stuck_hook(db, monkeypatch):
    """While one hook is stuck, another hook's delivery completes promptly (~1s)."""
    put_section(db, NotificationSettings(webhooks_enabled=True))
    db.add(WebhookEndpoint(name="stuck", url="https://hooks.example.com/stuck", enabled=True))
    db.add(WebhookEndpoint(name="ok", url="https://hooks.example.com/ok", enabled=True))
    ev = Event(event_type="port_opened", severity="high", ip="192.0.2.25", message="x", notify=True)
    db.add(ev)
    db.commit()

    hold = threading.Event()
    ok_at: list[float] = []
    t0 = time_mod.monotonic()

    def post(url, body, headers, *, deadline=8.0):
        if "stuck" in url:
            hold.wait(timeout=30)
            return 204
        ok_at.append(time_mod.monotonic() - t0)
        return 204

    _patch_http(monkeypatch, post)
    webhooks.start_delivery_worker()
    webhooks.schedule_event_delivery([ev.id])
    # Wait until the healthy hook finishes (without releasing the stuck one).
    deadline = time_mod.monotonic() + 5
    while not ok_at and time_mod.monotonic() < deadline:
        time_mod.sleep(0.05)
    assert ok_at, "healthy hook never delivered"
    assert ok_at[0] < 1.0, f"healthy hook took {ok_at[0]:.2f}s while peer stuck"
    hold.set()
    assert webhooks.wait_delivery_idle(timeout=10)
    rows = {h.name: h for h in db.scalars(select(WebhookEndpoint)).all()}
    db.refresh(rows["ok"])
    assert rows["ok"].last_success_at is not None


def test_queue_full_surfaces_on_hook_status(db, monkeypatch):
    put_section(db, NotificationSettings(webhooks_enabled=True))
    db.add(WebhookEndpoint(name="siem", url="https://hooks.example.com/q", enabled=True))
    ev = Event(event_type="port_opened", severity="high", ip="192.0.2.26", message="x", notify=True)
    db.add(ev)
    db.commit()
    webhooks.start_delivery_worker()
    # Fill the queue without letting the dispatcher drain it.
    monkeypatch.setattr(webhooks, "QUEUE_MAXSIZE", 1)
    # Replace the live queue with a tiny full one.
    tiny = __import__("queue").Queue(maxsize=1)
    tiny.put_nowait([ev.id])
    monkeypatch.setattr(webhooks, "_delivery_queue", tiny)
    webhooks.schedule_event_delivery([ev.id])  # should hit Full and record last_error off-thread
    row = db.scalars(select(WebhookEndpoint)).first()
    # Status is written on a daemon thread so the scan path never blocks on DB.
    deadline = __import__("time").monotonic() + 3
    while __import__("time").monotonic() < deadline:
        db.refresh(row)
        if row.last_error and "queue full" in row.last_error:
            break
        __import__("time").sleep(0.05)
    assert row.last_error and "dropped" in row.last_error and "queue full" in row.last_error
    assert "1 event" in row.last_error  # singular
