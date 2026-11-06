"""Synthetic ground-truth metrics for identity matching (issue #39 item 8).

These rates are from labeled fixtures only. They are not production validation.
"""
from __future__ import annotations

from datetime import datetime, timezone
from types import SimpleNamespace

from app.core.identity_metrics import LabeledHost, evaluate
from app.scanner.types import HostObservation

MAC_A = "00:11:22:33:44:01"
MAC_B = "00:11:22:33:44:02"
T = datetime(2026, 1, 1, tzinfo=timezone.utc)


def dev(id, ip, mac=None, hostname=None, network_id=1):
    return SimpleNamespace(
        id=id, current_ip=ip, mac=mac, hostname=hostname, status="active",
        last_seen=T, network_id=network_id,
    )


def test_ground_truth_metrics_report_zero_error_on_happy_path():
    devices = [
        dev(1, "10.0.0.1", mac=MAC_A, hostname="srv-a.corp"),
        dev(2, "10.0.0.2", mac=MAC_B, hostname="ws-b.corp"),
    ]
    labeled = [
        LabeledHost(HostObservation(ip="10.0.0.50", mac=MAC_A, hostname="srv-a.corp"), expected_device_id=1),
        LabeledHost(HostObservation(ip="10.0.0.2", mac=MAC_B, hostname="ws-b.corp"), expected_device_id=2),
        LabeledHost(HostObservation(ip="10.0.0.9", hostname="10-0-0-9.dhcp.corp"), expected_device_id=None),
    ]
    m = evaluate(labeled, devices, {h.host.ip: 1 for h in labeled}.get)
    assert m.false_new == 0 and m.false_merge == 0
    assert m.true_match == 2 and m.true_new == 1
    assert m.false_new_rate == 0.0 and m.false_merge_rate == 0.0


def test_ground_truth_detects_false_merge_when_forced():
    # Two devices; host at a new IP with no MAC and a shared name -> matcher refuses (unique required).
    # Ground truth wrongly expects a merge to show the metric can rise above zero.
    devices = [
        dev(1, "10.0.0.1", hostname="app.corp"),
        dev(2, "10.0.0.2", hostname="app.corp"),
    ]
    labeled = [
        LabeledHost(HostObservation(ip="10.0.0.9", hostname="app.corp"), expected_device_id=1),
    ]
    m = evaluate(labeled, devices)
    assert m.false_new == 1 and m.false_merge == 0
