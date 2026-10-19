"""Per-network site-to-site VPN flag: same speed as remote scans, with a no-fast-burst guard."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.api.auth import limiter
from app.core.runner import effective_scan_settings, vpn_port_timing
from app.main import app
from app.scanner.nmap_scanner import (
    DISCOVERY_TIMEOUT_S,
    build_discovery_args,
    discovery_max_rate,
    discovery_min_rate,
    discovery_rtt_ms,
    discovery_timeout,
)
from app.scanner.types import PortProfile
from app.settings_store import ScanSettings

from .helpers import ScriptedScanner, host, make_network, port, scan


def _arg(args: list[str], flag: str) -> str:
    return args[args.index(flag) + 1]


# Scan-command integrity invariant; the threat model and full index live in test_nmap_command_integrity.py.
def test_vpn_discovery_matches_remote_rates():
    # VPN uses the same remote tables that finished /16 S2S discovery in ~1h before the flag.
    for timing in ("polite", "normal", "fast"):
        vpn = build_discovery_args(privileged=True, timing=timing, vpn_s2s=True)
        remote = build_discovery_args(privileged=True, timing=timing, local_l2=False)
        assert _arg(vpn, "--min-rate") == _arg(remote, "--min-rate")
        assert _arg(vpn, "--max-rate") == _arg(remote, "--max-rate")
        assert _arg(vpn, "--min-parallelism") == "32"
        assert _arg(vpn, "--initial-rtt-timeout") == _arg(remote, "--initial-rtt-timeout")
        assert _arg(vpn, "--max-rtt-timeout") == _arg(remote, "--max-rtt-timeout")
        assert discovery_min_rate(timing, vpn_s2s=True) == discovery_min_rate(timing, local_l2=False)
        assert discovery_max_rate(timing, vpn_s2s=True) == discovery_max_rate(timing, local_l2=False)
        assert discovery_rtt_ms(timing, vpn_s2s=True) == discovery_rtt_ms(timing, local_l2=False)
        assert not any(a.startswith("-PU") for a in vpn)
    # Flag forces remote rates even when a NIC looks like local L2 (ARP path would be wrong over S2S).
    forced = build_discovery_args(privileged=True, timing="normal", local_l2=True, vpn_s2s=True)
    assert _arg(forced, "--max-rate") == "1000" and _arg(forced, "--min-parallelism") == "32"


def test_vpn_discovery_timeout_matches_remote():
    assert discovery_timeout(["10.0.0.0/24"], "normal", vpn_s2s=True) == DISCOVERY_TIMEOUT_S
    assert discovery_timeout(["10.0.0.0/18"], "normal", vpn_s2s=True) == discovery_timeout(
        ["10.0.0.0/18"], "normal", local_l2=False
    )


def test_effective_scan_settings_only_drop_fast_on_vpn():
    cfg = ScanSettings(timing="fast", parallelism=8, discovery_chunk_size=2048, port_batch_size=64)
    assert effective_scan_settings(cfg, False) is cfg
    vpn = effective_scan_settings(cfg, True)
    assert vpn.timing == "normal"
    assert vpn.parallelism == cfg.parallelism and vpn.port_batch_size == cfg.port_batch_size
    assert vpn.discovery_chunk_size == cfg.discovery_chunk_size
    normal = ScanSettings(timing="normal", parallelism=4)
    assert effective_scan_settings(normal, True) is normal  # no copy when nothing changes
    assert cfg.timing == "fast" and cfg.parallelism == 8  # stored settings untouched
    assert [vpn_port_timing(t) for t in ("polite", "normal", "fast")] == ["polite", "normal", "normal"]


class RecordingScanner(ScriptedScanner):
    def __init__(self, hosts):
        super().__init__(hosts)
        self.ctx_vpn: list[bool] = []
        self.profiles: list[PortProfile] = []

    def discover(self, targets, ctx):
        self.ctx_vpn.append(ctx.vpn_s2s)
        return super().discover(targets, ctx)

    def scan_ports(self, ips, profile, ctx):
        self.profiles.append(profile)
        return super().scan_ports(ips, profile, ctx)


@pytest.mark.parametrize("vpn_s2s", [False, True])
def test_runner_applies_vpn_flag_without_slowing_batches(db, vpn_s2s):
    net = make_network(db, cidr="10.5.0.0/22", name=f"Site {vpn_s2s}")
    net.vpn_s2s = vpn_s2s
    db.commit()
    scanner = RecordingScanner([host(f"10.5.0.{i}", [port(22, "ssh")]) for i in range(1, 21)])
    result = scan(scanner, network_id=net.id)
    assert result.status == "completed"
    assert scanner.ctx_vpn and all(v is vpn_s2s for v in scanner.ctx_vpn)
    # Port batches and rate caps stay on the admin profile - VPN no longer shrinks them.
    assert all(p.max_rate is None for p in scanner.profiles)


@pytest.fixture
def client(db_env):
    limiter.reset()
    with TestClient(app) as c:
        yield c


def test_network_api_round_trips_vpn_flag(client):
    assert client.post("/api/setup/admin", json={"username": "admin", "password": "correct-horse-1"}).status_code == 200
    h = {"X-CSRF-Token": client.cookies.get("nf_csrf", "")}
    net = client.post("/api/networks", json={"name": "Branch", "cidr": "10.7.0.0/24"}, headers=h).json()
    assert net["vpn_s2s"] is False
    body = {"name": "Branch", "cidr": "10.7.0.0/24", "vpn_s2s": True}
    assert client.put(f"/api/networks/{net['id']}", json=body, headers=h).json()["vpn_s2s"] is True
    listed = next(n for n in client.get("/api/networks").json() if n["id"] == net["id"])
    assert listed["vpn_s2s"] is True and listed["baseline_at"] is None


@pytest.mark.parametrize("vpn_s2s", [False, True])
def test_device_detail_exposes_network_vpn_flag(client, db, vpn_s2s):
    # Display-only: the UI explains a missing MAC over S2S; the MAC itself stays null (never guessed).
    assert client.post("/api/setup/admin", json={"username": "admin", "password": "correct-horse-1"}).status_code == 200
    net = make_network(db, cidr="10.8.0.0/24", name="Branch")
    net.vpn_s2s = vpn_s2s
    db.commit()
    assert scan(ScriptedScanner([host("10.8.0.5", [port(22, "ssh")])]), network_id=net.id).status == "completed"
    uuid = client.get("/api/devices").json()["items"][0]["uuid"]
    detail = client.get(f"/api/devices/{uuid}").json()
    assert detail["vpn_s2s"] is vpn_s2s
    assert detail["mac"] is None
