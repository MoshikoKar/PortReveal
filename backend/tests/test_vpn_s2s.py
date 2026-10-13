"""Per-network site-to-site VPN flag: rate-capped serial scan profile and API round-trip."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.api.auth import limiter
from app.core.runner import (
    VPN_S2S_DISCOVERY_CHUNK,
    VPN_S2S_PORT_BATCH,
    effective_scan_settings,
    vpn_port_timing,
)
from app.main import app
from app.scanner.nmap_scanner import (
    DISCOVERY_TIMEOUT_S,
    VPN_PORT_MAX_RATE,
    build_discovery_args,
    build_fixed_port_args,
    build_port_args,
    discovery_timeout,
)
from app.scanner.types import PortProfile
from app.settings_store import ScanSettings

from .helpers import ScriptedScanner, host, make_network, port, scan


def _arg(args: list[str], flag: str) -> str:
    return args[args.index(flag) + 1]


# Scan-command integrity invariant; the threat model and full index live in test_nmap_command_integrity.py.
def test_vpn_discovery_args_are_capped_and_serial():
    for timing in ("polite", "normal", "fast"):
        for local_l2 in (False, True):
            args = build_discovery_args(privileged=True, timing=timing, local_l2=local_l2, vpn_s2s=True)
            assert _arg(args, "--min-rate") == "50"
            assert _arg(args, "--max-rate") == "150"
            assert _arg(args, "--initial-rtt-timeout") == "400ms"
            assert _arg(args, "--max-rtt-timeout") == "1500ms"
            assert "--min-parallelism" not in args
            assert not any(a.startswith("-PU") for a in args)
    unpriv = build_discovery_args(privileged=False, timing="normal", vpn_s2s=True)
    assert _arg(unpriv, "--max-rate") == "150" and "--min-parallelism" not in unpriv


def test_vpn_discovery_timeout_covers_low_rate():
    assert discovery_timeout(["10.0.0.0/24"], "polite", vpn_s2s=True) == DISCOVERY_TIMEOUT_S
    assert discovery_timeout(["10.0.0.0/22"], "polite", vpn_s2s=True) > discovery_timeout(["10.0.0.0/22"], "polite")


def test_port_args_carry_vpn_max_rate():
    capped = PortProfile(full=False, top_ports=3000, max_rate=VPN_PORT_MAX_RATE)
    assert _arg(build_port_args(True, capped), "--max-rate") == str(VPN_PORT_MAX_RATE)
    assert _arg(build_fixed_port_args(True, capped, [8080, 11434]), "--max-rate") == str(VPN_PORT_MAX_RATE)
    assert "--exclude-ports" in build_port_args(True, capped)
    assert "--max-rate" not in build_port_args(True, PortProfile(full=False))


def test_effective_scan_settings_only_change_vpn_networks():
    cfg = ScanSettings(timing="fast", parallelism=8, discovery_chunk_size=2048, port_batch_size=64)
    assert effective_scan_settings(cfg, False) is cfg
    vpn = effective_scan_settings(cfg, True)
    assert (vpn.timing, vpn.parallelism) == ("polite", 1)
    assert vpn.discovery_chunk_size == VPN_S2S_DISCOVERY_CHUNK and vpn.port_batch_size == VPN_S2S_PORT_BATCH
    assert vpn.top_ports == cfg.top_ports and vpn.host_timeout_minutes == cfg.host_timeout_minutes
    small = effective_scan_settings(ScanSettings(discovery_chunk_size=64, port_batch_size=4), True)
    assert (small.discovery_chunk_size, small.port_batch_size) == (64, 4)
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
def test_runner_applies_vpn_profile(db, vpn_s2s):
    net = make_network(db, cidr="10.5.0.0/22", name=f"Site {vpn_s2s}")
    net.vpn_s2s = vpn_s2s
    db.commit()
    scanner = RecordingScanner([host(f"10.5.0.{i}", [port(22, "ssh")]) for i in range(1, 21)])
    result = scan(scanner, network_id=net.id)
    assert result.status == "completed"
    assert scanner.ctx_vpn and all(v is vpn_s2s for v in scanner.ctx_vpn)
    if vpn_s2s:
        assert all(len(c) <= 1 for c in scanner.discovery_targets)  # /22 split into /24 chunks
        assert len(scanner.discovery_targets) == 1024 // VPN_S2S_DISCOVERY_CHUNK
        assert all(len(b) <= VPN_S2S_PORT_BATCH for b in scanner.port_targets)
        assert all(p.max_rate == VPN_PORT_MAX_RATE for p in scanner.profiles)
    else:
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
