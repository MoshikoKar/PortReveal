"""Per-network site-to-site VPN flag: mild rate-capped scan profile and API round-trip."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.api.auth import limiter
from app.core.runner import (
    VPN_S2S_MAX_PARALLELISM,
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
    discovery_max_rate,
    discovery_min_rate,
    discovery_timeout,
)
from app.scanner.types import PortProfile
from app.settings_store import ScanSettings

from .helpers import ScriptedScanner, host, make_network, port, scan


def _arg(args: list[str], flag: str) -> str:
    return args[args.index(flag) + 1]


# Scan-command integrity invariant; the threat model and full index live in test_nmap_command_integrity.py.
def test_vpn_discovery_args_are_mildly_capped():
    # VPN stays near a normal remote scan, but never opens the remote-normal/fast ceiling (1000–2000).
    for timing, max_rate in (("polite", "300"), ("normal", "400"), ("fast", "400")):
        args = build_discovery_args(privileged=True, timing=timing, vpn_s2s=True)
        assert _arg(args, "--max-rate") == max_rate
        assert int(_arg(args, "--min-rate")) == discovery_min_rate(timing, vpn_s2s=True)
        assert _arg(args, "--min-parallelism") == "8"
        assert int(_arg(args, "--max-rate")) < discovery_max_rate(timing, local_l2=False)
        assert not any(a.startswith("-PU") for a in args)
    # Flag wins over local L2 tables too (admin said this network is over S2S).
    local = build_discovery_args(privileged=True, timing="normal", local_l2=True, vpn_s2s=True)
    assert _arg(local, "--max-rate") == "400" and "--min-parallelism" not in local


def test_vpn_discovery_timeout_covers_rate_floor():
    assert discovery_timeout(["10.0.0.0/24"], "normal", vpn_s2s=True) == DISCOVERY_TIMEOUT_S
    # Lower VPN floor than remote-normal needs a longer worst-case for a large silent chunk.
    assert discovery_timeout(["10.0.0.0/18"], "normal", vpn_s2s=True) > discovery_timeout(
        ["10.0.0.0/18"], "normal", local_l2=False
    )


def test_port_args_carry_vpn_max_rate():
    capped = PortProfile(full=False, top_ports=3000, max_rate=VPN_PORT_MAX_RATE)
    assert _arg(build_port_args(True, capped), "--max-rate") == str(VPN_PORT_MAX_RATE)
    assert _arg(build_fixed_port_args(True, capped, [8080, 11434]), "--max-rate") == str(VPN_PORT_MAX_RATE)
    assert "--exclude-ports" in build_port_args(True, capped)
    assert "--max-rate" not in build_port_args(True, PortProfile(full=False))


def test_effective_scan_settings_only_mildly_clamp_vpn_networks():
    cfg = ScanSettings(timing="fast", parallelism=8, discovery_chunk_size=2048, port_batch_size=64)
    assert effective_scan_settings(cfg, False) is cfg
    vpn = effective_scan_settings(cfg, True)
    assert vpn.timing == "normal"  # only fast is dropped
    assert vpn.parallelism == VPN_S2S_MAX_PARALLELISM
    assert vpn.discovery_chunk_size == cfg.discovery_chunk_size  # chunks unchanged
    assert vpn.port_batch_size == VPN_S2S_PORT_BATCH
    assert vpn.top_ports == cfg.top_ports and vpn.host_timeout_minutes == cfg.host_timeout_minutes
    small = effective_scan_settings(ScanSettings(parallelism=1, port_batch_size=4, timing="polite"), True)
    assert (small.parallelism, small.port_batch_size, small.timing) == (1, 4, "polite")
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
