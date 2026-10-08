import shutil
from pathlib import Path

import pytest

from app.netutils import AddressSet, PortScope, TargetError, validate_network_cidr
from app.scanner.nmap_parser import parse_nmap_xml
from app.scanner import nmap_scanner
from app.scanner.known_ports import STANDARD_EXTRA_TCP_PORTS
from app.scanner.nmap_iface import BindChoice
from app.scanner.nmap_parser import ParsedRun
from app.scanner.nmap_scanner import (
    DISCOVERY_TIMEOUT_S,
    NmapScanner,
    build_discovery_args,
    build_port_args,
    discovery_timeout,
    standard_port_spec,
    top_tcp_ports,
)
from app.scanner.types import HostObservation, PortObservation, PortProfile, ScanContext, ScanStageError

FIXTURES = Path(__file__).parent / "fixtures"


def test_parse_standard_scan_xml():
    run = parse_nmap_xml((FIXTURES / "standard_scan.xml").read_text())
    assert run.finished_ok
    assert 22 in PortScope(run.port_scope) and 8080 in PortScope(run.port_scope) and 9000 not in PortScope(run.port_scope)
    assert [h.ip for h in run.hosts] == ["10.20.15.22", "10.20.15.23"]  # down host skipped
    h = run.hosts[0]
    assert h.mac == "00:50:56:A1:B2:C3" and h.vendor == "VMware" and h.hostname == "server01.corp.local"
    assert [p.port for p in h.ports] == [22, 443, 8080]  # filtered port 80 ignored
    ssh = h.ports[0]
    assert (ssh.service, ssh.product, ssh.version, ssh.method, ssh.confidence) == (
        "ssh", "OpenSSH", "8.9p1 Ubuntu 3ubuntu0.10", "probed", 10)
    assert h.ports[0].reliable and not h.ports[2].reliable
    timed_out = run.hosts[1]
    assert timed_out.port_scan_failed and timed_out.ports is None


def test_parse_rejects_garbage_and_incomplete_output():
    with pytest.raises(ScanStageError):
        parse_nmap_xml("")
    with pytest.raises(ScanStageError):
        parse_nmap_xml("<html>nope")
    run = parse_nmap_xml('<?xml version="1.0"?><nmaprun><host><status state="up"/></host></nmaprun>')
    assert not run.finished_ok


def test_nmap_arguments_are_fixed_and_safe():
    disc = build_discovery_args(privileged=True, timing="normal")
    assert disc[0] == "-sn" and "-PE" in disc and any(a.startswith("-PS") for a in disc)
    unpriv = build_discovery_args(privileged=False, timing="normal")
    assert "-PE" not in unpriv and "--unprivileged" in unpriv
    # a rate floor keeps empty (silent) ranges from crawling past the chunk timeout
    assert disc[disc.index("--min-rate") + 1] == "300" and "--min-rate" in unpriv
    std = build_port_args(True, PortProfile(full=False, host_timeout_minutes=15), "22,80,443")
    assert std[std.index("-p") + 1] == "22,80,443" and "-sV" in std and "-Pn" in std
    assert "--top-ports" not in std  # nmap does not union --top-ports with -p
    assert "-A" not in std and "--script" not in " ".join(std)
    # timing/retries are the same with or without version detection
    portmap = build_port_args(True, PortProfile(full=False, host_timeout_minutes=15), "22,80,443", versions=False)
    assert portmap == [a for a in std if a != "-sV"]
    full = build_port_args(False, PortProfile(full=True, host_timeout_minutes=120), "1-65535")
    assert "1-65535" in full and "-sT" in full
    os_profile = PortProfile(full=False, os_detection=True)
    assert "-O" in build_port_args(True, os_profile, "80")
    assert "-O" not in build_port_args(True, os_profile, "80", os_scan=False)


def test_standard_port_spec_is_top_ports_union_extras(monkeypatch):
    monkeypatch.setattr(nmap_scanner, "top_tcp_ports", lambda exe, n: (22, 80, 443, 8080, 11434))
    scope = PortScope(standard_port_spec("nmap", 1000))
    assert all(p in scope for p in (22, 80, 443, 8080, *STANDARD_EXTRA_TCP_PORTS))
    assert scope.count() == len({22, 80, 443, 8080, *STANDARD_EXTRA_TCP_PORTS})  # deduplicated
    assert {5173, 5601, 6443, 7474, 8123, 11434, 15672} <= set(STANDARD_EXTRA_TCP_PORTS)


@pytest.mark.skipif(not shutil.which("nmap"), reason="nmap not installed")
def test_top_tcp_ports_matches_installed_nmap():
    ports = top_tcp_ports(shutil.which("nmap"), 1000)
    assert len(ports) == 1000 and len(set(ports)) == 1000
    assert {80, 443, 8080, 8443, 3389} <= set(ports)


def _obs(ip: str, *ports: tuple[int, str | None]) -> HostObservation:
    return HostObservation(ip=ip, ports=[
        PortObservation(port=p, service="svc", product=prod, method="probed" if prod else "table",
                        confidence=10 if prod else 3)
        for p, prod in ports
    ])


def _fake_nmap(monkeypatch, *replies):
    """An NmapScanner whose nmap runs return the given ParsedRuns (or raise them) in order."""
    monkeypatch.setattr(nmap_scanner, "resolve_bind", lambda exe, ips, priv: BindChoice(device=None, privileged=priv))
    monkeypatch.setattr(nmap_scanner, "top_tcp_ports", lambda exe, n: (22, 80, 443))
    sc = object.__new__(NmapScanner)
    sc.exe, sc.privileged = "nmap", True
    calls: list[tuple[list[str], list[str]]] = []

    def run(args, targets, timeout, ctx, label, device=None, source=None):
        calls.append((args, list(targets)))
        reply = replies[len(calls) - 1]
        if isinstance(reply, Exception):
            raise reply
        return reply

    sc._run = run
    return sc, calls


def test_cold_cache_is_a_single_version_pass(monkeypatch):
    sc, calls = _fake_nmap(monkeypatch, ParsedRun(hosts=[_obs("10.0.0.1", (22, "OpenSSH"))], port_scope="22,80"))
    res = sc.scan_ports(["10.0.0.1"], PortProfile(full=False), ScanContext(1))
    assert len(calls) == 1 and "-sV" in calls[0][0]
    assert res.hosts[0].ports[0].version_checked


def test_warm_cache_versions_only_uncached_ports(monkeypatch):
    portmap = ParsedRun(hosts=[_obs("10.0.0.1", (22, None), (80, None), (8080, None)),
                               _obs("10.0.0.2", (443, None)), _obs("10.0.0.3", (22, None))], port_scope="22,80,443")
    versions = ParsedRun(hosts=[_obs("10.0.0.1", (8080, "Jetty")), _obs("10.0.0.2", (443, "nginx"))])
    sc, calls = _fake_nmap(monkeypatch, portmap, versions)
    profile = PortProfile(full=False, os_detection=True,
                          version_cache={"10.0.0.1": frozenset({22, 80}), "10.0.0.3": frozenset({22})})
    res = sc.scan_ports(["10.0.0.1", "10.0.0.2", "10.0.0.3"], profile, ScanContext(1))
    (a1, _t1), (a2, t2) = calls
    assert "-sV" not in a1 and "-O" in a1  # port map (with OS detection) over the full port list
    assert "-sV" in a2 and "-O" not in a2 and a2[a2.index("-p") + 1] == "443,8080"
    assert t2 == ["10.0.0.1", "10.0.0.2"]  # fully cached hosts are not version-scanned again
    by_ip = {h.ip: {p.port: p for p in h.ports} for h in res.hosts}
    assert by_ip["10.0.0.1"][8080].product == "Jetty" and by_ip["10.0.0.1"][8080].version_checked
    assert not by_ip["10.0.0.1"][22].version_checked and not by_ip["10.0.0.1"][22].reliable
    assert by_ip["10.0.0.2"][443].product == "nginx"
    assert res.port_scope == "22,80,443"


def test_failed_version_pass_keeps_port_results(monkeypatch):
    portmap = ParsedRun(hosts=[_obs("10.0.0.1", (22, None), (8080, None))], port_scope="22,8080")
    sc, calls = _fake_nmap(monkeypatch, portmap, ScanStageError("nmap ports-versions timed out"))
    res = sc.scan_ports(["10.0.0.1"], PortProfile(full=False, version_cache={"10.0.0.1": frozenset({22})}),
                        ScanContext(1))
    h = res.hosts[0]
    assert len(calls) == 2 and not h.port_scan_failed
    assert [p.port for p in h.ports] == [22, 8080] and not any(p.version_checked for p in h.ports)


def test_discovery_timeout_scales_with_chunk_size():
    assert discovery_timeout(["10.0.4.0/22"], "normal") == DISCOVERY_TIMEOUT_S
    assert discovery_timeout(["10.0.0.0/18"], "normal") > DISCOVERY_TIMEOUT_S
    assert discovery_timeout(["10.0.0.0/22"], "polite") <= DISCOVERY_TIMEOUT_S * 2


def test_address_set_parsing_and_exclusions():
    s = AddressSet.from_specs("10.0.0.0/24, 10.0.1.10-20\n10.0.1.30-10.0.1.31 10.0.2.1")
    assert len(s) == 256 + 11 + 2 + 1
    ex = AddressSet.from_specs("10.0.0.0/25,10.0.1.15")
    rest = s.subtract(ex)
    assert len(rest) == 128 + 10 + 2 + 1
    assert "10.0.0.5" not in rest and "10.0.0.200" in rest and "10.0.1.15" not in rest


def test_address_set_chunks_cover_slash16():
    s = AddressSet.from_specs("10.20.0.0/16")
    chunks = s.chunks(1024)
    assert len(chunks) == 64
    assert sum(len(AddressSet.from_specs(c)) for c in chunks) == 65536


@pytest.mark.parametrize("bad", ["10.0.0.256", "10.0.0.0/33", "10.0.0.20-10", "fe80::1", "a b", "$(reboot)", "1.2.3.4;rm"])
def test_invalid_targets_rejected(bad):
    with pytest.raises(TargetError):
        AddressSet.from_specs(bad)


def test_network_size_limit():
    assert validate_network_cidr("10.20.5.0/16") == "10.20.0.0/16"
    with pytest.raises(TargetError):
        validate_network_cidr("10.0.0.0/8")


def test_port_scope():
    scope = PortScope("1,3-4,22,80-90")
    assert 3 in scope and 85 in scope and 91 not in scope and 2 not in scope
    assert PortScope.from_ports([1, 2, 3, 5, 7, 8]) == "1-3,5,7-8"
