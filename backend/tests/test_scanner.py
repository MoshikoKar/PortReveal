from pathlib import Path

import pytest

from app.netutils import AddressSet, PortScope, TargetError, validate_network_cidr
from app.scanner.nmap_parser import parse_nmap_xml
from app.scanner.nmap_scanner import (
    DISCOVERY_TIMEOUT_S,
    build_discovery_args,
    build_port_args,
    discovery_host_is_live,
    discovery_timeout,
)
from app.scanner.types import HostObservation, PortProfile, ScanStageError

FIXTURES = Path(__file__).parent / "fixtures"


def test_parse_standard_scan_xml():
    run = parse_nmap_xml((FIXTURES / "standard_scan.xml").read_text())
    assert run.finished_ok
    assert 22 in PortScope(run.port_scope) and 8080 in PortScope(run.port_scope) and 9000 not in PortScope(run.port_scope)
    assert [h.ip for h in run.hosts] == ["192.0.2.10", "192.0.2.11"]  # down host skipped
    h = run.hosts[0]
    assert h.mac == "00:50:56:A1:B2:C3" and h.vendor == "VMware" and h.hostname == "server01.example.com"
    assert [p.port for p in h.ports] == [22, 443, 8080]  # filtered port 80 ignored
    ssh = h.ports[0]
    assert (ssh.service, ssh.product, ssh.version, ssh.method, ssh.confidence) == (
        "ssh", "OpenSSH", "8.9p1 Ubuntu 3ubuntu0.10", "probed", 10)
    assert h.ports[0].reliable and not h.ports[2].reliable
    # No <os> element in this fixture: os_name falls back to the ssh service's ostype attribute,
    # and os_accuracy stays None (fallback guesses are never a numeric nmap -O accuracy).
    assert h.os_name == "Linux" and h.os_accuracy is None
    timed_out = run.hosts[1]
    assert timed_out.port_scan_failed and timed_out.ports is None


def test_parse_os_detection_picks_the_highest_accuracy_osmatch():
    xml = '''<?xml version="1.0"?>
    <nmaprun><host><status state="up"/>
    <address addr="10.0.0.5" addrtype="ipv4"/>
    <os>
      <osmatch name="Linux 5.0 - 5.14" accuracy="92"/>
      <osmatch name="Windows Server 2019" accuracy="98"/>
      <osmatch name="Linux 4.15 - 5.6" accuracy="90"/>
    </os>
    </host>
    <runstats><finished exit="success"/></runstats></nmaprun>'''
    run = parse_nmap_xml(xml)
    h = run.hosts[0]
    assert h.os_name == "Windows Server 2019" and h.os_accuracy == 98


def test_parse_os_detection_missing_accuracy_is_not_a_crash():
    xml = '''<?xml version="1.0"?>
    <nmaprun><host><status state="up"/>
    <address addr="10.0.0.6" addrtype="ipv4"/>
    <os><osmatch name="Mystery OS"/></os>
    </host>
    <runstats><finished exit="success"/></runstats></nmaprun>'''
    run = parse_nmap_xml(xml)
    h = run.hosts[0]
    assert h.os_name == "Mystery OS" and h.os_accuracy is None


def test_parse_timed_out_host_keeps_partial_ports():
    xml = '''<?xml version="1.0"?>
    <nmaprun><scaninfo protocol="tcp" services="1-65535"/>
    <host timedout="true"><status state="up"/>
    <address addr="10.0.0.5" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22"><state state="open"/>
        <service name="ssh" method="probed" conf="10"/></port>
      <port protocol="tcp" portid="80"><state state="open"/>
        <service name="http" method="probed" conf="10"/></port>
    </ports>
    </host>
    <runstats><finished exit="success"/></runstats></nmaprun>'''
    run = parse_nmap_xml(xml)
    h = run.hosts[0]
    assert h.port_scan_failed and [p.port for p in h.ports] == [22, 80]


def test_parse_rejects_garbage_and_incomplete_output():
    with pytest.raises(ScanStageError):
        parse_nmap_xml("")
    with pytest.raises(ScanStageError):
        parse_nmap_xml("<html>nope")
    run = parse_nmap_xml('<?xml version="1.0"?><nmaprun><host><status state="up"/></host></nmaprun>')
    assert not run.finished_ok


# Scan-command integrity invariant; the threat model and full index live in test_nmap_command_integrity.py.
def test_nmap_arguments_are_fixed_and_safe():
    # Discovery never sends UDP probes (slow on silent ranges, can upset fragile UDP services).
    disc = build_discovery_args(privileged=True, timing="normal")
    assert disc[0] == "-sn" and "-PE" in disc and any(a.startswith("-PS") for a in disc)
    assert not any(a.startswith("-PU") for a in disc)
    unpriv = build_discovery_args(privileged=False, timing="normal")
    assert "-PE" not in unpriv and "--unprivileged" in unpriv
    assert disc[disc.index("--min-rate") + 1] == "500" and "--min-rate" in unpriv
    assert disc[disc.index("--max-rate") + 1] == "1000" and "--max-rate" in unpriv
    assert disc[disc.index("--max-retries") + 1] == "1"
    assert disc[disc.index("--min-parallelism") + 1] == "32"
    assert disc[disc.index("--initial-rtt-timeout") + 1] == "100ms"
    assert disc[disc.index("--max-rtt-timeout") + 1] == "400ms" and "--max-rtt-timeout" in unpriv
    fast = build_discovery_args(privileged=True, timing="fast")
    assert fast[fast.index("--max-rtt-timeout") + 1] == "250ms"
    assert fast[fast.index("--max-rate") + 1] == "2000"
    local = build_discovery_args(privileged=True, timing="normal", local_l2=True)
    assert not any(a.startswith("-PU") for a in local)
    assert local[local.index("--min-rate") + 1] == "100"
    assert local[local.index("--max-rate") + 1] == "300"
    assert "--min-parallelism" not in local
    assert local[local.index("--max-rtt-timeout") + 1] == "800ms"
    std = build_port_args(True, PortProfile(full=False, top_ports=3000, host_timeout_minutes=15))
    assert "--top-ports" in std and "3000" in std and "-sV" in std and "-Pn" in std
    assert "-A" not in std and "--script" not in " ".join(std)
    assert "--version-light" in std and "-sU" not in std
    assert std[std.index("--exclude-ports") + 1] == "1720,2000,2443,2748,5060,5061"
    full = build_port_args(False, PortProfile(full=True, host_timeout_minutes=120))
    assert "1-65535" in full and "-sT" in full and "--exclude-ports" in full


def test_discovery_drops_nat_reset_without_mac():
    assert discovery_host_is_live(HostObservation(ip="10.0.0.1", reason="reset")) is False
    assert discovery_host_is_live(HostObservation(ip="10.0.0.1", reason="conn-refused")) is False
    assert discovery_host_is_live(HostObservation(ip="10.0.0.1", reason="admin-prohibited")) is False
    assert discovery_host_is_live(HostObservation(ip="10.0.0.1", mac="AA:BB:CC:DD:EE:FF", reason="reset"))
    assert discovery_host_is_live(HostObservation(ip="10.0.0.1", reason="echo-reply"))
    assert discovery_host_is_live(HostObservation(ip="10.0.0.1", reason="arp-response"))
    assert discovery_host_is_live(HostObservation(ip="10.0.0.1", reason="syn-ack"))
    assert discovery_host_is_live(HostObservation(ip="10.0.0.1", reason="udp-response"))
    xml = '''<?xml version="1.0"?>
    <nmaprun><host><status state="up" reason="reset"/>
    <address addr="10.0.0.9" addrtype="ipv4"/></host>
    <host><status state="up" reason="syn-ack"/>
    <address addr="10.0.0.2" addrtype="ipv4"/></host>
    <host><status state="up" reason="echo-reply"/>
    <address addr="10.0.0.1" addrtype="ipv4"/></host>
    <runstats><finished exit="success"/></runstats></nmaprun>'''
    run = parse_nmap_xml(xml)
    assert [h.ip for h in run.hosts] == ["10.0.0.9", "10.0.0.2", "10.0.0.1"]
    assert [h.ip for h in run.hosts if discovery_host_is_live(h)] == ["10.0.0.2", "10.0.0.1"]


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
