from app.scanner.nmap_iface import choose_bind, local_target_ips, parse_nmap_iflist

_SAMPLE_IFLIST = """
Starting Nmap 7.95 ( https://nmap.org )
************************INTERFACES************************
DEV  (SHORT) IP/MASK            TYPE     UP   MTU  MAC
unk0 (unk0)  100.64.0.1/32      other    up   1280
eth0 (eth0)  192.0.2.10/24      ethernet up   1500 00:00:5E:00:53:01
unk1 (unk1)  169.254.0.1/16     other    down 1500
eth1 (eth1)  169.254.1.1/16     ethernet down 1500 00:00:5E:00:53:02
lo0  (lo0)   127.0.0.1/8        loopback up   -1
eth5 (eth5)  198.51.96.1/20     ethernet up   1500 00:00:5E:00:53:03

DEV    WINDEVICE
unk0   \\Device\\NPF_{00000000-0000-0000-0000-000000000001}
eth0   \\Device\\NPF_{00000000-0000-0000-0000-000000000002}
"""


def test_parse_nmap_iflist_ipv4_only():
    ifaces = parse_nmap_iflist(_SAMPLE_IFLIST)
    by_dev = {i.dev: i for i in ifaces}
    assert set(by_dev) == {"unk0", "eth0", "unk1", "eth1", "lo0", "eth5"}
    assert by_dev["eth0"].is_ethernet and by_dev["eth0"].up
    assert str(by_dev["eth0"].network) == "192.0.2.0/24"
    assert by_dev["unk0"].type == "other" and not by_dev["unk0"].is_ethernet
    assert by_dev["lo0"].is_loopback


def test_choose_bind_prefers_local_ethernet_over_tunnel():
    ifaces = parse_nmap_iflist(_SAMPLE_IFLIST)
    # Tunnel (unk0) may own the OS route, but LAN overlap must bind eth0.
    choice = choose_bind(["192.0.2.0/24"], ifaces, privileged=True)
    assert choice.device == "eth0" and choice.privileged is True
    # Raw packets must carry eth0's address, not the tunnel's 100.x route source.
    assert choice.source == "192.0.2.10"

    single = choose_bind(["192.0.2.50"], ifaces, privileged=True)
    assert single.device == "eth0" and single.source == "192.0.2.10"


def test_choose_bind_tunnel_only_drops_privileged():
    ifaces = parse_nmap_iflist(_SAMPLE_IFLIST)
    # Only overlap is unk0 (CGNAT / other) - ARP cannot bind there.
    choice = choose_bind(["100.64.0.1"], ifaces, privileged=True)
    assert choice.device is None and choice.privileged is False


def test_choose_bind_no_overlap_keeps_settings():
    ifaces = parse_nmap_iflist(_SAMPLE_IFLIST)
    choice = choose_bind(["10.0.0.0/24"], ifaces, privileged=True)
    assert choice.device is None and choice.privileged is True


def test_choose_bind_ignores_down_and_link_local_when_better_exists():
    ifaces = parse_nmap_iflist(_SAMPLE_IFLIST)
    choice = choose_bind(["198.51.96.0/20"], ifaces, privileged=False)
    assert choice.device == "eth5" and choice.source is None


def test_local_target_ips_lists_own_addresses_inside_targets():
    ifaces = parse_nmap_iflist(_SAMPLE_IFLIST)
    assert local_target_ips(["192.0.2.0/24"], ifaces) == {"192.0.2.10"}
    assert local_target_ips(["192.0.2.10", "127.0.0.1"], ifaces) == {"192.0.2.10", "127.0.0.1"}
    assert local_target_ips(["192.0.2.50"], ifaces) == frozenset()
    assert local_target_ips(["169.254.1.1"], ifaces) == frozenset()  # interface is down


def test_choose_bind_self_only_targets_use_unbound_connect_probes():
    ifaces = parse_nmap_iflist(_SAMPLE_IFLIST)
    # A /32 of the scanner's own LAN address: raw packets bound to eth0 never loop back.
    choice = choose_bind(["192.0.2.10"], ifaces, privileged=True)
    assert choice.device is None and choice.privileged is False and choice.source is None
    assert choice.local_ips == {"192.0.2.10"}


def test_choose_bind_range_containing_self_keeps_bound_privileged_scan():
    ifaces = parse_nmap_iflist(_SAMPLE_IFLIST)
    choice = choose_bind(["192.0.2.0/24"], ifaces, privileged=True)
    assert choice.device == "eth0" and choice.privileged is True
    assert choice.local_ips == {"192.0.2.10"}  # the scanner probes those separately
    assert choose_bind(["192.0.2.50"], ifaces, privileged=True).local_ips == frozenset()
