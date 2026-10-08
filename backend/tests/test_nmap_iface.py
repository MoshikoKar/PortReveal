from app.scanner.nmap_iface import choose_bind, parse_nmap_iflist

_SAMPLE_IFLIST = """
Starting Nmap 7.95 ( https://nmap.org )
************************INTERFACES************************
DEV  (SHORT) IP/MASK            TYPE     UP   MTU  MAC
unk0 (unk0)  100.83.223.100/32  other    up   1280
eth0 (eth0)  192.168.69.102/24  ethernet up   1500 74:56:3C:BA:82:BA
unk1 (unk1)  169.254.82.85/16   other    down 1500
eth1 (eth1)  169.254.48.137/16  ethernet down 1500 D4:E9:8A:60:F3:20
lo0  (lo0)   127.0.0.1/8        loopback up   -1
eth5 (eth5)  172.25.16.1/20     ethernet up   1500 00:15:5D:31:13:F0

DEV    WINDEVICE
unk0   \\Device\\NPF_{37217669-42DA-4657-A55B-0D995D328250}
eth0   \\Device\\NPF_{E3028D88-58F2-4805-9020-58544856A72F}
"""


def test_parse_nmap_iflist_ipv4_only():
    ifaces = parse_nmap_iflist(_SAMPLE_IFLIST)
    by_dev = {i.dev: i for i in ifaces}
    assert set(by_dev) == {"unk0", "eth0", "unk1", "eth1", "lo0", "eth5"}
    assert by_dev["eth0"].is_ethernet and by_dev["eth0"].up
    assert str(by_dev["eth0"].network) == "192.168.69.0/24"
    assert by_dev["unk0"].type == "other" and not by_dev["unk0"].is_ethernet
    assert by_dev["lo0"].is_loopback


def test_choose_bind_prefers_local_ethernet_over_tunnel():
    ifaces = parse_nmap_iflist(_SAMPLE_IFLIST)
    # Tailscale (unk0) may own the OS route, but LAN overlap must bind eth0.
    choice = choose_bind(["192.168.69.0/24"], ifaces, privileged=True)
    assert choice.device == "eth0" and choice.privileged is True

    single = choose_bind(["192.168.69.50"], ifaces, privileged=True)
    assert single.device == "eth0"


def test_choose_bind_tunnel_only_drops_privileged():
    ifaces = parse_nmap_iflist(_SAMPLE_IFLIST)
    # Only overlap is unk0 (Tailscale / other) — ARP cannot bind there.
    choice = choose_bind(["100.83.223.100"], ifaces, privileged=True)
    assert choice.device is None and choice.privileged is False


def test_choose_bind_no_overlap_keeps_settings():
    ifaces = parse_nmap_iflist(_SAMPLE_IFLIST)
    choice = choose_bind(["10.20.0.0/24"], ifaces, privileged=True)
    assert choice.device is None and choice.privileged is True


def test_choose_bind_ignores_down_and_link_local_when_better_exists():
    ifaces = parse_nmap_iflist(_SAMPLE_IFLIST)
    choice = choose_bind(["172.25.16.0/20"], ifaces, privileged=False)
    assert choice.device == "eth5"
