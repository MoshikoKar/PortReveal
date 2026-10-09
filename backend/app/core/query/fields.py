"""Searchable fields: names, levels and documentation (the SQL lives in compile.py).

`level` decides matching semantics. Host fields describe the device. Port fields describe one open
service, and port terms combined with AND must match the *same* service, as in Shodan:
`port:443 product:nginx` means nginx on 443, not "has 443 and has nginx somewhere".
"""
from __future__ import annotations

from dataclasses import dataclass

HOST = "host"
PORT = "port"


@dataclass(frozen=True)
class FieldSpec:
    name: str
    level: str  # host | port
    kind: str  # text | exact | int | bool | time | expires | ip | has
    group: str
    help: str
    example: str
    aliases: tuple[str, ...] = ()
    # Key in a historical snapshot row when the field can be evaluated against daily snapshots
    history: str | None = None


_SPECS: tuple[FieldSpec, ...] = (
    # --- host -----------------------------------------------------------------------------------
    FieldSpec("ip", HOST, "ip", "Host", "Current IP: exact, wildcard (10.0.*.5) or CIDR", "ip:10.0.0.0/24",
              history="ip"),
    FieldSpec("net", HOST, "ip", "Host", "Current IP inside a CIDR", "net:192.168.10.0/24", history="ip"),
    FieldSpec("hostname", HOST, "text", "Host", "Hostname / DNS name", "hostname:srv-", ("host", "name"),
              history="hostname"),
    FieldSpec("mac", HOST, "text", "Host", "MAC address or OUI prefix", "mac:00:1A:2B", history="mac"),
    FieldSpec("vendor", HOST, "text", "Host", "Hardware vendor (from the MAC OUI)", "vendor:Dell"),
    FieldSpec("os", HOST, "text", "Host", "Operating system guess", "os:windows"),
    FieldSpec("status", HOST, "exact", "Host", "active, unknown or not_detected", "status:active",
              history="status"),
    FieldSpec("network", HOST, "text", "Host", "Configured network name", "network:\"Office LAN\"",
              history="network"),
    FieldSpec("zone", HOST, "exact", "Host", "Network zone (servers, users, iot, dmz, ...)", "zone:iot"),
    FieldSpec("tag", HOST, "exact", "Host", "Device tag (rule or manual)", "tag:camera", ("tags",),
              history="tags"),
    FieldSpec("type", HOST, "exact", "Host", "Classified device type", "type:printer", ("device_type",),
              history="type"),
    FieldSpec("score", HOST, "int", "Host", "Exposure score 0-100", "score:>=60", ("exposure",),
              history="score"),
    FieldSpec("first_seen", HOST, "time", "Host", "When the device was first seen", "first_seen:<7d"),
    FieldSpec("last_seen", HOST, "time", "Host", "When the device was last seen", "last_seen:>30d"),
    FieldSpec("new", HOST, "time", "Host", "First seen within this window", "new:7d"),
    FieldSpec("owner", HOST, "text", "Host", "Owner (operator-entered)", "owner:alice"),
    FieldSpec("location", HOST, "text", "Host", "Location (operator-entered)", "location:\"server room\""),
    FieldSpec("criticality", HOST, "exact", "Host", "low, medium, high or critical", "criticality:high"),
    FieldSpec("notes", HOST, "text", "Host", "Operator notes", "notes:decommission"),
    # --- service ------------------------------------------------------------------------------------
    FieldSpec("port", PORT, "int", "Service", "Open port number, range or list (port:* = any)",
              "port:22,3389", history="port"),
    FieldSpec("proto", PORT, "exact", "Service", "tcp or udp", "proto:udp", ("protocol", "transport"),
              history="proto"),
    FieldSpec("service", PORT, "text", "Service", "Service name", "service:ms-wbt-server", history="service"),
    FieldSpec("product", PORT, "text", "Service", "Product name", "product:OpenSSH", history="product"),
    FieldSpec("version", PORT, "text", "Service", "Product version", "version:8.9", history="version"),
    FieldSpec("info", PORT, "text", "Service", "Extra service info from nmap", "info:\"protocol 2.0\"",
              ("extrainfo",)),
    FieldSpec("cpe", PORT, "text", "Service", "CPE identifier", "cpe:\"cpe:/a:openbsd:openssh\""),
    FieldSpec("opened", PORT, "time", "Service", "When the port was (re)opened", "opened:<7d",
              ("port.first_seen",)),
    # --- HTTP (from the latest web capture of the port) -----------------------------------------------
    FieldSpec("http.title", PORT, "text", "HTTP", "Page title", "http.title:\"Grafana\"", ("title",)),
    FieldSpec("http.status", PORT, "int", "HTTP", "Status code of the landing page", "http.status:401"),
    FieldSpec("http.server", PORT, "text", "HTTP", "Server header", "http.server:IIS"),
    FieldSpec("http.content_type", PORT, "text", "HTTP", "Content-Type of the landing page",
              "http.content_type:json"),
    FieldSpec("http.location", PORT, "text", "HTTP", "Redirect target", "http.location:/login"),
    FieldSpec("http.login", PORT, "bool", "HTTP", "Landing page is a login form", "http.login:true"),
    FieldSpec("http.default_page", PORT, "bool", "HTTP", "Web server default/placeholder page",
              "http.default_page:true"),
    # --- presence ---------------------------------------------------------------------------------------
    FieldSpec("has", HOST, "has", "Presence", "Has a property: port, http, cpe, screenshot, login, tag, owner, "
              "notes, mac, hostname, os", "has:screenshot"),
)

HAS_PORT_VALUES = frozenset({"http", "cpe", "screenshot", "login", "port"})
HAS_HOST_VALUES = frozenset({"tag", "tags", "owner", "notes", "mac", "hostname", "os"})

FIELDS: dict[str, FieldSpec] = {}
for _spec in _SPECS:
    FIELDS[_spec.name] = _spec
    for _alias in _spec.aliases:
        FIELDS[_alias] = _spec


def resolve(name: str) -> FieldSpec | None:
    return FIELDS.get(name.lower())


def field_docs() -> list[dict]:
    """Field reference for the UI and API (canonical names only)."""
    return [
        {"name": s.name, "level": s.level, "kind": s.kind, "group": s.group, "help": s.help,
         "example": s.example, "aliases": list(s.aliases), "historical": s.history is not None}
        for s in _SPECS
    ]
