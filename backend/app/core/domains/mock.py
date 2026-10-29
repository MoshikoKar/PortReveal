"""Simulated domain-scan backend for SCANNER_MODE=mock (development default, e2e tests).

Mock mode promises no network traffic, so a domain scan neither runs subfinder/dnsx nor sends a DNS
query: answers come from a fixed per-domain scenario. Like the mock nmap scanner it advances: from
the second scan of a domain on, one extra public name appears (so change events can be seen).
"""
from __future__ import annotations

from .dnsops import Answer, AxfrRefused, ZoneRecord

MOCK_NOTE = "Simulated results (mock scanner): no tools were run and no DNS queries were sent."

# label -> (internal answer, public answer); None = no answer in that view
_BASE = {
    "www": ("192.0.2.10", "198.51.100.10"),
    "mail": ("192.0.2.25", "198.51.100.25"),
    "vpn": (None, "198.51.100.30"),
    "intranet": ("192.0.2.20", None),
    "dev": ("192.0.2.40", None),  # only in the zone transfer: internal (authorized)
}
_EXTRA = {"new": (None, "198.51.100.40")}
_PASSIVE = ("www", "mail", "vpn")
_AXFR = ("www", "mail", "intranet", "dev")
_PUBLIC_NS = {"ns1": "198.51.100.53"}


class MockDns:
    """Same interface as DnsClient; never touches the network."""

    def __init__(self, domain: str, public_resolvers: list[str], *, advanced: bool = False):
        self.domain = domain
        self.public = list(public_resolvers)
        self.labels = {**_BASE, **(_EXTRA if advanced else {})}

    def _answer(self, ip: str | None) -> Answer:
        return Answer(a=[ip], status="ok") if ip else Answer(status="nxdomain")

    def resolve(self, name: str, nameservers: list[str] | None) -> Answer:
        public = nameservers == self.public
        if name.endswith("." + self.domain):
            pair = self.labels.get(name[: -len(self.domain) - 1])
            if pair:
                return self._answer(pair[1] if public else pair[0])
        if public and name in {f"{ns}.{self.domain}" for ns in _PUBLIC_NS}:
            return self._answer(_PUBLIC_NS[name.split(".")[0]])
        return Answer(status="nxdomain")

    def system_nameservers(self) -> list[str]:
        return ["192.0.2.53"]

    def nameservers(self, domain: str, resolvers: list[str] | None) -> dict[str, list[str]]:
        return {f"{ns}.{domain}": [ip] for ns, ip in _PUBLIC_NS.items()}

    def axfr(self, zone: str, server: str, timeout: float) -> list[ZoneRecord]:
        if server in _PUBLIC_NS.values():
            raise AxfrRefused("TransferError")  # the simulated public NS refuses, as it should
        return [ZoneRecord(f"{label}.{zone}", "A", _BASE[label][0]) for label in _AXFR]


def mock_passive(domain: str, advanced: bool) -> list[str]:
    labels = list(_PASSIVE) + (list(_EXTRA) if advanced else [])
    return [f"{label}.{domain}" for label in labels]
