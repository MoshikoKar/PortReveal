"""Parse Nmap XML output (-oX) into normalized observations."""
from __future__ import annotations

from dataclasses import dataclass, field

from defusedxml import ElementTree as ET

from .types import HostObservation, PortObservation, ScanStageError


@dataclass
class ParsedRun:
    hosts: list[HostObservation] = field(default_factory=list)
    port_scope: str | None = None  # TCP port list from <scaninfo services=...>
    finished_ok: bool = True
    error: str | None = None


def _clean(value: str | None) -> str | None:
    value = (value or "").strip()
    return value or None


def parse_nmap_xml(xml_text: str) -> ParsedRun:
    if not xml_text or not xml_text.strip():
        raise ScanStageError("nmap produced no XML output")
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as exc:
        raise ScanStageError(f"could not parse nmap XML: {exc}") from exc
    if root.tag != "nmaprun":
        raise ScanStageError("unexpected XML document (not nmaprun)")

    run = ParsedRun()
    for info in root.findall("scaninfo"):
        if info.get("protocol") == "tcp" and info.get("services"):
            run.port_scope = info.get("services")

    finished = root.find("runstats/finished")
    if finished is None:
        # nmap was interrupted before finishing the document
        run.finished_ok = False
        run.error = "nmap output incomplete (no runstats)"
    elif finished.get("exit") == "error":
        run.finished_ok = False
        run.error = finished.get("errormsg") or "nmap reported an error"

    for host in root.findall("host"):
        status = host.find("status")
        if status is None or status.get("state") != "up":
            continue
        obs = HostObservation(ip="", reason=_clean(status.get("reason")))
        for addr in host.findall("address"):
            atype = addr.get("addrtype")
            if atype == "ipv4":
                obs.ip = addr.get("addr", "")
            elif atype == "mac":
                obs.mac = (addr.get("addr") or "").upper() or None
                obs.vendor = _clean(addr.get("vendor"))
        if not obs.ip:
            continue
        names = host.findall("hostnames/hostname")
        ptr = [n.get("name") for n in names if n.get("type") == "PTR" and n.get("name")]
        user = [n.get("name") for n in names if n.get("name")]
        obs.hostname = _clean((ptr or user or [None])[0])

        osmatch = host.find("os/osmatch")
        if osmatch is not None and osmatch.get("name"):
            obs.os_name = f"{osmatch.get('name')} ({osmatch.get('accuracy', '?')}%)"

        timed_out = host.get("timedout") == "true"
        ports_el = host.find("ports")
        if timed_out:
            obs.port_scan_failed = True
        elif ports_el is not None:
            obs.ports = []
            for p in ports_el.findall("port"):
                state = p.find("state")
                if state is None or state.get("state") != "open":
                    continue
                svc = p.find("service")
                po = PortObservation(port=int(p.get("portid", "0")), protocol=p.get("protocol", "tcp"))
                if svc is not None:
                    po.service = _clean(svc.get("name"))
                    po.product = _clean(svc.get("product"))
                    po.version = _clean(svc.get("version"))
                    po.extra_info = _clean(svc.get("extrainfo"))
                    po.method = _clean(svc.get("method"))
                    conf = svc.get("conf")
                    po.confidence = int(conf) if conf and conf.isdigit() else None
                    po.tunnel = _clean(svc.get("tunnel"))
                    cpes = [c.text.strip() for c in svc.findall("cpe") if c.text and c.text.strip()]
                    po.cpe = " ".join(dict.fromkeys(cpes))[:500] or None
                    if not obs.os_name and svc.get("ostype"):
                        obs.os_name = svc.get("ostype")
                obs.ports.append(po)
        run.hosts.append(obs)
    return run
