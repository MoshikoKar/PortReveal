"""Parse Nmap XML output (-oX) into normalized observations."""
from __future__ import annotations

from dataclasses import dataclass, field

from defusedxml import ElementTree as ET

from .types import HostObservation, PortObservation, ScanStageError

# NSE scripts whose output is kept (see nmap_scanner.SCRIPTS). Everything else nmap prints - including
# the "version" category scripts -sV runs on its own, such as mqtt-subscribe - is dropped.
KEPT_SCRIPTS = frozenset({
    "ssh-hostkey", "ssh2-enum-algos", "smb-protocols", "smb2-security-mode", "smb-os-discovery", "nbstat",
    "rdp-ntlm-info", "ssl-cert", "socks-auth-info", "vnc-info", "rtsp-methods",
})
_DROP_KEYS = frozenset({"pem", "modulus", "extensions"})  # ssl-cert bulk; the output text keeps the SAN
_MAX_OUTPUT = 4000


@dataclass
class ParsedRun:
    hosts: list[HostObservation] = field(default_factory=list)
    port_scope: str | None = None  # TCP port list from <scaninfo services=...>
    finished_ok: bool = True
    error: str | None = None


def _clean(value: str | None) -> str | None:
    value = (value or "").strip()
    return value or None


def _script_value(el):
    """<script>/<table> children as plain JSON: keyed elems/tables -> dict, unkeyed -> list."""
    items = []
    for child in el:
        if child.tag not in ("elem", "table") or child.get("key") in _DROP_KEYS:
            continue
        val = _script_value(child) if child.tag == "table" else (child.text or "").strip()
        items.append((child.get("key"), val))
    if items and all(k is not None for k, _ in items):
        return dict(items)
    return [v for _, v in items]


def _scripts(parent) -> dict[str, dict]:
    out = {}
    for sc in parent.findall("script"):
        sid = sc.get("id")
        output = (sc.get("output") or "").strip()
        if sid in KEPT_SCRIPTS and not output.startswith("ERROR:"):  # a failed script states no fact
            out[sid] = {"output": output[:_MAX_OUTPUT], "data": _script_value(sc)}
    return out


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
        obs = HostObservation(ip="")
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

        hostscript = host.find("hostscript")
        if hostscript is not None:
            obs.scripts = _scripts(hostscript)

        timed_out = host.get("timedout") == "true"
        ports_el = host.find("ports")
        if timed_out:
            obs.port_scan_failed = True
            obs.failure_reason = "host timed out"
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
                    if not obs.os_name and svc.get("ostype"):
                        obs.os_name = svc.get("ostype")
                po.scripts = _scripts(p)
                obs.ports.append(po)
        run.hosts.append(obs)
    return run
