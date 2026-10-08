"""Device self-identification: what a device says about itself (name, model, manufacturer, firmware).

Runs after a real (nmap) scan, like web capture, only for devices without a model whose last check
is older than the version-cache TTL. Every source sends at most one request per device (mDNS: one
PTR query, plus one TXT query when service instances were announced) with a 2 s timeout. Nothing is
inferred: a field is filled only from a value the device returned, and it records that source.
Unreachable sources just leave fields empty.

Sources: mDNS/DNS-SD (unicast to UDP 5353), SSDP/UPnP (unicast M-SEARCH to UDP 1900, description
XML only from the same IP), AirPlay /info (only where nmap confirmed AirPlay), IPP
Get-Printer-Attributes (only where nmap confirmed IPP). Raw printer ports 9100-9107 are never used.
"""
from __future__ import annotations

import ipaddress
import logging
import plistlib
import queue
import random
import socket
import struct
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta
from urllib.parse import urlparse

import httpx
from defusedxml import ElementTree as ET
from sqlalchemy import select

from ..db import session_scope, utcnow
from ..models import Device, DevicePort, ScanHost
from ..scanner.known_ports import is_raw_print_port
from ..settings_store import ScanSettings, get_section
from .port_profiles import auto_mark

log = logging.getLogger(__name__)

TIMEOUT_S = 2.0
_WORKERS = 8
_MAX_BODY = 256 * 1024
FIELDS = ("name", "model", "manufacturer", "firmware")
# DNS-SD service types whose TXT records carry self-reported model / name data.
MDNS_SERVICES = ("_device-info._tcp", "_airplay._tcp", "_googlecast._tcp", "_hap._tcp", "_ipp._tcp",
                 "_printer._tcp", "_smb._tcp", "_workstation._tcp")


Found = dict[str, tuple[str, str]]  # field -> (value, source)


def _put(found: Found, field: str, value, source: str) -> None:
    if field not in found and isinstance(value, str) and (value := value.strip()):
        found[field] = (value[:200], source)


# ---- mDNS / DNS-SD -------------------------------------------------------------------------------

_PTR, _TXT = 12, 16


def _encode_name(name: str) -> bytes:
    out = b""
    for label in name.rstrip(".").split("."):
        raw = label.encode("utf-8")[:63]
        out += bytes([len(raw)]) + raw
    return out + b"\x00"


def dns_query(qid: int, questions: list[tuple[str, int]]) -> bytes:
    msg = struct.pack("!HHHHHH", qid, 0, len(questions), 0, 0, 0)
    for name, qtype in questions:
        msg += _encode_name(name) + struct.pack("!HH", qtype, 1)
    return msg


def _read_name(data: bytes, off: int) -> tuple[str, int]:
    labels: list[str] = []
    end = None
    for _ in range(128):  # bounded: compression loops in hostile packets
        n = data[off]
        if n & 0xC0 == 0xC0:
            if end is None:
                end = off + 2
            off = ((n & 0x3F) << 8) | data[off + 1]
            continue
        off += 1
        if n == 0:
            break
        labels.append(data[off:off + n].decode("utf-8", errors="replace"))
        off += n
    return ".".join(labels), (end if end is not None else off)


def parse_dns(data: bytes) -> list[tuple[str, int, object]]:
    """Resource records of a DNS response: (name, type, PTR target str | TXT list[str] | None)."""
    qd, an, ns, ar = struct.unpack("!4H", data[4:12])
    off = 12
    for _ in range(qd):
        _, off = _read_name(data, off)
        off += 4
    out: list[tuple[str, int, object]] = []
    for _ in range(an + ns + ar):
        name, off = _read_name(data, off)
        rtype, _cls, _ttl, rdlen = struct.unpack("!HHIH", data[off:off + 10])
        off += 10
        rdata = data[off:off + rdlen]
        value: object = None
        if rtype == _PTR:
            value = _read_name(data, off)[0]
        elif rtype == _TXT:
            items, i = [], 0
            while i < len(rdata):
                n = rdata[i]
                items.append(rdata[i + 1:i + 1 + n].decode("utf-8", errors="replace"))
                i += 1 + n
            value = items
        out.append((name.lower(), rtype, value))
        off += rdlen
    return out


def _mdns_exchange(ip: str, questions: list[tuple[str, int]]) -> list[tuple[str, int, object]]:
    """One legacy unicast query to ip:5353 (the reply comes back to our source port, unicast)."""
    qid = random.randint(1, 0xFFFF)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(TIMEOUT_S)
        sock.sendto(dns_query(qid, questions), (ip, 5353))
        records: list[tuple[str, int, object]] = []
        try:
            while True:
                data, addr = sock.recvfrom(9000)
                if addr[0] == ip and len(data) >= 12:
                    try:
                        records += parse_dns(data)
                    except (IndexError, struct.error):
                        pass
                    if records:
                        sock.settimeout(0.3)  # collect a split reply, then stop
        except OSError:
            pass
    return records


def _txt_map(items) -> dict[str, str]:
    out = {}
    for item in items or []:
        key, sep, val = item.partition("=")
        if sep:
            out.setdefault(key.lower(), val)
    return out


def mdns_identity(ip: str, records_for=_mdns_exchange) -> Found:
    found: Found = {}
    rev = ipaddress.ip_address(ip).reverse_pointer
    recs = records_for(ip, [(rev, _PTR)] + [(f"{s}.local", _PTR) for s in MDNS_SERVICES])
    instances = {str(v).lower() for n, t, v in recs if t == _PTR and n != rev.lower() and v}
    txt = {n: v for n, t, v in recs if t == _TXT}
    labels = sorted({i.split("._", 1)[0] for i in instances if "._" in i})
    missing = [i for i in instances if i not in txt][:6] + [f"{lb}._device-info._tcp.local" for lb in labels[:2]]
    if missing:
        recs += records_for(ip, [(n, _TXT) for n in missing])
        txt.update({n: v for n, t, v in recs if t == _TXT})
    src = "mDNS"
    for n, t, v in recs:
        if t == _PTR and n == rev.lower() and v:
            _put(found, "name", str(v).removesuffix(".local").removesuffix(".local."), src)
    for name, items in sorted(txt.items()):
        kv = _txt_map(items)
        service = next((s for s in MDNS_SERVICES if f".{s}." in f".{name}."), "")
        tag = f"{src} {service}" if service else src
        _put(found, "model", kv.get("model") or kv.get("md") or kv.get("usb_mdl"), tag)
        _put(found, "manufacturer", kv.get("manufacturer") or kv.get("usb_mfg"), tag)
        _put(found, "firmware", kv.get("fv") or kv.get("firmware"), tag)
        _put(found, "name", kv.get("fn"), tag)
        if service in ("_ipp._tcp", "_printer._tcp"):
            _put(found, "model", kv.get("ty"), tag)
    for inst in sorted(instances):
        if "._workstation._tcp." in inst:
            _put(found, "name", inst.split("._", 1)[0].split(" [", 1)[0], f"{src} _workstation._tcp")
    return found


# ---- SSDP / UPnP ---------------------------------------------------------------------------------

_MSEARCH = (b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\n"
            b"MX: 1\r\nST: upnp:rootdevice\r\n\r\n")


def _ssdp_location(ip: str) -> str | None:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(TIMEOUT_S)
        sock.sendto(_MSEARCH, (ip, 1900))
        try:
            while True:
                data, addr = sock.recvfrom(4096)
                if addr[0] != ip:
                    continue
                for line in data.decode("latin-1").split("\r\n"):
                    key, _, val = line.partition(":")
                    if key.strip().lower() == "location":
                        return val.strip()
        except OSError:
            return None


def _get(url: str, **kw) -> httpx.Response | None:
    try:
        with httpx.Client(timeout=TIMEOUT_S, follow_redirects=False, verify=False) as c:
            with c.stream(kw.pop("method", "GET"), url, **kw) as r:
                body = b""
                for chunk in r.iter_bytes():
                    body += chunk
                    if len(body) > _MAX_BODY:
                        return None
                r._content = body
                return r
    except (httpx.HTTPError, OSError):
        return None


def parse_upnp(xml: bytes) -> Found:
    found: Found = {}
    root = ET.fromstring(xml)
    dev = next((el for el in root.iter() if el.tag.rsplit("}", 1)[-1] == "device"), None)
    if dev is None:
        return found
    vals = {el.tag.rsplit("}", 1)[-1]: (el.text or "") for el in dev}  # root device only, not sub-devices
    model = " ".join(v for v in (vals.get("modelName", "").strip(), vals.get("modelNumber", "").strip()) if v)
    _put(found, "name", vals.get("friendlyName"), "UPnP")
    _put(found, "model", model, "UPnP")
    _put(found, "manufacturer", vals.get("manufacturer"), "UPnP")
    _put(found, "firmware", vals.get("softwareVersion") or vals.get("firmwareVersion"), "UPnP")
    return found


def upnp_identity(ip: str) -> Found:
    loc = _ssdp_location(ip)
    if not loc:
        return {}
    u = urlparse(loc)
    if u.scheme not in ("http", "https") or u.hostname != ip or is_raw_print_port(u.port):
        return {}  # only the device's own description, never a third host
    r = _get(loc)
    if r is None or r.status_code != 200:
        return {}
    try:
        return parse_upnp(r.content)
    except ET.ParseError:
        return {}


# ---- AirPlay /info -------------------------------------------------------------------------------

def parse_airplay_info(body: bytes) -> Found:
    found: Found = {}
    info = plistlib.loads(body)
    if isinstance(info, dict):
        _put(found, "name", info.get("name"), "AirPlay")
        _put(found, "model", info.get("model"), "AirPlay")
        _put(found, "manufacturer", info.get("manufacturer"), "AirPlay")
        _put(found, "firmware", info.get("osBuildVersion") or info.get("firmwareRevision"), "AirPlay")
    return found


def airplay_identity(ip: str, port: int) -> Found:
    r = _get(f"http://{ip}:{port}/info")
    if r is None or r.status_code != 200:
        return {}
    try:
        return parse_airplay_info(r.content)
    except (plistlib.InvalidFileException, ValueError, OverflowError):
        return {}


# ---- IPP Get-Printer-Attributes ------------------------------------------------------------------

_IPP_ATTRS = ("printer-make-and-model", "printer-name", "printer-firmware-string-version", "printer-device-id")


def ipp_request(uri: str) -> bytes:
    def attr(tag: int, name: str, value: str) -> bytes:
        n, v = name.encode(), value.encode()
        return bytes([tag]) + struct.pack("!H", len(n)) + n + struct.pack("!H", len(v)) + v

    body = struct.pack("!BBHI", 2, 0, 0x000B, 1) + b"\x01"
    body += attr(0x47, "attributes-charset", "utf-8") + attr(0x48, "attributes-natural-language", "en")
    body += attr(0x45, "printer-uri", uri) + attr(0x44, "requested-attributes", _IPP_ATTRS[0])
    for extra in _IPP_ATTRS[1:]:
        body += attr(0x44, "", extra)  # additional value of the same attribute
    return body + b"\x03"


def parse_ipp(data: bytes) -> Found:
    found: Found = {}
    attrs: dict[str, str] = {}
    off, name = 8, ""
    while off < len(data):
        tag = data[off]
        off += 1
        if tag == 0x03:
            break
        if tag <= 0x0F:
            continue  # group delimiter
        nlen = struct.unpack("!H", data[off:off + 2])[0]
        off += 2
        name = data[off:off + nlen].decode("utf-8", "replace") or name
        off += nlen
        vlen = struct.unpack("!H", data[off:off + 2])[0]
        off += 2
        if tag in (0x41, 0x42, 0x44, 0x45, 0x30):  # text / name / keyword / uri / octetString
            attrs.setdefault(name, data[off:off + vlen].decode("utf-8", "replace"))
        off += vlen
    device_id = dict(p.split(":", 1) for p in attrs.get("printer-device-id", "").split(";") if ":" in p)
    _put(found, "model", attrs.get("printer-make-and-model"), "IPP")
    _put(found, "name", attrs.get("printer-name"), "IPP")
    _put(found, "firmware", attrs.get("printer-firmware-string-version"), "IPP")
    _put(found, "manufacturer", device_id.get("MFG") or device_id.get("MANUFACTURER"), "IPP")
    return found


def ipp_identity(ip: str, port: int) -> Found:
    r = _get(f"http://{ip}:{port}/ipp/print", method="POST", content=ipp_request(f"ipp://{ip}:{port}/ipp/print"),
             headers={"Content-Type": "application/ipp"})
    if r is None or r.status_code != 200 or len(r.content) < 9:
        return {}
    try:
        return parse_ipp(r.content)
    except (struct.error, IndexError, ValueError):
        return {}


# ---- orchestration -------------------------------------------------------------------------------

def _confirmed(p: DevicePort, *words: str) -> bool:
    text = f"{p.service or ''} {p.product or ''}".lower()
    return p.method == "probed" and any(w in text for w in words)


def probe_device(ip: str, ports: list[DevicePort]) -> Found:
    """All sources for one device, cheapest first; the first source to return a field wins."""
    steps = [lambda: mdns_identity(ip), lambda: upnp_identity(ip)]
    for p in ports:
        if is_raw_print_port(p.port):
            continue
        if _confirmed(p, "airplay", "airtunes"):
            steps.append(lambda port=p.port: airplay_identity(ip, port))
        elif _confirmed(p, "ipp"):
            steps.append(lambda port=p.port: ipp_identity(ip, port))
    found: Found = {}
    for step in steps:
        try:
            for field, val in step().items():
                found.setdefault(field, val)
        except Exception:  # one bad source must not stop the others
            log.debug("self-id source failed for %s", ip, exc_info=True)
    return found


def _due(details: dict | None, ttl_days: int, now: datetime) -> bool:
    ident = (details or {}).get("identity") or {}
    if ident.get("model"):
        return False
    checked = (details or {}).get("selfid_at")
    try:
        return checked is None or now - datetime.fromisoformat(checked) >= timedelta(days=max(ttl_days, 1))
    except ValueError:
        return True


def run_self_id(scan_id: int) -> int:
    """Probe the due devices seen up in `scan_id`. Returns how many devices were probed."""
    now = utcnow()
    with session_scope() as db:
        ttl = get_section(db, ScanSettings).version_cache_days
        devs = db.scalars(select(Device).join(ScanHost, ScanHost.device_id == Device.id)
                          .where(ScanHost.scan_id == scan_id, ScanHost.status == "up")).unique().all()
        todo = [(d.id, d.current_ip, [p for p in d.ports if p.is_open and p.protocol == "tcp"])
                for d in devs if _due(d.details, ttl, now)]
        for _, _, ports in todo:
            for p in ports:
                db.expunge(p)
    if not todo:
        return 0
    with ThreadPoolExecutor(max_workers=_WORKERS, thread_name_prefix="selfid") as pool:
        results = list(pool.map(lambda t: probe_device(t[1], t[2]), todo))
    with session_scope() as db:
        for (dev_id, _, _), found in zip(todo, results, strict=True):
            dev = db.get(Device, dev_id)
            if dev is None:
                continue
            details = dict(dev.details or {})
            ident = dict(details.get("identity") or {})
            for field, (value, source) in found.items():
                ident[field] = {"value": value, "source": source}
            details["identity"], details["selfid_at"] = ident, now.isoformat()
            dev.details = details
            for field in ("name", "model", "manufacturer"):
                if field in found:
                    auto_mark(dev, found[field][0], found[field][1])
    log.info("self-identification after scan %s: %d device(s) probed, %d returned data",
             scan_id, len(todo), sum(1 for f in results if f))
    return len(todo)


class SelfIdWorker:
    """One background thread; scans enqueue their id when they finish."""

    def __init__(self) -> None:
        self._queue: queue.Queue[int] = queue.Queue()
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()

    def start(self) -> None:
        if self._thread is None:
            self._stop.clear()
            self._thread = threading.Thread(target=self._loop, name="selfid", daemon=True)
            self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=5)
            self._thread = None

    def enqueue(self, scan_id: int) -> None:
        if self._thread is not None:
            self._queue.put(scan_id)

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                scan_id = self._queue.get(timeout=1.0)
            except queue.Empty:
                continue
            try:
                run_self_id(scan_id)
            except Exception:
                log.exception("self-identification after scan %s failed", scan_id)


self_id_worker = SelfIdWorker()
