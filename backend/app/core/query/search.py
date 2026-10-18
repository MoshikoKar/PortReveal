"""Execute inventory queries: host and service views, facets, counts, bulk ids, streaming export."""
from __future__ import annotations

import ipaddress
from collections import Counter, defaultdict
from collections.abc import Iterator
from dataclasses import dataclass

from sqlalchemy import func, select, true
from sqlalchemy.orm import Session

from ...db import utcnow
from ...models import (
    SCREENSHOT_CAPTURED,
    TAG_SOURCE_SUPPRESSED,
    Device,
    DevicePort,
    DeviceProfile,
    DeviceTag,
    Network,
    PortHttp,
    WebPage,
)
from ..mockdata import device_visible
from .compile import (
    Ctx,
    compile_host,
    compile_row,
    has_port_terms,
    join_flags,
    needs_http,
    service_from,
    validate,
)
from .parser import And, Node, QueryError, parse, quote_value, terms
from .sqlfn import ipv4_int_expr
from .values import time_window

SERVICES_PER_HOST = 6
MAX_FACETS = 12
MAX_FACET_LIMIT = 50
HOST_SORTS = ("score", "ip", "last_seen", "first_seen", "hostname")


def extract_before(node: Node | None) -> tuple[Node | None, object | None]:
    """Pull `before:` out of the AST. Returns (remaining node, date|None for historical search)."""
    from datetime import date as date_cls
    from datetime import timedelta

    if node is None:
        return None, None
    before_date = None
    kept: list[Node] = []
    for t in terms(node):
        if t.field and t.field.lower() == "before":
            raw = t.value.lstrip("<>= ").strip()
            try:
                before_date = date_cls.fromisoformat(raw[:10]) - timedelta(days=1)
            except ValueError:
                try:
                    _start, end = time_window(t, t.op, raw, Ctx().now)
                    ref = end or _start or Ctx().now
                    before_date = ref.date() if hasattr(ref, "date") else None
                except Exception:
                    before_date = None
            continue
        kept.append(t)
    if before_date is None:
        return node, None
    if not kept:
        return None, before_date
    if len(kept) == 1:
        return kept[0], before_date
    return And(tuple(kept)), before_date


def prepare(text: str | None) -> Node | None:
    """Parse and validate (unknown fields / bad values raise QueryError)."""
    node = parse(text or "")
    validate(node)
    return node


def make_ctx(db: Session) -> Ctx:
    return Ctx(dialect=db.get_bind().dialect.name, now=utcnow())


def host_conditions(db: Session, node: Node | None, ctx: Ctx | None = None) -> list:
    return [device_visible(db), compile_host(node, ctx or make_ctx(db))]


def _rows_from(node: Node | None = None):
    """Open services joined with their device and enrichment metadata (the row context)."""
    if node is None:
        return service_from(True, True, True, False).join(Device.__table__, Device.id == DevicePort.device_id)
    http, tls, snmp, shot, vuln = join_flags(node)
    return service_from(True, tls, snmp, shot, vuln).join(Device.__table__, Device.id == DevicePort.device_id)


def _host_order(db: Session, sort: str, desc: bool) -> list:
    ip_key = ipv4_int_expr(db.get_bind().dialect.name, Device.current_ip)

    def d(expr):
        return expr.desc() if desc else expr.asc()

    if sort == "ip":
        return [d(ip_key), d(Device.id)]
    if sort == "last_seen":
        return [d(Device.last_seen), Device.id.desc()]
    if sort == "first_seen":
        return [d(Device.first_seen), Device.id.desc()]
    if sort == "hostname":
        return [d(func.coalesce(func.nullif(Device.hostname, ""), "~")), ip_key.asc()]
    return [d(Device.exposure_score), ip_key.asc(), Device.id.asc()]


# --- serialization -----------------------------------------------------------------------------------
def http_out(h: PortHttp | None) -> dict | None:
    if h is None:
        return None
    return {"scheme": h.scheme, "status": h.status, "title": h.title, "server": h.server,
            "content_type": h.content_type, "location": h.location, "login": h.login,
            "default_page": h.default_page, "favicon_hash": h.favicon_hash,
            "html_hash": h.html_hash, "header_set_hash": h.header_set_hash,
            "web_vnc": h.web_vnc, "last_seen": h.last_seen}


def service_out(p: DevicePort, http: PortHttp | None) -> dict:
    return {
        "port": p.port, "protocol": p.protocol, "service": p.service, "product": p.product, "version": p.version,
        "extra_info": p.extra_info, "cpe": p.cpe.split() if p.cpe else [], "tunnel": p.tunnel,
        "method": p.method, "confidence": p.confidence, "first_seen": p.first_seen, "last_seen": p.last_seen,
        "opened_at": p.opened_at, "http": http_out(http),
    }


def _host_summary(d: Device, network: str | None, tags: list[str]) -> dict:
    return {
        "uuid": d.uuid, "ip": d.current_ip, "hostname": d.hostname, "mac": d.mac, "vendor": d.vendor,
        "os": d.os_name, "status": d.status, "network": network, "network_id": d.network_id,
        "type": d.device_type, "score": d.exposure_score or 0, "tags": tags,
        "first_seen": d.first_seen, "last_seen": d.last_seen,
    }


def _network_names(db: Session) -> dict[int, str]:
    return {n.id: n.name for n in db.scalars(select(Network)).all()}


def _tags_for(db: Session, ids: list[int]) -> dict[int, list[str]]:
    tags: dict[int, list[str]] = defaultdict(list)
    for dev_id, tag in db.execute(
        select(DeviceTag.device_id, DeviceTag.tag)
        .where(DeviceTag.device_id.in_(ids), DeviceTag.source != TAG_SOURCE_SUPPRESSED)
        .order_by(DeviceTag.tag)
    ):
        tags[dev_id].append(tag)
    return tags


# --- views ----------------------------------------------------------------------------------------------
@dataclass
class ResultPage:
    items: list[dict]
    total: int


def search_hosts(db: Session, node: Node | None, *, page: int = 1, page_size: int = 25, sort: str = "score",
                 desc: bool = True) -> ResultPage:
    ctx = make_ctx(db)
    conds = host_conditions(db, node, ctx)
    total = db.scalar(select(func.count(Device.id)).where(*conds)) or 0
    devices = list(db.scalars(
        select(Device).where(*conds).order_by(*_host_order(db, sort, desc))
        .offset((page - 1) * page_size).limit(page_size)
    ).all())
    return ResultPage(_decorate_hosts(db, devices, node, ctx), total)


def _decorate_hosts(db: Session, devices: list[Device], node: Node | None, ctx: Ctx) -> list[dict]:
    """Batch-load tags, open ports, the services that matched and a screenshot for one result page."""
    if not devices:
        return []
    ids = [d.id for d in devices]
    names = _network_names(db)
    tags = _tags_for(db, ids)
    ports: dict[int, list[dict]] = defaultdict(list)
    for dev_id, port, proto, svc in db.execute(
        select(DevicePort.device_id, DevicePort.port, DevicePort.protocol, DevicePort.service)
        .where(DevicePort.device_id.in_(ids), DevicePort.is_open.is_(True))
        .order_by(DevicePort.port, DevicePort.protocol)
    ):
        ports[dev_id].append({"port": port, "protocol": proto, "service": svc})
    row_cond = compile_row(node, ctx) if has_port_terms(node) else true()
    matched: dict[int, list[dict]] = defaultdict(list)
    counts: Counter = Counter()
    for p, http in db.execute(
        select(DevicePort, PortHttp).select_from(_rows_from())
        .where(DevicePort.device_id.in_(ids), DevicePort.is_open.is_(True), row_cond)
        .order_by(DevicePort.device_id, DevicePort.port)
    ).all():
        counts[p.device_id] += 1
        if len(matched[p.device_id]) < SERVICES_PER_HOST:
            matched[p.device_id].append(service_out(p, http))
    shots: dict[int, dict] = {}
    for page in db.scalars(
        select(WebPage).where(WebPage.device_id.in_(ids), WebPage.screenshot_status == SCREENSHOT_CAPTURED)
        .order_by(WebPage.captured_at.desc(), WebPage.id.desc())
    ):
        shots.setdefault(page.device_id, {"page_id": page.id, "port": page.port, "title": page.title,
                                          "captured_at": page.captured_at})
    out = []
    for d in devices:
        item = _host_summary(d, names.get(d.network_id), tags.get(d.id, []))
        item["open_ports"] = ports.get(d.id, [])
        item["services"] = matched.get(d.id, [])
        item["matched_services"] = counts.get(d.id, 0)
        item["screenshot"] = shots.get(d.id)
        out.append(item)
    return out


def search_services(db: Session, node: Node | None, *, page: int = 1, page_size: int = 50) -> ResultPage:
    ctx = make_ctx(db)
    conds = [DevicePort.is_open.is_(True), device_visible(db), compile_row(node, ctx)]
    total = db.scalar(select(func.count(DevicePort.id)).select_from(_rows_from()).where(*conds)) or 0
    ip_key = ipv4_int_expr(ctx.dialect, Device.current_ip)
    rows = db.execute(
        select(DevicePort, PortHttp, Device).select_from(_rows_from()).where(*conds)
        .order_by(ip_key, Device.id, DevicePort.port, DevicePort.protocol)
        .offset((page - 1) * page_size).limit(page_size)
    ).all()
    names = _network_names(db)
    items = []
    for p, http, d in rows:
        svc = service_out(p, http)
        svc["host"] = {"uuid": d.uuid, "ip": d.current_ip, "hostname": d.hostname, "type": d.device_type,
                       "score": d.exposure_score or 0, "network": names.get(d.network_id), "status": d.status}
        items.append(svc)
    return ResultPage(items, total)


def matching_host_ids(db: Session, node: Node | None, ctx: Ctx | None = None):
    """Select of matching device ids (for IN sub-queries)."""
    return select(Device.id).where(*host_conditions(db, node, ctx))


def matching_uuids(db: Session, node: Node | None, limit: int) -> list[str]:
    return list(db.scalars(select(Device.uuid).where(*host_conditions(db, node)).order_by(Device.id)
                           .limit(limit)).all())


def count(db: Session, node: Node | None) -> dict:
    ctx = make_ctx(db)
    hosts = db.scalar(select(func.count(Device.id)).where(*host_conditions(db, node, ctx))) or 0
    services = db.scalar(
        select(func.count(DevicePort.id)).select_from(_rows_from())
        .where(DevicePort.is_open.is_(True), compile_row(node, ctx),
               DevicePort.device_id.in_(matching_host_ids(db, node, ctx)))
    ) or 0
    return {"hosts": hosts, "services": services}


# --- facets ----------------------------------------------------------------------------------------------
_HOST_FACETS = {
    "type": lambda: Device.device_type,
    "os": lambda: Device.os_name,
    "vendor": lambda: Device.vendor,
    "status": lambda: Device.status,
}
_PROFILE_FACETS = {
    "criticality": lambda: DeviceProfile.criticality,
    "owner": lambda: DeviceProfile.owner,
    "location": lambda: DeviceProfile.location,
}
_PORT_FACETS = {
    "service": lambda: DevicePort.service,
    "product": lambda: DevicePort.product,
    "proto": lambda: DevicePort.protocol,
    "http.title": lambda: PortHttp.title,
    "http.server": lambda: PortHttp.server,
    "http.status": lambda: PortHttp.status,
}
FACET_NAMES = ("port", "tag", "network", "net", "version", *_HOST_FACETS, *_PROFILE_FACETS, *_PORT_FACETS)
_INT_FACETS = {"http.status"}


def parse_facets(spec: str | None, default: str = "port,product,tag,type,os") -> list[tuple[str, int]]:
    out: list[tuple[str, int]] = []
    for part in (spec if spec is not None else default).split(","):
        part = part.strip()
        if not part:
            continue
        name, _, lim = part.partition(":")
        name = name.strip().lower()
        if name not in FACET_NAMES:
            raise QueryError(f"unknown facet '{name}'")
        limit = 10
        if lim:
            if not lim.strip().isdigit():
                raise QueryError(f"facet limit must be a number: '{part}'")
            limit = max(1, min(int(lim), MAX_FACET_LIMIT))
        out.append((name, limit))
    if len(out) > MAX_FACETS:
        raise QueryError(f"too many facets (max {MAX_FACETS})")
    return out


def facet_term(field: str, value) -> str:
    """A query term selecting exactly this facet value."""
    if field in _INT_FACETS:
        return f"{field}:{value}"
    if field in ("tag", "type", "status", "proto", "criticality"):
        return f"{field}:{quote_value(str(value))}"
    return f"{field}:={quote_value(str(value))}"


def facets(db: Session, node: Node | None, wanted: list[tuple[str, int]]) -> dict[str, list[dict]]:
    """Counts of matching hosts per value. Port facets count among the services that matched."""
    ctx = make_ctx(db)
    host_ids = matching_host_ids(db, node, ctx)
    row_cond = compile_row(node, ctx) if has_port_terms(node) else true()
    return {name: _facet(db, name, limit, host_ids, row_cond, node) for name, limit in wanted}


def _items(rows, field: str, limit: int) -> list[dict]:
    out = []
    for value, n in rows:
        if value is None or value == "":
            continue
        out.append({"value": value, "count": int(n), "term": facet_term(field, value)})
        if len(out) >= limit:
            break
    return out


def _facet(db: Session, name: str, limit: int, host_ids, row_cond, node) -> list[dict]:
    n_hosts = func.count(func.distinct(DevicePort.device_id))
    svc_from = service_from(needs_http(node) or name.startswith("http.")).join(
        Device.__table__, Device.id == DevicePort.device_id)
    svc_where = (DevicePort.is_open.is_(True), DevicePort.device_id.in_(host_ids), row_cond)
    if name == "port":
        rows = db.execute(
            select(DevicePort.port, DevicePort.protocol, n_hosts).select_from(svc_from).where(*svc_where)
            .group_by(DevicePort.port, DevicePort.protocol).order_by(n_hosts.desc(), DevicePort.port).limit(limit)
        ).all()
        return [{"value": f"{p}/{proto}", "count": int(n),
                 "term": f"port:{p}" + (f" proto:{proto}" if proto != "tcp" else "")} for p, proto, n in rows]
    if name == "version":
        rows = db.execute(
            select(DevicePort.product, DevicePort.version, n_hosts).select_from(svc_from)
            .where(*svc_where, DevicePort.product.isnot(None), DevicePort.version.isnot(None))
            .group_by(DevicePort.product, DevicePort.version).order_by(n_hosts.desc()).limit(limit)
        ).all()
        return [{"value": f"{prod} {ver}", "count": int(n),
                 "term": f"{facet_term('product', prod)} {facet_term('version', ver)}"} for prod, ver, n in rows]
    if name in _PORT_FACETS:
        col = _PORT_FACETS[name]()
        rows = db.execute(select(col, n_hosts).select_from(svc_from).where(*svc_where, col.isnot(None))
                          .group_by(col).order_by(n_hosts.desc()).limit(limit + 1)).all()
        return _items(rows, name, limit)
    n_dev = func.count(func.distinct(Device.id))
    if name in _HOST_FACETS:
        col = _HOST_FACETS[name]()
        rows = db.execute(select(col, n_dev).where(Device.id.in_(host_ids), col.isnot(None))
                          .group_by(col).order_by(n_dev.desc()).limit(limit + 1)).all()
        return _items(rows, name, limit)
    if name in _PROFILE_FACETS:
        col = _PROFILE_FACETS[name]()
        n_prof = func.count(func.distinct(DeviceProfile.device_id))
        rows = db.execute(select(col, n_prof).where(DeviceProfile.device_id.in_(host_ids), col.isnot(None))
                          .group_by(col).order_by(n_prof.desc()).limit(limit + 1)).all()
        return _items(rows, name, limit)
    if name == "tag":
        n_tag = func.count(func.distinct(DeviceTag.device_id))
        rows = db.execute(
            select(DeviceTag.tag, n_tag)
            .where(DeviceTag.device_id.in_(host_ids), DeviceTag.source != TAG_SOURCE_SUPPRESSED)
            .group_by(DeviceTag.tag).order_by(n_tag.desc()).limit(limit)
        ).all()
        return _items(rows, "tag", limit)
    if name == "network":
        rows = db.execute(select(Network.name, n_dev).join(Device, Device.network_id == Network.id)
                          .where(Device.id.in_(host_ids)).group_by(Network.name).order_by(n_dev.desc())
                          .limit(limit)).all()
        return _items(rows, "network", limit)
    if name == "net":
        counter: Counter = Counter()
        for ip in db.scalars(select(Device.current_ip).where(Device.id.in_(host_ids)).limit(100_000)):
            try:
                addr = ipaddress.ip_address(ip)
            except ValueError:
                continue
            prefix = 24 if addr.version == 4 else 64
            counter[str(ipaddress.ip_network(f"{ip}/{prefix}", strict=False))] += 1
        return [{"value": net, "count": n, "term": f"net:{net}"} for net, n in counter.most_common(limit)]
    raise QueryError(f"unknown facet '{name}'")


# --- export ------------------------------------------------------------------------------------------------
EXPORT_MAX_ROWS = 100_000
_EXPORT_BATCH = 500


def iter_hosts(db: Session, node: Node | None, max_rows: int = EXPORT_MAX_ROWS) -> Iterator[dict]:
    """Every matching host with its open services, paged by id (no full materialization)."""
    ctx = make_ctx(db)
    conds = host_conditions(db, node, ctx)
    names = _network_names(db)
    last_id = 0
    sent = 0
    while sent < max_rows:
        batch = list(db.scalars(select(Device).where(*conds, Device.id > last_id).order_by(Device.id)
                                .limit(_EXPORT_BATCH)).all())
        if not batch:
            return
        ids = [d.id for d in batch]
        tags = _tags_for(db, ids)
        services: dict[int, list[dict]] = defaultdict(list)
        for p, http in db.execute(
            select(DevicePort, PortHttp).select_from(service_from(True))
            .where(DevicePort.device_id.in_(ids), DevicePort.is_open.is_(True))
            .order_by(DevicePort.device_id, DevicePort.port)
        ).all():
            services[p.device_id].append(service_out(p, http))
        for d in batch:
            item = _host_summary(d, names.get(d.network_id), tags.get(d.id, []))
            item["services"] = services.get(d.id, [])
            yield item
            sent += 1
            if sent >= max_rows:
                return
        last_id = batch[-1].id
