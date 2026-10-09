"""Compile a parsed query into SQLAlchemy conditions.

Two contexts:

* row  — one open service joined with its device (+ its HTTP metadata). Used for the services view
  and inside EXISTS sub-queries.
* host — one device. Port-level terms become EXISTS over the device's open services. Inside an AND,
  every port-only part (positive terms, and negations once a positive port term exists) goes into a
  single EXISTS, so they must hold for the *same* service. A negated port term with no positive
  partner means "host without": `-port:22` = no open 22.

Every leaf is two-valued (NULL columns never make a row "unknown"), so NOT behaves as expected.
"""
from __future__ import annotations

import ipaddress
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime

from sqlalchemy import and_, exists, func, not_, or_, select, true
from sqlalchemy.sql.elements import ColumnElement

from ...db import utcnow
from ...models import (
    SCREENSHOT_CAPTURED,
    TAG_SOURCE_SUPPRESSED,
    WEB_PAGE_LOGIN,
    Device,
    DeviceIP,
    DevicePort,
    DeviceProfile,
    DeviceTag,
    Network,
    PortHttp,
    WebPage,
)
from .fields import HAS_HOST_VALUES, HAS_PORT_VALUES, HOST, PORT, FieldSpec, resolve
from .parser import And, Node, Not, Or, QueryError, Term, split_value
from .sqlfn import ipv4_int_expr
from .values import contains_like, glob_to_like, int_range, parse_bool, time_window

MIXED = "mixed"


@dataclass
class Ctx:
    dialect: str = "sqlite"
    now: datetime = field(default_factory=utcnow)


# --- column maps ---------------------------------------------------------------------------------
P = DeviceProfile
# name: (wrapper, columns) — wrapper is "device", "profile", "tag" or "network"
_HOST_COLS: dict[str, tuple[str, Callable[[], list]]] = {
    "ip": ("device", lambda: [Device.current_ip]),
    "net": ("device", lambda: [Device.current_ip]),
    "hostname": ("device", lambda: [Device.hostname, Device.dns_name]),
    "mac": ("device", lambda: [Device.mac]),
    "vendor": ("device", lambda: [Device.vendor]),
    "os": ("device", lambda: [Device.os_name]),
    "status": ("device", lambda: [Device.status]),
    "type": ("device", lambda: [Device.device_type]),
    "score": ("device", lambda: [Device.exposure_score]),
    "first_seen": ("device", lambda: [Device.first_seen]),
    "new": ("device", lambda: [Device.first_seen]),
    "last_seen": ("device", lambda: [Device.last_seen]),
    "network": ("network", lambda: [Network.name]),
    "zone": ("network", lambda: [Network.zone]),
    "tag": ("tag", lambda: [DeviceTag.tag]),
    "owner": ("profile", lambda: [P.owner]),
    "location": ("profile", lambda: [P.location]),
    "criticality": ("profile", lambda: [P.criticality]),
    "notes": ("profile", lambda: [P.notes]),
}

# name: (table, columns) — table is "port" or "http" (outer-joined when needed)
_PORT_COLS: dict[str, tuple[str, Callable[[], list]]] = {
    "port": ("port", lambda: [DevicePort.port]),
    "proto": ("port", lambda: [DevicePort.protocol]),
    "service": ("port", lambda: [DevicePort.service]),
    "product": ("port", lambda: [DevicePort.product]),
    "version": ("port", lambda: [DevicePort.version]),
    "info": ("port", lambda: [DevicePort.extra_info]),
    "cpe": ("port", lambda: [DevicePort.cpe]),
    "opened": ("port", lambda: [DevicePort.opened_at]),
    "http.title": ("http", lambda: [PortHttp.title]),
    "http.status": ("http", lambda: [PortHttp.status]),
    "http.server": ("http", lambda: [PortHttp.server]),
    "http.content_type": ("http", lambda: [PortHttp.content_type]),
    "http.location": ("http", lambda: [PortHttp.location]),
    "http.login": ("http", lambda: [PortHttp.login]),
    "http.default_page": ("http", lambda: [PortHttp.default_page]),
}

_HAS_NEEDS_HTTP = {"http", "login"}


def _spec(term: Term) -> FieldSpec:
    spec = resolve(term.field or "")
    if spec is None:
        raise QueryError(f"unknown field '{term.field}'", term.pos)
    return spec


def _has_items(term: Term) -> list[str]:
    items = [v.lower() for v in split_value(term).items]
    for v in items:
        if v not in HAS_PORT_VALUES and v not in HAS_HOST_VALUES:
            raise QueryError(f"unknown has: value '{v}'", term.pos)
    return items


def level_of(term: Term) -> str:
    if term.field is None:
        return MIXED
    spec = _spec(term)
    if spec.kind == "has":
        port = [v in HAS_PORT_VALUES for v in _has_items(term)]
        return PORT if all(port) else HOST if not any(port) else MIXED
    return spec.level


def is_port_pure(node: Node) -> bool:
    if isinstance(node, Term):
        return level_of(node) == PORT
    if isinstance(node, Not):
        return is_port_pure(node.child)
    return all(is_port_pure(c) for c in node.children)


def needs_http(node: Node | None) -> bool:
    """True when the row condition reads HTTP metadata (so port_http must be joined)."""
    if node is None:
        return False
    if isinstance(node, Term):
        if node.field is None:
            return True
        spec = _spec(node)
        if spec.kind == "has":
            return any(v in _HAS_NEEDS_HTTP for v in _has_items(node))
        return spec.name in _PORT_COLS and _PORT_COLS[spec.name][0] == "http"
    if isinstance(node, Not):
        return needs_http(node.child)
    return any(needs_http(c) for c in node.children)


def service_from(with_http: bool = True):
    """FROM clause: device_ports, outer-joined with port_http when requested."""
    j = DevicePort.__table__
    if with_http:
        j = j.outerjoin(PortHttp.__table__, PortHttp.device_port_id == DevicePort.id)
    return j


def service_exists(cond: ColumnElement, with_http: bool) -> ColumnElement:
    return exists(
        select(DevicePort.id).select_from(service_from(with_http))
        .where(DevicePort.device_id == Device.id, DevicePort.is_open.is_(True), cond)
    )


# --- leaf builders -------------------------------------------------------------------------------
def _nn(col, cond) -> ColumnElement:
    return and_(col.isnot(None), cond)


def _exact_like(v: str) -> str:
    return v.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _text(cols: list, term: Term, *, mac: bool = False) -> ColumnElement:
    vals = split_value(term)
    out = []
    for raw in vals.items:
        v = raw.replace("-", ":").upper() if mac else raw
        if v == "*":
            out.append(or_(*[and_(c.isnot(None), c != "") for c in cols]))
            continue
        if vals.op == "=":
            pattern = _exact_like(v)
        elif "*" in v or "?" in v:
            pattern = glob_to_like(v)
        else:
            pattern = contains_like(v)
        out.append(or_(*[_nn(c, c.ilike(pattern, escape="\\")) for c in cols]))
    return or_(*out)


def _exact(cols: list, term: Term) -> ColumnElement:
    out = []
    for v in split_value(term).items:
        if v == "*":
            out.append(or_(*[and_(c.isnot(None), c != "") for c in cols]))
        elif "*" in v or "?" in v:
            out.append(or_(*[_nn(c, c.ilike(glob_to_like(v), escape="\\")) for c in cols]))
        else:
            out.append(or_(*[_nn(c, func.lower(c) == v.lower()) for c in cols]))
    return or_(*out)


def _int(cols: list, term: Term) -> ColumnElement:
    vals = split_value(term)
    out = []
    for raw in vals.items:
        if raw == "*":
            out.append(or_(*[c.isnot(None) for c in cols]))
            continue
        lo, hi = int_range(term, vals.op, raw)
        for c in cols:
            conds = [c.isnot(None)]
            if lo is not None:
                conds.append(c >= lo)
            if hi is not None:
                conds.append(c <= hi)
            out.append(and_(*conds))
    return or_(*out)


def _bool(cols: list, term: Term) -> ColumnElement:
    want = parse_bool(term, split_value(term, allow_list=False).items[0])
    return or_(*[c.is_(want) for c in cols])


def _time(cols: list, term: Term, ctx: Ctx) -> ColumnElement:
    vals = split_value(term, allow_list=False)
    after, before = time_window(term, vals.op, vals.items[0], ctx.now)
    out = []
    for c in cols:
        conds = [c.isnot(None)]
        if after is not None:
            conds.append(c >= after)
        if before is not None:
            conds.append(c < before)
        out.append(and_(*conds))
    return or_(*out)


def _ip(col, term: Term, ctx: Ctx) -> ColumnElement:
    out = []
    for v in split_value(term).items:
        if "/" in v:
            try:
                net = ipaddress.ip_network(v, strict=False)
            except ValueError:
                raise QueryError(f"'{term.field}' expects a CIDR like 10.0.0.0/24, not '{v}'", term.pos) from None
            if net.version != 4:
                raise QueryError("IPv6 ranges are not supported here; use a prefix like ip:fe80:*", term.pos)
            lo, hi = int(net.network_address), int(net.broadcast_address)
            out.append(and_(col.isnot(None), col.notlike("%:%"),
                            ipv4_int_expr(ctx.dialect, col).between(lo, hi)))
        elif "*" in v or "?" in v:
            out.append(_nn(col, col.like(glob_to_like(v), escape="\\")))
        else:
            out.append(_nn(col, col == v.strip()))
    return or_(*out)


def _active_tag(*extra: ColumnElement) -> ColumnElement:
    """Tag rows that count for search (rule + manual; dismissed suppressions do not)."""
    return and_(DeviceTag.source != TAG_SOURCE_SUPPRESSED, *extra)


def _wrap_host(wrapper: str, cond: ColumnElement) -> ColumnElement:
    if wrapper == "device":
        return cond
    if wrapper == "profile":
        return Device.id.in_(select(DeviceProfile.device_id).where(cond))
    if wrapper == "tag":
        return Device.id.in_(select(DeviceTag.device_id).where(_active_tag(cond)))
    if wrapper == "network":
        return and_(Device.network_id.isnot(None), Device.network_id.in_(select(Network.id).where(cond)))
    raise AssertionError(wrapper)


def _leaf(spec: FieldSpec, cols: list, term: Term, ctx: Ctx) -> ColumnElement:
    if spec.kind == "text":
        return _text(cols, term, mac=spec.name == "mac")
    if spec.kind == "exact":
        return _exact(cols, term)
    if spec.kind == "int":
        return _int(cols, term)
    if spec.kind == "bool":
        return _bool(cols, term)
    if spec.kind == "time":
        return _time(cols, term, ctx)
    if spec.kind == "ip":
        return _ip(cols[0], term, ctx)
    raise AssertionError(spec.kind)


def _has_port(value: str) -> ColumnElement:
    if value == "http":
        return PortHttp.id.isnot(None)
    if value == "cpe":
        return and_(DevicePort.cpe.isnot(None), DevicePort.cpe != "")
    if value == "port":
        return true()
    if value == "screenshot":
        return DevicePort.id.in_(select(WebPage.device_port_id).where(
            WebPage.device_port_id.isnot(None), WebPage.screenshot_status == SCREENSHOT_CAPTURED))
    if value == "login":
        return or_(PortHttp.login.is_(True), DevicePort.id.in_(select(WebPage.device_port_id).where(
            WebPage.device_port_id.isnot(None), WebPage.kind == WEB_PAGE_LOGIN)))
    raise AssertionError(value)


def _has_host(value: str) -> ColumnElement:
    if value in ("tag", "tags"):
        return Device.id.in_(select(DeviceTag.device_id).where(_active_tag()))
    simple = {"mac": Device.mac, "hostname": Device.hostname, "os": Device.os_name}
    if value in simple:
        c = simple[value]
        return and_(c.isnot(None), c != "")
    col = {"owner": P.owner, "notes": P.notes}[value]
    return Device.id.in_(select(DeviceProfile.device_id).where(col.isnot(None), col != ""))


def _free_text_parts(term: Term) -> tuple[ColumnElement, ColumnElement]:
    """(host condition, row condition) for a bare word: the classic device search plus service text."""
    q = term.value.strip()
    like = contains_like(q)
    host = or_(
        _nn(Device.current_ip, Device.current_ip.like(like, escape="\\")),
        _nn(Device.hostname, Device.hostname.ilike(like, escape="\\")),
        _nn(Device.dns_name, Device.dns_name.ilike(like, escape="\\")),
        _nn(Device.vendor, Device.vendor.ilike(like, escape="\\")),
        _nn(Device.os_name, Device.os_name.ilike(like, escape="\\")),
        _nn(Device.mac, Device.mac.ilike(contains_like(q.replace("-", ":").upper()), escape="\\")),
        Device.id.in_(select(DeviceIP.device_id).where(DeviceIP.ip.like(like, escape="\\"))),
        Device.id.in_(select(DeviceTag.device_id).where(_active_tag(DeviceTag.tag.ilike(like, escape="\\")))),
    )
    row_parts = [
        _nn(DevicePort.service, DevicePort.service.ilike(like, escape="\\")),
        _nn(DevicePort.product, DevicePort.product.ilike(like, escape="\\")),
        _nn(DevicePort.version, DevicePort.version.ilike(like, escape="\\")),
        _nn(DevicePort.extra_info, DevicePort.extra_info.ilike(like, escape="\\")),
        _nn(PortHttp.title, PortHttp.title.ilike(like, escape="\\")),
    ]
    port_txt = q.lower().removeprefix("tcp/").removeprefix("port:")
    if port_txt.isdigit() and len(port_txt) <= 5:
        row_parts.append(DevicePort.port == int(port_txt))
    return host, or_(*row_parts)


# --- row context ---------------------------------------------------------------------------------
def compile_row(node: Node | None, ctx: Ctx) -> ColumnElement:
    if node is None:
        return true()
    if isinstance(node, Not):
        return not_(compile_row(node.child, ctx))
    if isinstance(node, And):
        return and_(*[compile_row(c, ctx) for c in node.children])
    if isinstance(node, Or):
        return or_(*[compile_row(c, ctx) for c in node.children])
    return _row_term(node, ctx)


def _row_term(term: Term, ctx: Ctx) -> ColumnElement:
    if term.field is None:
        host, row = _free_text_parts(term)
        return or_(host, row)
    spec = _spec(term)
    if spec.kind == "has":
        return or_(*[_has_port(v) if v in HAS_PORT_VALUES else _has_host(v) for v in _has_items(term)])
    if spec.name in _PORT_COLS:
        if spec.name == "port" and split_value(term).items == ["*"]:
            return true()
        return _leaf(spec, _PORT_COLS[spec.name][1](), term, ctx)
    wrapper, cols = _HOST_COLS[spec.name]
    return _wrap_host(wrapper, _leaf(spec, cols(), term, ctx))


# --- host context --------------------------------------------------------------------------------
def compile_host(node: Node | None, ctx: Ctx) -> ColumnElement:
    if node is None:
        return true()
    if isinstance(node, Term):
        return _host_term(node, ctx)
    if isinstance(node, Not):
        return not_(compile_host(node.child, ctx))
    if isinstance(node, Or):
        if is_port_pure(node):
            return service_exists(compile_row(node, ctx), needs_http(node))
        return or_(*[compile_host(c, ctx) for c in node.children])
    # AND: one EXISTS for the port-only parts so they hold on the same service
    group = [c for c in node.children if not isinstance(c, Not) and is_port_pure(c)]
    negs = [c for c in node.children if isinstance(c, Not) and is_port_pure(c.child)] if group else []
    rest = [c for c in node.children if c not in group and c not in negs]
    conds: list[ColumnElement] = []
    if group:
        members = group + negs
        sub = And(tuple(members)) if len(members) > 1 else members[0]
        conds.append(service_exists(compile_row(sub, ctx), needs_http(sub)))
    conds += [compile_host(c, ctx) for c in rest]
    return and_(*conds)


def _host_term(term: Term, ctx: Ctx) -> ColumnElement:
    level = level_of(term)
    if level == PORT:
        return service_exists(_row_term(term, ctx), needs_http(term))
    if term.field is None:
        host, row = _free_text_parts(term)
        return or_(host, service_exists(row, True))
    spec = _spec(term)
    if spec.kind == "has":
        out = []
        for v in _has_items(term):
            if v in HAS_PORT_VALUES:
                out.append(service_exists(_has_port(v), v in _HAS_NEEDS_HTTP))
            else:
                out.append(_has_host(v))
        return or_(*out)
    wrapper, cols = _HOST_COLS[spec.name]
    return _wrap_host(wrapper, _leaf(spec, cols(), term, ctx))


def validate(node: Node | None) -> None:
    """Raise QueryError for unknown fields / bad values without touching the database."""
    if node is not None:
        compile_host(node, Ctx())


def has_port_terms(node: Node | None) -> bool:
    if node is None:
        return False
    if isinstance(node, Term):
        return level_of(node) != HOST
    if isinstance(node, Not):
        return has_port_terms(node.child)
    return any(has_port_terms(c) for c in node.children)
