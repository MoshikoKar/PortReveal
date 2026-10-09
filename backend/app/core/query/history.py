"""Point-in-time search: evaluate a query against the daily snapshots in Python.

Snapshots keep a compact copy of each network (hosts, open ports, and since v2 tags/type/score), so
only fields with a `history` key can be used. Semantics mirror compile.py exactly.
"""
from __future__ import annotations

import ipaddress
from collections import Counter
from datetime import date

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ...models import Network, Snapshot
from ...netutils import ip_sort_key
from ..mockdata import snapshot_visible
from ..snapshots import load_snapshot
from .compile import HOST, MIXED, PORT, is_port_pure, level_of
from .fields import resolve
from .parser import And, Node, Not, Or, QueryError, Term, quote_value, split_value, terms
from .values import glob_regex, int_range

_HAS_HISTORY = {"port", "udp", "tag", "tags", "mac", "hostname"}


def check_historical(node: Node | None) -> None:
    for t in terms(node):
        if t.field is None:
            continue
        spec = resolve(t.field)
        if spec is None:
            raise QueryError(f"unknown field '{t.field}'", t.pos)
        if spec.kind == "has":
            bad = [v for v in split_value(t).items if v.lower() not in _HAS_HISTORY]
            if bad:
                raise QueryError(f"has:{bad[0]} is not available in historical snapshots", t.pos)
        elif spec.history is None:
            raise QueryError(f"'{spec.name}' is not available in historical snapshots", t.pos)


def _text_match(values: list[str | None], term: Term) -> bool:
    vals = split_value(term)
    present = [v for v in values if v]
    for raw in vals.items:
        if raw == "*":
            if present:
                return True
            continue
        if vals.op == "=":
            if any(v.lower() == raw.lower() for v in present):
                return True
        elif "*" in raw or "?" in raw:
            rx = glob_regex(raw)
            if any(rx.match(v) for v in present):
                return True
        elif any(raw.lower() in v.lower() for v in present):
            return True
    return False


def _exact_match(values: list[str | None], term: Term) -> bool:
    present = [v for v in values if v]
    for raw in split_value(term).items:
        if raw == "*" and present:
            return True
        if "*" in raw or "?" in raw:
            rx = glob_regex(raw)
            if any(rx.match(v) for v in present):
                return True
        elif any(v.lower() == raw.lower() for v in present):
            return True
    return False


def _int_match(value: int | None, term: Term) -> bool:
    if value is None:
        return False
    vals = split_value(term)
    for raw in vals.items:
        if raw == "*":
            return True
        lo, hi = int_range(term, vals.op, raw)
        if (lo is None or value >= lo) and (hi is None or value <= hi):
            return True
    return False


def _ip_match(ip: str, term: Term) -> bool:
    for raw in split_value(term).items:
        if "/" in raw:
            try:
                if ipaddress.ip_address(ip) in ipaddress.ip_network(raw, strict=False):
                    return True
            except ValueError:
                continue
        elif "*" in raw or "?" in raw:
            if glob_regex(raw).match(ip):
                return True
        elif ip == raw.strip():
            return True
    return False


def _host_term(term: Term, h: dict) -> bool:
    spec = resolve(term.field or "")
    name = spec.name
    if spec.kind == "has":
        out = False
        for v in (x.lower() for x in split_value(term).items):
            if v in ("tag", "tags"):
                out |= bool(h["tags"])
            elif v == "mac":
                out |= bool(h["mac"])
            elif v == "hostname":
                out |= bool(h["hostname"])
        return out
    if name in ("ip", "net"):
        return _ip_match(h["ip"], term)
    if name == "hostname":
        return _text_match([h["hostname"]], term)
    if name == "mac":
        t = Term(term.field, term.value.replace("-", ":").upper(), term.quoted, term.pos, term.op)
        return _text_match([h["mac"]], t)
    if name == "status":
        return _exact_match([h["status"]], term)
    if name == "network":
        return _text_match([h["network"]], term)
    if name == "tag":
        return _exact_match(list(h["tags"]), term)
    if name == "type":
        return _exact_match([h["type"]], term)
    if name == "score":
        return _int_match(h["score"], term)
    raise QueryError(f"'{name}' is not available in historical snapshots", term.pos)


def _row_term(term: Term, h: dict, p: dict | None) -> bool:
    if term.field is None:
        q = term.value.strip().lower()
        host_hit = any(q in (v or "").lower() for v in (h["ip"], h["hostname"], h["mac"])) or any(
            q in t for t in h["tags"])
        if host_hit or p is None:
            return host_hit
        port_txt = q.removeprefix("tcp/").removeprefix("udp/")
        return any(q in (v or "").lower() for v in (p["service"], p["product"], p["version"])) or (
            port_txt.isdigit() and int(port_txt) == p["port"])
    spec = resolve(term.field)
    if spec.kind == "has":
        items = [v.lower() for v in split_value(term).items]
        out = False
        for v in items:
            if v == "port":
                out |= p is not None
            elif v == "udp":
                out |= p is not None and p["proto"] == "udp"
            else:
                out |= _host_term(Term("has", v), h)
        return out
    if spec.level == HOST:
        return _host_term(term, h)
    if p is None:
        return False
    if spec.name == "port":
        return _int_match(p["port"], term)
    if spec.name == "proto":
        return _exact_match([p["proto"]], term)
    return _text_match([p[spec.name]], term)


def row_match(node: Node, h: dict, p: dict | None) -> bool:
    if isinstance(node, Term):
        return _row_term(node, h, p)
    if isinstance(node, Not):
        return not row_match(node.child, h, p)
    if isinstance(node, And):
        return all(row_match(c, h, p) for c in node.children)
    return any(row_match(c, h, p) for c in node.children)


def _any_port(node: Node, h: dict) -> bool:
    return any(row_match(node, h, p) for p in h["ports"])


def host_match(node: Node | None, h: dict) -> bool:
    if node is None:
        return True
    if isinstance(node, Term):
        level = level_of(node)
        if level == PORT:
            return _any_port(node, h)
        if level == MIXED:
            return _row_term(node, h, None) or _any_port(node, h)
        return _host_term(node, h)
    if isinstance(node, Not):
        return not host_match(node.child, h)
    if isinstance(node, Or):
        if is_port_pure(node):
            return _any_port(node, h)
        return any(host_match(c, h) for c in node.children)
    group = [c for c in node.children if not isinstance(c, Not) and is_port_pure(c)]
    negs = [c for c in node.children if isinstance(c, Not) and is_port_pure(c.child)] if group else []
    rest = [c for c in node.children if c not in group and c not in negs]
    if group:
        members = group + negs
        sub = And(tuple(members)) if len(members) > 1 else members[0]
        if not _any_port(sub, h):
            return False
    return all(host_match(c, h) for c in rest)


def snapshot_hosts(db: Session, at: date) -> tuple[list[dict], list[dict]]:
    """Hosts from the latest snapshot of each network on or before `at`, plus the snapshots used."""
    latest = (
        select(Snapshot.network_id, func.max(Snapshot.snapshot_date).label("d"))
        .where(Snapshot.snapshot_date <= at, snapshot_visible(db)).group_by(Snapshot.network_id).subquery()
    )
    snaps = db.scalars(select(Snapshot).join(latest, (Snapshot.network_id == latest.c.network_id)
                                             & (Snapshot.snapshot_date == latest.c.d))).all()
    names = {n.id: n.name for n in db.scalars(select(Network)).all()}
    hosts: list[dict] = []
    used: list[dict] = []
    for s in snaps:
        payload = load_snapshot(s)
        net_name = (payload.get("network") or {}).get("name") or names.get(s.network_id)
        used.append({"network": net_name, "snapshot_date": s.snapshot_date.isoformat(), "scan_id": s.scan_id})
        for row in payload.get("devices", []):
            hosts.append({
                "uuid": row[0], "ip": row[1], "mac": row[2], "hostname": row[3], "status": row[4],
                "ports": [{"port": p[0], "proto": p[1], "service": p[2], "product": p[3], "version": p[4]}
                          for p in row[5]],
                "tags": list(row[6]) if len(row) > 6 and row[6] else [],
                "type": row[7] if len(row) > 7 else None,
                "score": row[8] if len(row) > 8 else None,
                "network": net_name,
            })
    return hosts, used


def search_history(db: Session, node: Node | None, at: date, *, page: int, page_size: int) -> dict:
    check_historical(node)
    hosts, used = snapshot_hosts(db, at)
    matched = sorted((h for h in hosts if host_match(node, h)), key=lambda h: ip_sort_key(h["ip"]))
    ports: Counter = Counter()
    products: Counter = Counter()
    tags: Counter = Counter()
    for h in matched:
        rows = [p for p in h["ports"] if node is None or row_match(node, h, p)]
        for key in {(p["port"], p["proto"]) for p in rows}:
            ports[key] += 1
        for prod in {p["product"] for p in rows if p["product"]}:
            products[prod] += 1
        for t in h["tags"]:
            tags[t] += 1
    start = (page - 1) * page_size
    return {
        "at": at.isoformat(),
        "snapshots": used,
        "total": len(matched),
        "items": matched[start:start + page_size],
        "facets": {
            "port": [{"value": f"{p}/{proto}", "count": n, "term": f"port:{p}" + (" proto:udp" if proto == "udp" else "")}
                     for (p, proto), n in ports.most_common(10)],
            "product": [{"value": v, "count": n, "term": f"product:={quote_value(v)}"} for v, n in products.most_common(10)],
            "tag": [{"value": v, "count": n, "term": f"tag:{quote_value(v)}"} for v, n in tags.most_common(10)],
        },
    }
