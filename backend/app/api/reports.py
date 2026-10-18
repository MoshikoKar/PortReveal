"""Inventory reports: exposure distribution, rare services, version skew, /24 subnets."""
from __future__ import annotations

import ipaddress
from collections import defaultdict

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import case, func, select
from sqlalchemy.orm import Session

from ..auth.deps import current_user
from ..core.exposure import HIGH_THRESHOLD, MEDIUM_THRESHOLD, RARE_MIN_HOSTS
from ..core.mockdata import device_visible
from ..core.query.sqlfn import ipv4_int_expr
from ..db import get_db
from ..models import (
    DEVICE_ACTIVE,
    VULN_STATE_DISMISSED,
    Device,
    DevicePort,
    DevicePortVuln,
    Network,
    User,
    Vulnerability,
)

router = APIRouter(prefix="/api/reports", tags=["reports"])

TOP_HOSTS = 20
SCORE_BUCKET = 10
MAX_BUCKET = 100 // SCORE_BUCKET - 1  # the last bucket is 90-100
MAX_ROWS = 200
IPV4_SPACE = 2 ** 32
HEATMAP_PREFIX = 24
HEATMAP_CELLS = 2 ** (32 - HEATMAP_PREFIX)


def _host(d: Device, networks: dict[int, str]) -> dict:
    return {"uuid": d.uuid, "ip": d.current_ip, "hostname": d.hostname, "type": d.device_type,
            "score": d.exposure_score or 0, "network": networks.get(d.network_id)}


def _networks(db: Session) -> dict[int, str]:
    return {n.id: n.name for n in db.scalars(select(Network)).all()}


@router.get("/exposure")
def exposure_report(db: Session = Depends(get_db), user: User = Depends(current_user)):
    ok = device_visible(db)
    bucket = case((Device.exposure_score >= MAX_BUCKET * SCORE_BUCKET, MAX_BUCKET),
                  else_=Device.exposure_score // SCORE_BUCKET)
    hist = dict(db.execute(select(bucket, func.count(Device.id)).where(ok).group_by(bucket)).tuples().all())
    lvl = case((Device.exposure_score >= HIGH_THRESHOLD, "high"),
               (Device.exposure_score >= MEDIUM_THRESHOLD, "medium"), else_="low")
    levels = {"high": 0, "medium": 0, "low": 0}
    levels.update(dict(db.execute(select(lvl, func.count(Device.id)).where(ok).group_by(lvl)).tuples().all()))
    names = _networks(db)
    ip_key = ipv4_int_expr(db.get_bind().dialect.name, Device.current_ip)
    top = db.scalars(select(Device).where(ok, Device.exposure_score > 0)
                     .order_by(Device.exposure_score.desc(), ip_key).limit(TOP_HOSTS)).all()
    return {
        "levels": levels,
        "thresholds": {"high": HIGH_THRESHOLD, "medium": MEDIUM_THRESHOLD},
        "distribution": [{"from": i * SCORE_BUCKET, "to": 100 if i == MAX_BUCKET else (i + 1) * SCORE_BUCKET - 1,
                          "count": int(hist.get(i, 0))} for i in range(MAX_BUCKET + 1)],
        "top": [_host(d, names) for d in top],
    }


@router.get("/vulnerabilities")
def vuln_report(db: Session = Depends(get_db), user: User = Depends(current_user)):
    """At-risk devices (risk/combined score) and the CVEs matched on the most devices (spec 5.7)."""
    ok = device_visible(db)
    names = _networks(db)
    ip_key = ipv4_int_expr(db.get_bind().dialect.name, Device.current_ip)
    top_devices = db.scalars(
        select(Device).where(ok, Device.risk_score > 0)
        .order_by(Device.combined_score.desc(), Device.risk_score.desc(), ip_key).limit(TOP_HOSTS)
    ).all()
    n_dev = func.count(func.distinct(Device.id))
    cve_rows = db.execute(
        select(Vulnerability.cve_id, Vulnerability.cvss_base, Vulnerability.kev, Vulnerability.epss, n_dev)
        .join(DevicePortVuln, DevicePortVuln.cve_id == Vulnerability.cve_id)
        .join(DevicePort, DevicePort.id == DevicePortVuln.device_port_id)
        .join(Device, Device.id == DevicePort.device_id)
        .where(ok, DevicePortVuln.state != VULN_STATE_DISMISSED)
        .group_by(Vulnerability.cve_id, Vulnerability.cvss_base, Vulnerability.kev, Vulnerability.epss)
        .order_by(Vulnerability.kev.desc(), Vulnerability.cvss_base.desc().nulls_last(), n_dev.desc())
        .limit(TOP_HOSTS)
    ).all()
    return {
        "top_devices": [
            {**_host(d, names), "risk": d.risk_score or 0, "combined": d.combined_score or 0} for d in top_devices
        ],
        "top_cves": [
            {"cve_id": c, "cvss_base": cvss, "kev": bool(kev), "epss": epss, "device_count": int(n)}
            for c, cvss, kev, epss, n in cve_rows
        ],
    }


@router.get("/rare-services")
def rare_services(db: Session = Depends(get_db), user: User = Depends(current_user)):
    """Ports open on exactly one host of a network that has at least RARE_MIN_HOSTS hosts."""
    ok = device_visible(db)
    sizes = select(Device.network_id).where(ok, Device.network_id.isnot(None)).group_by(Device.network_id) \
        .having(func.count(Device.id) >= RARE_MIN_HOSTS)
    n_hosts = func.count(func.distinct(DevicePort.device_id))
    rows = db.execute(
        select(Device.network_id, DevicePort.port, DevicePort.protocol, func.min(DevicePort.id))
        .join(Device, Device.id == DevicePort.device_id)
        .where(ok, DevicePort.is_open.is_(True), Device.network_id.in_(sizes))
        .group_by(Device.network_id, DevicePort.port, DevicePort.protocol).having(n_hosts == 1)
        .order_by(DevicePort.port).limit(MAX_ROWS)
    ).all()
    port_ids = [r[3] for r in rows]
    found = {p.id: (p, d) for p, d in db.execute(
        select(DevicePort, Device).join(Device, Device.id == DevicePort.device_id).where(DevicePort.id.in_(port_ids)))}
    names = _networks(db)
    out = []
    for net_id, port, proto, pid in rows:
        p, d = found[pid]
        out.append({"network": names.get(net_id), "port": port, "protocol": proto, "service": p.service,
                    "product": p.product, "version": p.version, "host": _host(d, names)})
    return {"min_hosts": RARE_MIN_HOSTS, "items": out}


@router.get("/version-skew")
def version_skew(db: Session = Depends(get_db), user: User = Depends(current_user)):
    """Products seen with two or more versions, with the host count per version."""
    ok = device_visible(db)
    n_hosts = func.count(func.distinct(DevicePort.device_id))
    multi = select(DevicePort.product).join(Device, Device.id == DevicePort.device_id).where(
        ok, DevicePort.is_open.is_(True), DevicePort.product.isnot(None), DevicePort.version.isnot(None),
        DevicePort.version != "",
    ).group_by(DevicePort.product).having(func.count(func.distinct(DevicePort.version)) >= 2)
    rows = db.execute(
        select(DevicePort.product, DevicePort.version, n_hosts).join(Device, Device.id == DevicePort.device_id)
        .where(ok, DevicePort.is_open.is_(True), DevicePort.product.in_(multi), DevicePort.version.isnot(None),
               DevicePort.version != "")
        .group_by(DevicePort.product, DevicePort.version)
    ).all()
    by_product: dict[str, list[dict]] = defaultdict(list)
    for product, version, n in rows:
        by_product[product].append({"version": version, "hosts": int(n)})
    items = [{"product": p, "versions": sorted(v, key=lambda x: -x["hosts"]), "hosts": sum(x["hosts"] for x in v)}
             for p, v in by_product.items()]
    items.sort(key=lambda x: (-len(x["versions"]), -x["hosts"], x["product"].lower()))
    return {"items": items[:MAX_ROWS]}


@router.get("/subnets")
def subnets(db: Session = Depends(get_db), user: User = Depends(current_user)):
    """Each IPv4 /24 with its host count, active count and max / average exposure score.

    Aggregated in SQL (GROUP BY the address's /24 number), so the response costs one row per
    subnet however many devices there are.
    """
    ip_key = ipv4_int_expr(db.get_bind().dialect.name, Device.current_ip)
    block = (ip_key // 256).label("block")
    score = func.coalesce(Device.exposure_score, 0)
    rows = db.execute(
        select(
            block,
            func.count().label("hosts"),
            func.sum(case((Device.status == DEVICE_ACTIVE, 1), else_=0)).label("active"),
            func.max(score).label("max_score"),
            func.sum(score).label("score_sum"),
        )
        .where(device_visible(db), Device.current_ip.like("%.%.%.%"), Device.current_ip.not_like("%:%"))
        .group_by(block)
        .order_by(block)
    ).all()
    items = []
    for blk, hosts, active, max_score, score_sum in rows:
        if blk is None or not 0 < int(blk) * 256 < IPV4_SPACE:  # 0 = not an IPv4 address
            continue
        net = str(ipaddress.IPv4Network((int(blk) * 256, 24)))
        items.append({
            "subnet": net, "hosts": int(hosts), "active": int(active or 0), "max_score": int(max_score or 0),
            "avg_score": round(int(score_sum or 0) / hosts, 1), "query": f"net:{net}",
        })
    return {"items": items}


@router.get("/heatmap")
def subnet_heatmap(
    subnet: str | None = None,
    db: Session = Depends(get_db),
    user: User = Depends(current_user),
):
    """/24 grids coloured by exposure score (LAN version of Shodan Maps).

    Returns one grid per IPv4 /24 that has at least one known host, sorted by address.
    With `subnet` (an IPv4 /24 in CIDR form), returns only that grid.
    """
    only_base: int | None = None
    if subnet:
        try:
            net = ipaddress.ip_network(subnet, strict=False)
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc
        if net.version != 4 or net.prefixlen != HEATMAP_PREFIX:
            raise HTTPException(422, f"heatmap requires an IPv4 /{HEATMAP_PREFIX}")
        only_base = int(net.network_address)

    devices = db.scalars(
        select(Device).where(device_visible(db), Device.current_ip.like("%.%.%.%"))
    ).all()
    blocks: dict[int, dict[int, Device]] = defaultdict(dict)
    for d in devices:
        try:
            addr = int(ipaddress.IPv4Address(d.current_ip))
        except ValueError:
            continue
        base = addr & ~(HEATMAP_CELLS - 1)
        if base == 0 or (only_base is not None and base != only_base):
            continue
        blocks[base][addr & (HEATMAP_CELLS - 1)] = d

    items = []
    for base in sorted(blocks):
        by_host = blocks[base]
        assert by_host, "only occupied /24s are collected"
        net = ipaddress.IPv4Network((base, HEATMAP_PREFIX))
        cells = []
        for i in range(HEATMAP_CELLS):
            d = by_host.get(i)
            cells.append({
                "host": i,
                "ip": str(ipaddress.IPv4Address(base + i)),
                "present": d is not None,
                "score": (d.exposure_score or 0) if d else 0,
                "uuid": d.uuid if d else None,
                "hostname": d.hostname if d else None,
                "status": d.status if d else None,
            })
        items.append({"subnet": str(net), "hosts": len(by_host), "query": f"net:{net}", "cells": cells})
    return {"items": items}
