"""Exposure score (0-100): a weighted sum of risky services and context, with its explanation."""
from __future__ import annotations

import math
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..models import Device, DevicePort, DeviceProfile
from .tagging import DeviceFacts

MAX_SCORE = 100
HIGH_THRESHOLD = 60
MEDIUM_THRESHOLD = 30
NEW_HOST_DAYS = 7
RARE_MIN_HOSTS = 5  # uniqueness only means something in a network with at least this many hosts
EXPOSED_ZONES = ("users", "iot", "guest")
ZONE_MULTIPLIER = 1.5

ADMIN = "admin"
DATABASE = "database"


@dataclass(frozen=True)
class PortFactor:
    factor: str
    label: str
    ports: tuple[int, ...]
    services: tuple[str, ...]
    points: int
    kind: str | None = None


PORT_FACTORS: tuple[PortFactor, ...] = (
    PortFactor("telnet", "Telnet", (23,), ("telnet",), 30, ADMIN),
    PortFactor("docker", "Docker API", (2375,), ("docker",), 30, ADMIN),
    PortFactor("rdp", "RDP", (3389,), ("ms-wbt-server",), 25, ADMIN),
    PortFactor("vnc", "VNC", (5900,), ("vnc",), 25, ADMIN),
    PortFactor("smb", "SMB", (445,), ("microsoft-ds",), 20),
    PortFactor("mysql", "MySQL", (3306,), ("mysql",), 20, DATABASE),
    PortFactor("postgresql", "PostgreSQL", (5432,), ("postgresql",), 20, DATABASE),
    PortFactor("mssql", "MS SQL", (1433,), ("ms-sql-s",), 20, DATABASE),
    PortFactor("oracle", "Oracle", (1521,), ("oracle-tns",), 20, DATABASE),
    PortFactor("mongodb", "MongoDB", (27017,), ("mongodb",), 20, DATABASE),
    PortFactor("redis", "Redis", (6379,), ("redis",), 20, DATABASE),
    PortFactor("ftp", "FTP", (21,), ("ftp",), 15),
)
LOGIN_POINTS = 10
DEFAULT_PAGE_POINTS = 5
NEW_HOST_POINTS = 10
UNIQUE_SERVICE_POINTS = 5


def level(score: int) -> str:
    if score >= HIGH_THRESHOLD:
        return "high"
    if score >= MEDIUM_THRESHOLD:
        return "medium"
    return "low"


def _round(x: float) -> int:
    return int(math.floor(x + 0.5))


def compute(f: DeviceFacts, unique: list[str], now: datetime) -> tuple[int, list[dict]]:
    """(score, [{factor, points, detail}]) for one device. `unique` lists its services found nowhere
    else in its network."""
    zone = f.network.zone if f.network else None
    boost = zone in EXPOSED_ZONES
    factors: list[dict] = []
    for pf in PORT_FACTORS:
        hits = [s for s in f.services if (s.proto == "tcp" and s.port in pf.ports)
                or (s.service or "").lower() in pf.services]
        if not hits:
            continue
        points: float = pf.points
        detail = f"{pf.label} open on " + ", ".join(s.label for s in hits)
        if boost and pf.kind in (ADMIN, DATABASE):
            points *= ZONE_MULTIPLIER
            detail += f" (x{ZONE_MULTIPLIER:g} in the {zone} zone)"
        factors.append({"factor": pf.factor, "points": _round(points), "detail": detail})
    login = [s.label for s in f.services if s.login]
    if login:
        factors.append({"factor": "http_login", "points": LOGIN_POINTS,
                        "detail": "HTTP login page on " + ", ".join(login)})
    default = [s.label for s in f.services if s.default_page]
    if default:
        factors.append({"factor": "default_page", "points": DEFAULT_PAGE_POINTS,
                        "detail": "Default web server page on " + ", ".join(default)})
    first_seen = f.device.first_seen
    if first_seen is not None and first_seen > now - timedelta(days=NEW_HOST_DAYS):
        factors.append({"factor": "new_host", "points": NEW_HOST_POINTS,
                        "detail": f"First seen less than {NEW_HOST_DAYS} days ago"})
    if unique:
        factors.append({"factor": "unique_service", "points": UNIQUE_SERVICE_POINTS,
                        "detail": "Only host in its network with " + ", ".join(unique)})
    return min(MAX_SCORE, sum(x["points"] for x in factors)), factors


def unique_services(db: Session, network_ids: set[int]) -> dict[int, list[str]]:
    """device id -> services ("port/proto") open on no other host of its network (networks of 5+ hosts)."""
    ids = [i for i in network_ids if i is not None]
    if not ids:
        return {}
    sizes = dict(db.execute(select(Device.network_id, func.count(Device.id))
                            .where(Device.network_id.in_(ids)).group_by(Device.network_id)).tuples().all())
    big = [n for n, size in sizes.items() if size >= RARE_MIN_HOSTS]
    if not big:
        return {}
    n_hosts = func.count(func.distinct(DevicePort.device_id))
    rows = db.execute(
        select(func.min(DevicePort.device_id), DevicePort.port, DevicePort.protocol)
        .join(Device, Device.id == DevicePort.device_id)
        .where(DevicePort.is_open.is_(True), Device.network_id.in_(big))
        .group_by(Device.network_id, DevicePort.port, DevicePort.protocol).having(n_hosts == 1)
    ).all()
    out: dict[int, list[str]] = defaultdict(list)
    for dev_id, port, proto in sorted(rows, key=lambda r: (r[0], r[1])):
        out[dev_id].append(f"{port}/{proto}")
    return out


def apply_scores(db: Session, facts: list[DeviceFacts], unique: dict[int, list[str]], *, now: datetime) -> None:
    for f in facts:
        score, factors = compute(f, unique.get(f.device.id, []), now)
        f.device.exposure_score = score
        if f.profile is None:
            f.profile = DeviceProfile(device_id=f.device.id)
            db.add(f.profile)
        f.profile.exposure_factors = factors
