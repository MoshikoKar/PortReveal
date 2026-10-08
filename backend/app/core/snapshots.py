"""Daily logical snapshots of the normalized network state.

One row per network per local day (re-running a scan the same day replaces it).
The payload is compact zlib-compressed JSON: a few KB for hundreds of hosts,
instead of keeping raw nmap XML.
"""
from __future__ import annotations

import json
import zlib
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from ..models import DEVICE_ACTIVE, Device, Network, Scan, Snapshot

SNAPSHOT_VERSION = 1


def build_state(db: Session, network: Network) -> list[list]:
    devices = db.scalars(
        select(Device).where(Device.network_id == network.id).options(selectinload(Device.ports))
    ).all()
    rows = []
    for d in sorted(devices, key=lambda x: x.uuid):
        ports = [[p.port, p.protocol, p.service, p.product, p.version] for p in d.ports if p.is_open]
        rows.append([d.uuid, d.current_ip, d.mac, d.hostname, d.status, ports])
    return rows


def create_snapshot(db: Session, network: Network, scan: Scan, now: datetime) -> Snapshot:
    db.flush()
    state = build_state(db, network)
    payload = {
        "v": SNAPSHOT_VERSION,
        "network": {"id": network.id, "name": network.name, "cidr": network.cidr},
        "scan_id": scan.id,
        "taken_at": now.isoformat(),
        "columns": ["uuid", "ip", "mac", "hostname", "status", "ports[port,proto,service,product,version]"],
        "devices": state,
    }
    blob = zlib.compress(json.dumps(payload, separators=(",", ":")).encode(), 9)
    day = now.astimezone().date()
    snap = db.scalar(select(Snapshot).where(Snapshot.network_id == network.id, Snapshot.snapshot_date == day))
    if snap is None:
        snap = Snapshot(network_id=network.id, snapshot_date=day)
        db.add(snap)
    snap.scan_id = scan.id
    snap.created_at = now
    snap.hosts_total = len(state)
    snap.hosts_active = sum(1 for r in state if r[4] == DEVICE_ACTIVE)
    snap.open_ports = sum(len(r[5]) for r in state)
    snap.data = blob
    return snap


def load_snapshot(snap: Snapshot) -> dict:
    return json.loads(zlib.decompress(snap.data).decode())
