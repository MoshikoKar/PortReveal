"""Static vs dynamic IP heuristic (spec section 7), derived from device_ips history only.

No new scanning or probing: the signal already exists in `device_ips` (address history per
device) and `Device.hostname` (generic, IP-derived names already detected by identity.py).
"""
from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import (
    IP_ASSIGNMENT_DYNAMIC,
    IP_ASSIGNMENT_STATIC,
    IP_ASSIGNMENT_UNKNOWN,
    Device,
    DeviceIP,
)
from .identity import is_generic_hostname
from .tagging import DeviceFacts

# Too little history to say anything either way.
MIN_HISTORY_DAYS = 3
# A single address held at least this long counts as static.
STABLE_MIN_DAYS = 14
# Two or more addresses seen within this trailing window => dynamic (DHCP-style churn).
DYNAMIC_WINDOW_DAYS = 30
DYNAMIC_MIN_IPS = 2


def compute(device: Device, ip_rows: list[tuple[str, datetime, datetime]], now: datetime) -> str:
    """ip_rows: (ip, first_seen, last_seen) history of this device, any order."""
    if not ip_rows:
        return IP_ASSIGNMENT_UNKNOWN
    earliest = min(first for _ip, first, _last in ip_rows)
    age = now - earliest
    recent_ips = {ip for ip, _first, last in ip_rows if last >= now - timedelta(days=DYNAMIC_WINDOW_DAYS)}
    if len(recent_ips) >= DYNAMIC_MIN_IPS:
        return IP_ASSIGNMENT_DYNAMIC
    if age < timedelta(days=MIN_HISTORY_DAYS):
        return IP_ASSIGNMENT_UNKNOWN
    if len(ip_rows) == 1 and age >= timedelta(days=STABLE_MIN_DAYS):
        return IP_ASSIGNMENT_STATIC
    # A hostname that is itself derived from the IP (e.g. "10-0-0-5.dhcp") is a DHCP-style
    # naming convention; a *missing* hostname says nothing either way, so it is not a signal here.
    has_generic_name = bool(device.hostname) and is_generic_hostname(device.hostname, device.current_ip)
    if len(ip_rows) >= 2 and has_generic_name:
        return IP_ASSIGNMENT_DYNAMIC
    return IP_ASSIGNMENT_UNKNOWN


def apply_ip_assignment(db: Session, facts: list[DeviceFacts], *, now: datetime) -> None:
    """Set `Device.ip_assignment` for every device in `facts` from its address history."""
    ids = [f.device.id for f in facts]
    if not ids:
        return
    by_device: dict[int, list[tuple[str, datetime, datetime]]] = defaultdict(list)
    rows = db.execute(
        select(DeviceIP.device_id, DeviceIP.ip, DeviceIP.first_seen, DeviceIP.last_seen)
        .where(DeviceIP.device_id.in_(ids))
    ).all()
    for device_id, ip, first_seen, last_seen in rows:
        by_device[device_id].append((ip, first_seen, last_seen))
    for f in facts:
        f.device.ip_assignment = compute(f.device, by_device.get(f.device.id, []), now)
