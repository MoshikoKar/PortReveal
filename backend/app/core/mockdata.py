"""Hiding mock-scanner (simulated) data and archived-network findings from the UI.

The switches only filter what lists, counts and the dashboard show; nothing is deleted and
change detection is unaffected. A device counts as mock when every scan that observed it was a
mock scan, so one real (nmap) sighting makes it real. A device counts as archived when its
network was archived (removed in Settings > Networks); devices outside any network stay visible.
"""
from __future__ import annotations

from sqlalchemy import and_, func, or_, select, true
from sqlalchemy.orm import Session

from ..models import Device, Event, Network, Scan, ScanHost, Snapshot
from ..netutils import AddressSet, TargetError
from ..settings_store import get_value, set_value

HIDE_KEY = "hide_mock_data"


def mock_hidden(db: Session) -> bool:
    return bool(get_value(db, HIDE_KEY, False))


def set_mock_hidden(db: Session, hidden: bool) -> None:
    set_value(db, HIDE_KEY, hidden)


def _is_mock_scan():
    return Scan.scanner_mode == "mock"


def _is_real_scan():
    return or_(Scan.scanner_mode.is_(None), Scan.scanner_mode != "mock")


def _mock_scan_ids():
    return select(Scan.id).where(_is_mock_scan())


def _seen_by(mock: bool):
    cond = _is_mock_scan() if mock else _is_real_scan()
    return select(ScanHost.device_id).join(Scan, Scan.id == ScanHost.scan_id).where(cond)


def _is_mock_device():
    return and_(Device.id.in_(_seen_by(True)), Device.id.not_in(_seen_by(False)))


def _mock_device_ids():
    return select(Device.id).where(_is_mock_device())


def _archived_network_ids():
    return select(Network.id).where(Network.archived_at.isnot(None))


def _any_archived(db: Session) -> bool:
    return db.scalar(_archived_network_ids().limit(1)) is not None


def archived_hidden_device_ids(db: Session) -> list[int] | None:
    """Device PKs hidden with the network: linked to it, or unassigned but inside its CIDR.

    ``None`` means no network is archived (callers skip the filter). An empty list means
    archived networks exist but have no matching devices.
    """
    nets = list(db.scalars(select(Network).where(Network.archived_at.isnot(None))))
    if not nets:
        return None
    archived_ids = {n.id for n in nets}
    scopes: list[AddressSet] = []
    for n in nets:
        try:
            scopes.append(AddressSet.from_specs(n.cidr))
        except TargetError:
            continue
    hide: list[int] = []
    for did, nid, ip in db.execute(select(Device.id, Device.network_id, Device.current_ip)):
        if nid in archived_ids:
            hide.append(did)
        elif nid is None and ip and any(ip in scope for scope in scopes):
            hide.append(did)
    return hide


def _hidden_device_cond(db: Session):
    hidden = archived_hidden_device_ids(db)
    if hidden is None:
        return None
    if not hidden:
        return true()
    return Device.id.not_in(hidden)


# --- filters: `true()` while nothing is hidden, so callers can always add them --------
def scan_visible(db: Session):
    return _is_real_scan() if mock_hidden(db) else true()


def device_visible(db: Session, *, include_archived: bool = False):
    conds = []
    if mock_hidden(db):
        conds.append(~_is_mock_device())
    if not include_archived:
        extra = _hidden_device_cond(db)
        if extra is not None:
            conds.append(extra)
    return and_(*conds) if conds else true()


def event_visible(db: Session, *, include_archived: bool = False):
    conds = []
    if mock_hidden(db):
        conds += [or_(Event.scan_id.is_(None), Event.scan_id.not_in(_mock_scan_ids())),
                  or_(Event.device_id.is_(None), Event.device_id.not_in(_mock_device_ids()))]
    if not include_archived:
        hidden = archived_hidden_device_ids(db)
        if hidden:
            conds.append(or_(Event.device_id.is_(None), Event.device_id.not_in(hidden)))
    return and_(*conds) if conds else true()


def snapshot_visible(db: Session):
    conds = []
    if mock_hidden(db):
        conds.append(or_(Snapshot.scan_id.is_(None), Snapshot.scan_id.not_in(_mock_scan_ids())))
    if _any_archived(db):
        conds.append(Snapshot.network_id.not_in(_archived_network_ids()))
    return and_(*conds) if conds else true()


def mock_counts(db: Session) -> dict[str, int]:
    return {
        "scans": db.scalar(select(func.count(Scan.id)).where(_is_mock_scan())) or 0,
        "devices": db.scalar(select(func.count(Device.id)).where(_is_mock_device())) or 0,
        "events": db.scalar(select(func.count(Event.id)).where(or_(Event.scan_id.in_(_mock_scan_ids()),
                                                                  Event.device_id.in_(_mock_device_ids())))) or 0,
    }
