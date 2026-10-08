"""Hiding mock-scanner (simulated) data from the UI.

The switch only filters what lists, counts and the dashboard show; nothing is deleted and
change detection is unaffected. A device counts as mock when every scan that observed it was a
mock scan, so one real (nmap) sighting makes it real.
"""
from __future__ import annotations

from sqlalchemy import and_, func, or_, select, true
from sqlalchemy.orm import Session

from ..models import Device, Event, Scan, ScanHost, Snapshot
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


# --- filters: `true()` while mock data is shown, so callers can always add them --------
def scan_visible(db: Session):
    return _is_real_scan() if mock_hidden(db) else true()


def device_visible(db: Session):
    return ~_is_mock_device() if mock_hidden(db) else true()


def event_visible(db: Session):
    if not mock_hidden(db):
        return true()
    return and_(or_(Event.scan_id.is_(None), Event.scan_id.not_in(_mock_scan_ids())),
                or_(Event.device_id.is_(None), Event.device_id.not_in(_mock_device_ids())))


def snapshot_visible(db: Session):
    if not mock_hidden(db):
        return true()
    return or_(Snapshot.scan_id.is_(None), Snapshot.scan_id.not_in(_mock_scan_ids()))


def mock_counts(db: Session) -> dict[str, int]:
    return {
        "scans": db.scalar(select(func.count(Scan.id)).where(_is_mock_scan())) or 0,
        "devices": db.scalar(select(func.count(Device.id)).where(_is_mock_device())) or 0,
        "events": db.scalar(select(func.count(Event.id)).where(or_(Event.scan_id.in_(_mock_scan_ids()),
                                                                  Event.device_id.in_(_mock_device_ids())))) or 0,
    }
