"""Maintains `vuln_finding_lifecycle` (first-seen/resolved tracking), the durable side-channel
`DevicePortVuln` cannot provide since `matched_at` is overwritten on every re-match and the row is
hard-deleted once a finding stops matching (see models.VulnFindingLifecycle).

Ground truth only: this module does not apply mock/archived visibility filtering, so a finding
toggled in/out of view by the mock-data switch is never mistaken for "resolved". Visibility is
applied later, by summary.py, when it reads these rows for display.
"""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from ...models import VULN_STATE_DISMISSED, Device, DevicePort, DevicePortVuln, VulnFindingLifecycle

RESOLUTION_NO_LONGER_MATCHED = "no_longer_matched"
RESOLUTION_DEVICE_REMOVED = "device_removed"


def sync_finding_lifecycle(db: Session, *, now: datetime) -> dict[str, int]:
    """Insert new finding identities, bump `last_seen_at` on ones still present, reopen any that
    were resolved and reappeared, and resolve ones no longer present. Call after matching/dismiss
    state has settled for the batch (end of a vuln job or a feed sync), not per-request.
    """
    current = db.execute(
        select(Device.uuid, DevicePort.port, DevicePort.protocol, DevicePortVuln.cve_id,
               Device.network_id, DevicePortVuln.state)
        .join(DevicePort, DevicePort.device_id == Device.id)
        .join(DevicePortVuln, DevicePortVuln.device_port_id == DevicePort.id)
    ).all()
    current_by_identity = {
        (uuid, port, protocol, cve_id): (network_id, state)
        for uuid, port, protocol, cve_id, network_id, state in current
    }
    existing_by_identity = {
        (row.device_uuid, row.port, row.protocol, row.cve_id): row
        for row in db.scalars(select(VulnFindingLifecycle)).all()
    }
    live_device_uuids = set(db.scalars(select(Device.uuid)))

    stats = {"new": 0, "resolved": 0, "reopened": 0}
    for identity, (network_id, state) in current_by_identity.items():
        dismissed = state == VULN_STATE_DISMISSED
        row = existing_by_identity.get(identity)
        if row is None:
            device_uuid, port, protocol, cve_id = identity
            db.add(VulnFindingLifecycle(
                device_uuid=device_uuid, port=port, protocol=protocol, cve_id=cve_id,
                network_id=network_id, first_seen_at=now, last_seen_at=now,
                dismissed_at=now if dismissed else None,
            ))
            stats["new"] += 1
            continue
        row.last_seen_at = now
        row.network_id = network_id
        if row.resolved_at is not None:
            row.resolved_at = None
            row.resolution = None
            stats["reopened"] += 1
        row.dismissed_at = (row.dismissed_at or now) if dismissed else None

    for identity, row in existing_by_identity.items():
        if identity in current_by_identity or row.resolved_at is not None:
            continue
        row.resolved_at = now
        row.resolution = (
            RESOLUTION_DEVICE_REMOVED if identity[0] not in live_device_uuids else RESOLUTION_NO_LONGER_MATCHED
        )
        stats["resolved"] += 1

    db.flush()
    return stats
