"""SSH host-key fingerprint via safe ssh-keyscan (no auth)."""
from __future__ import annotations

import hashlib
import logging
import shutil
import subprocess
import sys

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import Device, DevicePort

log = logging.getLogger(__name__)


def ssh_keyscan_available() -> bool:
    return shutil.which("ssh-keyscan") is not None


def fetch_ssh_hostkey_sha256(ip: str, port: int = 22, *, timeout: float = 5.0) -> str | None:
    exe = shutil.which("ssh-keyscan")
    if not exe:
        return None
    args = [exe, "-T", str(max(1, int(timeout))), "-p", str(port), "-t", "rsa,ecdsa,ed25519", ip]
    kw: dict = {"capture_output": True, "timeout": timeout + 2, "text": True}
    if sys.platform == "win32":
        kw["creationflags"] = subprocess.CREATE_NO_WINDOW  # type: ignore[attr-defined]
    try:
        proc = subprocess.run(args, **kw)
    except (OSError, subprocess.TimeoutExpired):
        return None
    lines = [ln for ln in (proc.stdout or "").splitlines() if ln.strip() and not ln.startswith("#")]
    if not lines:
        return None
    # Hash the first key line (host key material after host/type)
    parts = lines[0].split()
    if len(parts) < 3:
        return None
    material = parts[2].encode()
    return hashlib.sha256(material).hexdigest()


def enrich_device_ssh(db: Session, device_id: int, ip: str) -> bool:
    ports = db.scalars(select(DevicePort).where(
        DevicePort.device_id == device_id, DevicePort.is_open.is_(True),
        DevicePort.port.in_((22, 2222)),
    )).all()
    if not ports and not any(
        (p.service or "").lower() == "ssh"
        for p in db.scalars(select(DevicePort).where(
            DevicePort.device_id == device_id, DevicePort.is_open.is_(True),
        ))
    ):
        return False
    port = ports[0].port if ports else 22
    fp = fetch_ssh_hostkey_sha256(ip, port)
    if not fp:
        return False
    dev = db.get(Device, device_id)
    if dev is None:
        return False
    dev.ssh_hostkey_sha256 = fp
    return True
