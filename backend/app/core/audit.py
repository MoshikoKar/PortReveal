"""Lightweight audit log of administrative actions."""
from __future__ import annotations

import json
import logging

from sqlalchemy.orm import Session

from ..models import AuditLog

log = logging.getLogger("audit")


def audit(db: Session, username: str | None, action: str, target: str | None = None,
          details: dict | str | None = None, ip: str | None = None) -> None:
    text = json.dumps(details, default=str) if isinstance(details, dict) else details
    db.add(AuditLog(username=username, action=action, target=target, details=text, ip=ip))
    log.info("%s %s %s %s", username, action, target or "", text or "")
