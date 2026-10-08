"""Development seed: makes `npm run dev` immediately usable (admin user, demo network, baseline)."""
from __future__ import annotations

import logging

from sqlalchemy import func, select

from .config import get_settings
from .core.manager import create_scan
from .db import session_scope
from .models import ROLE_ADMIN, SCAN_STANDARD, Network, User
from .scanner import scanner_status
from .security import hash_password
from .settings_store import set_value

log = logging.getLogger(__name__)
DEV_NETWORK = ("Mock Lab", "10.99.0.0/24", "Development network (mock scanner)")


def seed_dev() -> bool:
    s = get_settings()
    if not s.is_dev or not s.dev_seed:
        return False
    with session_scope() as db:
        if (db.scalar(select(func.count(User.id))) or 0) > 0:
            return False
        db.add(User(username=s.dev_admin_username, password_hash=hash_password(s.dev_admin_password),
                    role=ROLE_ADMIN, source="local", display_name="Development admin"))
        net = db.scalar(select(Network).where(Network.name == DEV_NETWORK[0]))
        if net is None:
            net = Network(name=DEV_NETWORK[0], cidr=DEV_NETWORK[1], description=DEV_NETWORK[2])
            db.add(net)
            db.flush()
        set_value(db, "setup_completed", True)
        if scanner_status().effective_mode == "mock":
            create_scan(db, SCAN_STANDARD, network=net, requested_by="dev-seed")
    log.warning("DEV SEED: created user '%s' (password from DEV_ADMIN_PASSWORD) and network %s %s",
                s.dev_admin_username, DEV_NETWORK[0], DEV_NETWORK[1])
    return True
