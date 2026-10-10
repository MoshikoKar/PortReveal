"""Directory import: AD computer objects via existing LDAP settings (read-only).

Flags devices as tag `in-ad` when their hostname matches an AD computer; does not invent
devices that were never scanned. "In AD but never seen" is reported as a list for operators.
"""
from __future__ import annotations

import logging

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..auth.ldap_auth import _connect, _server
from ..db import utcnow
from ..models import TAG_SOURCE_RULE, Device, DeviceTag
from ..security import decrypt_secret
from ..settings_store import LdapSettings, get_section
from .tagging import normalize_tag

log = logging.getLogger(__name__)

_COMPUTER_FILTER = "(&(objectCategory=computer)(objectClass=computer))"


def list_ad_computers(cfg: LdapSettings) -> list[dict]:
    """Return [{name, dns, os}] from AD. Empty when LDAP is disabled or unreachable."""
    if not cfg.enabled or not cfg.server_uri or not cfg.user_base_dn:
        return []
    try:
        from ldap3 import ALL_ATTRIBUTES, SUBTREE, Connection
    except ImportError:
        return []
    try:
        server = _server(cfg)
        conn = _connect(cfg, server, cfg.bind_dn, decrypt_secret(cfg.bind_password_enc))
        if conn is None:
            return []
        conn.search(cfg.user_base_dn, _COMPUTER_FILTER, SUBTREE,
                    attributes=["cn", "dNSHostName", "operatingSystem", "lastLogonTimestamp"])
        out = []
        for e in conn.entries:
            out.append({
                "name": str(e.cn) if hasattr(e, "cn") else None,
                "dns": str(e.dNSHostName).rstrip(".").lower() if hasattr(e, "dNSHostName") and e.dNSHostName else None,
                "os": str(e.operatingSystem) if hasattr(e, "operatingSystem") else None,
            })
        conn.unbind()
        return out
    except Exception:
        log.exception("AD computer import failed")
        return []


def sync_ad_tags(db: Session) -> dict:
    """Tag inventory hosts that appear in AD; return counts and never-seen names."""
    cfg = get_section(db, LdapSettings)
    comps = list_ad_computers(cfg)
    if not comps:
        return {"matched": 0, "never_seen": [], "ad_computers": 0}
    by_name = {}
    for c in comps:
        for key in (c.get("dns"), c.get("name")):
            if key:
                by_name[key.lower().split(".")[0]] = c
    devices = db.scalars(select(Device)).all()
    matched = 0
    seen_keys: set[str] = set()
    now = utcnow()
    tag = normalize_tag("in-ad")
    for d in devices:
        keys = []
        for h in (d.hostname, d.dns_name):
            if h:
                keys.append(h.lower().rstrip(".").split(".")[0])
        hit = next((by_name[k] for k in keys if k in by_name), None)
        if not hit:
            continue
        matched += 1
        for k in keys:
            seen_keys.add(k)
        existing = db.scalar(select(DeviceTag).where(DeviceTag.device_id == d.id, DeviceTag.tag == tag))
        if existing is None:
            db.add(DeviceTag(device_id=d.id, tag=tag, source=TAG_SOURCE_RULE,
                             reason="hostname matches AD computer object", created_at=now))
        if hit.get("os") and not d.os_name:
            d.os_name = hit["os"]
    never = sorted({(c.get("dns") or c.get("name") or "") for c in comps
                    if (c.get("dns") or c.get("name") or "").lower().split(".")[0] not in seen_keys})
    never = [n for n in never if n]
    return {"matched": matched, "never_seen": never[:200], "ad_computers": len(comps)}
