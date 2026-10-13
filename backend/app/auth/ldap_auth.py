"""LDAP / Active Directory authentication (ldap3, pure Python).

Flow: bind with the service account, search the user, bind as the user with
the supplied password, then map group membership to a role.
"""
from __future__ import annotations

import logging
import ssl
from dataclasses import dataclass

from ldap3 import BASE, NONE, SUBTREE, Connection, Server, Tls
from ldap3.core.exceptions import LDAPCommunicationError, LDAPException, LDAPStartTLSError
from ldap3.utils.conv import escape_filter_chars

from ..models import ROLE_ADMIN, ROLE_VIEWER
from ..security import decrypt_secret
from ..settings_store import LdapSettings

log = logging.getLogger(__name__)


@dataclass
class LdapResult:
    ok: bool
    role: str | None = None
    display_name: str | None = None
    error: str | None = None


class LdapBindError(LDAPException):
    """The server answered but refused the bind (wrong DN or password, locked account)."""


def classify_error(exc: BaseException) -> str:
    """A short, stable reason for the UI and audit log. Raw exception text (server names, DNs, library
    internals) stays in the application log only."""
    if isinstance(exc, LdapBindError):
        return "bind refused (check the bind DN and password)"
    if isinstance(exc, LDAPStartTLSError | ssl.SSLError):
        return "TLS negotiation or certificate verification failed"
    if isinstance(exc, LDAPCommunicationError | OSError):
        return "could not reach the LDAP server"
    if isinstance(exc, LDAPException):
        return "the LDAP server returned an error"
    return "unexpected error (details in the application log)"


def _server(cfg: LdapSettings) -> Server:
    tls = Tls(validate=ssl.CERT_REQUIRED if cfg.verify_tls else ssl.CERT_NONE)
    return Server(cfg.server_uri, use_ssl=cfg.server_uri.lower().startswith("ldaps://"), get_info=NONE,
                  connect_timeout=cfg.timeout_seconds, tls=tls)


def _connect(cfg: LdapSettings, server: Server, user: str | None, password: str | None) -> Connection:
    conn = Connection(server, user=user or None, password=password or None, auto_bind=False,
                      receive_timeout=cfg.timeout_seconds, raise_exceptions=False)
    try:
        conn.open()
        if cfg.start_tls and not cfg.server_uri.lower().startswith("ldaps://"):
            conn.start_tls()
        if not conn.bind():
            raise LdapBindError(f"bind failed: {conn.result.get('description', 'invalid credentials')}")
    except Exception:
        _unbind(conn)  # opened socket must not leak when STARTTLS or the bind fails
        raise
    return conn


def _unbind(conn: Connection | None) -> None:
    """Close a connection, never raising (cleanup runs on error paths)."""
    if conn is None:
        return
    try:
        conn.unbind()
    except Exception:  # already closed / network gone
        pass


def _is_member(conn: Connection, cfg: LdapSettings, user_dn: str, member_of: list[str], group_dn: str) -> bool:
    if not group_dn:
        return False
    if any(g.lower() == group_dn.lower() for g in member_of):
        return True
    # Nested AD groups (LDAP_MATCHING_RULE_IN_CHAIN), falls back to plain member check elsewhere
    flt = f"(|(member:1.2.840.113556.1.4.1941:={escape_filter_chars(user_dn)})(member={escape_filter_chars(user_dn)}))"
    try:
        conn.search(group_dn, flt, search_scope=BASE, attributes=["cn"])
        return bool(conn.entries)
    except LDAPException:
        return False


def ldap_authenticate(cfg: LdapSettings, username: str, password: str) -> LdapResult:
    if not cfg.enabled or not cfg.server_uri:
        return LdapResult(False, error="LDAP is not enabled")
    if not username or not password:
        return LdapResult(False, error="username and password required")  # never allow anonymous binds
    svc: Connection | None = None
    try:
        server = _server(cfg)
        svc = _connect(cfg, server, cfg.bind_dn, decrypt_secret(cfg.bind_password_enc))
        flt = cfg.user_filter.replace("{username}", escape_filter_chars(username))
        svc.search(cfg.user_base_dn, flt, search_scope=SUBTREE,
                   attributes=["cn", "displayName", "memberOf"], size_limit=2)
        if len(svc.entries) != 1:
            return LdapResult(False, error="user not found" if not svc.entries else "ambiguous user")
        entry = svc.entries[0]
        user_dn = entry.entry_dn
        attrs = entry.entry_attributes_as_dict
        member_of = [str(g) for g in attrs.get("memberOf", [])]
        display = (attrs.get("displayName") or attrs.get("cn") or [username])[0]
        try:
            _unbind(_connect(cfg, server, user_dn, password))
        except LDAPException:
            return LdapResult(False, error="invalid credentials")
        if _is_member(svc, cfg, user_dn, member_of, cfg.admin_group_dn):
            role = ROLE_ADMIN
        elif not cfg.viewer_group_dn or _is_member(svc, cfg, user_dn, member_of, cfg.viewer_group_dn):
            role = ROLE_VIEWER
        else:
            return LdapResult(False, error="user is not a member of an allowed group")
        return LdapResult(True, role=role, display_name=str(display))
    except Exception as exc:  # LDAP and network errors
        log.warning("LDAP authentication error (%s): %s", type(exc).__name__, exc)
        return LdapResult(False, error=f"LDAP error: {classify_error(exc)}")
    finally:
        _unbind(svc)  # every path, including early returns (user not found, not in an allowed group)


def ldap_test(cfg: LdapSettings) -> tuple[bool, str]:
    """Check connectivity + service bind + base DN search."""
    conn: Connection | None = None
    try:
        server = _server(cfg)
        conn = _connect(cfg, server, cfg.bind_dn, decrypt_secret(cfg.bind_password_enc))
        conn.search(cfg.user_base_dn, "(objectClass=*)", search_scope=BASE, attributes=["objectClass"])
        ok = bool(conn.entries)
        return (True, "Connected and bound successfully; user base DN found.") if ok else (
            False, "Bound successfully but the user base DN was not found.")
    except Exception as exc:
        log.warning("LDAP test failed (%s): %s", type(exc).__name__, exc)
        return False, f"LDAP test failed: {classify_error(exc)}."
    finally:
        _unbind(conn)
