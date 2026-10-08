"""LDAP connections are always unbound, including early returns and exceptions."""
from __future__ import annotations

import pytest

from app.auth import ldap_auth
from app.settings_store import LdapSettings


class FakeConn:
    instances: list[FakeConn] = []
    bind_ok = True
    search_raises = False
    entries_found: list = []

    def __init__(self, server, user=None, password=None, **_kw):
        self.user = user
        self.unbound = False
        self.entries: list = []
        self.result = {"description": "invalidCredentials"}
        FakeConn.instances.append(self)

    def open(self):
        pass

    def start_tls(self):
        pass

    def bind(self):
        return FakeConn.bind_ok

    def search(self, *_a, **_kw):
        if FakeConn.search_raises:
            raise RuntimeError("socket closed")
        self.entries = list(FakeConn.entries_found)

    def unbind(self):
        self.unbound = True


@pytest.fixture
def fake_ldap(monkeypatch):
    FakeConn.instances, FakeConn.bind_ok, FakeConn.search_raises, FakeConn.entries_found = [], True, False, []
    monkeypatch.setattr(ldap_auth, "Connection", FakeConn)
    monkeypatch.setattr(ldap_auth, "decrypt_secret", lambda _v: "svc-pass")
    return FakeConn


def cfg() -> LdapSettings:
    return LdapSettings(enabled=True, server_uri="ldap://dc.example.test", bind_dn="cn=svc",
                        user_base_dn="ou=users", user_filter="(uid={username})")


def test_authenticate_user_not_found_unbinds_service_connection(fake_ldap):
    res = ldap_auth.ldap_authenticate(cfg(), "nobody", "pw")
    assert not res.ok and res.error == "user not found"
    assert fake_ldap.instances and all(c.unbound for c in fake_ldap.instances)


def test_authenticate_failed_bind_unbinds(fake_ldap):
    fake_ldap.bind_ok = False
    res = ldap_auth.ldap_authenticate(cfg(), "alice", "pw")
    assert not res.ok
    assert fake_ldap.instances and all(c.unbound for c in fake_ldap.instances)


def test_ldap_test_search_error_unbinds(fake_ldap):
    fake_ldap.search_raises = True
    ok, msg = ldap_auth.ldap_test(cfg())
    assert not ok and "socket closed" in msg
    assert len(fake_ldap.instances) == 1 and fake_ldap.instances[0].unbound
