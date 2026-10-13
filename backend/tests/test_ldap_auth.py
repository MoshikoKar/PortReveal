"""LDAP: connections are always unbound, successful binds map groups to roles, and /api/auth/login
routes local accounts locally and everyone else through the directory only when LDAP is enabled."""
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
    assert not ok and msg == "LDAP test failed: unexpected error (details in the application log)."
    assert "socket closed" not in msg  # raw exception text stays in the server log
    assert len(fake_ldap.instances) == 1 and fake_ldap.instances[0].unbound


# --- successful authentication and role mapping ---------------------------------------------------
class FakeEntry:
    def __init__(self, dn: str, display: str, member_of: list[str]):
        self.entry_dn = dn
        self.entry_attributes_as_dict = {"displayName": [display], "cn": ["ignored"], "memberOf": member_of}


def test_authenticate_success_maps_admin_group_to_admin(fake_ldap):
    fake_ldap.entries_found = [FakeEntry("uid=alice,ou=users", "Alice A", ["CN=NF-Admins,OU=Groups"])]
    res = ldap_auth.ldap_authenticate(cfg().model_copy(update={"admin_group_dn": "cn=nf-admins,ou=groups"}),
                                      "alice", "pw")
    assert res.ok and res.role == "admin" and res.display_name == "Alice A" and res.error is None
    # service bind, then a bind as the user's DN with the supplied password
    assert [c.user for c in fake_ldap.instances] == ["cn=svc", "uid=alice,ou=users"]
    assert all(c.unbound for c in fake_ldap.instances)


def test_authenticate_success_without_viewer_group_maps_to_viewer(fake_ldap):
    fake_ldap.entries_found = [FakeEntry("uid=bob,ou=users", "Bob B", [])]
    res = ldap_auth.ldap_authenticate(cfg(), "bob", "pw")
    assert res.ok and res.role == "viewer" and res.display_name == "Bob B"


def test_authenticate_success_requires_viewer_group_when_configured(fake_ldap):
    fake_ldap.entries_found = [FakeEntry("uid=bob,ou=users", "Bob B", ["cn=nf-viewers,ou=groups"])]
    viewers = cfg().model_copy(update={"viewer_group_dn": "cn=nf-viewers,ou=groups"})
    res = ldap_auth.ldap_authenticate(viewers, "bob", "pw")
    assert res.ok and res.role == "viewer"


def test_authenticate_never_binds_anonymously(fake_ldap):
    assert ldap_auth.ldap_authenticate(cfg(), "alice", "").error == "username and password required"
    assert ldap_auth.ldap_authenticate(cfg().model_copy(update={"enabled": False}), "alice", "pw").ok is False
    assert fake_ldap.instances == []


def test_errors_are_classified_without_raw_text():
    from ldap3.core.exceptions import LDAPSocketOpenError, LDAPStartTLSError

    assert ldap_auth.classify_error(ldap_auth.LdapBindError("bind failed: invalidCredentials")) == \
        "bind refused (check the bind DN and password)"
    assert "reach" in ldap_auth.classify_error(LDAPSocketOpenError("socket to dc01.corp.example:389 failed"))
    assert "TLS" in ldap_auth.classify_error(LDAPStartTLSError("wrong version"))
    assert "unexpected" in ldap_auth.classify_error(ValueError("boom"))


# --- /api/auth/login routing with LDAP enabled -------------------------------------------------------
@pytest.fixture
def client(db_env):
    from fastapi.testclient import TestClient

    from app.api.auth import limiter
    from app.main import app

    limiter.reset()
    with TestClient(app) as c:
        assert c.post("/api/setup/admin", json={"username": "admin", "password": "correct-horse-1"}).status_code == 200
        c.post("/api/auth/logout", headers={"X-CSRF-Token": c.cookies.get("nf_csrf", "")})
        yield c


def _enable_ldap(enabled: bool = True) -> None:
    from app.db import session_scope
    from app.settings_store import put_section

    with session_scope() as s:
        put_section(s, cfg().model_copy(update={"enabled": enabled}))


def test_login_provisions_ldap_user_with_mapped_role(client, monkeypatch):
    _enable_ldap()
    calls = []

    def fake_auth(c, username, password):
        calls.append((username, password))
        return ldap_auth.LdapResult(True, role="viewer", display_name="Alice A")

    monkeypatch.setattr("app.api.auth.ldap_authenticate", fake_auth)
    r = client.post("/api/auth/login", json={"username": "alice", "password": "dir-pass"})
    assert r.status_code == 200, r.text
    user = r.json()["user"]
    assert user["source"] == "ldap" and user["role"] == "viewer" and user["display_name"] == "Alice A"
    assert calls == [("alice", "dir-pass")]

    # the next login refreshes the role from the directory
    monkeypatch.setattr("app.api.auth.ldap_authenticate",
                        lambda c, u, p: ldap_auth.LdapResult(True, role="admin", display_name="Alice A"))
    client.post("/api/auth/logout", headers={"X-CSRF-Token": client.cookies.get("nf_csrf", "")})
    assert client.post("/api/auth/login", json={"username": "alice", "password": "dir-pass"}).json()["user"]["role"] \
        == "admin"


def test_login_rejects_failed_ldap_auth(client, monkeypatch):
    _enable_ldap()
    monkeypatch.setattr("app.api.auth.ldap_authenticate",
                        lambda c, u, p: ldap_auth.LdapResult(False, error="invalid credentials"))
    r = client.post("/api/auth/login", json={"username": "alice", "password": "nope"})
    assert r.status_code == 401 and r.json()["detail"] == "Invalid username or password"


def test_local_users_never_go_to_ldap(client, monkeypatch):
    _enable_ldap()

    def must_not_call(*_a):
        raise AssertionError("local account authenticated against LDAP")

    monkeypatch.setattr("app.api.auth.ldap_authenticate", must_not_call)
    assert client.post("/api/auth/login", json={"username": "admin", "password": "correct-horse-1"}).status_code == 200
    client.post("/api/auth/logout", headers={"X-CSRF-Token": client.cookies.get("nf_csrf", "")})
    assert client.post("/api/auth/login", json={"username": "admin", "password": "wrong"}).status_code == 401


def test_ldap_disabled_skips_directory_for_unknown_users(client, monkeypatch):
    _enable_ldap(False)

    def must_not_call(*_a):
        raise AssertionError("LDAP is disabled")

    monkeypatch.setattr("app.api.auth.ldap_authenticate", must_not_call)
    assert client.post("/api/auth/login", json={"username": "alice", "password": "dir-pass"}).status_code == 401
