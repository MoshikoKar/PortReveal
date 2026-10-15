"""Large subnets are captured completely; internal SSO redirects are followed."""
from __future__ import annotations

from sqlalchemy import select

from app.core.identity import normalize_hostname
from app.core.web_capture import CaptureContext, run_web_capture
from app.core.web_capture.auto import maybe_enqueue_auto_web_capture
from app.core.web_capture.classify import looks_like_login_url
from app.core.web_capture.internal import InternalHosts
from app.core.web_capture.inventory import find_web_endpoints
from app.core.web_capture.screenshot import _load_error
from app.models import WEB_CAPTURE_QUEUED, Scan, WebCapture
from app.netutils import AddressSet
from app.settings_store import WebCaptureSettings, put_section
from tests.helpers import ScriptedScanner, host, make_network, port, scan

# Text order would put .100 before .2 and .51 after .201: numeric order must win.
IPS = ["10.0.0.2", "10.0.0.51", "10.0.0.100", "10.0.0.201"]


def _web_hosts(db, name: str):
    net = make_network(db, "10.0.0.0/24", name=name)
    scan(ScriptedScanner([host(ip, [port(80, "http"), port(443, "https")]) for ip in IPS]), network_id=net.id)
    return net


def test_endpoint_cap_is_applied_per_host_in_numeric_order(db):
    _web_hosts(db, "Cap")
    deferred: list[str] = []
    endpoints, notes = find_web_endpoints(db, set(IPS), max_endpoints=5, deferred=deferred)
    # 2 endpoints per host: hosts .2 and .51 fit (4), .100 would split -> deferred with the rest
    assert [e.ip for e in endpoints] == ["10.0.0.2", "10.0.0.2", "10.0.0.51", "10.0.0.51"]
    assert deferred == ["10.0.0.100", "10.0.0.201"]
    assert any("2 host(s) deferred" in n for n in notes)


def test_capture_job_continues_with_hosts_that_did_not_fit(db):
    put_section(db, WebCaptureSettings(enabled=True, force_mock=True, max_endpoints=4))
    db.commit()
    _web_hosts(db, "Continue")
    for job in db.scalars(select(WebCapture)).all():  # drop any job the setup scan queued
        db.delete(job)
    cap = WebCapture(targets="10.0.0.0/24")
    db.add(cap)
    db.commit()
    run_web_capture(cap.id, CaptureContext(cap.id))
    db.expire_all()
    cont = db.scalar(select(WebCapture).where(WebCapture.id != cap.id))
    assert cont is not None and cont.status == WEB_CAPTURE_QUEUED
    assert cont.targets == "10.0.0.100,10.0.0.201"
    assert f"#{cont.id}" in (db.get(WebCapture, cap.id).notes or "")

    # The continuation covers the rest and does not continue again
    run_web_capture(cont.id, CaptureContext(cont.id))
    db.expire_all()
    assert db.scalar(select(WebCapture).where(WebCapture.id > cont.id)) is None


def test_auto_capture_splits_instead_of_dropping_hosts(db):
    put_section(db, WebCaptureSettings(enabled=True, auto_after_scan=True, auto_only_new_or_changed=False,
                                       force_mock=True, max_addresses=3))
    db.commit()
    net = _web_hosts(db, "AutoSplit")
    for job in db.scalars(select(WebCapture)).all():  # drop the job the baseline scan queued
        db.delete(job)
    db.commit()
    s = db.scalar(select(Scan).order_by(Scan.id.desc()))
    maybe_enqueue_auto_web_capture(db, s)
    db.commit()
    jobs = db.scalars(select(WebCapture).order_by(WebCapture.id)).all()
    assert [j.targets for j in jobs] == ["10.0.0.2,10.0.0.51,10.0.0.100", "10.0.0.201"]
    assert net.id


def test_auto_capture_merges_into_waiting_job(db):
    put_section(db, WebCaptureSettings(enabled=True, auto_after_scan=True, auto_only_new_or_changed=False,
                                       force_mock=True))
    db.commit()
    _web_hosts(db, "AutoMerge")
    waiting = db.scalar(select(WebCapture))
    waiting.targets = "10.0.0.2"
    db.commit()
    s = db.scalar(select(Scan).order_by(Scan.id.desc()))
    assert maybe_enqueue_auto_web_capture(db, s) == waiting.id
    assert waiting.targets == ",".join(IPS)
    assert len(db.scalars(select(WebCapture)).all()) == 1


def test_internal_redirect_scope():
    internal = InternalHosts(AddressSet.from_specs("10.0.0.0/16"), {"172.16.5.5"}, AddressSet.from_specs("10.0.9.9"))
    assert internal.allows("https://10.0.12.70:8400/oauth/authorize?client_id=x")
    assert internal.allows("http://172.16.5.5/")  # inventory device outside configured networks
    assert not internal.allows("https://10.0.9.9/")  # excluded address: never visited
    assert not internal.allows("https://192.0.2.10/")  # not ours
    assert not internal.allows("ftp://10.0.0.5/")
    assert not internal.allows("https://no-such-host.invalid/")


def test_sso_login_urls():
    assert looks_like_login_url("https://sso.corp:8400/oauth/authorize?response_type=code")
    assert looks_like_login_url("https://kc.corp/realms/main/protocol/openid-connect/auth?x=1")
    assert looks_like_login_url("https://app.corp/login")
    assert not looks_like_login_url("https://app.corp/dashboard")


def test_browser_load_error_names_the_failed_redirect():
    assert _load_error("https://app.corp/", ["https://sso.corp:4000/oauth/authorize", "net::ERR_CONNECTION_REFUSED"]) \
        == "redirect to sso.corp:4000 failed (connection refused)"
    assert _load_error("https://app.corp/", ["https://app.corp/", "net::ERR_NAME_NOT_RESOLVED"]) \
        == "page failed to load (DNS name not found)"
    assert _load_error("https://app.corp/", []) == "browser could not load the page"


def test_doubled_ptr_domain_is_collapsed():
    assert normalize_hostname("Shop10.Corp.Example.Corp.Example.") == "shop10.corp.example"
    assert normalize_hostname("srv.corp.example") == "srv.corp.example"
    assert normalize_hostname("a.b.b") == "a.b.b"
