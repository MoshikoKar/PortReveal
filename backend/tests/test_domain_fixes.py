"""Domain scan follow-ups: wordlists in use by a domain, recipient-group domain scope, no false "gone"
on partial scans, per-phase progress with live inventory writes and cancel-keeps-results.

All DNS answers and tool runs are faked (no network)."""
from __future__ import annotations

import json
from pathlib import Path

from alembic import command
from sqlalchemy import create_engine, select, text

from app.core.channels import group_matches_event
from app.core.domains.dnsops import Answer
from app.core.domains.manager import enqueue_domain_scan
from app.core.domains.progress import Progress
from app.core.domains.runner import batch_size, run_domain_scan
from app.db import session_scope, utcnow
from app.migrate import alembic_config
from app.models import Device, Domain, DomainScan, Event, RecipientGroup, Subdomain, Wordlist
from app.scanner.types import ScanContext
from app.settings_store import DomainDiscoverySettings, get_section, put_section
from tests.helpers import make_network
from tests.test_domains import (  # noqa: F401  (client is a pytest fixture)
    PUBLIC_NS,
    FakeDns,
    _domain_body,
    _subdomains,
    client,
    csrf,
    fake_tools,
    make_domain,
    run_scan_now,
)


class FlakyDns(FakeDns):
    """FakeDns whose views can time out for chosen names: {(view, name)}."""

    def __init__(self, *a, errors=(), **kw):
        super().__init__(*a, **kw)
        self.errors = set(errors)

    def resolve(self, name, nameservers):
        view = "public" if nameservers == PUBLIC_NS else "internal"
        if (view, name) in self.errors:
            return Answer(status="timeout")
        return super().resolve(name, nameservers)


# --- 1) wordlist in use by a domain -----------------------------------------------------------------
def _wordlist(db, name="subs", kind="subdomains") -> Wordlist:
    w = Wordlist(name=name, kind=kind, source="upload", storage_name=f"{'a' * 31}{len(name) % 10}.txt", entries=2,
                 skipped=0, size_bytes=10, sha256="0" * 64, created_by="test")
    db.add(w)
    db.commit()
    return w


def test_wordlist_used_by_domain_cannot_be_deleted(client, db):  # noqa: F811
    w = _wordlist(db)
    for name in ("example.com", "example.org"):
        r = client.post("/api/domains", json=_domain_body(name=name, wordlist_mode="library", wordlist_id=w.id),
                        headers=csrf(client))
        assert r.status_code == 201, r.text
    lib = client.get("/api/wordlists").json()
    row = next(x for x in lib["items"] if x["id"] == w.id)
    assert [d["name"] for d in row["domains"]] == ["example.com", "example.org"]

    for url in (f"/api/wordlists/{w.id}", f"/api/wordlists/{w.id}?force=true"):  # force only covers Web capture
        r = client.delete(url, headers=csrf(client))
        assert r.status_code == 409
        body = r.json()
        assert body["code"] == "wordlist_in_use"
        assert body["message"].startswith("In use by 2 domain(s): example.com, example.org")
        assert [d["name"] for d in body["domains"]] == ["example.com", "example.org"]
    db.expire_all()
    assert db.get(Wordlist, w.id) is not None  # no silent fallback

    # Once no domain uses it any more, the delete goes through.
    for d in client.get("/api/domains").json():
        client.put(f"/api/domains/{d['id']}", json=_domain_body(name=d["name"]), headers=csrf(client))
    assert client.delete(f"/api/wordlists/{w.id}", headers=csrf(client)).status_code == 204


# --- 2) recipient-group domain scope ----------------------------------------------------------------
def _grp(**kw) -> RecipientGroup:
    return RecipientGroup(name="G", enabled=True, min_severity="info", **kw)


def _dev_event(db, network_id) -> Event:
    dev = Device(network_id=network_id, current_ip="192.0.2.10", status="active", first_seen=utcnow(), last_seen=utcnow())
    db.add(dev)
    db.flush()
    ev = Event(event_type="port_opened", severity="high", message="m", notify=True, device_id=dev.id, created_at=utcnow())
    db.add(ev)
    db.flush()
    db.refresh(ev)
    return ev


def test_domain_scope_matching(db):
    lab = make_network(db, cidr="192.0.2.0/24", name="Lab")
    other = make_network(db, cidr="198.51.100.0/24", name="Other")
    d1, d2 = make_domain(db), make_domain(db, name="example.org")
    dom_ev = Event(event_type="subdomain_new", severity="low", message="m", notify=True, domain_id=d1.id,
                   hostname="a.example.com", created_at=utcnow())
    dev_ev = _dev_event(db, lab.id)

    # Network filter + all domains: still receives domain events; device events use the network scope.
    g = _grp(network_ids=[other.id], domain_ids=None)
    assert group_matches_event(g, dom_ev) is True
    assert group_matches_event(g, dev_ev) is False
    g = _grp(network_ids=[lab.id], domain_ids=None)
    assert group_matches_event(g, dev_ev) is True
    # Selected domains
    assert group_matches_event(_grp(domain_ids=[d1.id]), dom_ev) is True
    assert group_matches_event(_grp(domain_ids=[d2.id]), dom_ev) is False
    # Domain scope never filters device events
    assert group_matches_event(_grp(domain_ids=[d2.id]), dev_ev) is True


def test_group_api_domain_scope(client, db):  # noqa: F811
    d = make_domain(db)
    body = {"name": "DNS", "delivery_mode": "daily", "digest_time": "08:00", "domain_ids": [d.id],
            "destinations": [{"kind": "email", "target": "dns@example.com"}]}
    r = client.post("/api/recipient-groups", json=body, headers=csrf(client))
    assert r.status_code == 201, r.text
    g = r.json()
    assert g["domain_ids"] == [d.id] and g["summary"].endswith("Domains: example.com")
    assert client.post("/api/recipient-groups", json={**body, "domain_ids": [999]},
                       headers=csrf(client)).status_code == 422
    r = client.patch(f"/api/recipient-groups/{g['id']}", json={"domain_ids": None}, headers=csrf(client))
    assert r.json()["domain_ids"] == [] and "Domains" not in r.json()["summary"]


def test_migration_defaults_existing_groups_to_all_domains(tmp_path: Path):
    url = f"sqlite:///{(tmp_path / 'mig.db').as_posix()}"
    cfg = alembic_config(url)
    command.upgrade(cfg, "0035")
    eng = create_engine(url)
    with eng.begin() as conn:
        conn.execute(text(
            "INSERT INTO recipient_groups (name, enabled, is_default, min_severity, network_ids, delivery_mode, "
            "max_per_hour, dedupe_seconds, quiet_bypass_critical, rate_sent, created_at, updated_at) VALUES "
            "('SOC', 1, 0, 'info', :nets, 'daily', 20, 300, 1, 0, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)"),
            {"nets": json.dumps([1])})
        conn.execute(text("INSERT INTO domains (name, enabled, wordlist_mode, passive_enabled, axfr_enabled, created_at, "
                          "updated_at) VALUES ('example.com', 1, 'none', 1, 0, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)"))
        conn.execute(text("INSERT INTO subdomains (domain_id, name, exposure, wildcard, status, first_seen, last_seen) "
                          "VALUES (1, 'www.example.com', 'external', 0, 'active', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)"))
    command.upgrade(cfg, "head")
    with eng.connect() as conn:
        assert conn.execute(text("SELECT domain_ids FROM recipient_groups")).scalar() is None
        assert tuple(conn.execute(text("SELECT missed_scans, unverified, in_progress FROM subdomains")).one()) == (0, 0, 0)
    command.downgrade(cfg, "0035")
    with eng.connect() as conn:
        cols = {r[1] for r in conn.execute(text("PRAGMA table_info(recipient_groups)"))}
        assert "domain_ids" not in cols and "network_ids" in cols
    eng.dispose()


# --- 3) no false "gone" -----------------------------------------------------------------------------
def _three_names_dns(**kw) -> FlakyDns:
    return FlakyDns(internal={"app.example.com": ["192.0.2.10"], "db.example.com": ["192.0.2.20"]},
                    public={"www.example.com": ["198.51.100.10"]}, **kw)


def test_partial_scan_produces_no_gone_or_exposure_events(db, monkeypatch):
    fake_tools(monkeypatch, subfinder=[{"host": "www.example.com"}], dnsx_internal=[
        {"host": "app.example.com", "a": ["192.0.2.10"]}, {"host": "db.example.com", "a": ["192.0.2.20"]}])
    d = make_domain(db, wordlist_mode="custom", custom_words=["app", "db"])
    run_scan_now(d.id, _three_names_dns())
    before = _subdomains(db, d.id)
    seen = before["app.example.com"].last_seen

    # Next scan: the internal resolver times out for app (public now answers -> would look "external"),
    # and db really disappears. The scan is partial: no exposure change for app, no gone for db.
    dns = _three_names_dns(errors={("internal", "app.example.com")})
    dns.tables["public"]["app.example.com"] = ["198.51.100.20"]
    del dns.tables["internal"]["db.example.com"]
    job_id = run_scan_now(d.id, dns)
    job = db.get(DomainScan, job_id)
    assert job.status == "partial"
    assert any("internal resolver" in r for r in job.stats["partial_reasons"])
    assert job.stats["checks"]["internal_resolver"] == "errors"
    types = {(e.event_type, e.hostname) for e in db.scalars(select(Event).where(Event.domain_scan_id == job_id))}
    assert not any(t in {"subdomain_gone", "subdomain_exposure_changed", "subdomain_ip_changed"} for t, _ in types)
    subs = _subdomains(db, d.id)
    app_row = subs["app.example.com"]
    assert app_row.unverified and app_row.exposure == "internal" and app_row.last_seen == seen  # state kept
    assert subs["db.example.com"].status == "active" and subs["db.example.com"].missed_scans == 0
    assert not subs["www.example.com"].unverified
    resolve = next(p for p in job.phases if p["key"] == "resolve")
    assert "internal resolver" in resolve["reason"]


def test_gone_only_after_two_consecutive_complete_misses(db, monkeypatch):
    fake_tools(monkeypatch, subfinder=[{"host": "www.example.com"}, {"host": "app.example.com"}])
    d = make_domain(db)
    run_scan_now(d.id, _three_names_dns())
    missing = _three_names_dns()
    del missing.tables["internal"]["app.example.com"]

    def gone_events():
        return db.scalars(select(Event).where(Event.domain_id == d.id, Event.event_type == "subdomain_gone")).all()

    run_scan_now(d.id, missing)  # complete miss #1
    assert _subdomains(db, d.id)["app.example.com"].missed_scans == 1 and not gone_events()
    # A partial scan in between neither counts nor resets the misses.
    flaky = _three_names_dns(errors={("public", "www.example.com")})
    del flaky.tables["internal"]["app.example.com"]
    assert db.get(DomainScan, run_scan_now(d.id, flaky)).status == "partial"
    row = _subdomains(db, d.id)["app.example.com"]
    assert row.status == "active" and row.missed_scans == 1 and not gone_events()
    run_scan_now(d.id, missing)  # complete miss #2
    assert _subdomains(db, d.id)["app.example.com"].status == "gone"
    assert [e.hostname for e in gone_events()] == ["app.example.com"]
    # Seen again on a complete scan: active, misses reset, reported as new.
    back = run_scan_now(d.id, _three_names_dns())
    assert _subdomains(db, d.id)["app.example.com"].status == "active"
    assert db.scalar(select(Event.id).where(Event.domain_scan_id == back, Event.event_type == "subdomain_new"))


# --- 4) progress ------------------------------------------------------------------------------------
def test_progress_phase_transitions_and_monotonic_percent():
    t = [0.0]
    pg = Progress(None, write=False, clock=lambda: t[0], estimates={"wordlist_internal": 100, "wordlist_public": 100})
    pg.skip("passive", "turned off for this domain")
    pg.start("wordlist_internal", total=100, unit="candidates")
    seen = [pg.compute_percent()]
    for n in (20, 50, 100):
        t[0] += 2
        pg.update("wordlist_internal", processed=n, queries=n * 3)
        seen.append(pg.compute_percent())
    snap = {p["key"]: p for p in pg.snapshot()}
    w = snap["wordlist_internal"]
    assert (w["status"], w["processed"], w["total"]) == ("running", 100, 100)
    assert w["rate"] == 50.0 and w["eta_s"] == 0
    pg.finish("wordlist_internal")
    # A phase's total growing (resolution learns its real size) must not move the bar backwards.
    pg.start("resolve", total=10_000, unit="names")
    seen.append(pg.compute_percent())
    assert seen == sorted(seen) and seen[-1] < 0.99
    assert snap["passive"]["status"] == "skipped" and snap["passive"]["reason"] == "turned off for this domain"
    pg.stop_all("cancelled")
    final = {p["key"]: p["status"] for p in pg.snapshot()}
    assert final["resolve"] == "failed" and final["port_scan"] == "skipped"
    assert all(p["status"] != "running" for p in pg.phases)


def test_runner_records_phases_batches_and_skips(db, monkeypatch):
    calls = fake_tools(monkeypatch, dnsx_internal=[{"host": "w5.example.com", "a": ["192.0.2.5"]}])
    with session_scope() as s:
        assert batch_size(get_section(s, DomainDiscoverySettings)) == 60  # 20 q/s default
    words = [f"w{i}" for i in range(130)]
    d = make_domain(db, passive_enabled=False, wordlist_mode="custom", custom_words=words)
    job_id = run_scan_now(d.id, FakeDns(internal={"w5.example.com": ["192.0.2.5"]}))
    job = db.get(DomainScan, job_id)
    phases = {p["key"]: p for p in job.phases}
    assert [p["key"] for p in job.phases] == ["passive", "wordlist_internal", "wordlist_public", "axfr",
                                             "public_axfr", "resolve", "diff", "port_scan"]
    assert phases["passive"]["status"] == "skipped" and phases["passive"]["reason"] == "turned off for this domain"
    assert phases["axfr"]["status"] == "skipped" and phases["axfr"]["reason"] == "turned off for this domain"
    wi = phases["wordlist_internal"]
    assert (wi["status"], wi["processed"], wi["total"], wi["found"]) == ("done", 130, 130, 1)
    assert sum(1 for c in calls if c[0].endswith("dnsx")) == 6  # 3 batches per view
    assert phases["resolve"]["status"] == "done" and phases["resolve"]["total"] == 1
    assert all(p["finished_at"] for p in job.phases if p["status"] == "done")
    assert job.status == "completed" and job.progress == 1.0


def test_live_inventory_writes_while_scanning(db, monkeypatch):
    fake_tools(monkeypatch, subfinder=[{"host": "www.example.com"}, {"host": "api.example.com"}])
    d = make_domain(db)
    seen: list[tuple] = []

    class Watching(FakeDns):
        def resolve(self, name, nameservers):
            if name == "www.example.com" and nameservers == PUBLIC_NS:
                with session_scope() as s:
                    seen.extend((r.name, r.in_progress, r.exposure)
                                for r in s.scalars(select(Subdomain).where(Subdomain.domain_id == d.id)))
            return super().resolve(name, nameservers)

    dns = Watching(public={"www.example.com": ["198.51.100.10"], "api.example.com": ["198.51.100.11"]})
    with session_scope() as s:
        job_id = enqueue_domain_scan(s, s.get(Domain, d.id)).id
    run_domain_scan(job_id, ScanContext(job_id), dns=dns, progress_interval=0)
    # While www is being resolved: it is already in the inventory from the passive phase (in progress,
    # unclassified), and api - resolved just before - already carries its provisional classification.
    assert sorted(seen) == [("api.example.com", True, "external"), ("www.example.com", True, "unresolved")]
    subs = _subdomains(db, d.id)
    assert {n: (r.in_progress, r.exposure) for n, r in subs.items()} == {
        "www.example.com": (False, "external"), "api.example.com": (False, "external")}


def test_cancel_mid_phase_keeps_results_as_partial(db, monkeypatch):
    names = [f"h{i}.example.com" for i in range(6)]
    fake_tools(monkeypatch, subfinder=[{"host": n} for n in names])
    d = make_domain(db)
    with session_scope() as s:
        job_id = enqueue_domain_scan(s, s.get(Domain, d.id)).id
    ctx = ScanContext(job_id)

    class Cancelling(FakeDns):
        def resolve(self, name, nameservers):
            if name == "h3.example.com":
                ctx.cancel()  # operator clicks Cancel while names are being resolved
            return super().resolve(name, nameservers)

    run_domain_scan(job_id, ctx, dns=Cancelling(public={n: ["198.51.100.10"] for n in names}))
    job = db.get(DomainScan, job_id)
    assert job.status == "partial" and any("Cancelled during Resolve" in r for r in job.stats["partial_reasons"])
    phases = {p["key"]: p for p in job.phases}
    assert phases["resolve"]["status"] == "failed" and phases["resolve"]["reason"] == "cancelled"
    assert phases["port_scan"]["status"] == "skipped"
    subs = _subdomains(db, d.id)
    kept = {n for n, r in subs.items() if not r.unverified}
    assert {"h0.example.com", "h1.example.com", "h2.example.com"} <= kept  # resolved before the cancel
    assert subs["h5.example.com"].unverified and not subs["h5.example.com"].in_progress  # found, not yet checked
    assert not db.scalar(select(Event.id).where(Event.domain_scan_id == job_id, Event.event_type == "subdomain_gone"))


def test_wordlist_truncation_is_reported(client, db, monkeypatch):  # noqa: F811
    fake_tools(monkeypatch)
    with session_scope() as s:
        cfg = get_section(s, DomainDiscoverySettings)
        cfg.max_wordlist_entries = 50
        put_section(s, cfg)
    d = make_domain(db, passive_enabled=False, wordlist_mode="custom", custom_words=[f"w{i}" for i in range(130)])
    job = db.get(DomainScan, run_scan_now(d.id, FakeDns()))
    phases = {p["key"]: p for p in job.phases}
    for key in ("wordlist_internal", "wordlist_public"):
        assert phases[key]["status"] == "done" and phases[key]["total"] == 50
        assert phases[key]["reason"] == "wordlist truncated: 50 of 130 entries used (Max wordlist entries)"
    dom = client.get(f"/api/domains/{d.id}").json()
    assert (dom["wordlist_entries"], dom["wordlist_limit"]) == (130, 50)
