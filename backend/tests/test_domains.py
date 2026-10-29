"""Domain scans: validation, tool argv / JSON-lines handling, classification, wildcard marking, AXFR
(authorized / refused / open to the public), diff + severity routing, auto port scan with exclusions,
manual lookup, provider-key masking, retention, RBAC and the separate queue.

Every binary and every DNS answer is mocked: no network access.
"""
from __future__ import annotations

import os
import subprocess
import sys
from datetime import timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.api.auth import limiter
from app.core import channels
from app.core.channels import HOLD_DIGEST, HOLD_HOURLY, deliver_channel_event_ids
from app.core.domains import runner as domain_runner
from app.core.domains import tools
from app.core.domains.classify import classify_exposure, compute_flags, is_private_ip, wildcard_marked
from app.core.domains.diff import Snap, diff_snapshots
from app.core.domains.dnsops import Answer, AxfrRefused, ZoneRecord
from app.core.domains.manager import DomainScanManager, enqueue_domain_scan
from app.core.domains.providers import mask_key, provider_keys, render_provider_config, write_provider_config
from app.core.domains.validate import (
    DomainError,
    candidates,
    discovered_name,
    in_domain,
    normalize_domain,
    normalize_resolvers,
    normalize_words,
)
from app.core.retention import purge_expired
from app.db import session_scope, utcnow
from app.main import app
from app.models import (
    DELIVERY_DAILY,
    DELIVERY_IMMEDIATE,
    DEST_EMAIL,
    SCAN_COMPLETED,
    SCAN_QUEUED,
    AppSetting,
    AuditLog,
    Domain,
    DomainScan,
    Event,
    Exclusion,
    RecipientDestination,
    RecipientGroup,
    RecipientHold,
    Scan,
    Subdomain,
    SubdomainObservation,
)
from app.netutils import AddressSet
from app.scanner.types import ScanContext
from app.settings_store import DomainDiscoverySettings, get_section, put_section
from tests.helpers import make_network

INTERNAL_NS = ["192.0.2.53"]
PUBLIC_NS = ["198.51.100.53"]


# --- fakes ----------------------------------------------------------------------------------------
class FakeDns:
    """Two resolver views keyed by the nameserver list the runner passes; optional wildcard answers."""

    def __init__(self, internal=None, public=None, *, wildcard_internal=None, wildcard_public=None,
                 axfr=None, ns=None, domain="example.com"):
        self.tables = {"internal": dict(internal or {}), "public": dict(public or {})}
        self.wildcard = {"internal": wildcard_internal or [], "public": wildcard_public or []}
        self.axfr_map = dict(axfr or {})
        self.ns = dict(ns or {})
        self.domain = domain
        self.axfr_calls: list[str] = []

    def _view(self, nameservers):
        return "public" if nameservers == PUBLIC_NS else "internal"

    def resolve(self, name, nameservers):
        view = self._view(nameservers)
        ips = self.tables[view].get(name)
        if ips is None and self.wildcard[view] and in_domain(name, self.domain) and name != self.domain:
            ips = self.wildcard[view]
        if not ips:
            return Answer(status="nxdomain")
        return Answer(a=[i for i in ips if ":" not in i], aaaa=[i for i in ips if ":" in i], status="ok")

    def system_nameservers(self):
        return list(INTERNAL_NS)

    def nameservers(self, domain, resolvers):
        return dict(self.ns)

    def axfr(self, zone, server, timeout):
        self.axfr_calls.append(server)
        recs = self.axfr_map.get(server)
        if recs is None:
            raise AxfrRefused("TransferError")
        return recs


def fake_tools(monkeypatch, subfinder=(), dnsx_internal=(), dnsx_public=(), bad_lines=0):
    """subfinder / dnsx 'installed', their JSON-lines output given per call."""
    monkeypatch.setattr(tools, "resolve_tool", lambda name: f"/opt/tools/{name}")
    calls: list[list[str]] = []

    def run(cmd, ctx, timeout_s):
        calls.append(cmd)
        if cmd[0].endswith("subfinder"):
            return tools.ToolResult(list(subfinder), bad_lines, False, 0, "")
        res_file = cmd[cmd.index("-r") + 1]
        recs = dnsx_public if "public" in os.path.basename(res_file) else dnsx_internal
        return tools.ToolResult(list(recs), 0, False, 0, "")

    monkeypatch.setattr(tools, "run_jsonl_tool", run)
    return calls


def make_domain(db, **kw) -> Domain:
    d = Domain(name="example.com", enabled=True, wordlist_mode="none", passive_enabled=True, axfr_enabled=False,
               internal_resolvers=list(INTERNAL_NS), public_resolvers=list(PUBLIC_NS), created_by="test")
    for k, v in kw.items():
        setattr(d, k, v)
    db.add(d)
    db.commit()
    return d


def run_scan_now(domain_id: int, dns: FakeDns) -> int:
    with session_scope() as s:
        job_id = enqueue_domain_scan(s, s.get(Domain, domain_id)).id
    domain_runner.run_domain_scan(job_id, ScanContext(job_id), dns=dns)
    return job_id


@pytest.fixture
def client(db_env):
    limiter.reset()
    with TestClient(app) as c:
        assert c.post("/api/setup/admin", json={"username": "admin", "password": "correct-horse-1"}).status_code == 200
        yield c


def csrf(c: TestClient) -> dict:
    return {"X-CSRF-Token": c.cookies.get("nf_csrf", "")}


# --- validation -----------------------------------------------------------------------------------
@pytest.mark.parametrize("raw,expected", [
    ("Example.COM.", "example.com"),
    ("  test.example.com ", "test.example.com"),
    ("bücher.example", "xn--bcher-kva.example"),
    ("xn--bcher-kva.example", "xn--bcher-kva.example"),
])
def test_normalize_domain_accepts_and_punycodes(raw, expected):
    assert normalize_domain(raw) == expected


@pytest.mark.parametrize("raw", [
    "", "example", "192.0.2.1", "*.example.com", "https://example.com", "exa mple.com", "a..example.com",
    "-bad.example.com", "bad-.example.com", "under_score.example.com", "x" * 64 + ".example.com",
    ("a." * 130) + "com", "example.com;rm", "exam\nple.com", "example.123",
])
def test_normalize_domain_rejects(raw):
    with pytest.raises(DomainError):
        normalize_domain(raw)


def test_in_domain_uses_label_boundaries():
    assert in_domain("a.example.com", "example.com")
    assert in_domain("example.com", "example.com")
    assert not in_domain("notexample.com", "example.com")
    assert not in_domain("example.com.evil.test", "example.com")


def test_discovered_names_are_filtered_to_the_domain():
    assert discovered_name("WWW.Example.com.", "example.com") == "www.example.com"
    assert discovered_name("_sip._tcp.example.com", "example.com") == "_sip._tcp.example.com"
    assert discovered_name("*.example.com", "example.com") is None
    assert discovered_name("test.example.org", "example.com") is None
    assert discovered_name("bad name.example.com", "example.com") is None
    assert discovered_name(42, "example.com") is None


def test_resolvers_and_words_validation():
    assert normalize_resolvers([" 192.0.2.1 ", "192.0.2.1", "2001:db8::1"]) == ["192.0.2.1", "2001:db8::1"]
    with pytest.raises(DomainError):
        normalize_resolvers(["dns.example.com"])
    with pytest.raises(DomainError):
        normalize_resolvers([f"192.0.2.{i}" for i in range(1, 10)])
    assert normalize_words(["WWW", "dev.api", "www"]) == ["www", "dev.api"]
    with pytest.raises(DomainError):
        normalize_words(["bad word"])
    assert candidates("example.com", ["www", "bad word", "dev", "www"], 10) == ["www.example.com", "dev.example.com"]
    assert candidates("example.com", ["a", "b", "c"], 2) == ["a.example.com", "b.example.com"]


# --- tool command lines and JSON lines ------------------------------------------------------------
def test_subfinder_and_dnsx_argv_are_plain_lists(tmp_path):
    cmd = tools.build_subfinder_cmd("subfinder", tmp_path / "domains.txt", provider_config=tmp_path / "pc.yaml",
                                    max_minutes=5)
    assert all(isinstance(a, str) for a in cmd)
    assert cmd[:3] == ["subfinder", "-dL", str(tmp_path / "domains.txt")]
    assert "-oJ" in cmd and "-silent" in cmd and "-duc" in cmd
    assert cmd[cmd.index("-pc") + 1] == str(tmp_path / "pc.yaml")
    assert cmd[cmd.index("-max-time") + 1] == "5"
    assert "-pc" not in tools.build_subfinder_cmd("subfinder", tmp_path / "d.txt", provider_config=None, max_minutes=5)

    cmd = tools.build_dnsx_cmd("dnsx", tmp_path / "hosts.txt", tmp_path / "resolvers.txt", rate_per_second=7)
    assert cmd[:5] == ["dnsx", "-l", str(tmp_path / "hosts.txt"), "-r", str(tmp_path / "resolvers.txt")]
    assert "-json" in cmd and cmd[cmd.index("-rl") + 1] == "7"
    assert {"-a", "-aaaa", "-cname"} <= set(cmd)


def test_parse_jsonl_skips_malformed_lines():
    lines = ['{"host": "a.example.com"}', "", "not json", '{"host": "b.example.com"', "[1, 2]", "42",
             '{"host": "c.example.com", "source": "crtsh"}']
    records, bad = tools.parse_jsonl(lines)
    assert [r["host"] for r in records] == ["a.example.com", "c.example.com"]
    assert bad == 4


class _FakeProc:
    def __init__(self, stdout: str, *, hang: bool = False):
        self.stdout_text = stdout
        self.hang = hang
        self.killed = False
        self.returncode = 0

    def communicate(self, timeout=None):
        if self.hang and not self.killed:
            raise subprocess.TimeoutExpired("tool", timeout)
        return self.stdout_text, "warn: something"

    def kill(self):
        self.killed = True
        self.returncode = -9


def test_run_jsonl_tool_never_uses_a_shell(monkeypatch):
    seen = {}

    def fake_popen(args, **kwargs):
        seen["args"], seen["kwargs"] = args, kwargs
        return _FakeProc('{"host": "a.example.com"}\ngarbage\n')

    monkeypatch.setattr(tools.subprocess, "Popen", fake_popen)
    ctx = ScanContext(1)
    res = tools.run_jsonl_tool(["subfinder", "-dL", "in.txt", "-oJ"], ctx, timeout_s=5)
    assert isinstance(seen["args"], list) and seen["kwargs"]["shell"] is False
    assert seen["kwargs"]["stdin"] == subprocess.DEVNULL
    assert res.records == [{"host": "a.example.com"}] and res.bad_lines == 1 and not res.timed_out
    with pytest.raises(TypeError):
        tools.run_jsonl_tool("subfinder -d example.com", ctx, timeout_s=5)  # type: ignore[arg-type]


def test_run_jsonl_tool_kills_on_timeout(monkeypatch):
    proc = _FakeProc("", hang=True)
    monkeypatch.setattr(tools.subprocess, "Popen", lambda args, **kw: proc)
    res = tools.run_jsonl_tool(["dnsx", "-l", "x"], ScanContext(1), timeout_s=0.01)
    assert proc.killed and res.timed_out


def test_tool_missing_is_reported_not_raised(db_env, monkeypatch):
    monkeypatch.setattr(tools.shutil, "which", lambda name: None)
    st = tools.tool_status(refresh=True)
    assert set(st) == {"subfinder", "dnsx"}
    assert not st["subfinder"].found and "not installed" in st["subfinder"].message
    tools._status_cache = None


def test_tool_found_in_app_tools_dir(db_env, monkeypatch):
    monkeypatch.setattr(tools.shutil, "which", lambda name: None)
    exe = tools.tools_dir() / ("dnsx.exe" if sys.platform == "win32" else "dnsx")
    exe.parent.mkdir(parents=True, exist_ok=True)
    exe.write_text("")
    assert tools.resolve_tool("dnsx") == str(exe)
    assert tools.resolve_tool("subfinder") is None


# --- classification ---------------------------------------------------------------------------------
def test_classify_exposure():
    assert classify_exposure(["192.0.2.1"], ["198.51.100.1"]) == "both"
    assert classify_exposure([], ["198.51.100.1"]) == "external"
    assert classify_exposure(["192.0.2.1"], []) == "internal"
    assert classify_exposure([], []) == "unresolved"


def test_flags_private_ip_exposed_and_ground_truth():
    in_lab = AddressSet.from_specs("192.0.2.0/24").__contains__
    assert is_private_ip("10.1.2.3") and is_private_ip("fd00::1") and not is_private_ip("198.51.100.1")
    # Split DNS answering a private address publicly
    assert compute_flags(["passive"], "both", ["10.1.2.3"], ["10.1.2.3"]) == ["private_ip_public"]
    # Public answer inside a configured network counts as internal too
    assert "private_ip_public" in compute_flags(["passive"], "external", [], ["192.0.2.9"], in_lab)
    # Ordinary split DNS (public address outside): nothing to flag
    assert compute_flags(["passive", "axfr"], "both", ["192.0.2.9"], ["198.51.100.9"], in_lab) == []
    # AXFR only -> internal (authorized)
    assert compute_flags(["axfr"], "internal", ["192.0.2.9"], [], in_lab) == ["internal_authorized"]
    # AXFR name that passive sources leak, resolving only internally -> internal name exposed
    assert compute_flags(["axfr", "passive"], "internal", ["192.0.2.9"], [], in_lab) == ["internal_name_exposed"]


def test_wildcard_marking():
    wc = {"internal": [], "public": ["198.51.100.99"]}
    assert wildcard_marked([], ["198.51.100.99"], wc)
    assert not wildcard_marked([], ["198.51.100.10"], wc)
    assert not wildcard_marked(["192.0.2.5"], ["198.51.100.99"], wc)  # internal view is real
    assert not wildcard_marked([], [], wc)
    assert not wildcard_marked([], ["198.51.100.99"], None)


# --- full pipeline ------------------------------------------------------------------------------------
def _lab_dns(**overrides) -> FakeDns:
    internal = {"www.example.com": ["192.0.2.10"], "dev.example.com": ["192.0.2.20"],
                "leak.example.com": ["192.0.2.30"], "secret.example.com": ["192.0.2.40"]}
    public = {"www.example.com": ["198.51.100.10"], "leak.example.com": ["10.1.2.3"]}
    axfr = {"192.0.2.53": [ZoneRecord(n, "A", ips[0]) for n, ips in internal.items()]
            + [ZoneRecord("*.example.com", "A", "192.0.2.99")]}
    ns = {"ns1.example.com": ["198.51.100.1"]}
    kw = dict(internal=internal, public=public, axfr=axfr, ns=ns)
    kw.update(overrides)
    return FakeDns(**kw)


def _subdomains(db, domain_id) -> dict[str, Subdomain]:
    db.expire_all()
    return {s.name: s for s in db.scalars(select(Subdomain).where(Subdomain.domain_id == domain_id))}


def test_pipeline_baseline_classifies_and_reports_only_critical(db, monkeypatch):
    make_network(db, cidr="192.0.2.0/24", name="Lab")
    db.add(Exclusion(value="192.0.2.40", enabled=True))
    d = make_domain(db, wordlist_mode="custom", custom_words=["www", "dev", "vpn"], axfr_enabled=True,
                    axfr_servers=["192.0.2.53"])
    fake_tools(monkeypatch,
               subfinder=[{"host": "www.example.com"}, {"host": "leak.example.com"},
                          {"host": "evil.other.test"}, {"host": "*.example.com"}, {"host": "gone-stale.example.com"}],
               dnsx_internal=[{"host": "dev.example.com", "a": ["192.0.2.20"]}],
               dnsx_public=[{"host": "www.example.com", "a": ["198.51.100.10"]}], bad_lines=2)
    dns = _lab_dns()
    job_id = run_scan_now(d.id, dns)

    job = db.get(DomainScan, job_id)
    assert job.status == SCAN_COMPLETED, (job.error, job.notes)
    assert "malformed" in (job.notes or "")
    subs = _subdomains(db, d.id)
    assert set(subs) == {"www.example.com", "dev.example.com", "leak.example.com", "secret.example.com"}
    assert subs["www.example.com"].exposure == "both"
    assert set(subs["www.example.com"].sources) == {"passive", "wordlist", "axfr"}
    assert subs["dev.example.com"].exposure == "internal"
    assert subs["secret.example.com"].flags == ["internal_authorized"]
    assert set(subs["leak.example.com"].flags) == {"private_ip_public", "internal_name_exposed"}
    hosting = {h["ip"]: h for h in subs["www.example.com"].hosting}
    assert hosting["192.0.2.10"]["kind"] == "network" and hosting["192.0.2.10"]["network"] == "Lab"
    assert hosting["198.51.100.10"]["kind"] == "external"

    # Baseline: the exposure finding only, no "new subdomain" noise
    events = db.scalars(select(Event).where(Event.domain_id == d.id)).all()
    assert [(e.event_type, e.hostname, e.severity) for e in events] == [
        ("internal_name_exposed", "leak.example.com", "high")]
    # Snapshot stored per scan
    assert db.scalar(select(SubdomainObservation.id).where(SubdomainObservation.domain_scan_id == job_id).limit(1))
    # AXFR: authorized server ok, public NS refused
    assert job.axfr["authorized"]["192.0.2.53"]["status"] == "ok"
    assert job.axfr["public"]["ns1.example.com (198.51.100.1)"]["status"] == "refused"

    # New addresses -> one port scan in the normal queue, exclusions and unmanaged private ranges respected
    scan = db.get(Scan, job.port_scan_id)
    assert scan is not None and scan.status == SCAN_QUEUED and scan.network_id is None
    targets = AddressSet.from_specs(scan.targets)
    assert "192.0.2.10" in targets and "198.51.100.10" in targets
    assert "192.0.2.40" not in targets  # excluded
    assert "10.1.2.3" not in targets  # private, outside every configured network


def test_pipeline_diff_events_and_severity(db, monkeypatch):
    make_network(db, cidr="192.0.2.0/24", name="Lab")
    d = make_domain(db, axfr_enabled=True, axfr_servers=["192.0.2.53"])
    fake_tools(monkeypatch, subfinder=[{"host": "www.example.com"}, {"host": "leak.example.com"}])
    run_scan_now(d.id, _lab_dns())

    # Next scan: dev disappears, www moves, a new public name points into the Lab network,
    # and the public authoritative server now allows AXFR from the scan host.
    fake_tools(monkeypatch, subfinder=[{"host": "www.example.com"}, {"host": "leak.example.com"},
                                       {"host": "new.example.com"}])
    dns = _lab_dns()
    del dns.tables["internal"]["dev.example.com"]
    dns.axfr_map["192.0.2.53"] = [r for r in dns.axfr_map["192.0.2.53"] if r.name != "dev.example.com"]
    dns.tables["public"]["www.example.com"] = ["198.51.100.11"]
    dns.tables["public"]["new.example.com"] = ["192.0.2.50"]
    dns.axfr_map["198.51.100.1"] = [ZoneRecord("open.example.com", "A", "198.51.100.77")]
    dns.tables["public"]["open.example.com"] = ["198.51.100.77"]
    job_id = run_scan_now(d.id, dns)

    events = {(e.event_type, e.hostname): e for e in db.scalars(select(Event).where(Event.domain_scan_id == job_id))}
    assert events[("subdomain_new", "new.example.com")].severity == "high"  # external, inside a configured network
    assert events[("subdomain_new", "open.example.com")].severity == "low"
    assert ("subdomain_gone", "dev.example.com") not in events  # one miss is not "gone"
    ip_ev = events[("subdomain_ip_changed", "www.example.com")]
    assert ip_ev.old_value == "192.0.2.10, 198.51.100.10" and ip_ev.new_value == "192.0.2.10, 198.51.100.11"
    zt = events[("zone_transfer_open", "example.com")]
    assert zt.severity == "high" and "ns1.example.com" in zt.message
    assert ("internal_name_exposed", "leak.example.com") not in events  # already reported
    subs = _subdomains(db, d.id)
    assert subs["dev.example.com"].status == "active" and subs["dev.example.com"].missed_scans == 1
    job = db.get(DomainScan, job_id)
    assert job.status == SCAN_COMPLETED
    assert job.stats["new"] == 2 and job.stats["gone"] == 0 and job.stats["zone_transfer_open"] == 1
    targets = AddressSet.from_specs(db.get(Scan, job.port_scan_id).targets)
    assert "198.51.100.11" in targets and "192.0.2.50" in targets and "192.0.2.10" not in targets

    # Second consecutive complete miss: now it is gone, with one event.
    third = run_scan_now(d.id, dns)
    gone = db.scalars(select(Event).where(Event.domain_scan_id == third, Event.event_type == "subdomain_gone")).all()
    assert [(e.hostname, e.severity) for e in gone] == [("dev.example.com", "low")]
    assert _subdomains(db, d.id)["dev.example.com"].status == "gone"


def test_exposure_change_internal_to_external_is_critical():
    prev = {"app.example.com": Snap("app.example.com", "internal", frozenset({"192.0.2.5"}))}
    cur = {"app.example.com": Snap("app.example.com", "both", frozenset({"192.0.2.5", "198.51.100.5"}),
                                   frozenset({"198.51.100.5"}))}
    changes = diff_snapshots(prev, cur, lambda ip: False)
    exp = next(c for c in changes if c.event_type == "subdomain_exposure_changed")
    assert exp.severity == "high" and (exp.old_value, exp.new_value) == ("internal", "both")
    back = diff_snapshots(cur, prev, lambda ip: False)
    assert next(c for c in back if c.event_type == "subdomain_exposure_changed").severity == "medium"


def test_wildcard_detected_and_marked_not_filtered(db, monkeypatch):
    d = make_domain(db, wordlist_mode="custom", custom_words=["foo", "bar"])
    fake_tools(monkeypatch, subfinder=[{"host": "www.example.com"}],
               dnsx_public=[{"host": "foo.example.com", "a": ["198.51.100.99"]},
                            {"host": "bar.example.com", "a": ["198.51.100.99"]}])
    run_scan_now(d.id, FakeDns(public={"www.example.com": ["198.51.100.10"]}))  # baseline without wildcard
    dns = FakeDns(public={"www.example.com": ["198.51.100.10"]}, wildcard_public=["198.51.100.99"])
    job_id = run_scan_now(d.id, dns)
    job = db.get(DomainScan, job_id)
    assert job.wildcard == {"internal": [], "public": ["198.51.100.99"]}
    subs = _subdomains(db, d.id)
    assert subs["foo.example.com"].wildcard and subs["bar.example.com"].wildcard  # kept, only marked
    assert not subs["www.example.com"].wildcard
    types = [e.event_type for e in db.scalars(select(Event).where(Event.domain_scan_id == job_id))]
    assert "wildcard_detected" in types


def test_axfr_refused_is_partial_and_missing_tools_are_skipped(db, monkeypatch):
    d = make_domain(db, axfr_enabled=True, axfr_servers=["192.0.2.53"], wordlist_mode="custom", custom_words=["www"])
    monkeypatch.setattr(tools, "resolve_tool", lambda name: None)
    job_id = run_scan_now(d.id, FakeDns(internal={"www.example.com": ["192.0.2.10"]}))
    job = db.get(DomainScan, job_id)
    assert job.status == "partial"  # the authorized zone transfer (a source) failed
    assert job.axfr["authorized"]["192.0.2.53"]["status"] == "refused"
    assert "subfinder is not installed" in job.notes and "dnsx is not installed" in job.notes
    phases = {p["key"]: p for p in job.phases}
    assert phases["passive"]["status"] == "skipped" and phases["passive"]["reason"] == "subfinder not installed"
    assert phases["wordlist_internal"]["status"] == "skipped" and phases["wordlist_public"]["status"] == "skipped"
    assert phases["axfr"]["status"] == "failed" and "192.0.2.53" in phases["axfr"]["reason"]
    assert any("Zone transfer" in r for r in job.stats["partial_reasons"])
    assert job.stats["checks"]["axfr"] == "failed"
    assert _subdomains(db, d.id) == {}  # nothing discovered, nothing invented


def test_provider_config_is_temporary_and_private(db, monkeypatch, tmp_path):
    from app.security import encrypt_secret

    with session_scope() as s:
        cfg = get_section(s, DomainDiscoverySettings)
        cfg.virustotal_key_enc = encrypt_secret("vt-secret-0123456789")
        put_section(s, cfg)
    d = make_domain(db)
    seen = {}
    monkeypatch.setattr(tools, "resolve_tool", lambda name: f"/opt/tools/{name}")

    def run(cmd, ctx, timeout_s):
        pc = cmd[cmd.index("-pc") + 1]
        seen["path"] = pc
        with open(pc, encoding="utf-8") as fh:
            seen["content"] = fh.read()
        if sys.platform != "win32":
            seen["mode"] = os.stat(pc).st_mode & 0o777
        return tools.ToolResult([], 0, False, 0, "")

    monkeypatch.setattr(tools, "run_jsonl_tool", run)
    run_scan_now(d.id, FakeDns())
    assert 'virustotal:\n  - "vt-secret-0123456789"' in seen["content"]
    assert not os.path.exists(seen["path"])  # deleted after the run
    if sys.platform != "win32":
        assert seen["mode"] == 0o600


def test_provider_helpers():
    assert mask_key("") == "" and mask_key("short") == "••••" and mask_key("abcdefgh12345678") == "••••5678"
    text = render_provider_config({"shodan": 'k"ey', "virustotal": "v"})
    assert text == 'shodan:\n  - "k\\"ey"\nvirustotal:\n  - "v"\n'
    cfg = DomainDiscoverySettings(other_provider="chaos")
    assert provider_keys(cfg) == {}


def test_write_provider_config_none_without_keys(tmp_path):
    assert write_provider_config(tmp_path, {}) is None
    p = write_provider_config(tmp_path, {"shodan": "x"})
    assert p is not None and p.read_text(encoding="utf-8") == 'shodan:\n  - "x"\n'


# --- severity routing -----------------------------------------------------------------------------------
def _group(db, mode):
    g = RecipientGroup(name=f"G-{mode}", enabled=True, is_default=False, min_severity="info", delivery_mode=mode,
                       digest_time="08:00", max_per_hour=20, dedupe_seconds=0, quiet_bypass_critical=True,
                       rate_sent=0, created_at=utcnow(), updated_at=utcnow())
    db.add(g)
    db.flush()
    db.add(RecipientDestination(group_id=g.id, kind=DEST_EMAIL, enabled=True, target=f"{mode}@example.com"))
    return g


def test_domain_event_routing_critical_immediate_normal_digest(db, monkeypatch):
    daily = _group(db, DELIVERY_DAILY)
    immediate = _group(db, DELIVERY_IMMEDIATE)
    crit = Event(event_type="zone_transfer_open", severity="high", message="Zone transfer open", notify=True,
                 created_at=utcnow(), hostname="example.com")
    normal = Event(event_type="subdomain_new", severity="low", message="New subdomain a.example.com", notify=True,
                   created_at=utcnow(), hostname="a.example.com")
    db.add_all([crit, normal])
    db.commit()
    sent: list[str] = []
    monkeypatch.setattr(channels, "send_email", lambda cfg, subject, plain, html=None, **kw: sent.append(subject))
    deliver_channel_event_ids([crit.id, normal.id])
    db.expire_all()
    holds = {(h.group_id, h.event_id): h.reason for h in db.scalars(select(RecipientHold))}
    assert (daily.id, crit.id) not in holds and (immediate.id, crit.id) not in holds  # sent right away
    assert holds[(daily.id, normal.id)] == HOLD_DIGEST
    assert holds[(immediate.id, normal.id)] == HOLD_HOURLY


def test_recipient_group_accepts_domain_event_types(client):
    r = client.post("/api/recipient-groups", headers=csrf(client), json={
        "name": "DNS", "enabled": True, "event_types": ["zone_transfer_open", "subdomain_new"],
        "min_severity": "info", "delivery_mode": "daily", "digest_time": "08:00",
        "destinations": [{"kind": "email", "target": "dns@example.com"}],
    })
    assert r.status_code == 201, r.text
    assert r.json()["event_types"] == ["zone_transfer_open", "subdomain_new"]


# --- API: CRUD, RBAC, lookup, settings ------------------------------------------------------------------
def _domain_body(**kw):
    body = {"name": "example.com", "enabled": True, "wordlist_mode": "none", "passive_enabled": True,
            "axfr_enabled": False, "axfr_servers": [], "internal_resolvers": list(INTERNAL_NS),
            "public_resolvers": list(PUBLIC_NS), "schedule": {"enabled": False, "time": "03:30", "days": [0]}}
    body.update(kw)
    return body


def test_domain_crud_and_validation(client):
    r = client.post("/api/domains", json=_domain_body(name="Example.COM."), headers=csrf(client))
    assert r.status_code == 201, r.text
    dom = r.json()
    assert dom["name"] == "example.com" and dom["counts"]["active"] == 0
    assert client.post("/api/domains", json=_domain_body(), headers=csrf(client)).status_code == 409
    assert client.post("/api/domains", json=_domain_body(name="192.0.2.1"), headers=csrf(client)).status_code == 422
    assert client.post("/api/domains", json=_domain_body(name="test.example.org", internal_resolvers=["dns.local"]),
                       headers=csrf(client)).status_code == 422
    assert client.post("/api/domains", json=_domain_body(name="test.example.org", wordlist_mode="library"),
                       headers=csrf(client)).status_code == 422
    r = client.put(f"/api/domains/{dom['id']}", json=_domain_body(wordlist_mode="custom", custom_words=["www", "dev"],
                                                                  notes="lab"), headers=csrf(client))
    assert r.status_code == 200 and r.json()["custom_words"] == ["www", "dev"]
    assert client.get("/api/domains").json()[0]["notes"] == "lab"
    r = client.post(f"/api/domains/{dom['id']}/scan", headers=csrf(client))
    assert r.status_code == 201 and r.json()["status"] == "queued"
    assert client.post(f"/api/domains/{dom['id']}/scan", headers=csrf(client)).status_code == 409
    assert client.delete(f"/api/domains/{dom['id']}", headers=csrf(client)).status_code == 409  # scan queued
    assert client.post(f"/api/domain-scans/{r.json()['id']}/cancel", headers=csrf(client)).status_code == 200
    assert client.delete(f"/api/domains/{dom['id']}", headers=csrf(client)).status_code == 204


def test_viewer_reads_but_cannot_change_or_lookup(client):
    client.post("/api/domains", json=_domain_body(), headers=csrf(client))
    client.post("/api/users", json={"username": "viewer1", "password": "viewer-pass-1", "role": "viewer"},
                headers=csrf(client))
    client.post("/api/auth/logout", headers=csrf(client))
    client.post("/api/auth/login", json={"username": "viewer1", "password": "viewer-pass-1"})
    doms = client.get("/api/domains")
    assert doms.status_code == 200 and doms.json()[0]["name"] == "example.com"
    did = doms.json()[0]["id"]
    assert client.get(f"/api/domains/{did}/subdomains").status_code == 200
    assert client.get(f"/api/domains/{did}/scans").status_code == 200
    assert client.post("/api/domains", json=_domain_body(name="test.example.org"), headers=csrf(client)).status_code == 403
    assert client.post(f"/api/domains/{did}/scan", headers=csrf(client)).status_code == 403
    assert client.post("/api/domains/lookup", json={"hostname": "test.example.com"}, headers=csrf(client)).status_code == 403
    assert client.get("/api/settings/domain-discovery").status_code == 403


def test_manual_lookup_in_domain_only_add_and_port_scan(client, monkeypatch):
    with session_scope() as s:
        make_network(s, cidr="192.0.2.0/24", name="Lab")
        s.add(Exclusion(value="192.0.2.66", enabled=True))
    client.post("/api/domains", json=_domain_body(), headers=csrf(client))
    dns = FakeDns(internal={"test.example.com": ["192.0.2.10"]},
                  public={"test.example.com": ["198.51.100.10"], "cdn.example.com": ["198.51.100.20"],
                          "excl.example.com": ["192.0.2.66"]})
    monkeypatch.setattr("app.core.domains.lookup.make_dns", lambda domain, public, cfg: dns)

    r = client.post("/api/domains/lookup", json={"hostname": "evil.example.org"}, headers=csrf(client))
    assert r.status_code == 422 and "not inside any configured domain" in r.text
    assert client.post("/api/domains/lookup", json={"hostname": "bad host.example.com"},
                       headers=csrf(client)).status_code == 422

    r = client.post("/api/domains/lookup", json={"hostname": "Test.Example.com"}, headers=csrf(client))
    assert r.status_code == 200, r.text
    res = r.json()
    assert res["hostname"] == "test.example.com" and res["exposure"] == "both" and not res["in_inventory"]
    assert {h["kind"] for h in res["hosting"]} == {"network", "external"}

    # Hosted outside our networks: still works
    ext = client.post("/api/domains/lookup", json={"hostname": "cdn.example.com"}, headers=csrf(client)).json()
    assert ext["exposure"] == "external" and ext["hosting"][0]["kind"] == "external"

    r = client.post("/api/domains/lookup/add", json={"hostname": "test.example.com"}, headers=csrf(client))
    assert r.status_code == 201 and r.json()["sources"] == ["manual"]
    did = client.get("/api/domains").json()[0]["id"]
    listed = client.get(f"/api/domains/{did}/subdomains", params={"source": "manual"}).json()
    assert [s["name"] for s in listed["items"]] == ["test.example.com"]

    r = client.post("/api/domains/lookup/port-scan", json={"hostname": "test.example.com"}, headers=csrf(client))
    assert r.status_code == 200 and r.json()["targets"] == ["192.0.2.10", "198.51.100.10"]
    assert client.post("/api/domains/lookup/port-scan", json={"hostname": "excl.example.com"},
                       headers=csrf(client)).status_code == 409  # only address is excluded

    with session_scope() as s:
        actions = [a.action for a in s.scalars(select(AuditLog).order_by(AuditLog.id))]
    assert {"domain.lookup", "domain.lookup_add", "domain.lookup_port_scan"} <= set(actions)


def test_subdomain_filters(client, db):
    client.post("/api/domains", json=_domain_body(), headers=csrf(client))
    did = client.get("/api/domains").json()[0]["id"]
    now = utcnow()
    for name, exposure, sources, wildcard, status in [
        ("a.example.com", "external", ["passive"], False, "active"),
        ("b.example.com", "internal", ["axfr"], False, "active"),
        ("c.example.com", "both", ["wordlist", "passive"], True, "active"),
        ("d.example.com", "external", ["passive"], False, "gone"),
    ]:
        db.add(Subdomain(domain_id=did, name=name, exposure=exposure, sources=sources, wildcard=wildcard,
                         status=status, ips=["198.51.100.1"], first_seen=now, last_seen=now))
    db.commit()

    def names(**params):
        return [s["name"] for s in client.get(f"/api/domains/{did}/subdomains", params=params).json()["items"]]

    assert names() == ["a.example.com", "b.example.com", "c.example.com"]
    assert names(status="all") == ["a.example.com", "b.example.com", "c.example.com", "d.example.com"]
    assert names(exposure="external") == ["a.example.com"]
    assert names(source="passive") == ["a.example.com", "c.example.com"]
    assert names(wildcard="true") == ["c.example.com"]
    assert names(q="b.ex") == ["b.example.com"]
    assert names(sort="-name") == ["c.example.com", "b.example.com", "a.example.com"]


def test_settings_keys_are_encrypted_masked_and_never_logged(client, db):
    key = "vt-0123456789abcdef"
    body = {"concurrency": 2, "dns_rate_per_second": 10, "virustotal_key": key, "other_provider": "bad name!",
            "other_key": "other-secret-value-1"}
    r = client.put("/api/settings/domain-discovery", json=body, headers=csrf(client))
    assert r.status_code == 422 and key not in r.text
    body["other_provider"] = "Chaos"  # stored lower-case
    r = client.put("/api/settings/domain-discovery", json=body, headers=csrf(client))
    assert r.status_code == 200, r.text
    assert key not in r.text and r.json()["keys"]["virustotal"] == {"set": True, "masked": "••••cdef"}
    got = client.get("/api/settings/domain-discovery").json()
    assert got["concurrency"] == 2 and got["keys"]["shodan"]["set"] is False
    assert got["keys"]["other"]["provider"] == "chaos" and "other-secret" not in str(got)
    db.expire_all()
    stored = db.get(AppSetting, "domain_discovery").value
    assert key not in str(stored) and stored["virustotal_key_enc"]
    assert all(key not in (a.details or "") for a in db.scalars(select(AuditLog)))
    # null keeps, "" clears
    r = client.put("/api/settings/domain-discovery", json={"virustotal_key": None, "shodan_key": ""}, headers=csrf(client))
    assert r.json()["keys"]["virustotal"]["set"] is True and r.json()["keys"]["shodan"]["set"] is False
    r = client.put("/api/settings/domain-discovery", json={"virustotal_key": ""}, headers=csrf(client))
    assert r.json()["keys"]["virustotal"] == {"set": False, "masked": ""}


def test_system_status_reports_tools(client, monkeypatch):
    monkeypatch.setattr(tools.shutil, "which", lambda name: None)
    tools._status_cache = None
    body = client.get("/api/system/status").json()
    assert set(body["domain_scans"]["tools"]) == {"subfinder", "dnsx"}
    assert body["domain_scans"]["tools"]["dnsx"]["found"] is False
    tools._status_cache = None


# --- retention -------------------------------------------------------------------------------------------
def test_retention_purges_old_domain_history(db):
    d = make_domain(db)
    now = utcnow()
    old = DomainScan(domain_id=d.id, status=SCAN_COMPLETED, trigger="manual", created_at=now - timedelta(days=100),
                     progress=1.0)
    recent = DomainScan(domain_id=d.id, status=SCAN_COMPLETED, trigger="manual", created_at=now - timedelta(days=5),
                        progress=1.0)
    running_old = DomainScan(domain_id=d.id, status="running", trigger="manual", created_at=now - timedelta(days=100),
                             progress=0.5)
    db.add_all([old, recent, running_old])
    db.flush()
    db.add_all([SubdomainObservation(domain_scan_id=old.id, name="a.example.com", exposure="external"),
                SubdomainObservation(domain_scan_id=recent.id, name="a.example.com", exposure="external")])
    db.add_all([
        Subdomain(domain_id=d.id, name="gone-old.example.com", exposure="external", status="gone",
                  first_seen=now - timedelta(days=200), last_seen=now - timedelta(days=95)),
        Subdomain(domain_id=d.id, name="gone-new.example.com", exposure="external", status="gone",
                  first_seen=now, last_seen=now - timedelta(days=10)),
        Subdomain(domain_id=d.id, name="active-old.example.com", exposure="external", status="active",
                  first_seen=now - timedelta(days=200), last_seen=now - timedelta(days=95)),
    ])
    db.commit()
    counts, _ = purge_expired(db, 365, domain_days=90)
    db.commit()
    assert counts["domain_scans"] == 1 and counts["subdomain_observations"] == 1 and counts["subdomains"] == 1
    ids = set(db.scalars(select(DomainScan.id)))
    assert ids == {recent.id, running_old.id}
    assert {s.name for s in db.scalars(select(Subdomain))} == {"gone-new.example.com", "active-old.example.com"}


# --- separate queue / concurrency --------------------------------------------------------------------------
def test_domain_queue_concurrency_and_network_scan_priority(db):
    mgr = DomainScanManager()
    doms = [make_domain(db, name=n) for n in ("example.com", "example.org", "example.net")]
    jobs = [enqueue_domain_scan(db, d) for d in doms]
    db.commit()
    assert mgr.next_job() == jobs[0].id
    # One slot (default concurrency 1) busy -> nothing else starts
    mgr._running[jobs[0].id] = (ScanContext(jobs[0].id), None)  # type: ignore[assignment]
    assert mgr.next_job() is None
    with session_scope() as s:
        cfg = get_section(s, DomainDiscoverySettings)
        cfg.concurrency = 2
        put_section(s, cfg)
    assert mgr.next_job() == jobs[1].id
    # A queued network scan has priority: no new domain job starts
    db.add(Scan(scan_type="discovery", status=SCAN_QUEUED, targets="192.0.2.1", target_count=1))
    db.commit()
    assert mgr.next_job() is None
    # The domain queue never creates network-scan rows of its own
    assert db.scalar(select(Scan.id).where(Scan.requested_by.like("domain%"))) is None


def test_restart_recovery_marks_running_domain_scans_failed(db):
    d = make_domain(db)
    job = enqueue_domain_scan(db, d)
    job.status = "running"
    db.commit()
    DomainScanManager.recover_interrupted()
    db.expire_all()
    assert db.get(DomainScan, job.id).status == "failed"


def test_cancel_queued_domain_scan(db):
    d = make_domain(db)
    job = enqueue_domain_scan(db, d)
    db.commit()
    assert DomainScanManager().cancel(job.id) is True
    db.expire_all()
    assert db.get(DomainScan, job.id).status == "cancelled"


# --- mock scanner mode (dev default, e2e) ------------------------------------------------------------------
def test_mock_mode_simulates_without_tools_or_dns(db, monkeypatch):
    def no_network(*a, **kw):
        raise AssertionError("mock mode must not run tools or send DNS queries")

    monkeypatch.setattr(tools, "run_jsonl_tool", no_network)
    monkeypatch.setattr("app.core.domains.dnsops.DnsClient.resolve", no_network)
    d = make_domain(db, wordlist_mode="custom", custom_words=["www", "intranet"], axfr_enabled=True)
    with session_scope() as s:
        first = enqueue_domain_scan(s, s.get(Domain, d.id)).id
    domain_runner.run_domain_scan(first, ScanContext(first))  # no dns injected: simulated backend
    job = db.get(DomainScan, first)
    assert job.status == SCAN_COMPLETED and job.notes.startswith("Simulated results")
    subs = _subdomains(db, d.id)
    assert subs["www.example.com"].exposure == "both" and "dev.example.com" in subs
    assert subs["dev.example.com"].flags == ["internal_authorized"]
    with session_scope() as s:
        second = enqueue_domain_scan(s, s.get(Domain, d.id)).id
    domain_runner.run_domain_scan(second, ScanContext(second))
    new = db.scalars(select(Event).where(Event.domain_scan_id == second, Event.event_type == "subdomain_new")).all()
    assert [e.hostname for e in new] == ["new.example.com"]
