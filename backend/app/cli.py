"""Command line helpers (non-interactive; usable by scripts and AI agents).

    python -m app.cli migrate
    python -m app.cli reset-db                    # SQLite dev DB only
    python -m app.cli create-user NAME PASSWORD [--role admin|viewer]
    python -m app.cli scan --type standard --network "Mock Lab"   # run synchronously
    python -m app.cli scan --type full --targets 10.99.0.10
    python -m app.cli mock-reset
    python -m app.cli retention
    python -m app.cli status
    python -m app.cli search "port:22 -tag:lab"
    python -m app.cli export-data [PATH]
    python -m app.cli import-data PATH --yes
    python -m app.cli vuln-import PATH   # offline NVD JSON snapshot into the local cache
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from sqlalchemy import func, select

from .config import get_settings


def _boot():
    from .db import init_engine
    from .logging_setup import setup_logging
    from .migrate import upgrade

    setup_logging()
    upgrade()
    init_engine()


def cmd_migrate(_args) -> int:
    _boot()
    print("migrations applied")
    return 0


def cmd_reset_db(args) -> int:
    s = get_settings()
    if s.db_type != "sqlite":
        print("reset-db only deletes SQLite development databases. Drop PostgreSQL databases manually.")
        return 1
    path = Path(s.sqlalchemy_url.replace("sqlite:///", "", 1))
    for suffix in ("", "-wal", "-shm"):
        p = Path(str(path) + suffix)
        if p.exists():
            p.unlink()
            print(f"deleted {p}")
    _boot()
    print("fresh development database created (the dev seed runs on next app start)")
    return 0


def cmd_create_user(args) -> int:
    _boot()
    from .db import session_scope
    from .models import User
    from .security import hash_password

    with session_scope() as db:
        if db.scalar(select(User.id).where(func.lower(User.username) == args.username.lower())):
            print("user already exists")
            return 1
        db.add(User(username=args.username, password_hash=hash_password(args.password), role=args.role,
                    source="local"))
    print(f"created {args.role} user {args.username}")
    return 0


def cmd_scan(args) -> int:
    _boot()
    from .core.manager import create_scan
    from .core.runner import run_scan
    from .db import session_scope
    from .models import Network, Scan
    from .netutils import AddressSet

    with session_scope() as db:
        if args.network:
            net = db.scalar(select(Network).where(Network.name == args.network))
            if net is None and args.network.isdigit():
                net = db.get(Network, int(args.network))
            if net is None:
                print(f"network not found: {args.network}")
                return 1
            if net.archived_at is not None:
                print(f"network is archived: {net.name} (restore it in Settings > Networks first)")
                return 1
            scan = create_scan(db, args.type, network=net, requested_by="cli")
        elif args.targets:
            scan = create_scan(db, args.type, targets=AddressSet.from_specs(args.targets, allow_hostname=True),
                               requested_by="cli")
        else:
            print("give --network or --targets")
            return 1
        scan_id = scan.id
    status = run_scan(scan_id)
    with session_scope() as db:
        s = db.get(Scan, scan_id)
        print(json.dumps({"scan_id": s.id, "status": status, "hosts": s.hosts_discovered,
                          "events": s.events_count, "baseline": s.is_baseline, "notes": s.notes,
                          "error": s.error}, indent=2))
    return 0 if status in ("completed", "partial") else 2


def cmd_mock_reset(_args) -> int:
    _boot()
    from .core.runner import mock_step_key
    from .db import session_scope
    from .models import Network
    from .settings_store import set_value

    with session_scope() as db:
        for n in db.scalars(select(Network)).all():
            set_value(db, mock_step_key(n.id), 0)
    print("mock scenario reset to step 0 for all networks")
    return 0


def cmd_retention(_args) -> int:
    _boot()
    from .core.retention import run_retention
    from .db import session_scope
    from .settings_store import RetentionSettings, ScanSettings, get_section

    with session_scope() as db:
        ret = get_section(db, RetentionSettings)
        counts = run_retention(db, ret.days, get_section(db, ScanSettings).raw_retention_days,
                               rtt_days=ret.rtt_sample_days)
    print(json.dumps(counts))
    return 0


def cmd_status(_args) -> int:
    _boot()
    from .db import check_db
    from .scanner import scanner_status

    s = get_settings()
    st = scanner_status(refresh=True)
    ok, msg = check_db()
    print(json.dumps({
        "env": s.app_env, "database": s.db_type, "database_ok": ok, "scanner_mode": st.effective_mode,
        "nmap_detected": st.nmap_detected, "nmap_version": st.nmap_version, "message": st.message,
    }, indent=2))
    return 0


def cmd_search(args) -> int:
    _boot()
    from .core.query import QueryError, prepare
    from .core.query.search import search_hosts
    from .db import session_scope

    try:
        node = prepare(args.query)
    except QueryError as exc:
        where = f" (at {exc.pos})" if exc.pos is not None else ""
        print(f"query error{where}: {exc}", file=sys.stderr)
        return 1
    with session_scope() as db:
        res = search_hosts(db, node, page=1, page_size=args.limit)
        for h in res.items:
            ports = ",".join(str(s["port"]) for s in h["services"])
            print(f"{h['ip']:<16} {h['hostname'] or '-':<32} {ports}")
        print(f"{len(res.items)} of {res.total} hosts", file=sys.stderr)
    return 0


def cmd_export_data(args) -> int:
    _boot()
    from .core.data_transfer import DataTransferError, default_export_path, export_inventory
    from .db import session_scope

    dest = Path(args.path) if args.path else default_export_path()
    try:
        with session_scope() as db:
            path = export_inventory(db, dest)
    except DataTransferError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    print(json.dumps({"path": str(path), "ok": True}, indent=2))
    return 0


def cmd_import_data(args) -> int:
    _boot()
    from .core.data_transfer import DataTransferError, import_inventory
    from .db import session_scope

    if not args.yes:
        print("refusing to import without --yes (replaces networks, devices, scans, events, snapshots)",
              file=sys.stderr)
        return 1
    try:
        with session_scope() as db:
            result = import_inventory(db, Path(args.path), confirm=True)
    except DataTransferError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2))
    return 0


def cmd_vuln_import(args) -> int:
    """Load NVD 2.0 JSON (optionally .gz) from a file or directory into the local cache."""
    _boot()
    from .core.vuln.match import match_all
    from .core.vuln.score import apply_risk_scores
    from .core.vuln.sync import import_nvd_json
    from .core.vuln.watchlist import check_watchlist_safe, schedule_watchlist_delivery
    from .db import session_scope, utcnow
    from .models import Device

    event_ids: list[int] = []
    try:
        with session_scope() as db:
            result = import_nvd_json(db, args.path)
            now = utcnow()
            result["match"] = match_all(db, now=now)
            ids = list(db.scalars(select(Device.id)))
            apply_risk_scores(db, ids, now=now)
            wl = check_watchlist_safe(db, now=now)
            event_ids = list(wl.get("event_ids") or [])
            result["watchlist"] = {k: v for k, v in wl.items() if k != "event_ids"}
    except FileNotFoundError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    except Exception as exc:
        print(f"vuln-import failed: {exc}", file=sys.stderr)
        return 1
    # CLI exits immediately after return — deliver synchronously so webhooks are not lost.
    schedule_watchlist_delivery(event_ids, wait=True)
    print(json.dumps(result, indent=2, default=str))
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="python -m app.cli")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("migrate").set_defaults(fn=cmd_migrate)
    sub.add_parser("reset-db").set_defaults(fn=cmd_reset_db)
    cu = sub.add_parser("create-user")
    cu.add_argument("username")
    cu.add_argument("password")
    cu.add_argument("--role", choices=["admin", "viewer"], default="admin")
    cu.set_defaults(fn=cmd_create_user)
    sc = sub.add_parser("scan")
    sc.add_argument("--type", choices=["discovery", "standard", "full"], default="standard")
    sc.add_argument("--network")
    sc.add_argument("--targets")
    sc.set_defaults(fn=cmd_scan)
    sub.add_parser("mock-reset").set_defaults(fn=cmd_mock_reset)
    sub.add_parser("retention").set_defaults(fn=cmd_retention)
    sub.add_parser("status").set_defaults(fn=cmd_status)
    se = sub.add_parser("search", help='search the inventory, e.g. search "port:22 -tag:lab"')
    se.add_argument("query")
    se.add_argument("--limit", type=int, default=100, help="maximum hosts to print (default 100)")
    se.set_defaults(fn=cmd_search)
    ex = sub.add_parser("export-data", help="export inventory ZIP (networks, devices, scans, history)")
    ex.add_argument("path", nargs="?", help="output zip path (default: portreveal-inventory-YYYYMMDD.zip)")
    ex.set_defaults(fn=cmd_export_data)
    im = sub.add_parser("import-data", help="replace inventory from ZIP (destructive; keeps users/settings)")
    im.add_argument("path", help="input zip path")
    im.add_argument("--yes", action="store_true", help="required confirmation to replace inventory")
    im.set_defaults(fn=cmd_import_data)
    vi = sub.add_parser("vuln-import", help="import NVD JSON snapshot(s) into the local vulnerability cache")
    vi.add_argument("path", help="JSON/.json.gz file or directory of NVD 2.0 feeds")
    vi.set_defaults(fn=cmd_vuln_import)
    args = p.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
