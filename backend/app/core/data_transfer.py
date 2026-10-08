"""Portable inventory export/import (ZIP of JSONL tables).

Moves scan inventory + history between environments (SQLite <-> PostgreSQL) without
re-running nmap. Users, sessions, app settings, audit log, and web captures are not
included; existing web-capture rows on the target are cleared on import so device FKs
do not block the wipe.

Both directions stream: export pages each table by id and writes JSONL straight into the
ZIP entry; import validates the package in one streaming pass (nothing kept in memory),
then wipes and re-inserts in fixed-size Core batches. The wipe + insert stays a single
transaction on purpose, so a failed import never leaves a half-replaced inventory.
"""
from __future__ import annotations

import base64
import io
import json
import logging
import zipfile
from collections.abc import Iterable
from datetime import date, datetime, timezone
from pathlib import Path
from typing import BinaryIO

from sqlalchemy import Date, DateTime, LargeBinary, delete, func, insert, select, text
from sqlalchemy.orm import Session

from .. import __version__
from ..config import get_settings
from ..db import UTCDateTime
from ..models import (
    SCAN_ACTIVE_STATES,
    WEB_CAPTURE_ACTIVE_STATES,
    Device,
    DeviceIP,
    DevicePort,
    Event,
    Exclusion,
    Network,
    Scan,
    ScanHost,
    Snapshot,
    WebCapture,
    WebPage,
)
from .web_storage import cleanup_capture_dirs, delete_capture_files

log = logging.getLogger(__name__)

FORMAT_VERSION = 1
MANIFEST_NAME = "manifest.json"
TABLES_DIR = "tables"

# Dependency order for insert; wipe uses the reverse (plus web_* cleared first).
INVENTORY_TABLES: tuple[tuple[str, type], ...] = (
    ("exclusions", Exclusion),
    ("networks", Network),
    ("devices", Device),
    ("device_ips", DeviceIP),
    ("device_ports", DevicePort),
    ("scans", Scan),
    ("scan_hosts", ScanHost),
    ("events", Event),
    ("snapshots", Snapshot),
)

INVENTORY_BY_NAME = {name: model for name, model in INVENTORY_TABLES}

# Rows per export page / import insert batch.
BATCH_ROWS = 2000


class DataTransferError(Exception):
    """User-facing export/import failure."""


def _alembic_revision(db: Session) -> str:
    row = db.execute(text("SELECT version_num FROM alembic_version")).scalar()
    if not row:
        raise DataTransferError("database has no alembic_version; run migrations first")
    return str(row)


def _encode_value(value):
    if value is None:
        return None
    if isinstance(value, datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    if isinstance(value, date):
        return value.isoformat()
    if isinstance(value, bytes):
        return {"__bytes__": base64.b64encode(value).decode("ascii")}
    return value


def _decode_value(value, column):
    if value is None:
        return None
    if isinstance(value, dict) and "__bytes__" in value:
        return base64.b64decode(value["__bytes__"])
    col_type = column.type
    if isinstance(col_type, (UTCDateTime, DateTime)):
        if isinstance(value, str):
            text_val = value.replace("Z", "+00:00")
            dt = datetime.fromisoformat(text_val)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
    if isinstance(col_type, Date):
        if isinstance(value, str):
            return date.fromisoformat(value)
    if isinstance(col_type, LargeBinary) and isinstance(value, str):
        return base64.b64decode(value)
    return value


def _dict_to_kwargs(model, data: dict) -> dict:
    kwargs = {}
    for col in model.__table__.columns:
        if col.name not in data:
            continue
        kwargs[col.name] = _decode_value(data[col.name], col)
    return kwargs


def default_export_path(directory: Path | None = None) -> Path:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d")
    name = f"network-finder-inventory-{stamp}.zip"
    return (directory or Path.cwd()) / name


def _iter_table(db: Session, model) -> Iterable[dict]:
    """Yield a table's rows as JSON-ready dicts, paging by id (no full-table materialization)."""
    table = model.__table__
    last_id = None
    while True:
        stmt = select(table).order_by(table.c.id).limit(BATCH_ROWS)
        if last_id is not None:
            stmt = stmt.where(table.c.id > last_id)
        batch = db.execute(stmt).mappings().all()
        if not batch:
            return
        for row in batch:
            yield {col.name: _encode_value(row[col.name]) for col in table.columns}
        last_id = batch[-1]["id"]


def export_inventory(db: Session, dest: Path | BinaryIO | None = None) -> Path | None:
    """Write inventory ZIP to dest. Returns Path when dest is a path (or None and BytesIO used)."""
    revision = _alembic_revision(db)

    path_out: Path | None = None
    if dest is None:
        path_out = default_export_path()
        dest = path_out
    if isinstance(dest, Path):
        path_out = dest
        dest.parent.mkdir(parents=True, exist_ok=True)
        buffer: BinaryIO = open(dest, "wb")
        close_buffer = True
    else:
        buffer = dest
        close_buffer = False

    counts: dict[str, int] = {}
    try:
        with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            for name, model in INVENTORY_TABLES:
                n = 0
                # force_zip64: the entry size is unknown up front and may exceed 2 GiB.
                with zf.open(f"{TABLES_DIR}/{name}.jsonl", "w", force_zip64=True) as entry:
                    for row in _iter_table(db, model):
                        entry.write(json.dumps(row, separators=(",", ":")).encode("utf-8") + b"\n")
                        n += 1
                counts[name] = n
            # Written last so the counts are exactly what was streamed; readers look entries up by name.
            manifest = {
                "format_version": FORMAT_VERSION,
                "app_version": __version__,
                "schema_revision": revision,
                "exported_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                "tables": counts,
            }
            zf.writestr(MANIFEST_NAME, json.dumps(manifest, indent=2) + "\n")
    finally:
        if close_buffer:
            buffer.close()

    log.info("exported inventory tables=%s path=%s", counts, path_out)
    return path_out


def _read_zip(src: Path | BinaryIO) -> zipfile.ZipFile:
    if isinstance(src, Path):
        if not src.is_file():
            raise DataTransferError(f"file not found: {src}")
        return zipfile.ZipFile(src, "r")
    if isinstance(src, (bytes, bytearray)):
        return zipfile.ZipFile(io.BytesIO(src), "r")
    seekable = getattr(src, "seekable", None)  # SpooledTemporaryFile has it only from Python 3.11
    if seekable is not None and seekable():
        return zipfile.ZipFile(src, "r")  # e.g. an upload's spooled temp file: read in place, no copy
    return zipfile.ZipFile(io.BytesIO(src.read()), "r")


def _load_manifest(zf: zipfile.ZipFile) -> dict:
    try:
        raw = zf.read(MANIFEST_NAME)
    except KeyError as exc:
        raise DataTransferError("invalid package: missing manifest.json") from exc
    try:
        manifest = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise DataTransferError("invalid package: manifest.json is not valid JSON") from exc
    if manifest.get("format_version") != FORMAT_VERSION:
        raise DataTransferError(
            f"unsupported format_version {manifest.get('format_version')!r}; expected {FORMAT_VERSION}"
        )
    return manifest


def _iter_table_rows(zf: zipfile.ZipFile, name: str) -> Iterable[dict]:
    """Yield the decoded rows of one table entry, streaming line by line."""
    path = f"{TABLES_DIR}/{name}.jsonl"
    try:
        entry = zf.open(path)
    except KeyError as exc:
        raise DataTransferError(f"invalid package: missing {path}") from exc
    with entry:
        for i, raw_line in enumerate(entry, start=1):
            line = raw_line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise DataTransferError(f"invalid JSON in {path} line {i}") from exc
            if not isinstance(row, dict):
                raise DataTransferError(f"invalid row in {path} line {i}: expected a JSON object")
            yield row


def _check_limits(zf: zipfile.ZipFile, manifest: dict) -> None:
    """Refuse packages over the configured size/row limits before anything is parsed or wiped."""
    cfg = get_settings()
    max_bytes = cfg.import_max_uncompressed_mb * 1024 * 1024
    total = sum(info.file_size for info in zf.infolist())
    if total > max_bytes:
        raise DataTransferError(
            f"package too large: {total / 1024 / 1024:.0f} MB uncompressed exceeds the "
            f"{cfg.import_max_uncompressed_mb} MB limit (IMPORT_MAX_UNCOMPRESSED_MB)"
        )
    declared = manifest.get("tables")
    rows = sum(v for v in declared.values() if isinstance(v, int)) if isinstance(declared, dict) else 0
    if rows > cfg.import_max_rows:
        raise DataTransferError(
            f"package too large: {rows} rows exceeds the {cfg.import_max_rows} row limit (IMPORT_MAX_ROWS)"
        )


def _validate_tables(zf: zipfile.ZipFile) -> None:
    """Parse every table once without keeping rows, so bad JSON is caught before the wipe."""
    max_rows = get_settings().import_max_rows
    total = 0
    for name, _model in INVENTORY_TABLES:
        for _row in _iter_table_rows(zf, name):
            total += 1
            if total > max_rows:  # the manifest's counts are a claim; enforce the real ones too
                raise DataTransferError(f"package too large: more than {max_rows} rows (IMPORT_MAX_ROWS)")


def _insert_batch(db: Session, model, batch: list[dict]) -> None:
    # executemany needs one key set per statement; exported rows all share one, so this is one group.
    groups: dict[frozenset, list[dict]] = {}
    for kwargs in batch:
        groups.setdefault(frozenset(kwargs), []).append(kwargs)
    for rows in groups.values():
        db.execute(insert(model.__table__), rows)


def _assert_idle(db: Session) -> None:
    active_scans = db.scalar(
        select(func.count()).select_from(Scan).where(Scan.status.in_(SCAN_ACTIVE_STATES))
    ) or 0
    if active_scans:
        raise DataTransferError(f"cannot import while {active_scans} scan(s) are queued or running")
    active_caps = db.scalar(
        select(func.count()).select_from(WebCapture).where(WebCapture.status.in_(WEB_CAPTURE_ACTIVE_STATES))
    ) or 0
    if active_caps:
        raise DataTransferError(f"cannot import while {active_caps} web-capture job(s) are queued or running")


def _wipe_inventory(db: Session) -> dict[str, int]:
    """Delete inventory (and web-capture rows that reference devices/ports)."""
    deleted: dict[str, int] = {}
    capture_uuids = list(db.scalars(select(WebCapture.uuid)).all())
    for label, stmt in (
        ("web_pages", delete(WebPage)),
        ("web_captures", delete(WebCapture)),
        ("events", delete(Event)),
        ("scan_hosts", delete(ScanHost)),
        ("snapshots", delete(Snapshot)),
        ("device_ports", delete(DevicePort)),
        ("device_ips", delete(DeviceIP)),
        ("devices", delete(Device)),
        ("scans", delete(Scan)),
        ("networks", delete(Network)),
        ("exclusions", delete(Exclusion)),
    ):
        result = db.execute(stmt)
        deleted[label] = int(result.rowcount or 0)
    db.flush()
    for uuid in capture_uuids:
        delete_capture_files(uuid)
    cleanup_capture_dirs(set())
    return deleted


def _reset_sequences(db: Session, table_names: Iterable[str]) -> None:
    bind = db.get_bind()
    if bind.dialect.name != "postgresql":
        return
    allowed = {name for name, _ in INVENTORY_TABLES}
    for name in table_names:
        if name not in allowed:
            continue
        # Table names are from the fixed allow-list above, not user input.
        db.execute(text(
            f"SELECT setval(pg_get_serial_sequence('{name}', 'id'), "
            f"COALESCE((SELECT MAX(id) FROM {name}), 1), true)"
        ))


def import_inventory(db: Session, src: Path | BinaryIO, *, confirm: bool) -> dict:
    """Replace local inventory with the package. Requires confirm=True."""
    if not confirm:
        raise DataTransferError("import refuses to run without confirm=True / --yes")

    _assert_idle(db)
    local_revision = _alembic_revision(db)

    with _read_zip(src) as zf:
        names = set(zf.namelist())
        if MANIFEST_NAME not in names:
            raise DataTransferError("invalid package: missing manifest.json")
        manifest = _load_manifest(zf)
        package_revision = manifest.get("schema_revision")
        if package_revision != local_revision:
            raise DataTransferError(
                f"schema mismatch: package is {package_revision!r}, database is {local_revision!r}"
            )

        _check_limits(zf, manifest)
        _validate_tables(zf)

        wiped = _wipe_inventory(db)
        # Drop identity-map entries so re-inserting the same primary keys is safe.
        db.expunge_all()
        imported: dict[str, int] = {}
        for name, model in INVENTORY_TABLES:
            n = 0
            batch: list[dict] = []
            for data in _iter_table_rows(zf, name):
                batch.append(_dict_to_kwargs(model, data))
                if len(batch) >= BATCH_ROWS:
                    _insert_batch(db, model, batch)
                    n += len(batch)
                    batch = []
            if batch:
                _insert_batch(db, model, batch)
                n += len(batch)
            imported[name] = n
        _reset_sequences(db, [name for name, _ in INVENTORY_TABLES])
        db.flush()

    result = {
        "schema_revision": local_revision,
        "wiped": wiped,
        "imported": imported,
        "exported_at": manifest.get("exported_at"),
        "app_version": manifest.get("app_version"),
    }
    log.info("imported inventory wiped=%s imported=%s", wiped, imported)
    return result
