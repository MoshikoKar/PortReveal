"""Wordlist library (admin only): upload, import from URL, re-import, rename, delete.

Every change is audited. Lists are parsed and sanitized by core.wordlists; files are stored under
server-generated names. URL imports run only from these explicit admin actions, never during scans.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, Response, UploadFile
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from ..auth.deps import client_ip, require_admin
from ..core.audit import audit
from ..core.web_capture.classify import APP_PATHS
from ..core.wordlists import (
    KIND_PATHS,
    KINDS,
    SOURCE_BUILTIN,
    SOURCE_UPLOAD,
    SOURCE_URL,
    Limits,
    ParseResult,
    WordlistError,
    expects_gzip,
    fetch_url,
    ingest,
    iter_file,
    name_from_filename,
    redact_url,
    remove_stored,
    url_filename,
    validate_name,
    validate_url,
)
from ..db import get_db, utcnow
from ..models import WORDLIST_MODE_LIBRARY, Domain, User, Wordlist
from ..settings_store import WebCaptureSettings, get_section, put_section
from .errors import error_body

router = APIRouter(prefix="/api/wordlists", tags=["wordlists"])


class ImportIn(BaseModel):
    url: str = Field(..., max_length=2048)
    kind: str = Field(KIND_PATHS, max_length=20)
    name: str | None = Field(None, max_length=200)


class RenameIn(BaseModel):
    name: str = Field(..., max_length=200)


def _selected_id(db: Session) -> int | None:
    return get_section(db, WebCaptureSettings).discovery_wordlist_id


def _domain_users(db: Session, ids: list[int]) -> dict[int, list[dict]]:
    """Domains whose wordlist brute force uses each list ({wordlist id: [{"id", "name"}]})."""
    if not ids:
        return {}
    out: dict[int, list[dict]] = {}
    for d in db.scalars(select(Domain).where(Domain.wordlist_id.in_(ids), Domain.wordlist_mode == WORDLIST_MODE_LIBRARY)
                        .order_by(Domain.name)):
        out.setdefault(d.wordlist_id, []).append({"id": d.id, "name": d.name})
    return out


def in_use_message(domains: list[dict]) -> str:
    names = ", ".join(d["name"] for d in domains[:5]) + (f" +{len(domains) - 5}" if len(domains) > 5 else "")
    return f"In use by {len(domains)} domain(s): {names}. Choose another wordlist for them first."


def _out(w: Wordlist, selected: int | None, domains: list[dict] | None = None) -> dict:
    return {
        "id": w.id,
        "name": w.name,
        "kind": w.kind,
        "source": w.source,
        "source_url": w.source_url,
        "original_filename": w.original_filename,
        "entries": w.entries,
        "skipped": w.skipped,
        "size_bytes": w.size_bytes,
        "sha256": w.sha256,
        "created_at": w.created_at,
        "updated_at": w.updated_at,
        "created_by": w.created_by,
        "in_use": w.id == selected,
        "domains": domains or [],
    }


def _http(exc: WordlistError) -> HTTPException:
    return HTTPException(exc.status, str(exc))


def _kind(kind: str) -> str:
    k = (kind or "").strip().lower()
    if k not in KINDS:
        raise HTTPException(422, f"type must be one of: {', '.join(KINDS)}")
    return k


def _name_taken(db: Session, name: str, exclude_id: int | None = None) -> bool:
    q = select(Wordlist.id).where(func.lower(Wordlist.name) == name.lower())
    if exclude_id is not None:
        q = q.where(Wordlist.id != exclude_id)
    return db.scalar(q) is not None


def _pick_name(db: Session, requested: str | None, fallback: str) -> str:
    """An explicit name must be free; a derived one gets a " (2)" style suffix instead."""
    if requested and requested.strip():
        name = validate_name(requested)
        if _name_taken(db, name):
            raise HTTPException(409, f"a wordlist named '{name}' already exists")
        return name
    base = validate_name(fallback)
    name, n = base, 2
    while _name_taken(db, name):
        suffix = f" ({n})"
        name, n = base[: 64 - len(suffix)] + suffix, n + 1
    return name


def _get(db: Session, wordlist_id: int) -> Wordlist:
    w = db.get(Wordlist, wordlist_id)
    if w is None:
        raise HTTPException(404, "wordlist not found")
    return w


def _create(db: Session, user: User, *, name: str, kind: str, source: str, storage: str, result: ParseResult,
            source_url: str | None = None, original_filename: str | None = None) -> Wordlist:
    w = Wordlist(
        name=name, kind=kind, source=source, source_url=source_url, original_filename=original_filename,
        storage_name=storage, entries=result.accepted, skipped=result.skipped, size_bytes=result.size_bytes,
        sha256=result.sha256, created_by=user.username,
    )
    db.add(w)
    try:
        db.flush()
    except IntegrityError:
        db.rollback()
        remove_stored(storage)
        raise HTTPException(409, f"a wordlist named '{name}' already exists") from None
    return w


@router.get("")
def list_wordlists(db: Session = Depends(get_db), user: User = Depends(require_admin)):
    selected = _selected_id(db)
    rows = db.scalars(select(Wordlist).order_by(func.lower(Wordlist.name))).all()
    users = _domain_users(db, [w.id for w in rows])
    return {
        "items": [_out(w, selected, users.get(w.id)) for w in rows],
        "builtin": {"name": "Built-in", "kind": KIND_PATHS, "source": SOURCE_BUILTIN,
                    "entries": len(APP_PATHS), "in_use": not selected},
        "limits": Limits.from_settings().as_dict(),
        "subdomain_discovery": True,  # subdomain lists feed Domain scans (wordlist brute force with dnsx)
    }


@router.post("/upload", status_code=201)
def upload_wordlist(
    request: Request,
    file: UploadFile = File(...),
    kind: str = Form(KIND_PATHS),
    name: str | None = Form(None),
    db: Session = Depends(get_db),
    user: User = Depends(require_admin),
):
    kind = _kind(kind)
    filename = (file.filename or "").replace("\\", "/").rsplit("/", 1)[-1][:255]
    try:
        expect_gz = expects_gzip(filename)
        list_name = _pick_name(db, name, name_from_filename(filename))
        file.file.seek(0)
        storage, result = ingest(iter_file(file.file), kind=kind, expect_gz=expect_gz)
    except WordlistError as exc:
        raise _http(exc) from None
    w = _create(db, user, name=list_name, kind=kind, source=SOURCE_UPLOAD, storage=storage, result=result,
                original_filename=filename)
    audit(db, user.username, "wordlist.upload", w.name,
          {"id": w.id, "kind": kind, "file": filename, "sha256": result.sha256, **result.summary()},
          client_ip(request))
    db.commit()
    return {"wordlist": _out(w, _selected_id(db), _domain_users(db, [w.id]).get(w.id)), "summary": result.summary()}


def _fetch_into_store(db: Session, user: User, request: Request, url: str, kind: str, action: str,
                      target: str | None) -> tuple[str, ParseResult]:
    """Download + parse; a refused import (blocked address, bad content) is audited before raising."""
    limits = Limits.from_settings()
    try:
        validate_url(url, limits.allow_http)
        expect_gz = expects_gzip(url_filename(url), require_ext=False)
        return ingest(fetch_url(url, limits), kind=kind, expect_gz=expect_gz, limits=limits)
    except WordlistError as exc:
        db.rollback()
        audit(db, user.username, f"{action}_rejected", target,
              {"url": redact_url(url)[:300], "reason": str(exc)}, client_ip(request))
        db.commit()
        raise _http(exc) from None


@router.post("/import", status_code=201)
def import_wordlist(body: ImportIn, request: Request, db: Session = Depends(get_db),
                    user: User = Depends(require_admin)):
    kind = _kind(body.kind)
    url = body.url.strip()
    try:
        list_name = _pick_name(db, body.name, name_from_filename(url_filename(url)))
    except WordlistError as exc:
        raise _http(exc) from None
    storage, result = _fetch_into_store(db, user, request, url, kind, "wordlist.import", list_name)
    w = _create(db, user, name=list_name, kind=kind, source=SOURCE_URL, storage=storage, result=result,
                source_url=url, original_filename=url_filename(url)[:255] or None)
    audit(db, user.username, "wordlist.import", w.name,
          {"id": w.id, "kind": kind, "url": url, "sha256": result.sha256, **result.summary()}, client_ip(request))
    db.commit()
    return {"wordlist": _out(w, _selected_id(db), _domain_users(db, [w.id]).get(w.id)), "summary": result.summary()}


@router.post("/{wordlist_id}/reimport")
def reimport_wordlist(wordlist_id: int, request: Request, db: Session = Depends(get_db),
                      user: User = Depends(require_admin)):
    w = _get(db, wordlist_id)
    if w.source != SOURCE_URL or not w.source_url:
        raise HTTPException(409, "only wordlists imported from a URL can be re-imported")
    url, name = w.source_url, w.name
    storage, result = _fetch_into_store(db, user, request, url, w.kind, "wordlist.reimport", name)
    w = _get(db, wordlist_id)
    old_storage, previous, old_sha = w.storage_name, w.entries, w.sha256
    w.storage_name, w.entries, w.skipped = storage, result.accepted, result.skipped
    w.size_bytes, w.sha256, w.updated_at = result.size_bytes, result.sha256, utcnow()
    audit(db, user.username, "wordlist.reimport", w.name,
          {"id": w.id, "url": url, "previous_entries": previous, "entries": result.accepted,
           "sha256": result.sha256, "changed": old_sha != result.sha256}, client_ip(request))
    db.commit()
    remove_stored(old_storage)
    return {
        "wordlist": _out(w, _selected_id(db), _domain_users(db, [w.id]).get(w.id)),
        "summary": result.summary(),
        "previous_entries": previous,
        "changed": old_sha != result.sha256,
    }


@router.patch("/{wordlist_id}")
def rename_wordlist(wordlist_id: int, body: RenameIn, request: Request, db: Session = Depends(get_db),
                    user: User = Depends(require_admin)):
    w = _get(db, wordlist_id)
    try:
        name = validate_name(body.name)
    except WordlistError as exc:
        raise _http(exc) from None
    if _name_taken(db, name, exclude_id=w.id):
        raise HTTPException(409, f"a wordlist named '{name}' already exists")
    old = w.name
    w.name, w.updated_at = name, utcnow()
    audit(db, user.username, "wordlist.rename", name, {"id": w.id, "from": old, "to": name}, client_ip(request))
    db.commit()
    return _out(w, _selected_id(db), _domain_users(db, [w.id]).get(w.id))


@router.delete("/{wordlist_id}", status_code=204)
def delete_wordlist(wordlist_id: int, request: Request, force: bool = False, db: Session = Depends(get_db),
                    user: User = Depends(require_admin)):
    """In use by Web capture: refused (409) unless ``force``, which reverts discovery to the built-in list.
    In use by a domain (wordlist brute force): always refused (409, with the domains); never a silent fallback."""
    w = _get(db, wordlist_id)
    domains = _domain_users(db, [w.id]).get(w.id)
    if domains:
        return JSONResponse(status_code=409, content=error_body(409, in_use_message(domains), "wordlist_in_use",
                                                                domains=domains))
    in_use = _selected_id(db) == w.id
    if in_use and not force:
        raise HTTPException(409, "this wordlist is selected for Web capture discovery; "
                                 "select another list first or delete with fallback to the built-in list")
    if in_use:
        cfg = get_section(db, WebCaptureSettings)
        cfg.discovery_wordlist_id = None
        put_section(db, cfg)
    storage = w.storage_name
    audit(db, user.username, "wordlist.delete", w.name,
          {"id": w.id, "kind": w.kind, "sha256": w.sha256, "was_selected": in_use}, client_ip(request))
    db.delete(w)
    db.commit()
    remove_stored(storage)
    return Response(status_code=204)
