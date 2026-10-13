"""Saved searches: watches (alert on new matches) and policies (every new match is a violation)."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from ..auth.deps import client_ip, current_user
from ..core.audit import audit
from ..core.query.search import prepare
from ..core.watches import evaluate
from ..db import get_db
from ..models import ROLE_ADMIN, SEARCH_KIND_POLICY, SEARCH_KIND_WATCH, SavedSearch, SavedSearchHit, User
from .common import FULL_REPLACE

router = APIRouter(prefix="/api/saved-searches", tags=["saved-searches"])

KINDS = (SEARCH_KIND_WATCH, SEARCH_KIND_POLICY)


class SavedSearchIn(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    query: str = Field(min_length=1, max_length=1000)
    description: str | None = Field(None, max_length=1000)
    kind: str = SEARCH_KIND_WATCH
    alert: bool = True

    @field_validator("name", "query")
    @classmethod
    def _strip(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("must not be blank")
        return v

    @field_validator("kind")
    @classmethod
    def _kind(cls, v: str) -> str:
        if v not in KINDS:
            raise ValueError(f"kind must be one of: {', '.join(KINDS)}")
        return v


def _can_edit(s: SavedSearch, user: User) -> bool:
    return user.role == ROLE_ADMIN or (s.created_by or "").lower() == user.username.lower()


def _out(s: SavedSearch, user: User) -> dict:
    return {
        "id": s.id, "name": s.name, "query": s.query, "description": s.description, "kind": s.kind,
        "alert": s.alert, "created_by": s.created_by, "created_at": s.created_at, "updated_at": s.updated_at,
        "last_run_at": s.last_run_at, "last_count": s.last_count, "last_error": s.last_error,
        "initialized": s.initialized, "can_edit": _can_edit(s, user),
    }


def _get(db: Session, search_id: int, user: User, *, edit: bool = False) -> SavedSearch:
    s = db.get(SavedSearch, search_id)
    if s is None:
        raise HTTPException(404, "Saved search not found")
    if edit and not _can_edit(s, user):
        raise HTTPException(403, "Only the owner or an administrator can change this saved search")
    return s


@router.get("")
def list_saved_searches(db: Session = Depends(get_db), user: User = Depends(current_user)):
    return [_out(s, user) for s in db.scalars(select(SavedSearch).order_by(SavedSearch.name)).all()]


@router.post("", status_code=201)
def create_saved_search(body: SavedSearchIn, request: Request, db: Session = Depends(get_db),
                        user: User = Depends(current_user)):
    prepare(body.query)
    s = SavedSearch(**body.model_dump(), created_by=user.username)
    db.add(s)
    db.flush()
    evaluate(db, s)  # baseline: current matches are recorded without alerts
    audit(db, user.username, "saved_search.create", s.name, body.model_dump(), client_ip(request))
    db.commit()
    return _out(s, user)


@router.put("/{search_id}", description=FULL_REPLACE)
def update_saved_search(search_id: int, body: SavedSearchIn, request: Request, db: Session = Depends(get_db),
                        user: User = Depends(current_user)):
    s = _get(db, search_id, user, edit=True)
    prepare(body.query)
    rebaseline = s.query != body.query
    for k, v in body.model_dump().items():
        setattr(s, k, v)
    if rebaseline:
        db.execute(delete(SavedSearchHit).where(SavedSearchHit.search_id == s.id))
        s.initialized = False
        db.flush()
        evaluate(db, s)
    audit(db, user.username, "saved_search.update", s.name, body.model_dump(), client_ip(request))
    db.commit()
    return _out(s, user)


@router.delete("/{search_id}", status_code=204)
def delete_saved_search(search_id: int, request: Request, db: Session = Depends(get_db),
                        user: User = Depends(current_user)):
    s = _get(db, search_id, user, edit=True)
    audit(db, user.username, "saved_search.delete", s.name, {"query": s.query}, client_ip(request))
    db.delete(s)
    db.commit()
