"""Personal read-only API tokens. The secret is shown once at creation; only its hash is stored."""
from __future__ import annotations

from datetime import timedelta

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..auth.deps import API_TOKEN_PREFIX, client_ip, session_user
from ..core.audit import audit
from ..db import get_db, utcnow
from ..models import ApiToken, User
from ..security import hash_token, new_token
from .common import UNPAGED_LIST, Row

router = APIRouter(prefix="/api/tokens", tags=["tokens"])

MAX_TOKENS_PER_USER = 20
MAX_EXPIRY_DAYS = 3650
PREFIX_LEN = 12


class TokenIn(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    expires_days: int | None = Field(None, ge=1, le=MAX_EXPIRY_DAYS)

    @field_validator("name")
    @classmethod
    def _name(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("must not be blank")
        return v


def _out(t: ApiToken) -> dict:
    return {"id": t.id, "name": t.name, "prefix": t.prefix, "created_at": t.created_at,
            "last_used_at": t.last_used_at, "expires_at": t.expires_at, "revoked": t.revoked}


@router.get("", response_model=list[Row], description=UNPAGED_LIST)
def list_tokens(db: Session = Depends(get_db), user: User = Depends(session_user)):
    rows = db.scalars(select(ApiToken).where(ApiToken.user_id == user.id).order_by(ApiToken.id.desc())).all()
    return [_out(t) for t in rows]


@router.post("", status_code=201)
def create_token(body: TokenIn, request: Request, db: Session = Depends(get_db), user: User = Depends(session_user)):
    active = db.scalars(select(ApiToken.id).where(ApiToken.user_id == user.id, ApiToken.revoked.is_(False))).all()
    if len(active) >= MAX_TOKENS_PER_USER:
        raise HTTPException(409, f"At most {MAX_TOKENS_PER_USER} active tokens per user; revoke one first")
    secret = API_TOKEN_PREFIX + new_token()
    t = ApiToken(user_id=user.id, name=body.name, prefix=secret[:PREFIX_LEN], token_hash=hash_token(secret),
                 expires_at=utcnow() + timedelta(days=body.expires_days) if body.expires_days else None)
    db.add(t)
    db.flush()
    audit(db, user.username, "token.create", body.name, {"id": t.id, "expires_days": body.expires_days},
          client_ip(request))
    db.commit()
    return {**_out(t), "token": secret}


def _revoke(db: Session, token_id: int, user: User, request: Request) -> ApiToken:
    t = db.get(ApiToken, token_id)
    if t is None or t.user_id != user.id:
        raise HTTPException(404, "Token not found")
    t.revoked = True
    audit(db, user.username, "token.revoke", t.name, {"id": t.id}, client_ip(request))
    db.commit()
    return t


@router.delete("/{token_id}", status_code=204)
def revoke_token(token_id: int, request: Request, db: Session = Depends(get_db), user: User = Depends(session_user)):
    """Revoke the token (soft delete).

    The row is kept with ``revoked: true`` so the audit trail and the token list still show it; a revoked
    token can never authenticate again. ``POST /api/tokens/{id}/revoke`` does the same and returns the token.
    """
    _revoke(db, token_id, user, request)


@router.post("/{token_id}/revoke")
def revoke_token_action(token_id: int, request: Request, db: Session = Depends(get_db),
                        user: User = Depends(session_user)):
    """Revoke the token and return its updated record (same effect as ``DELETE /api/tokens/{id}``)."""
    return _out(_revoke(db, token_id, user, request))
