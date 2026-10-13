"""Local user management. Two roles only: admin and viewer."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from ..auth.deps import client_ip, require_admin
from ..core.audit import audit
from ..db import get_db
from ..models import ROLE_ADMIN, User, UserSession
from ..security import hash_password
from .common import user_out
from .setup import MIN_PASSWORD, USERNAME_RE

router = APIRouter(prefix="/api/users", tags=["users"])


class UserIn(BaseModel):
    username: str = Field(min_length=2, max_length=150)
    password: str = Field(min_length=MIN_PASSWORD, max_length=1024)
    role: str = Field(pattern="^(admin|viewer)$")
    display_name: str | None = Field(None, max_length=200)

    @field_validator("username")
    @classmethod
    def _u(cls, v: str) -> str:
        v = v.strip()
        if not USERNAME_RE.match(v):
            raise ValueError("username may contain letters, digits and . _ @ -")
        return v


class UserPatch(BaseModel):
    role: str | None = Field(None, pattern="^(admin|viewer)$")
    is_active: bool | None = None
    password: str | None = Field(None, min_length=MIN_PASSWORD, max_length=1024)
    display_name: str | None = Field(None, max_length=200)


def _active_local_admins(db: Session, excluding: int | None = None) -> int:
    q = select(func.count(User.id)).where(User.role == ROLE_ADMIN, User.source == "local", User.is_active.is_(True))
    if excluding is not None:
        q = q.where(User.id != excluding)
    return db.scalar(q) or 0


@router.get("")
def list_users(db: Session = Depends(get_db), user: User = Depends(require_admin)):
    return [user_out(u) for u in db.scalars(select(User).order_by(User.username)).all()]


@router.post("", status_code=201)
def create_user(body: UserIn, request: Request, db: Session = Depends(get_db), user: User = Depends(require_admin)):
    if db.scalar(select(User.id).where(func.lower(User.username) == body.username.lower())):
        raise HTTPException(409, "A user with this name already exists")
    u = User(username=body.username, password_hash=hash_password(body.password), role=body.role,
             display_name=body.display_name, source="local", is_active=True)
    db.add(u)
    db.flush()
    audit(db, user.username, "user.create", u.username, {"role": u.role}, client_ip(request))
    db.commit()
    return user_out(u)


@router.patch("/{user_id}")
def update_user(user_id: int, body: UserPatch, request: Request, db: Session = Depends(get_db),
                user: User = Depends(require_admin)):
    u = db.get(User, user_id)
    if u is None:
        raise HTTPException(404, "User not found")
    demote = body.role is not None and body.role != ROLE_ADMIN and u.role == ROLE_ADMIN
    disable = body.is_active is False and u.is_active
    if u.id == user.id and (demote or disable):
        raise HTTPException(409, "You cannot demote or disable your own account")
    if (demote or disable) and u.source == "local" and u.role == ROLE_ADMIN and _active_local_admins(db, u.id) == 0:
        raise HTTPException(409, "At least one active local administrator must remain (fallback access)")
    if body.password is not None and u.source != "local":
        raise HTTPException(409, "Passwords of LDAP users are managed in the directory")
    changes = body.model_dump(exclude_none=True, exclude={"password"})
    for k, v in changes.items():
        setattr(u, k, v)
    if body.password is not None:
        u.password_hash = hash_password(body.password)
        changes["password_changed"] = True
    if body.is_active is False or body.password is not None:
        db.execute(delete(UserSession).where(UserSession.user_id == u.id, UserSession.id != _sid(request, u.id)))
    audit(db, user.username, "user.update", u.username, changes, client_ip(request))
    db.commit()
    return user_out(u)


def _sid(request: Request, user_id: int) -> int:
    sess = getattr(request.state, "session", None)
    return sess.id if sess is not None and sess.user_id == user_id else -1


@router.delete("/{user_id}", status_code=204)
def delete_user(user_id: int, request: Request, db: Session = Depends(get_db), user: User = Depends(require_admin)):
    u = db.get(User, user_id)
    if u is None:
        raise HTTPException(404, "User not found")
    if u.id == user.id:
        raise HTTPException(409, "You cannot delete your own account")
    if u.source == "local" and u.role == ROLE_ADMIN and _active_local_admins(db, u.id) == 0:
        raise HTTPException(409, "At least one active local administrator must remain (fallback access)")
    audit(db, user.username, "user.delete", u.username, None, client_ip(request))
    db.delete(u)
    db.commit()
