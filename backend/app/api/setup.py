"""First-run wizard support."""
from __future__ import annotations

import re

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .. import __version__
from ..auth.deps import client_ip, require_admin, start_session
from ..config import get_settings
from ..core.audit import audit
from ..db import get_db
from ..models import ROLE_ADMIN, User
from ..scanner import scanner_status
from ..security import hash_password
from ..settings_store import get_value, set_value
from .auth import require_json
from .common import user_out

router = APIRouter(prefix="/api/setup", tags=["setup"])
USERNAME_RE = re.compile(r"^[A-Za-z0-9._@-]{2,150}$")
MIN_PASSWORD = 8


class AdminIn(BaseModel):
    username: str = Field(min_length=2, max_length=150)
    password: str = Field(min_length=MIN_PASSWORD, max_length=1024)
    display_name: str | None = Field(None, max_length=200)

    @field_validator("username")
    @classmethod
    def _u(cls, v: str) -> str:
        v = v.strip()
        if not USERNAME_RE.match(v):
            raise ValueError("username may contain letters, digits and . _ @ -")
        return v


@router.get("/status")
def setup_status(db: Session = Depends(get_db)):
    s = get_settings()
    users = db.scalar(select(func.count(User.id))) or 0
    st = scanner_status()
    return {
        "needs_admin": users == 0,
        "setup_completed": bool(get_value(db, "setup_completed", False)),
        "dev_mode": s.is_dev,
        "scanner_mode": st.effective_mode,
        "version": __version__,
    }


@router.post("/admin", dependencies=[Depends(require_json)])
def create_first_admin(body: AdminIn, request: Request, response: Response, db: Session = Depends(get_db)):
    if (db.scalar(select(func.count(User.id))) or 0) > 0:
        raise HTTPException(409, "An administrator already exists")
    user = User(username=body.username, display_name=body.display_name, password_hash=hash_password(body.password),
                role=ROLE_ADMIN, source="local", is_active=True)
    db.add(user)
    db.flush()
    sess = start_session(db, user, request, response)
    audit(db, user.username, "setup.admin_created", user.username, None, client_ip(request))
    db.commit()
    return {"user": user_out(user), "csrf_token": sess.csrf_token}


@router.post("/complete")
def complete_setup(request: Request, user: User = Depends(require_admin), db: Session = Depends(get_db)):
    set_value(db, "setup_completed", True)
    audit(db, user.username, "setup.completed", None, None, client_ip(request))
    db.commit()
    return {"ok": True}
