from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..auth.deps import client_ip, current_user, require_admin
from ..core.audit import audit
from ..db import get_db
from ..models import Exclusion, User
from ..netutils import AddressSet, TargetError, split_specs
from .common import FULL_REPLACE

router = APIRouter(prefix="/api/exclusions", tags=["exclusions"])


class ExclusionIn(BaseModel):
    value: str = Field(min_length=1, max_length=10000)
    description: str | None = Field(None, max_length=1000)
    enabled: bool = True

    @field_validator("value")
    @classmethod
    def _value(cls, v: str) -> str:
        specs = split_specs(v)
        if not specs:
            raise ValueError("value is empty")
        try:
            AddressSet.from_specs(specs)
        except TargetError as exc:
            raise ValueError(str(exc)) from exc
        return ", ".join(specs)


def exclusion_out(e: Exclusion) -> dict:
    try:
        count = len(AddressSet.from_specs(e.value))
    except TargetError:
        count = 0
    return {
        "id": e.id,
        "value": e.value,
        "description": e.description,
        "enabled": e.enabled,
        "address_count": count,
        "created_at": e.created_at,
        "updated_at": e.updated_at,
    }


@router.get("")
def list_exclusions(db: Session = Depends(get_db), user: User = Depends(current_user)):
    return [exclusion_out(e) for e in db.scalars(select(Exclusion).order_by(Exclusion.id)).all()]


@router.post("", status_code=201)
def create_exclusion(body: ExclusionIn, request: Request, db: Session = Depends(get_db),
                     user: User = Depends(require_admin)):
    e = Exclusion(value=body.value, description=body.description, enabled=body.enabled)
    db.add(e)
    db.flush()
    audit(db, user.username, "exclusion.create", body.value, body.model_dump(), client_ip(request))
    db.commit()
    return exclusion_out(e)


@router.put("/{exclusion_id}", description=FULL_REPLACE)
def update_exclusion(exclusion_id: int, body: ExclusionIn, request: Request, db: Session = Depends(get_db),
                     user: User = Depends(require_admin)):
    e = db.get(Exclusion, exclusion_id)
    if e is None:
        raise HTTPException(404, "Exclusion not found")
    before = {"value": e.value, "enabled": e.enabled, "description": e.description}
    e.value, e.description, e.enabled = body.value, body.description, body.enabled
    audit(db, user.username, "exclusion.update", body.value, {"before": before, "after": body.model_dump()},
          client_ip(request))
    db.commit()
    return exclusion_out(e)


@router.delete("/{exclusion_id}", status_code=204)
def delete_exclusion(exclusion_id: int, request: Request, db: Session = Depends(get_db),
                     user: User = Depends(require_admin)):
    e = db.get(Exclusion, exclusion_id)
    if e is None:
        raise HTTPException(404, "Exclusion not found")
    audit(db, user.username, "exclusion.delete", e.value, None, client_ip(request))
    db.delete(e)
    db.commit()
