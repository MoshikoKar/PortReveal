from __future__ import annotations

import asyncio
import json
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import StreamingResponse
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from ..auth.deps import current_user
from ..core.mockdata import event_visible
from ..db import SessionLocal, get_db
from ..models import EVENT_TYPES, Device, Event, User
from .common import Paging, event_out, like_pattern, paged

router = APIRouter(prefix="/api/events", tags=["events"])


@router.get("")
def list_events(
    type: str | None = Query(None, description="comma separated event types"),
    severity: str | None = Query(None, pattern="^(high|medium|low|info)$"),
    q: str | None = Query(None, max_length=200),
    since: datetime | None = None,
    until: datetime | None = None,
    scan_id: int | None = None,
    paging: Paging = Depends(),
    db: Session = Depends(get_db),
    user: User = Depends(current_user),
):
    conds = [event_visible(db)]
    if type:
        types = [t for t in type.split(",") if t]
        bad = [t for t in types if t not in EVENT_TYPES]
        if bad:
            raise HTTPException(422, f"unknown event type(s): {', '.join(bad)}")
        conds.append(Event.event_type.in_(types))
    if severity:
        conds.append(Event.severity == severity)
    if since:
        conds.append(Event.created_at >= since)
    if until:
        conds.append(Event.created_at <= until)
    if scan_id is not None:
        conds.append(Event.scan_id == scan_id)
    if q:
        like = like_pattern(q.strip())
        conds.append(or_(
            Event.message.ilike(like, escape="\\"),
            Event.ip.like(like, escape="\\"),
            Event.device_id.in_(select(Device.id).where(or_(Device.hostname.ilike(like, escape="\\"),
                                                            Device.mac.ilike(like, escape="\\")))),
        ))
    total = db.scalar(select(func.count(Event.id)).where(*conds)) or 0
    rows = db.scalars(
        select(Event).where(*conds).order_by(Event.id.desc()).offset(paging.offset).limit(paging.page_size)
    ).unique().all()
    return paged([event_out(e) for e in rows], total, paging)


@router.get("/stream")
async def event_stream(request: Request, user: User = Depends(current_user)):
    """Server-Sent Events feed of new inventory events (SIEM-friendly push)."""

    async def gen():
        last_id = 0
        with SessionLocal() as db:
            last_id = db.scalar(select(func.max(Event.id))) or 0
        yield f"event: ready\ndata: {json.dumps({'last_id': last_id})}\n\n"
        while True:
            if await request.is_disconnected():
                break
            with SessionLocal() as db:
                rows = db.scalars(
                    select(Event).where(Event.id > last_id, event_visible(db))
                    .order_by(Event.id).limit(50)
                ).unique().all()
                for e in rows:
                    last_id = e.id
                    yield f"event: {e.event_type}\ndata: {json.dumps(event_out(e), default=str)}\n\n"
            await asyncio.sleep(2.0)

    return StreamingResponse(gen(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})
