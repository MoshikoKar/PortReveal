"""Admin inventory export/import endpoints."""
from __future__ import annotations

import io
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from ..auth.deps import client_ip, require_admin
from ..core.audit import audit
from ..core.data_transfer import DataTransferError, export_inventory, import_inventory
from ..db import get_db
from ..models import User

router = APIRouter(prefix="/api/data", tags=["data"])


@router.get("/export")
def export_data(request: Request, db: Session = Depends(get_db), user: User = Depends(require_admin)):
    buf = io.BytesIO()
    try:
        export_inventory(db, buf)
    except DataTransferError as exc:
        raise HTTPException(400, str(exc)) from exc
    buf.seek(0)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d")
    filename = f"network-finder-inventory-{stamp}.zip"
    audit(db, user.username, "data.export", filename, None, client_ip(request))
    db.commit()
    return StreamingResponse(
        buf,
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.post("/import")
async def import_data(
    request: Request,
    confirm: bool = Form(False),
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    user: User = Depends(require_admin),
):
    if not confirm:
        raise HTTPException(400, "confirm must be true to replace inventory")
    name = file.filename or "upload.zip"
    if not name.lower().endswith(".zip"):
        raise HTTPException(400, "file must be a .zip inventory package")
    raw = await file.read()
    if not raw:
        raise HTTPException(400, "empty upload")
    try:
        result = import_inventory(db, io.BytesIO(raw), confirm=True)
    except DataTransferError as exc:
        raise HTTPException(400, str(exc)) from exc
    audit(db, user.username, "data.import", name, {"imported": result.get("imported")}, client_ip(request))
    db.commit()
    return result
