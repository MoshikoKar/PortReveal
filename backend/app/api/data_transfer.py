"""Admin inventory export/import endpoints."""
from __future__ import annotations

import tempfile
from collections.abc import Iterator
from datetime import datetime, timezone
from typing import BinaryIO

from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from ..auth.deps import client_ip, require_admin
from ..config import get_settings
from ..core.audit import audit
from ..core.data_transfer import DataTransferError, export_inventory, import_inventory
from ..db import get_db
from ..models import User

router = APIRouter(prefix="/api/data", tags=["data"])

# The export ZIP is built here first: in memory while small, then on disk (never the whole table set as rows).
EXPORT_SPOOL_BYTES = 16 * 1024 * 1024
CHUNK_BYTES = 64 * 1024


def _stream_and_close(f: BinaryIO) -> Iterator[bytes]:
    try:
        while chunk := f.read(CHUNK_BYTES):
            yield chunk
    finally:
        f.close()


def _upload_size(f: BinaryIO) -> int:
    pos = f.tell()
    f.seek(0, 2)
    size = f.tell()
    f.seek(pos)
    return size


@router.get("/export")
def export_data(request: Request, db: Session = Depends(get_db), user: User = Depends(require_admin)):
    buf = tempfile.SpooledTemporaryFile(max_size=EXPORT_SPOOL_BYTES)
    try:
        export_inventory(db, buf)
    except DataTransferError as exc:
        buf.close()
        raise HTTPException(400, str(exc)) from exc
    except Exception:
        buf.close()
        raise
    buf.seek(0)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d")
    filename = f"portreveal-inventory-{stamp}.zip"
    audit(db, user.username, "data.export", filename, None, client_ip(request))
    db.commit()
    return StreamingResponse(
        _stream_and_close(buf),
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.post("/import")
def import_data(
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
    # The upload is already spooled to a temp file by the server; read it in place instead of into memory.
    size = _upload_size(file.file)
    if not size:
        raise HTTPException(400, "empty upload")
    max_mb = get_settings().import_max_upload_mb
    if size > max_mb * 1024 * 1024:
        raise HTTPException(413, f"package too large: {size / 1024 / 1024:.0f} MB exceeds the {max_mb} MB "
                                 "upload limit (IMPORT_MAX_UPLOAD_MB)")
    file.file.seek(0)
    try:
        result = import_inventory(db, file.file, confirm=True)  # commits, then removes old capture files
    except DataTransferError as exc:
        raise HTTPException(400, str(exc)) from exc
    audit(db, user.username, "data.import", name, {"imported": result.get("imported")}, client_ip(request))
    db.commit()
    return result
