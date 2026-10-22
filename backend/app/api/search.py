"""Inventory search: Shodan-style `field:value` queries over stored nmap and Web Capture data."""
from __future__ import annotations

import csv
import io
import json
from collections.abc import Iterator
from datetime import date, datetime

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from ..auth.deps import current_user
from ..core.query.fields import field_docs
from ..core.query.history import search_history
from ..core.query.search import (
    HOST_SORTS,
    count,
    extract_before,
    facets,
    iter_hosts,
    matching_uuids,
    parse_facets,
    prepare,
    search_hosts,
    search_services,
)
from ..core.vuln.filters import csv_safe_cell
from ..db import SessionLocal, get_db
from ..models import User
from .common import Paging, paging_with
from .devices import MAX_UUIDS

router = APIRouter(prefix="/api/search", tags=["search"])

MAX_QUERY_LEN = 1000
# Search pages are costlier than plain lists (scoring, nested services), so the ceiling is 100, not 500.
SEARCH_PAGE_SIZE = 25
MAX_PAGE_SIZE = 100
SearchPaging = paging_with(SEARCH_PAGE_SIZE, MAX_PAGE_SIZE)
EXPORT_FORMATS = ("csv", "ndjson")
CSV_COLUMNS = ("ip", "hostname", "mac", "vendor", "os", "status", "network", "type", "score", "tags",
               "first_seen", "last_seen", "services")
_ASC_BY_DEFAULT = {"ip", "hostname"}

QueryParam = Query("", max_length=MAX_QUERY_LEN)


@router.get("")
def search(
    q: str = QueryParam,
    view: str = Query("hosts", pattern="^(hosts|services)$"),
    sort: str = Query("score", pattern="^(" + "|".join(HOST_SORTS) + ")$"),
    order: str | None = Query(None, pattern="^(asc|desc)$"),
    at: date | None = None,
    paging: Paging = Depends(SearchPaging),
    db: Session = Depends(get_db),
    user: User = Depends(current_user),
):
    page, page_size = paging.page, paging.page_size
    node = prepare(q)
    node, before = extract_before(node)
    hist_at = at or before
    if hist_at is not None:
        out = search_history(db, node, hist_at, page=page, page_size=page_size)
        out.update({"page": page, "page_size": page_size, "at": str(hist_at)})
        return out
    if view == "services":
        res = search_services(db, node, page=page, page_size=page_size)
    else:
        desc = (order or ("asc" if sort in _ASC_BY_DEFAULT else "desc")) == "desc"
        res = search_hosts(db, node, page=page, page_size=page_size, sort=sort, desc=desc)
    return {"items": res.items, "total": res.total, "page": page, "page_size": page_size}


@router.get("/facets")
def search_facets(
    q: str = QueryParam,
    facets_spec: str | None = Query(None, alias="facets", max_length=500),
    db: Session = Depends(get_db),
    user: User = Depends(current_user),
):
    wanted = parse_facets(facets_spec)
    return facets(db, prepare(q), wanted)


@router.get("/count")
def search_count(q: str = QueryParam, db: Session = Depends(get_db), user: User = Depends(current_user)):
    return count(db, prepare(q))


@router.get("/fields")
def search_fields(user: User = Depends(current_user)):
    return field_docs()


@router.get("/uuids")
def search_uuids(q: str = QueryParam, db: Session = Depends(get_db), user: User = Depends(current_user)):
    """Device UUIDs matching the query (bulk scan / web capture selection)."""
    node = prepare(q)
    uuids = matching_uuids(db, node, MAX_UUIDS + 1)
    if len(uuids) > MAX_UUIDS:
        total = count(db, node)["hosts"]
        raise HTTPException(422, f"Too many matching devices ({total}); maximum selectable is {MAX_UUIDS}")
    return {"uuids": uuids, "total": len(uuids)}


def _json_default(value):
    if isinstance(value, datetime | date):
        return value.isoformat()
    raise TypeError(f"not serializable: {type(value).__name__}")


def _service_label(s: dict) -> str:
    parts = [f"{s['port']}/{s['protocol']}"]
    name = " ".join(x for x in (s.get("product"), s.get("version")) if x) or s.get("service")
    if name:
        parts.append(name)
    return " ".join(parts)


def _csv_row(h: dict) -> list:
    cells = [
        h["ip"], h["hostname"] or "", h["mac"] or "", h["vendor"] or "", h["os"] or "", h["status"],
        h["network"] or "", h["type"] or "", h["score"], " ".join(h["tags"]),
        h["first_seen"].isoformat() if h["first_seen"] else "",
        h["last_seen"].isoformat() if h["last_seen"] else "",
        "; ".join(_service_label(s) for s in h["services"]),
    ]
    return [csv_safe_cell(c) for c in cells]


def _export_lines(q: str, fmt: str) -> Iterator[str]:
    db = SessionLocal()
    try:
        node = prepare(q)
        if fmt == "ndjson":
            for h in iter_hosts(db, node):
                yield json.dumps(h, default=_json_default) + "\n"
            return
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(CSV_COLUMNS)
        for h in iter_hosts(db, node):
            writer.writerow(_csv_row(h))
            if buf.tell() > 64_000:
                yield buf.getvalue()
                buf.seek(0)
                buf.truncate()
        yield buf.getvalue()
    finally:
        db.close()


@router.get("/export")
def search_export(
    q: str = QueryParam,
    format: str = Query("csv", pattern="^(" + "|".join(EXPORT_FORMATS) + ")$"),
    user: User = Depends(current_user),
):
    prepare(q)  # reject a bad query with 400 before the stream starts
    stamp = datetime.now().strftime("%Y%m%d-%H%M")
    media = "text/csv" if format == "csv" else "application/x-ndjson"
    return StreamingResponse(
        _export_lines(q, format),
        media_type=f"{media}; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="portreveal-search-{stamp}.{format}"'},
    )
