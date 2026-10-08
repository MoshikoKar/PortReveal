"""Safe on-disk storage for Web Capture screenshots."""
from __future__ import annotations

import logging
import re
import shutil
from pathlib import Path

from ..config import get_settings

log = logging.getLogger(__name__)

_SAFE_UUID = re.compile(r"^[0-9a-fA-F-]{36}$")


def captures_root() -> Path:
    root = get_settings().data_path / "web-captures"
    root.mkdir(parents=True, exist_ok=True)
    return root


def capture_dir(capture_uuid: str) -> Path:
    if not _SAFE_UUID.fullmatch(capture_uuid):
        raise ValueError("invalid capture uuid")
    path = captures_root() / capture_uuid
    path.mkdir(parents=True, exist_ok=True)
    return path


def screenshot_relpath(capture_uuid: str, page_uuid: str) -> str:
    if not _SAFE_UUID.fullmatch(capture_uuid) or not _SAFE_UUID.fullmatch(page_uuid):
        raise ValueError("invalid uuid")
    return f"{capture_uuid}/{page_uuid}.webp"


def resolve_screenshot(relpath: str | None) -> Path | None:
    """Resolve a stored relative path under data/web-captures; reject traversal."""
    if not relpath:
        return None
    rel = Path(relpath)
    if rel.is_absolute() or ".." in rel.parts:
        return None
    if len(rel.parts) != 2 or not rel.name.endswith(".webp"):
        return None
    if not _SAFE_UUID.fullmatch(rel.parts[0]) or not _SAFE_UUID.fullmatch(rel.stem):
        return None
    full = (captures_root() / rel).resolve()
    try:
        full.relative_to(captures_root().resolve())
    except ValueError:
        return None
    return full if full.is_file() else None


def write_screenshot(capture_uuid: str, page_uuid: str, data: bytes) -> str:
    rel = screenshot_relpath(capture_uuid, page_uuid)
    path = captures_root() / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return rel


def delete_capture_files(capture_uuid: str) -> None:
    if not _SAFE_UUID.fullmatch(capture_uuid):
        return
    path = captures_root() / capture_uuid
    if path.is_dir():
        shutil.rmtree(path, ignore_errors=True)


def cleanup_capture_dirs(keep_uuids: set[str]) -> int:
    """Remove capture directories whose uuid is not in keep_uuids (orphans)."""
    root = captures_root()
    if not root.is_dir():
        return 0
    removed = 0
    for d in root.iterdir():
        if not d.is_dir():
            continue
        if d.name not in keep_uuids:
            shutil.rmtree(d, ignore_errors=True)
            removed += 1
    return removed
