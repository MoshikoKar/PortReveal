"""Safe on-disk storage for Web Capture screenshots."""
from __future__ import annotations

import logging
import os
import re
import shutil
from io import BytesIO
from pathlib import Path

from ..config import get_settings

log = logging.getLogger(__name__)

_SAFE_UUID = re.compile(r"^[0-9a-fA-F-]{36}$")
# Grid thumbnails: small WebP next to each full screenshot (<page uuid>.thumb.webp).
THUMB_WIDTH = 400
THUMB_QUALITY = 60
_THUMB_SUFFIX = ".thumb.webp"


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


def _is_link(p: Path) -> bool:
    """Symlink, or Windows junction: either could lead outside the captures dir."""
    isjunction = getattr(os.path, "isjunction", None)  # Python 3.12+
    return p.is_symlink() or bool(isjunction and isjunction(p))


def resolve_screenshot(relpath: str | None) -> Path | None:
    """Resolve a stored relative path under data/web-captures; reject traversal.

    Read-only and cheap, as the gallery checks every listed page: no mkdir and no realpath per file.
    """
    if not relpath:
        return None
    rel = Path(relpath)
    if rel.is_absolute() or ".." in rel.parts:
        return None
    if len(rel.parts) != 2 or not rel.name.endswith(".webp"):
        return None
    if not _SAFE_UUID.fullmatch(rel.parts[0]) or not _SAFE_UUID.fullmatch(rel.stem):
        return None
    # The checks above keep the path lexically inside the captures dir (<uuid>/<uuid>.webp); only a
    # link - the capture dir or the file itself - could still lead elsewhere, so links are refused.
    cap_dir = get_settings().data_path / "web-captures" / rel.parts[0]
    full = cap_dir / rel.name
    if _is_link(cap_dir) or _is_link(full):
        return None
    return full if full.is_file() else None


def write_screenshot(capture_uuid: str, page_uuid: str, data: bytes) -> str:
    """Store a screenshot and its grid thumbnail (best effort: a missing thumbnail is rebuilt on request)."""
    rel = screenshot_relpath(capture_uuid, page_uuid)
    path = captures_root() / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    thumb = make_thumbnail(data)
    if thumb is not None:
        _thumb_path(path).write_bytes(thumb)
    return rel


def _thumb_path(full: Path) -> Path:
    return full.with_name(full.stem + _THUMB_SUFFIX)


def make_thumbnail(data: bytes) -> bytes | None:
    """A ~400px wide WebP of a screenshot, or None when the image cannot be read."""
    try:
        from PIL import Image

        with Image.open(BytesIO(data)) as img:
            img = img.convert("RGB")
            if img.width > THUMB_WIDTH:
                img = img.resize((THUMB_WIDTH, max(1, round(img.height * THUMB_WIDTH / img.width))), Image.LANCZOS)
            out = BytesIO()
            img.save(out, format="WEBP", quality=THUMB_QUALITY, method=4)
            return out.getvalue()
    except Exception as exc:
        log.debug("thumbnail failed: %s", exc)
        return None


def resolve_thumbnail(relpath: str | None, *, build: bool = True) -> Path | None:
    """The grid thumbnail of a stored screenshot. Screenshots saved before thumbnails existed get one
    built (once) from the full image; None when the screenshot itself is gone or unreadable."""
    full = resolve_screenshot(relpath)
    if full is None:
        return None
    thumb = _thumb_path(full)
    if thumb.is_file():
        return thumb
    if not build:
        return None
    data = make_thumbnail(full.read_bytes())
    if data is None:
        return None
    thumb.write_bytes(data)
    return thumb


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
