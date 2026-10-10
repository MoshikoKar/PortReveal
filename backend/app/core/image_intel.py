"""Screenshot perceptual hash (and optional OCR) for grouping / search."""
from __future__ import annotations

import logging
from io import BytesIO
from pathlib import Path

log = logging.getLogger(__name__)


def average_hash(data: bytes, *, size: int = 8) -> str | None:
    """Simple aHash (64-bit hex). Soft-fails if Pillow cannot decode."""
    try:
        from PIL import Image
    except ImportError:
        return None
    try:
        img = Image.open(BytesIO(data)).convert("L").resize((size, size), Image.Resampling.LANCZOS)
    except Exception:
        return None
    pixels = list(img.getdata())
    avg = sum(pixels) / len(pixels)
    bits = "".join("1" if p >= avg else "0" for p in pixels)
    return f"{int(bits, 2):016x}"


def ocr_text(data: bytes) -> str | None:
    """Optional OCR via pytesseract when installed; otherwise None."""
    try:
        import pytesseract
        from PIL import Image
    except ImportError:
        return None
    try:
        img = Image.open(BytesIO(data))
        text = pytesseract.image_to_string(img) or ""
        text = " ".join(text.split())
        return text[:2000] if text else None
    except Exception:
        return None


def enrich_screenshot_file(path: Path) -> tuple[str | None, str | None]:
    if not path.is_file():
        return None, None
    data = path.read_bytes()
    return average_hash(data), ocr_text(data)
