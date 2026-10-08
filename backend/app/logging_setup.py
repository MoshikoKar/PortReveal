from __future__ import annotations

import logging
import logging.handlers
import sys

from .config import get_settings

_configured = False


def setup_logging() -> None:
    global _configured
    if _configured:
        return
    s = get_settings()
    fmt = logging.Formatter("%(asctime)s %(levelname)-7s %(name)s: %(message)s", "%Y-%m-%d %H:%M:%S")
    root = logging.getLogger()
    root.setLevel(s.log_level.upper())
    stream = logging.StreamHandler(sys.stdout)
    stream.setFormatter(fmt)
    root.addHandler(stream)
    try:
        log_dir = s.data_path / "logs"
        log_dir.mkdir(parents=True, exist_ok=True)
        fh = logging.handlers.RotatingFileHandler(log_dir / "app.log", maxBytes=5_000_000, backupCount=3,
                                                  encoding="utf-8")
        fh.setFormatter(fmt)
        root.addHandler(fh)
    except OSError as exc:
        root.warning("file logging disabled: %s", exc)
    for noisy in ("uvicorn.access", "sqlalchemy.engine", "watchfiles", "alembic.runtime.migration"):
        logging.getLogger(noisy).setLevel(logging.WARNING)
    _configured = True
