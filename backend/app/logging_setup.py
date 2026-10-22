from __future__ import annotations

import json
import logging
import logging.handlers
import os
import socket
import sys
from datetime import datetime, timezone

from . import __version__
from .config import get_settings
from .request_context import current_request_id

_configured = False

SERVICE_NAME = "portreveal"
# `extra={...}` keys copied into JSON records. An allowlist keeps arbitrary attributes (and secrets passed
# by mistake) out of the log pipeline.
JSON_EXTRA_FIELDS = ("request_id", "user", "client_ip", "scan_id", "capture_id", "network_id", "webhook_id")


class RequestContextFilter(logging.Filter):
    """Stamp each record with the id of the HTTP request being handled (None outside requests)."""

    def filter(self, record: logging.LogRecord) -> bool:
        if getattr(record, "request_id", None) is None:
            record.request_id = current_request_id()
        return True


class JsonFormatter(logging.Formatter):
    """Render one JSON object per record for log collectors."""

    def __init__(self) -> None:
        super().__init__()
        # Static identity, so records from several instances stay apart once aggregated.
        self._identity = {"service": SERVICE_NAME, "version": __version__, "host": socket.gethostname(), "pid": os.getpid()}

    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "timestamp": datetime.fromtimestamp(record.created, tz=timezone.utc)
            .isoformat(timespec="milliseconds")
            .replace("+00:00", "Z"),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            **self._identity,
        }
        for key in JSON_EXTRA_FIELDS:
            value = getattr(record, key, None)
            if value is not None:
                payload[key] = value if isinstance(value, int | float | bool) else str(value)
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        if record.stack_info:
            payload["stack"] = self.formatStack(record.stack_info)
        return json.dumps(payload, ensure_ascii=False)


def setup_logging() -> None:
    global _configured
    if _configured:
        return
    s = get_settings()
    fmt = (
        JsonFormatter()
        if s.log_format == "json"
        else logging.Formatter("%(asctime)s %(levelname)-7s %(name)s: %(message)s", "%Y-%m-%d %H:%M:%S")
    )
    root = logging.getLogger()
    root.setLevel(s.log_level.upper())
    context = RequestContextFilter()
    stream = logging.StreamHandler(sys.stdout)
    stream.setFormatter(fmt)
    stream.addFilter(context)
    root.addHandler(stream)
    try:
        log_dir = s.data_path / "logs"
        log_dir.mkdir(parents=True, exist_ok=True)
        fh = logging.handlers.RotatingFileHandler(log_dir / "app.log", maxBytes=5_000_000, backupCount=3, encoding="utf-8")
        fh.setFormatter(fmt)
        fh.addFilter(context)
        root.addHandler(fh)
    except OSError as exc:
        root.warning("file logging disabled: %s", exc)
    # httpx/httpcore log full request URLs at INFO (Slack/Teams webhook tokens live in the path).
    for noisy in (
        "uvicorn.access",
        "sqlalchemy.engine",
        "watchfiles",
        "alembic.runtime.migration",
        "httpx",
        "httpcore",
    ):
        logging.getLogger(noisy).setLevel(logging.WARNING)
    _configured = True
