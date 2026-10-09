from __future__ import annotations

import json
import logging
import sys

from app.config import Settings
from app.logging_setup import JsonFormatter


def test_settings_accept_json_log_format():
    assert Settings(log_format="json").log_format == "json"


def test_json_formatter_emits_machine_readable_record():
    record = logging.LogRecord(
        name="app.test",
        level=logging.WARNING,
        pathname=__file__,
        lineno=20,
        msg="device %s",
        args=("offline",),
        exc_info=None,
    )

    payload = json.loads(JsonFormatter().format(record))

    assert payload["timestamp"].endswith("Z")
    assert payload["level"] == "WARNING"
    assert payload["logger"] == "app.test"
    assert payload["message"] == "device offline"


def test_json_formatter_includes_exception():
    try:
        raise ValueError("bad input")
    except ValueError:
        exc_info = sys.exc_info()

    record = logging.LogRecord("app.test", logging.ERROR, __file__, 40, "failed", (), exc_info)
    payload = json.loads(JsonFormatter().format(record))

    assert "ValueError: bad input" in payload["exception"]
