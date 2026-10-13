"""Per-request correlation id, shared between the HTTP middleware and log records.

The middleware in main.py accepts a well-formed ``X-Request-Id`` from the client (the UI sends one) or
generates a new id, echoes it on the response, and stores it here so every log line written while the
request is handled can carry it (see logging_setup.RequestContextFilter).
"""
from __future__ import annotations

import contextvars
import re
import uuid

REQUEST_ID_HEADER = "X-Request-Id"

# Client-supplied ids are logged verbatim, so only short, plain tokens are accepted.
_SAFE_ID = re.compile(r"^[A-Za-z0-9._:-]{1,64}$")
_request_id: contextvars.ContextVar[str | None] = contextvars.ContextVar("request_id", default=None)


def request_id_from(incoming: str | None) -> str:
    """The client's id when it is safe to log, otherwise a fresh one."""
    if incoming and _SAFE_ID.match(incoming):
        return incoming
    return uuid.uuid4().hex


def current_request_id() -> str | None:
    return _request_id.get()


def bind_request_id(value: str) -> contextvars.Token:
    return _request_id.set(value)


def unbind_request_id(token: contextvars.Token) -> None:
    _request_id.reset(token)
