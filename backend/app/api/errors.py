"""One error body for every API failure.

    {"code": "conflict", "message": "Scan is already completed", "detail": "Scan is already completed"}

``code`` is stable and machine-readable (clients branch on it), ``message`` is for people. ``detail`` is
the FastAPI field older clients read; it stays for v1 (for validation errors it is FastAPI's list of
errors, also given as ``details``). Search syntax errors add ``pos``, the offset in the query.
"""
from __future__ import annotations

from typing import Any

from fastapi import HTTPException

# Default code per HTTP status; an ApiError can name a more specific one.
STATUS_CODES = {
    400: "bad_request",
    401: "unauthorized",
    403: "forbidden",
    404: "not_found",
    405: "method_not_allowed",
    409: "conflict",
    413: "payload_too_large",
    415: "unsupported_media_type",
    422: "validation_error",
    429: "rate_limited",
    500: "internal_error",
    502: "upstream_failed",
    503: "service_unavailable",
    504: "upstream_timeout",
}


def code_for(status: int) -> str:
    return STATUS_CODES.get(status, "client_error" if status < 500 else "server_error")


class ApiError(HTTPException):
    """An HTTPException with a specific machine-readable ``code`` (default: the status's code)."""

    def __init__(self, status_code: int, message: str, code: str | None = None,
                 headers: dict[str, str] | None = None):
        super().__init__(status_code, message, headers)
        self.code = code or code_for(status_code)


def error_body(status: int, message: str, code: str | None = None, *, detail: Any = None,
               **extra: Any) -> dict:
    body = {"code": code or code_for(status), "message": message,
            "detail": message if detail is None else detail}
    body.update(extra)
    return body


def validation_message(errors: list[dict]) -> str:
    """'body.port: Input should be less than 65536; ...' from FastAPI/pydantic validation errors."""
    parts = []
    for e in errors:
        loc = ".".join(str(x) for x in e.get("loc", ()) if x != "body")
        msg = str(e.get("msg", "invalid value")).removeprefix("Value error, ")
        parts.append(f"{loc}: {msg}" if loc else msg)
    return "; ".join(parts) or "Invalid request"
