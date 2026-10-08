"""Unit tests for HTTP response size capping (no network)."""
from __future__ import annotations

from app.core.web_capture.probe import _read_limited


class _FakeResp:
    def __init__(self, chunks: list[bytes]):
        self._chunks = chunks

    def iter_bytes(self):
        yield from self._chunks


def test_read_limited_caps_size():
    data, truncated = _read_limited(_FakeResp([b"a" * 100, b"b" * 100]), max_bytes=150)
    assert len(data) == 150
    assert truncated is True


def test_read_limited_full_body():
    data, truncated = _read_limited(_FakeResp([b"hello"]), max_bytes=100)
    assert data == b"hello"
    assert truncated is False
