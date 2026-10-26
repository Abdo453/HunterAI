"""Regression tests for Windows legacy-code-page (cp1256) console safety.

Before ``core.console`` existed, printing the AI-preflight banner (box drawing +
emoji) raised ``UnicodeEncodeError`` on a cp1256 console and aborted the
pipeline.  These tests pin the fix.
"""
import io
import sys

from core.console import configure_stdio, safe_print


class _ReconfigureUnsupported(io.StringIO):
    """Mimics pytest's capture wrapper: ``reconfigure`` is not supported."""

    def reconfigure(self, *args, **kwargs):
        raise AttributeError("reconfigure")


class _ReconfigureClosed(io.StringIO):
    """Mimics a closed stream."""

    def reconfigure(self, *args, **kwargs):
        raise ValueError("I/O operation on closed file")


def test_safe_print_degrades_on_cp1256(monkeypatch):
    buf = io.BytesIO()
    stream = io.TextIOWrapper(buf, encoding="cp1256", errors="strict")
    monkeypatch.setattr(sys, "stdout", stream)

    safe_print("╔══ 🧠 HUNTERAI ══╗")

    stream.flush()
    written = buf.getvalue()
    assert b"?" in written
    assert b"HUNTERAI" in written


def test_configure_stdio_never_raises_on_wrapper(monkeypatch):
    monkeypatch.setattr(sys, "stdout", _ReconfigureUnsupported())
    monkeypatch.setattr(sys, "stderr", _ReconfigureUnsupported())

    configure_stdio()  # must not raise


def test_configure_stdio_never_raises_on_closed_stream(monkeypatch):
    monkeypatch.setattr(sys, "stdout", _ReconfigureClosed())
    monkeypatch.setattr(sys, "stderr", _ReconfigureClosed())

    configure_stdio()  # must not raise
