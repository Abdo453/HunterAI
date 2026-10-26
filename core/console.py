"""Console/stdio helpers that are safe on Windows legacy code pages (e.g. cp1256).

The project prints Unicode banners, box-drawing characters and emoji.  On a
Windows console whose active code page cannot represent them, ``print`` raises
``UnicodeEncodeError`` and aborts the caller (pipeline, UI worker, CLI).  These
helpers make stdio best-effort UTF-8 and provide a never-crashing ``print``
fallback for streams that cannot be reconfigured (such as pytest capture).
"""
from __future__ import annotations

import sys
from typing import Any


def configure_stdio() -> None:
    """Best-effort switch of stdout/stderr to UTF-8 with replacement.

    Never raises: pytest capture objects and other wrappers may not implement
    ``reconfigure`` (AttributeError) or may be closed (ValueError/OSError).
    """
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]
        except (AttributeError, ValueError, OSError):
            pass


def safe_print(*args: Any, **kwargs: Any) -> None:
    """``print`` that degrades to the stream encoding instead of raising."""
    try:
        print(*args, **kwargs)
    except UnicodeEncodeError:
        stream = kwargs.get("file") or sys.stdout
        encoding = getattr(stream, "encoding", None) or "utf-8"
        text = " ".join(str(arg) for arg in args)
        print(text.encode(encoding, errors="replace").decode(encoding, errors="replace"), **kwargs)
