"""Cross-platform crash-safe atomic file writers.

Adapted from PentesterFlow/agent ``src/persist/atomicFile.ts``
(commit ``0759d873a07350a70283c9751f7d136905f777c7``, licensed under Apache-2.0;
see ``THIRD_PARTY_LICENSES/PENTESTERFLOW_APACHE2.txt`` and ``NOTICE``).

Guarantees crash-safe full-snapshot writes by:
1. Creating a sibling temporary file exclusively with ``O_CREAT | O_EXCL`` so
   concurrent writers or symlink traps never collide.
2. Writing the full payload and calling ``os.fsync(fd)`` prior to closing.
3. Atomically replacing the destination path with ``os.replace``.
4. Performing a best-effort directory ``fsync`` on POSIX filesystems so the
   rename metadata update survives power loss.
5. Cleaning up the temporary file on any failure without masking the error.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import secrets
import sys
import time
from pathlib import Path
from typing import Any

logger = logging.getLogger("hunter_ai.persist.atomic_file")

DEFAULT_FILE_MODE = 0o600
_WINDOWS_REPLACE_RETRIES = 6
_WINDOWS_REPLACE_DELAY_S = 0.02


def _make_tmp_path(target: Path) -> Path:
    suffix = secrets.token_hex(4)
    return target.parent / f".{target.name}.tmp.{os.getpid()}.{suffix}"


def fsync_dir_best_effort(path: Path) -> None:
    """Best-effort fsync on the parent directory (POSIX durability guarantee)."""
    if sys.platform == "win32":
        return
    o_rdonly = getattr(os, "O_RDONLY", 0)
    o_directory = getattr(os, "O_DIRECTORY", 0)
    fd: int | None = None
    try:
        fd = os.open(str(path.parent), o_rdonly | o_directory)
        os.fsync(fd)
    except OSError as exc:
        logger.debug("Directory fsync skipped for %s: %s", path.parent, exc)
    finally:
        if fd is not None:
            try:
                os.close(fd)
            except OSError as close_exc:
                logger.debug("Directory fd close error for %s: %s", path.parent, close_exc)


def _replace_with_windows_retry(src: Path, dst: Path) -> None:
    """Replace *dst* with *src*, retrying brief Windows sharing violations."""
    if sys.platform != "win32":
        os.replace(src, dst)
        return
    last_exc: OSError | None = None
    for attempt in range(_WINDOWS_REPLACE_RETRIES):
        try:
            os.replace(src, dst)
            return
        except PermissionError as exc:
            last_exc = exc
            time.sleep(_WINDOWS_REPLACE_DELAY_S * (attempt + 1))
    assert last_exc is not None
    raise last_exc


def atomic_write_bytes(
    path: str | Path,
    content: bytes,
    *,
    mode: int = DEFAULT_FILE_MODE,
    fsync: bool = True,
) -> Path:
    """Crash-safe atomic write of *content* bytes to *path* using O_CREAT|O_EXCL + fsync + os.replace."""
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    if not isinstance(content, (bytes, bytearray, memoryview)):
        raise TypeError(f"Expected bytes-like content, got {type(content).__name__}")

    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_BINARY", 0)
    tmp_path: Path | None = None
    fd: int | None = None

    for _ in range(8):
        cand = _make_tmp_path(target)
        try:
            fd = os.open(str(cand), flags, mode)
            tmp_path = cand
            break
        except FileExistsError:
            continue
    if fd is None or tmp_path is None:
        raise FileExistsError(f"Unable to allocate unique temp file for {target}")

    try:
        view = memoryview(content)
        total = 0
        while total < len(view):
            written = os.write(fd, view[total:])
            if written <= 0:
                raise OSError(f"Short write while persisting {tmp_path}")
            total += written
        if fsync:
            os.fsync(fd)
        os.close(fd)
        fd = None

        _replace_with_windows_retry(tmp_path, target)
        fsync_dir_best_effort(target)
        if sys.platform != "win32":
            try:
                os.chmod(target, mode)
            except OSError as chmod_exc:
                logger.debug("chmod %o skipped for %s: %s", mode, target, chmod_exc)
        return target
    except Exception:
        if fd is not None:
            try:
                os.close(fd)
            except OSError as close_exc:
                logger.debug("Failed closing tmp fd for %s: %s", tmp_path, close_exc)
        try:
            tmp_path.unlink(missing_ok=True)
        except OSError as unlink_exc:
            logger.debug("Failed removing tmp file %s: %s", tmp_path, unlink_exc)
        raise


def atomic_write_text(
    path: str | Path,
    content: str,
    *,
    encoding: str = "utf-8",
    mode: int = DEFAULT_FILE_MODE,
    fsync: bool = True,
) -> Path:
    """Crash-safe atomic write of UTF-8 text to *path*."""
    if not isinstance(content, str):
        raise TypeError(f"Expected str content, got {type(content).__name__}")
    return atomic_write_bytes(path, content.encode(encoding), mode=mode, fsync=fsync)


def atomic_write_json(
    path: str | Path,
    data: Any,
    *,
    indent: int = 2,
    sort_keys: bool = False,
    ensure_ascii: bool = False,
    mode: int = DEFAULT_FILE_MODE,
    fsync: bool = True,
) -> Path:
    """Crash-safe atomic write of JSON-serialized *data* to *path*."""
    serialized = json.dumps(
        data,
        indent=indent,
        sort_keys=sort_keys,
        ensure_ascii=ensure_ascii,
        default=str,
    )
    return atomic_write_text(path, serialized + "\n", mode=mode, fsync=fsync)


async def atomic_write_bytes_async(
    path: str | Path,
    content: bytes,
    *,
    mode: int = DEFAULT_FILE_MODE,
    fsync: bool = True,
) -> Path:
    """Async offload wrapper around ``atomic_write_bytes``."""
    return await asyncio.to_thread(atomic_write_bytes, path, content, mode=mode, fsync=fsync)


async def atomic_write_text_async(
    path: str | Path,
    content: str,
    *,
    encoding: str = "utf-8",
    mode: int = DEFAULT_FILE_MODE,
    fsync: bool = True,
) -> Path:
    """Async offload wrapper around ``atomic_write_text``."""
    return await asyncio.to_thread(
        atomic_write_text, path, content, encoding=encoding, mode=mode, fsync=fsync
    )


async def atomic_write_json_async(
    path: str | Path,
    data: Any,
    *,
    indent: int = 2,
    sort_keys: bool = False,
    ensure_ascii: bool = False,
    mode: int = DEFAULT_FILE_MODE,
    fsync: bool = True,
) -> Path:
    """Async offload wrapper around ``atomic_write_json``."""
    return await asyncio.to_thread(
        atomic_write_json,
        path,
        data,
        indent=indent,
        sort_keys=sort_keys,
        ensure_ascii=ensure_ascii,
        mode=mode,
        fsync=fsync,
    )
