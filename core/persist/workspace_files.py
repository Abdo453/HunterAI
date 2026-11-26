"""Containment-enforced workspace file storage with size and count limits.

Adapted from vxcontrol/pentagi ``backend/pkg/flowfiles/files.go``
(commit ``cffed9485aa1cca70762cd08a57ac62a80406258``, licensed under MIT;
see ``THIRD_PARTY_LICENSES/PENTAGI_MIT.txt`` and ``NOTICE``).
"""

from __future__ import annotations

import hashlib
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List, Optional, Sequence

from core.persist.atomic_file import DEFAULT_FILE_MODE, atomic_write_bytes

UPLOADS_DIR_NAME = "uploads"
CONTAINER_DIR_NAME = "container"
RESOURCES_DIR_NAME = "resources"
ARTIFACTS_DIR_NAME = "artifacts"

DEFAULT_ALLOWED_SUBDIRS = (
    UPLOADS_DIR_NAME,
    CONTAINER_DIR_NAME,
    RESOURCES_DIR_NAME,
    ARTIFACTS_DIR_NAME,
)

MAX_FILENAME_LENGTH = 255
DEFAULT_MAX_FILE_SIZE = 50 * 1024 * 1024  # 50 MB per file
DEFAULT_MAX_FILE_COUNT = 1000
DEFAULT_MAX_TOTAL_SIZE = 500 * 1024 * 1024  # 500 MB per workspace

_FORBIDDEN_COMPONENT_CHARS = frozenset({'/', '\\', ':', '*', '?', '"', '<', '>', '|'})
_WINDOWS_RESERVED_NAMES = frozenset(
    {
        "CON",
        "PRN",
        "AUX",
        "NUL",
        *(f"COM{i}" for i in range(1, 10)),
        *(f"LPT{i}" for i in range(1, 10)),
    }
)
_FLOW_ID_SAFE_RE = re.compile(r"^[A-Za-z0-9._-]{1,128}$")


@dataclass(frozen=True)
class WorkspaceFileEntry:
    """Metadata record for a regular file inside a flow/run workspace."""

    file_id: str
    name: str
    rel_path: str
    abs_path: Path
    size_bytes: int
    is_dir: bool
    modified_at: float


def _validate_component(component: str) -> str:
    clean = (component or "").strip()
    if not clean or clean in {".", "..", "/"}:
        raise ValueError(f"Invalid path component: {component!r}")
    if len(clean) > MAX_FILENAME_LENGTH:
        raise ValueError(f"Path component exceeds {MAX_FILENAME_LENGTH} characters")
    for ch in clean:
        code = ord(ch)
        if code < 0x20 or code == 0x7F:
            raise ValueError("Path component contains control characters")
        if ch in _FORBIDDEN_COMPONENT_CHARS:
            raise ValueError(f"Path component contains disallowed character {ch!r}")
    stem = clean.split(".", 1)[0].upper()
    if stem in _WINDOWS_RESERVED_NAMES:
        raise ValueError(f"Path component uses reserved device name {clean!r}")
    if clean.endswith(".") or clean.endswith(" "):
        raise ValueError("Path component cannot end with a dot or trailing space")
    return clean


def sanitize_filename(filename: str) -> str:
    """Extract and strictly validate a safe basename free of traversal/control/ADS characters."""
    trimmed = (filename or "").strip()
    if not trimmed:
        raise ValueError("Filename is required")
    if "\x00" in trimmed:
        raise ValueError("Filename contains NUL byte")
    # Check raw segments for explicit traversal attempts or ADS colons before extracting basename
    normalized = trimmed.replace("\\", "/")
    if ":" in normalized:
        raise ValueError("Filename contains disallowed ':' character")
    if normalized.endswith("/"):
        raise ValueError("Filename cannot end with a path separator")
    raw_segments = normalized.split("/")
    if any(seg == ".." for seg in raw_segments):
        raise ValueError("Filename contains disallowed traversal segment '..'")
    base = raw_segments[-1]
    return _validate_component(base)


def sanitize_relative_subpath(rel_path: str) -> str:
    """Validate and normalize a multi-segment relative path using forward slashes."""
    trimmed = (rel_path or "").strip()
    if not trimmed:
        raise ValueError("Relative path is required")
    if "\x00" in trimmed or ":" in trimmed:
        raise ValueError("Path contains disallowed control or drive/ADS characters")
    normalized = trimmed.replace("\\", "/")
    if normalized.startswith("/"):
        raise ValueError("Path must be relative (no leading slash)")
    raw_parts = [p for p in normalized.split("/") if p != ""]
    if not raw_parts:
        raise ValueError("Relative path is empty")
    clean_parts: List[str] = []
    for part in raw_parts:
        if part in {".", ".."}:
            raise ValueError(f"Path traversal component {part!r} is forbidden")
        clean_parts.append(_validate_component(part))
    return "/".join(clean_parts)


def is_within_dir(target_path: str | Path, base_dir: str | Path) -> bool:
    """Return True iff *target_path* stays strictly inside *base_dir* after resolving symlinks."""
    try:
        base_real = Path(os.path.realpath(str(base_dir)))
        target_real = Path(os.path.realpath(str(target_path)))
        return target_real == base_real or target_real.is_relative_to(base_real)
    except (OSError, ValueError):
        return False


def flow_data_dir(base_dir: str | Path, flow_id: str | int) -> Path:
    """Return the validated per-flow/run workspace directory under *base_dir*."""
    fid = str(flow_id).strip()
    if not fid or not _FLOW_ID_SAFE_RE.fullmatch(fid) or ".." in fid:
        raise ValueError(f"Invalid flow_id {flow_id!r}")
    root = Path(base_dir)
    candidate = root / f"flow-{fid}-data"
    if not is_within_dir(candidate, root):
        raise PermissionError("Flow data directory escapes workspace base directory")
    return candidate


def resolve_cached_path(
    base_dir: str | Path,
    flow_id: str | int,
    req_path: str,
    *,
    allowed_roots: Sequence[str] = DEFAULT_ALLOWED_SUBDIRS,
) -> Path:
    """Resolve a workspace-relative cached file path enforcing root allowlist and containment.

    Adapted from PentAGI ``flowfiles.ResolveCachedPath``: requires a relative path
    starting with an allowed category prefix (``uploads``, ``container``,
    ``resources``, ``artifacts``), validates every component, and enforces
    symlink-safe containment inside ``flow-<id>-data``.
    """
    clean_rel = sanitize_relative_subpath(req_path)
    parts = clean_rel.split("/")
    allowed = tuple(allowed_roots)
    if parts[0] not in allowed:
        raise ValueError(f"Path must start with one of {allowed!r}, got {parts[0]!r}")

    fdir = flow_data_dir(base_dir, flow_id)
    abs_path = fdir.joinpath(*parts)
    if not is_within_dir(abs_path, fdir):
        raise PermissionError("Resolved path escapes flow workspace directory")

    # Reject any existing symlink component along the path
    cursor = fdir
    for part in parts:
        cursor = cursor / part
        if cursor.is_symlink():
            raise PermissionError(f"Symlink component rejected in workspace path: {part!r}")

    return abs_path


class WorkspaceFileStore:
    """Bounded file manager for a flow/run workspace with file-size, count, and total-size caps."""

    def __init__(
        self,
        base_dir: str | Path,
        *,
        max_file_size: int = DEFAULT_MAX_FILE_SIZE,
        max_file_count: int = DEFAULT_MAX_FILE_COUNT,
        max_total_size: int = DEFAULT_MAX_TOTAL_SIZE,
        allowed_roots: Sequence[str] = DEFAULT_ALLOWED_SUBDIRS,
    ) -> None:
        self.base_dir = Path(base_dir)
        self.max_file_size = int(max_file_size)
        self.max_file_count = int(max_file_count)
        self.max_total_size = int(max_total_size)
        self.allowed_roots = tuple(allowed_roots)

    def resolve(self, flow_id: str | int, rel_path: str) -> Path:
        return resolve_cached_path(
            self.base_dir,
            flow_id,
            rel_path,
            allowed_roots=self.allowed_roots,
        )

    def _current_usage(self, flow_id: str | int) -> tuple[int, int]:
        fdir = flow_data_dir(self.base_dir, flow_id)
        if not fdir.is_dir():
            return 0, 0
        count = 0
        total_bytes = 0
        for root_name in self.allowed_roots:
            sub = fdir / root_name
            if not sub.is_dir() or sub.is_symlink():
                continue
            for dirpath, dirnames, filenames in os.walk(sub, followlinks=False):
                # Do not traverse symlinked directories or temp staging entries
                dirnames[:] = [
                    d
                    for d in dirnames
                    if not (Path(dirpath) / d).is_symlink() and not d.startswith(".tmp.")
                ]
                for fname in filenames:
                    if fname.startswith((".upload-", ".pull-", ".")):
                        continue
                    fpath = Path(dirpath) / fname
                    if fpath.is_symlink():
                        continue
                    try:
                        st = fpath.lstat()
                    except OSError:
                        continue
                    count += 1
                    total_bytes += int(st.st_size)
        return count, total_bytes

    def write_file(
        self,
        flow_id: str | int,
        rel_path: str,
        content: bytes,
        *,
        mode: int = DEFAULT_FILE_MODE,
    ) -> WorkspaceFileEntry:
        """Atomically write *content* into the flow workspace enforcing size and count caps."""
        if not isinstance(content, (bytes, bytearray, memoryview)):
            raise TypeError("content must be bytes-like")
        raw = bytes(content)
        if len(raw) > self.max_file_size:
            raise ValueError(
                f"File exceeds maximum single-file limit ({len(raw)} > {self.max_file_size} bytes)"
            )

        dest = self.resolve(flow_id, rel_path)
        existing_size = 0
        existed = False
        if dest.exists():
            if dest.is_symlink() or dest.is_dir():
                raise PermissionError("Cannot overwrite directory or symlink")
            existed = True
            existing_size = int(dest.lstat().st_size)

        cur_count, cur_total = self._current_usage(flow_id)
        new_count = cur_count if existed else cur_count + 1
        new_total = cur_total - existing_size + len(raw)

        if new_count > self.max_file_count:
            raise ValueError(
                f"Workspace exceeds maximum file count ({new_count} > {self.max_file_count})"
            )
        if new_total > self.max_total_size:
            raise ValueError(
                f"Workspace exceeds maximum total size ({new_total} > {self.max_total_size} bytes)"
            )

        atomic_write_bytes(dest, raw, mode=mode)
        st = dest.lstat()
        norm_rel = sanitize_relative_subpath(rel_path)
        return WorkspaceFileEntry(
            file_id=hashlib.sha256(norm_rel.encode("utf-8")).hexdigest()[:24],
            name=dest.name,
            rel_path=norm_rel,
            abs_path=dest,
            size_bytes=int(st.st_size),
            is_dir=False,
            modified_at=float(st.st_mtime),
        )

    def read_file(self, flow_id: str | int, rel_path: str) -> bytes:
        dest = self.resolve(flow_id, rel_path)
        if not dest.is_file() or dest.is_symlink():
            raise FileNotFoundError(f"Workspace file not found: {rel_path}")
        return dest.read_bytes()

    def list_files(
        self,
        flow_id: str | int,
        *,
        roots: Optional[Iterable[str]] = None,
    ) -> List[WorkspaceFileEntry]:
        fdir = flow_data_dir(self.base_dir, flow_id)
        if not fdir.is_dir():
            return []
        selected = tuple(roots) if roots is not None else self.allowed_roots
        entries: List[WorkspaceFileEntry] = []
        for root_name in selected:
            if root_name not in self.allowed_roots:
                continue
            sub = fdir / root_name
            if not sub.is_dir() or sub.is_symlink():
                continue
            for dirpath, dirnames, filenames in os.walk(sub, followlinks=False):
                dirnames[:] = sorted(
                    d
                    for d in dirnames
                    if not (Path(dirpath) / d).is_symlink() and not d.startswith((".pull-", ".upload-"))
                )
                for fname in sorted(filenames):
                    if fname.startswith((".pull-", ".upload-", ".")):
                        continue
                    fpath = Path(dirpath) / fname
                    if fpath.is_symlink() or not fpath.is_file():
                        continue
                    if not is_within_dir(fpath, fdir):
                        continue
                    st = fpath.lstat()
                    rel = fpath.relative_to(fdir).as_posix()
                    entries.append(
                        WorkspaceFileEntry(
                            file_id=hashlib.sha256(rel.encode("utf-8")).hexdigest()[:24],
                            name=fname,
                            rel_path=rel,
                            abs_path=fpath,
                            size_bytes=int(st.st_size),
                            is_dir=False,
                            modified_at=float(st.st_mtime),
                        )
                    )
        entries.sort(key=lambda e: (e.rel_path, e.name))
        return entries
