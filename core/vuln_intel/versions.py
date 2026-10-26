"""Deterministic version parsing and comparison.

This module deliberately does **not** use an LLM.  Advisory version ranges and
installed versions must be compared by code so a wrong answer is reproducible
and testable.

It is not a full Composer/npm semver implementation.  It handles the numeric
core used by NVD/OSV ranges (``8.1.2``, ``1.0.0-beta1``, ``v2.4.1``) and
extracts a numeric core from distro-style strings (``8.1.2-1ubuntu2.14``).
Unparseable input returns ``None`` (unknown), never ``False``.
"""
from __future__ import annotations

import re
from typing import Optional

try:  # packaging is already a project dependency
    from packaging.version import InvalidVersion, Version
except Exception:  # pragma: no cover - defensive
    InvalidVersion = Exception  # type: ignore
    Version = None  # type: ignore

_CORE_RE = re.compile(r"^\s*[vV]?(\d+(?:\.\d+){0,3})")
_UNKNOWN = {"", "*", "-", "unknown", "n/a", "none", "null"}


def parse_version(value: object) -> Optional["Version"]:
    """Parse a version string into a comparable ``packaging.version.Version``.

    Returns ``None`` when the value is missing or cannot be interpreted.  This
    is intentional: callers must distinguish "not affected" from "unknown".
    """
    if value is None or Version is None:
        return None
    raw = str(value).strip()
    if raw.lower() in _UNKNOWN:
        return None
    raw = raw.lstrip("vV")
    try:
        return Version(raw)
    except (InvalidVersion, ValueError):
        pass

    # Distro / vendor suffixes: 8.1.2-1ubuntu2.14 -> 8.1.2
    match = _CORE_RE.match(raw)
    if not match:
        return None
    try:
        return Version(match.group(1))
    except (InvalidVersion, ValueError):
        return None


def compare_versions(a: object, b: object) -> Optional[int]:
    """Return -1/0/1, or ``None`` when either side is unparseable."""
    va = parse_version(a)
    vb = parse_version(b)
    if va is None or vb is None:
        return None
    if va < vb:
        return -1
    if va > vb:
        return 1
    return 0


def version_in_range(
    version: object,
    *,
    start_including: Optional[str] = None,
    start_excluding: Optional[str] = None,
    end_including: Optional[str] = None,
    end_excluding: Optional[str] = None,
) -> Optional[bool]:
    """Evaluate a version against advisory bounds.

    ``None`` means the answer is unknown (unparseable version or bound), not
    "not affected".
    """
    v = parse_version(version)
    if v is None:
        return None

    if start_including:
        bound = parse_version(start_including)
        if bound is None:
            return None
        if v < bound:
            return False
    if start_excluding:
        bound = parse_version(start_excluding)
        if bound is None:
            return None
        if v <= bound:
            return False
    if end_including:
        bound = parse_version(end_including)
        if bound is None:
            return None
        if v > bound:
            return False
    if end_excluding:
        bound = parse_version(end_excluding)
        if bound is None:
            return None
        if v >= bound:
            return False
    return True


def normalize_package_name(name: object) -> str:
    """Normalize a package name for comparison (case/whitespace only).

    We intentionally do not strip vendor prefixes or apply ecosystem-specific
    aliasing here; that belongs in the triage layer with evidence.
    """
    if name is None:
        return ""
    return str(name).strip().lower()
