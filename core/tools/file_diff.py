"""
Context-Anchored Unified Diff Applier
=====================================
Adapted from PentAGI ``backend/pkg/tools/file_diff.go`` (commit ``cffed94``, MIT License).

Applies unified diffs purely by matching context and removed lines against the
file content; hunk header line numbers are used ONLY as tie-breakers between
equally valid matches. A stale line number therefore applies cleanly, whereas a
hunk whose removed/context lines are absent from the target file fails closed
atomically (never leaving a partially patched file on disk).
"""
from __future__ import annotations

import os
import re
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Sequence, Tuple

MAX_DIFF_HUNK_PREVIEW_BYTES = 200
_RELAXED_TRIM_CHARS = " \t\r"

_UNIFIED_DIFF_HUNK_HEADER_RE = re.compile(
    r"^@@(?:\s+-(\d+)(?:,(\d+))?\s+\+(\d+)(?:,(\d+))?)?\s*(?:@@)?"
)


class DiffApplyError(ValueError):
    """Raised when a unified diff cannot be parsed or cleanly applied."""


@dataclass(frozen=True)
class DiffHunkLine:
    sign: str  # ' ' (context), '-' (removed), '+' (added)
    text: str


@dataclass
class DiffHunk:
    header: str
    old_start: int = 1
    has_position: bool = False
    lines: List[DiffHunkLine] = field(default_factory=list)


@dataclass
class _LocatedHunk:
    hunk: DiffHunk
    win: List[DiffHunkLine]
    start: int
    old_len: int


def parse_unified_diff(diff_text: str) -> List[DiffHunk]:
    """Parse a unified diff into ``DiffHunk`` records.

    Tolerates optional ``---`` / ``+++`` headers, ``\\ No newline at end of file``
    markers, bare ``@@`` headers without line numbers, and blank context lines.
    """
    normalized = diff_text.replace("\r\n", "\n")
    if normalized.endswith("\n"):
        normalized = normalized[:-1]
    if not normalized:
        raise DiffApplyError("diff is empty")

    lines = normalized.split("\n")
    i = 0
    while i < len(lines) and not lines[i].startswith("@@"):
        trimmed = lines[i].strip()
        if trimmed and not trimmed.startswith("---") and not trimmed.startswith("+++"):
            raise DiffApplyError(
                f'expected a hunk header ("@@ -old +new @@") but found: {lines[i]!r}'
            )
        i += 1
    if i >= len(lines):
        raise DiffApplyError('diff contains no hunks (no "@@ ... @@" header found)')

    hunks: List[DiffHunk] = []
    while i < len(lines):
        header = lines[i]
        m = _UNIFIED_DIFF_HUNK_HEADER_RE.match(header)
        if not m:
            raise DiffApplyError(f"invalid hunk header: {header!r}")

        hunk = DiffHunk(header=header, old_start=1, has_position=False)
        if m.group(1):
            hunk.old_start = int(m.group(1))
            hunk.has_position = True
        i += 1

        while i < len(lines) and not lines[i].startswith("@@"):
            line = lines[i]
            i += 1
            if line.startswith("\\"):
                # e.g. "\ No newline at end of file"
                continue
            if line == "":
                hunk.lines.append(DiffHunkLine(sign=" ", text=""))
                continue
            sign = line[0]
            if sign not in (" ", "-", "+"):
                raise DiffApplyError(
                    f"invalid diff line (must start with ' ', '-', or '+'): {line!r}"
                )
            hunk.lines.append(DiffHunkLine(sign=sign, text=line[1:]))

        if not hunk.lines:
            raise DiffApplyError(f"hunk {header!r} has no content lines")
        hunks.append(hunk)

    return hunks


def _split_file_lines(content: str) -> Tuple[List[str], bool]:
    if content == "":
        return [], True
    has_eol = content.endswith("\n")
    if has_eol:
        content = content[:-1]
    return content.split("\n"), has_eol


def _join_file_lines(lines: Sequence[str], has_eol: bool) -> str:
    if not lines:
        return ""
    out = "\n".join(lines)
    if has_eol:
        out += "\n"
    return out


def _change_span(h: DiffHunk) -> Tuple[int, int, bool]:
    first, last = -1, -1
    for idx, ln in enumerate(h.lines):
        if ln.sign != " ":
            if first < 0:
                first = idx
            last = idx
    return first, last, first >= 0


def _hunk_window(h: DiffHunk, fuzz: int) -> List[DiffHunkLine]:
    first, last, ok = _change_span(h)
    if not ok:
        return []
    return h.lines[max(first - fuzz, 0) : min(last + 1 + fuzz, len(h.lines))]


def _window_old_side(win: Sequence[DiffHunkLine]) -> List[str]:
    return [ln.text for ln in win if ln.sign != "+"]


def _lines_equal(file_line: str, diff_line: str, relaxed: bool) -> bool:
    if file_line.removesuffix("\r") == diff_line.removesuffix("\r"):
        return True
    return relaxed and (
        file_line.rstrip(_RELAXED_TRIM_CHARS) == diff_line.rstrip(_RELAXED_TRIM_CHARS)
    )


def _find_matches(lines: Sequence[str], want: Sequence[str], relaxed: bool) -> List[int]:
    if not want or len(want) > len(lines):
        return []
    out: List[int] = []
    want_len = len(want)
    for i in range(0, len(lines) - want_len + 1):
        if all(_lines_equal(lines[i + j], want[j], relaxed) for j in range(want_len)):
            out.append(i)
    return out


def _pick_match(cands: Sequence[int], h: DiffHunk, search_from: int) -> int:
    in_order = [c for c in cands if c >= search_from]
    pool = in_order if in_order else list(cands)
    if not h.has_position:
        return pool[0]
    hint = h.old_start - 1
    best = pool[0]
    for c in pool[1:]:
        if abs(c - hint) < abs(best - hint):
            best = c
    return best


def _locate_hunk(lines: Sequence[str], h: DiffHunk, search_from: int) -> Optional[_LocatedHunk]:
    first, last, has_change = _change_span(h)
    if not has_change:
        return None
    max_fuzz = max(first, len(h.lines) - 1 - last)

    full = _hunk_window(h, max_fuzz)
    want_full = _window_old_side(full)
    if want_full:
        cands = _find_matches(lines, want_full, False)
        if cands:
            return _LocatedHunk(
                hunk=h,
                win=full,
                start=_pick_match(cands, h, search_from),
                old_len=len(want_full),
            )
        core = _window_old_side(_hunk_window(h, 0))
        if core and not _find_matches(lines, core, True):
            return None

    for fuzz in range(max_fuzz, -1, -1):
        win = _hunk_window(h, fuzz)
        want = _window_old_side(win)
        if not want:
            continue
        for relaxed in (False, True):
            cands = _find_matches(lines, want, relaxed)
            if len(cands) == 1:
                return _LocatedHunk(hunk=h, win=win, start=cands[0], old_len=len(want))

    if len(_window_old_side(h.lines)) == 0 and (h.has_position or len(lines) == 0):
        start = min(max(h.old_start - 1, 0), len(lines))
        return _LocatedHunk(hunk=h, win=list(h.lines), start=start, old_len=0)

    return None


def _hunk_eol(lines: Sequence[str], start: int) -> str:
    idx = min(start, len(lines) - 1)
    if idx >= 0 and lines[idx].endswith("\r"):
        return "\r"
    return ""


def _render_new_side(loc: _LocatedHunk, lines: Sequence[str]) -> List[str]:
    eol = _hunk_eol(lines, loc.start)
    out: List[str] = []
    cursor = loc.start
    for hl in loc.win:
        if hl.sign == " ":
            out.append(lines[cursor])
            cursor += 1
        elif hl.sign == "-":
            cursor += 1
        elif hl.sign == "+":
            out.append(hl.text.removesuffix("\r") + eol)
    return out


def _apply_located_hunks(lines: Sequence[str], located: Sequence[_LocatedHunk]) -> List[str]:
    ordered = sorted(located, key=lambda item: item.start)
    out: List[str] = []
    cursor = 0
    for loc in ordered:
        if loc.start < cursor:
            raise DiffApplyError(
                f"hunk {loc.hunk.header!r} overlaps an earlier hunk in the same diff"
            )
        out.extend(lines[cursor : loc.start])
        out.extend(_render_new_side(loc, lines))
        cursor = loc.start + loc.old_len
    out.extend(lines[cursor:])
    return out


def _hunk_old_preview(h: DiffHunk) -> str:
    text = "".join(f"{ln.text}\n" for ln in h.lines if ln.sign != "+")
    if len(text) <= MAX_DIFF_HUNK_PREVIEW_BYTES:
        return text
    return text[:MAX_DIFF_HUNK_PREVIEW_BYTES] + "..."


def apply_unified_diff(content: str, diff_text: str) -> Tuple[str, int]:
    """Apply ``diff_text`` to ``content`` in memory.

    Returns ``(patched_content, hunks_applied)`` or raises ``DiffApplyError``
    without partial mutation.
    """
    hunks = parse_unified_diff(diff_text)
    lines, has_eol = _split_file_lines(content)

    located: List[_LocatedHunk] = []
    failed: List[str] = []
    search_from = 0

    for h in hunks:
        _, _, ok_change = _change_span(h)
        if not ok_change:
            failed.append(f"{h.header} (has no '-' or '+' line, so it changes nothing)")
            continue
        loc = _locate_hunk(lines, h, search_from)
        if loc is None:
            failed.append(
                f"{h.header} (not found in the file, looked for: {_hunk_old_preview(h)!r})"
            )
            continue
        located.append(loc)
        search_from = loc.start + loc.old_len

    if failed:
        raise DiffApplyError(
            f"{len(failed)} of {len(hunks)} hunk(s) could not be applied - read the file again "
            f"and retry with context that matches its current content exactly:\n"
            + "\n".join(failed)
        )

    new_lines = _apply_located_hunks(lines, located)
    return _join_file_lines(new_lines, has_eol), len(hunks)


def apply_unified_diff_to_file(
    file_path: str | Path,
    diff_text: str,
    *,
    allowed_root: Optional[str | Path] = None,
) -> int:
    """Atomically apply a unified diff to a file on disk.

    When ``allowed_root`` is provided, enforces ``Path.resolve()`` containment
    before reading or writing.
    """
    target = Path(file_path).resolve(strict=False)
    if allowed_root is not None:
        root = Path(allowed_root).resolve(strict=False)
        if not (target == root or target.is_relative_to(root)):
            raise PermissionError(
                f"Target path {target} escapes allowed root {root}"
            )
    if not target.is_file():
        raise FileNotFoundError(f"File not found: {target}")

    original = target.read_text(encoding="utf-8")
    patched, count = apply_unified_diff(original, diff_text)

    fd, tmp_name = tempfile.mkstemp(dir=str(target.parent), prefix=".diff_", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as fh:
            fh.write(patched)
        os.replace(tmp_name, target)
    except Exception:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise
    return count
