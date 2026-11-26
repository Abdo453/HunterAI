"""Thinking-tag stripping and chunk-boundary-safe streaming filter.

Adapted from PentesterFlow/agent ``src/agent/sanitize.ts``
(commit ``0759d873a07350a70283c9751f7d136905f777c7``, licensed under Apache-2.0;
see ``THIRD_PARTY_LICENSES/PENTESTERFLOW_APACHE2.txt`` and ``NOTICE``).

Modifications for HunterAI:
- Preserves JSON tool-call envelopes cleanly (even when thinking blocks precede
  or surround JSON tool payloads, and without mangling JSON string literals).
"""
from __future__ import annotations

import json
import re
from typing import Tuple

# Innermost matched pair (repeated application peels nested blocks inside-out).
_THINK_PAIR_RE = re.compile(
    r"(?:<(?:think|thinking|reasoning)>|◁think▷)"
    r"(?:(?!(?:<(?:think|thinking|reasoning)>|◁think▷))[\s\S])*?"
    r"(?:</(?:think|thinking|reasoning)>|◁/think▷)\s*",
    re.IGNORECASE,
)

# Stray/unclosed lone tags left after paired removal.
_LONE_THINK_TAG_RE = re.compile(
    r"</?(?:think|thinking|reasoning)>|◁/?think▷",
    re.IGNORECASE,
)

_ANY_THINK_TAG_RE = re.compile(
    r"</?(?:think|thinking|reasoning)>|◁/?think▷",
    re.IGNORECASE,
)

_TOOL_ENVELOPE_KEYS = frozenset({
    "tool_calls",
    "toolCalls",
    "tool_call",
    "toolCall",
    "function_call",
    "functionCall",
    "function",
    "tool",
    "tool_name",
    "toolName",
})

THINK_OPEN_TAGS: Tuple[str, ...] = ("<think>", "<thinking>", "<reasoning>", "◁think▷")
THINK_CLOSE_TAGS: Tuple[str, ...] = ("</think>", "</thinking>", "</reasoning>", "◁/think▷")
ALL_THINK_TAGS: Tuple[str, ...] = THINK_OPEN_TAGS + THINK_CLOSE_TAGS


def _is_json_tool_envelope(text: str) -> bool:
    """Return True if *text* is already a valid JSON tool-call envelope."""
    stripped = (text or "").strip()
    if not stripped or stripped[0] not in "{[":
        return False
    try:
        parsed = json.loads(stripped)
    except (ValueError, TypeError):
        return False
    if isinstance(parsed, dict):
        return bool(set(parsed.keys()) & _TOOL_ENVELOPE_KEYS) or (
            "name" in parsed and any(k in parsed for k in ("arguments", "args", "parameters", "input"))
        )
    if isinstance(parsed, list) and parsed:
        first = parsed[0]
        return isinstance(first, dict) and (
            bool(set(first.keys()) & _TOOL_ENVELOPE_KEYS)
            or ("name" in first and any(k in first for k in ("arguments", "args", "parameters", "input")))
        )
    return False


def strip_thinking_tags(text: str) -> str:
    """Remove model thinking/reasoning blocks while preserving answer text and JSON tool envelopes.

    - Matched open/close pairs are removed (including nested blocks).
    - Unclosed open tags strip only the tag marker, preserving trailing text.
    - Pure JSON tool-call envelopes (even if their argument strings mention
      ``<think>`` literally) are returned untouched.
    """
    if not text or not _ANY_THINK_TAG_RE.search(text):
        return text
    if _is_json_tool_envelope(text):
        return text

    out = text
    while True:
        nxt = _THINK_PAIR_RE.sub("", out)
        if nxt == out:
            break
        out = nxt
    out = _LONE_THINK_TAG_RE.sub("", out)
    return out.lstrip()


def _find_first_tag(s: str, tags: Tuple[str, ...]) -> Tuple[int, int]:
    lower = s.lower()
    best_idx = -1
    best_len = 0
    for tag in tags:
        idx = lower.find(tag)
        if idx >= 0 and (best_idx < 0 or idx < best_idx):
            best_idx = idx
            best_len = len(tag)
    return best_idx, best_len


def _safe_prefix_length(s: str, tags: Tuple[str, ...]) -> int:
    lower = s.lower()
    hold = 0
    for tag in tags:
        max_p = min(len(tag) - 1, len(lower))
        for p in range(max_p, hold, -1):
            if lower.endswith(tag[:p]):
                hold = p
                break
    return len(s) - hold


class ThinkingStreamFilter:
    """Chunk-boundary-safe incremental filter for streaming LLM output.

    Suppresses ``<think>...</think>``, ``<thinking>...</thinking>``,
    ``<reasoning>...</reasoning>``, and ``◁think▷...◁/think▷`` blocks even when
    tag delimiters are split arbitrarily across stream chunks.

    JSON tool-call envelopes emitted after (or without) thinking blocks pass
    through intact. When a chunk stream starts with ``{`` or ``[`` (a raw JSON
    tool-call envelope), thinking tags inside JSON string values are preserved.
    """

    def __init__(self) -> None:
        self._in_thinking: bool = False
        self._pending: str = ""
        self._emitted_any: bool = False
        self._json_depth: int = 0
        self._in_json_string: bool = False
        self._json_escape: bool = False
        self._in_json_envelope: bool = False

    def _consume_json_char(self, ch: str) -> None:
        if self._in_json_string:
            if self._json_escape:
                self._json_escape = False
            elif ch == "\\":
                self._json_escape = True
            elif ch == '"':
                self._in_json_string = False
            return
        if ch == '"':
            self._in_json_string = True
        elif ch in "{[":
            self._json_depth += 1
        elif ch in "}]":
            self._json_depth = max(0, self._json_depth - 1)
            if self._json_depth == 0:
                self._in_json_envelope = False

    def push(self, chunk: str) -> str:
        """Feed one streamed delta and return only display-safe text."""
        if not chunk:
            return ""
        self._pending += chunk
        out_parts: list[str] = []

        while self._pending:
            if self._in_json_envelope:
                # Emit characters while tracking balanced JSON structure so
                # literal "<think>" inside a JSON tool argument is never stripped.
                emitted_chars: list[str] = []
                idx = 0
                while idx < len(self._pending) and self._in_json_envelope:
                    ch = self._pending[idx]
                    emitted_chars.append(ch)
                    self._consume_json_char(ch)
                    idx += 1
                self._pending = self._pending[idx:]
                if emitted_chars:
                    self._emitted_any = True
                    out_parts.append("".join(emitted_chars))
                continue

            if self._in_thinking:
                c_idx, c_len = _find_first_tag(self._pending, THINK_CLOSE_TAGS)
                if c_idx < 0:
                    safe = _safe_prefix_length(self._pending, THINK_CLOSE_TAGS)
                    self._pending = self._pending[safe:]
                    break
                self._pending = self._pending[c_idx + c_len :].lstrip()
                self._in_thinking = False
                continue

            # Detect start of a raw JSON tool-call envelope right at message start
            # or right after a closed thinking block.
            stripped_lead = self._pending.lstrip()
            if stripped_lead and stripped_lead[0] in "{[" and not self._emitted_any:
                lead_ws = len(self._pending) - len(stripped_lead)
                if lead_ws > 0:
                    out_parts.append(self._pending[:lead_ws])
                    self._pending = stripped_lead
                self._in_json_envelope = True
                self._json_depth = 0
                self._in_json_string = False
                self._json_escape = False
                continue

            o_idx, o_len = _find_first_tag(self._pending, THINK_OPEN_TAGS)
            c_idx, c_len = _find_first_tag(self._pending, THINK_CLOSE_TAGS)
            open_first = o_idx >= 0 and (c_idx < 0 or o_idx <= c_idx)
            next_idx, next_len = (o_idx, o_len) if open_first else (c_idx, c_len)

            if next_idx < 0:
                safe = _safe_prefix_length(self._pending, ALL_THINK_TAGS)
                if safe > 0:
                    segment = self._pending[:safe]
                    if segment.strip():
                        self._emitted_any = True
                    out_parts.append(segment)
                    self._pending = self._pending[safe:]
                break

            if next_idx > 0:
                segment = self._pending[:next_idx]
                if segment.strip():
                    self._emitted_any = True
                out_parts.append(segment)
            self._pending = self._pending[next_idx + next_len :]
            if open_first:
                self._in_thinking = True
            else:
                self._pending = self._pending.lstrip()

        return "".join(out_parts)

    def flush(self) -> str:
        """Flush buffered tail at end of stream."""
        out = "" if self._in_thinking else self._pending
        self._pending = ""
        self._in_thinking = False
        self._in_json_envelope = False
        self._json_depth = 0
        self._in_json_string = False
        self._json_escape = False
        return out


__all__ = [
    "ALL_THINK_TAGS",
    "THINK_CLOSE_TAGS",
    "THINK_OPEN_TAGS",
    "ThinkingStreamFilter",
    "strip_thinking_tags",
]
