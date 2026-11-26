"""UTF-8 rune-safe truncation, bounded HeadTailBuffer, and control-sequence scrubbing.

Adapted from:
- vxcontrol/pentagi ``backend/pkg/tools/executor.go`` (``truncateResult``)
  (commit ``cffed9485aa1cca70762cd08a57ac62a80406258``, licensed under MIT;
  see ``THIRD_PARTY_LICENSES/PENTAGI_MIT.txt`` and ``NOTICE``).
- PentesterFlow/agent ``src/tools/shell.ts`` (``HeadTailBuffer``) and
  ``src/ui/toolResultFormat.ts`` (``stripControlSequences``)
  (commit ``0759d873a07350a70283c9751f7d136905f777c7``, licensed under Apache-2.0;
  see ``THIRD_PARTY_LICENSES/PENTESTERFLOW_APACHE2.txt`` and ``NOTICE``).
"""
from __future__ import annotations

from collections import deque
import re
from typing import Deque, Union

#: Default head/tail half-size in UTF-8 bytes for ``truncate_result``.
DEFAULT_RESULT_SIZE_LIMIT: int = 16 * 1024

# ANSI ESC-introduced sequences (OSC, CSI, single-char ESC), C1 controls, and C0 except \n and \t.
_ESC_SEQUENCE_RE = re.compile(
    r"\x1b(?:\][^\x07\x1b]*(?:\x07|\x1b\\)|[\[\?][0-9;:?]*[a-zA-Z]|[@-Z\\-_])"
)
_C1_CONTROL_RE = re.compile(r"\x9b[0-?]*[ -/]*[@-~]|\x9d[^\x9c]*(?:\x9c|$)|[\x80-\x9f]")
_OTHER_CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def strip_control_sequences(text: str) -> str:
    """Strip ANSI/OSC escape sequences (OSC 52/0/2/8, CSI) and unsafe control bytes.

    Preserves ``\\n`` and ``\\t`` for readable output while blocking terminal
    spoofing, clipboard injection, and hidden-character obfuscation.
    """
    if not text:
        return ""
    cleaned = _ESC_SEQUENCE_RE.sub("", text)
    cleaned = _C1_CONTROL_RE.sub("", cleaned)
    cleaned = _OTHER_CONTROL_RE.sub("", cleaned)
    return cleaned


def _is_utf8_continuation(byte_val: int) -> bool:
    return 0x80 <= byte_val < 0xC0


def _decode_utf8_head(buf: bytes) -> str:
    """Decode UTF-8 bytes whose end may fall mid-codepoint without emitting U+FFFD."""
    end = len(buf)
    if end == 0:
        return ""
    # Walk back over any incomplete trailing multi-byte sequence.
    start_of_last = end - 1
    while start_of_last > 0 and _is_utf8_continuation(buf[start_of_last]):
        start_of_last -= 1
    lead = buf[start_of_last]
    expected_len = 1
    if lead < 0x80:
        expected_len = 1
    elif (lead & 0xE0) == 0xC0:
        expected_len = 2
    elif (lead & 0xF0) == 0xE0:
        expected_len = 3
    elif (lead & 0xF8) == 0xF0:
        expected_len = 4
    else:
        # Invalid trailing lead byte — drop it
        return buf[:start_of_last].decode("utf-8", errors="ignore")
    if end - start_of_last < expected_len:
        end = start_of_last
    return buf[:end].decode("utf-8", errors="ignore")


def _decode_utf8_tail(buf: bytes) -> str:
    """Decode UTF-8 bytes whose start may fall mid-codepoint without emitting U+FFFD."""
    start = 0
    n = len(buf)
    while start < n and start < 3 and _is_utf8_continuation(buf[start]):
        start += 1
    return buf[start:].decode("utf-8", errors="ignore")


def truncate_result(
    result: str,
    *,
    max_half_bytes: int = DEFAULT_RESULT_SIZE_LIMIT,
) -> str:
    """UTF-8 rune-safe head+tail truncation on valid character boundaries.

    Never splits a multi-byte UTF-8 rune (e.g. Arabic, CJK, emoji). When the
    encoded byte length exceeds ``max_half_bytes * 2``, retains valid UTF-8 head
    and tail slices with an explicit byte-range omission marker.
    """
    if not result:
        return ""
    limit = max(16, int(max_half_bytes))
    raw = result.encode("utf-8")
    total = len(raw)
    if total <= limit * 2:
        return result

    head = limit
    while head > 0 and _is_utf8_continuation(raw[head]):
        head -= 1

    tail = total - limit
    while tail < total and _is_utf8_continuation(raw[tail]):
        tail += 1

    head_text = raw[:head].decode("utf-8", errors="strict")
    tail_text = raw[tail:].decode("utf-8", errors="strict")
    return (
        f"{head_text}\n"
        f"[0:{head} bytes]\n"
        f"... [truncated] ...\n"
        f"[{tail}:{total} bytes]\n"
        f"{tail_text}"
    )


class HeadTailBuffer:
    """Bounded UTF-8 byte buffer retaining the first half and last half of a stream.

    Memory usage stays bounded to ``~cap`` bytes plus one chunk regardless of
    total stream length, and elision always falls cleanly on UTF-8 rune boundaries.
    """

    def __init__(self, cap: int) -> None:
        self.cap = max(2, int(cap))
        self._half = self.cap // 2
        self._head: list[bytes] = []
        self._head_len: int = 0
        self._tail: Deque[bytes] = deque()
        self._tail_len: int = 0
        self._total: int = 0

    @property
    def total_bytes(self) -> int:
        return self._total

    def push(self, chunk: Union[bytes, bytearray, str]) -> None:
        """Append raw bytes (or UTF-8 str) into the bounded head/tail buffer."""
        raw = chunk.encode("utf-8") if isinstance(chunk, str) else bytes(chunk)
        if not raw:
            return
        self._total += len(raw)
        rest = raw
        if self._head_len < self._half:
            room = self._half - self._head_len
            if len(rest) <= room:
                self._head.append(rest)
                self._head_len += len(rest)
                return
            self._head.append(rest[:room])
            self._head_len += room
            rest = rest[room:]

        self._tail.append(rest)
        self._tail_len += len(rest)
        while len(self._tail) > 1 and (self._tail_len - len(self._tail[0])) >= self._half:
            dropped = self._tail.popleft()
            self._tail_len -= len(dropped)

    def render(self) -> str:
        """Render the retained head + truncation notice + tail as valid UTF-8 text."""
        head_buf = b"".join(self._head)
        tail_full = b"".join(self._tail)
        tail_buf = tail_full[-self._half :] if len(tail_full) > self._half else tail_full
        retained = len(head_buf) + len(tail_buf)
        if self._total <= retained:
            return (head_buf + tail_buf).decode("utf-8", errors="replace")
        head_str = _decode_utf8_head(head_buf)
        tail_str = _decode_utf8_tail(tail_buf)
        dropped = self._total - retained
        return f"{head_str}\n[... truncated {dropped} bytes ...]\n{tail_str}"


__all__ = [
    "DEFAULT_RESULT_SIZE_LIMIT",
    "HeadTailBuffer",
    "strip_control_sequences",
    "truncate_result",
]
