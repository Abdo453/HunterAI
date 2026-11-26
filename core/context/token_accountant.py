"""Incremental token estimation and cumulative provider usage bookkeeping.

Adapted from PentesterFlow/agent ``src/agent/tokenAccountant.ts``
(commit ``0759d873a07350a70283c9751f7d136905f777c7``, licensed under Apache-2.0;
see ``THIRD_PARTY_LICENSES/PENTESTERFLOW_APACHE2.txt`` and ``NOTICE``).
"""
from __future__ import annotations

from dataclasses import dataclass
import json
from typing import Any, Dict, Optional, Sequence


@dataclass
class UsageTotals:
    """Cumulative actual provider-reported token usage."""

    input_tokens: int = 0
    output_tokens: int = 0
    cached_input_tokens: int = 0
    calls: int = 0

    def copy(self) -> "UsageTotals":
        return UsageTotals(
            input_tokens=self.input_tokens,
            output_tokens=self.output_tokens,
            cached_input_tokens=self.cached_input_tokens,
            calls=self.calls,
        )

    def to_dict(self) -> Dict[str, int]:
        return {
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
            "cached_input_tokens": self.cached_input_tokens,
            "total_tokens": self.input_tokens + self.output_tokens,
            "calls": self.calls,
        }


def estimate_message_tokens(message: Any) -> int:
    """Estimate token count for one message (~4 UTF-8 bytes per token)."""
    if isinstance(message, str):
        return len(message.encode("utf-8")) // 4
    if not isinstance(message, dict):
        content = getattr(message, "content", "")
        return len(str(content or "").encode("utf-8")) // 4

    total = len(str(message.get("content") or "").encode("utf-8")) // 4
    tool_calls = message.get("tool_calls") or message.get("toolCalls") or []
    for tc in tool_calls:
        if not isinstance(tc, dict):
            continue
        fn = tc.get("function") if isinstance(tc.get("function"), dict) else tc
        name = str(fn.get("name") or "")
        args = fn.get("arguments") or fn.get("args") or ""
        if not isinstance(args, str):
            args = json.dumps(args, default=str)
        total += len((name + args).encode("utf-8")) // 4
    return total


class TokenAccountant:
    """Tracks incremental history token estimates alongside actual backend usage."""

    def __init__(self) -> None:
        self._token_count: int = 0
        self._tools_tokens_cache: int = 0
        self._tools_tokens_key: int = -1
        self._usage = UsageTotals()

    def approx_tokens(self) -> int:
        return self._token_count

    def get_usage(self) -> UsageTotals:
        return self._usage.copy()

    def account_usage(
        self,
        *,
        input_tokens: int = 0,
        output_tokens: int = 0,
        cached_input_tokens: int = 0,
    ) -> None:
        self._usage.input_tokens += max(0, int(input_tokens))
        self._usage.output_tokens += max(0, int(output_tokens))
        self._usage.cached_input_tokens += max(0, int(cached_input_tokens))
        self._usage.calls += 1

    def recompute(self, history: Sequence[Any]) -> int:
        self._token_count = sum(estimate_message_tokens(m) for m in history)
        return self._token_count

    def account_for_push(self, message: Any) -> int:
        delta = estimate_message_tokens(message)
        self._token_count += delta
        return self._token_count

    def tools_token_estimate(self, tools: Optional[Sequence[Any]]) -> int:
        if not tools:
            return 0
        key = len(tools)
        if key != self._tools_tokens_key:
            try:
                serialized = json.dumps(list(tools), default=str)
                self._tools_tokens_cache = len(serialized.encode("utf-8")) // 4
            except (TypeError, ValueError):
                self._tools_tokens_cache = 0
            self._tools_tokens_key = key
        return self._tools_tokens_cache


__all__ = [
    "TokenAccountant",
    "UsageTotals",
    "estimate_message_tokens",
]
