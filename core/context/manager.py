"""Canonical HunterAI Context Manager — Unified Entrypoint for AST Budgeting, Compaction & Offloading.

Replaces brittle ``json.dumps(...)[:N]`` slicing with structured field-budget
compaction, rune-safe truncation, AST chain compaction, and scrubbed tool offload.
"""
from __future__ import annotations

import copy
import json
import logging
from pathlib import Path
import re
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

from core.context.chain_ast import (
    ChainAST,
    calculate_message_size,
    chain_byte_budget,
    chain_fits_window,
)
from core.context.compaction import (
    CompactionCircuitBreaker,
    CompactionResult,
    SessionMemory,
    SummarizeFn,
    compact_chain,
    guard_working_context,
    microcompact_messages,
)
from core.context.reconcile import reconcile_tool_calls, synthesize_unanswered_tool_results
from core.context.token_accountant import TokenAccountant, estimate_message_tokens
from core.context.tool_offload import (
    OFFLOAD_CHAR_THRESHOLD,
    OFFLOAD_PREVIEW_CHARS,
    OffloadResult,
    maybe_offload_tool_result,
)
from core.context.truncate import (
    HeadTailBuffer,
    strip_control_sequences,
    truncate_result,
)
from core.secret_sanitizer import SecretSanitizer

logger = logging.getLogger("hunter_ai.context.manager")

HEADERS_TO_STRIP: Set[str] = {
    "connection",
    "keep-alive",
    "accept-encoding",
    "accept-language",
    "upgrade-insecure-requests",
    "sec-ch-ua",
    "sec-ch-ua-mobile",
    "sec-ch-ua-platform",
    "sec-fetch-dest",
    "sec-fetch-mode",
    "sec-fetch-site",
    "sec-fetch-user",
    "pragma",
    "cache-control",
}

_STATIC_ASSET_RE = re.compile(r"\.(css|png|jpg|jpeg|gif|svg|woff2?|ico)$", re.IGNORECASE)


def compress_http_headers(headers: Dict[str, str]) -> Dict[str, str]:
    """Strip low-signal transport/client-hint HTTP headers."""
    return {k: v for k, v in (headers or {}).items() if str(k).lower() not in HEADERS_TO_STRIP}


def deduplicate_endpoints(endpoints: Sequence[str]) -> List[str]:
    """Deduplicate endpoints by normalized path and drop static asset noise."""
    seen: Set[str] = set()
    clean_list: List[str] = []
    for ep in endpoints or ():
        s = str(ep or "")
        base = s.split("?", 1)[0]
        if _STATIC_ASSET_RE.search(base):
            continue
        if base not in seen:
            seen.add(base)
            clean_list.append(s)
    return clean_list


def compress_response_body(
    body: str,
    *,
    max_chars: int = 2000,
    reflection_marker: Optional[str] = None,
) -> str:
    """Compress oversized HTTP bodies with control stripping and rune-safe truncation."""
    if not body:
        return ""
    cleaned = strip_control_sequences(body)
    if len(cleaned) <= max_chars:
        return cleaned

    if reflection_marker and reflection_marker in cleaned:
        idx = cleaned.find(reflection_marker)
        half = max(200, (max_chars - len(reflection_marker)) // 2)
        start = max(0, idx - half)
        end = min(len(cleaned), idx + len(reflection_marker) + half)
        return (
            f"[SNIPPED_HEAD: {start} chars]...\n"
            f"{cleaned[start:end]}\n"
            f"...[SNIPPED_TAIL: {len(cleaned) - end} chars]"
        )

    return truncate_result(cleaned, max_half_bytes=max(128, max_chars // 2))


def _trim_structured_value(val: Any, *, max_str_bytes: int, max_list_items: int, depth: int = 0) -> Any:
    """Recursively shrink strings/lists inside a JSON object without breaking JSON validity."""
    if depth > 8:
        return "[nested structure omitted]"
    if isinstance(val, str):
        cleaned = strip_control_sequences(val)
        if len(cleaned.encode("utf-8")) <= max_str_bytes:
            return cleaned
        return truncate_result(cleaned, max_half_bytes=max(64, max_str_bytes // 2))
    if isinstance(val, list):
        kept = [
            _trim_structured_value(item, max_str_bytes=max_str_bytes, max_list_items=max_list_items, depth=depth + 1)
            for item in val[:max_list_items]
        ]
        if len(val) > max_list_items:
            kept.append({"_omitted_items": len(val) - max_list_items})
        return kept
    if isinstance(val, dict):
        return {
            str(k): _trim_structured_value(
                v,
                max_str_bytes=max_str_bytes,
                max_list_items=max_list_items,
                depth=depth + 1,
            )
            for k, v in val.items()
        }
    return val


class ContextManager:
    """Canonical stateful + utility context manager for HunterAI agents and Copilot."""

    def __init__(
        self,
        *,
        context_window: int = 16384,
        offload_dir: Optional[str | Path] = None,
    ) -> None:
        self.context_window = max(2048, int(context_window))
        self.offload_dir = Path(offload_dir) if offload_dir is not None else None
        self.accountant = TokenAccountant()
        self.circuit_breaker = CompactionCircuitBreaker()
        self.session_memory = SessionMemory()

    @classmethod
    def estimate_tokens(cls, text_or_data: Any) -> int:
        if isinstance(text_or_data, str):
            return max(1, len(text_or_data.encode("utf-8")) // 4) if text_or_data else 0
        if isinstance(text_or_data, (dict, list)):
            dumped = json.dumps(text_or_data, default=str)
            return max(1, len(dumped.encode("utf-8")) // 4)
        return estimate_message_tokens(text_or_data)

    def offload_tool_output(
        self,
        tool_call_id: str,
        tool_name: str,
        result: str,
        *,
        offload_dir: Optional[str | Path] = None,
    ) -> OffloadResult:
        return maybe_offload_tool_result(
            offload_dir or self.offload_dir,
            tool_call_id,
            tool_name,
            result,
        )

    def prepare_messages(
        self,
        messages: Sequence[Dict[str, Any]],
        *,
        tools: Optional[Sequence[Any]] = None,
        window: Optional[int] = None,
        summarizer: Optional[SummarizeFn] = None,
    ) -> CompactionResult:
        """Reconcile, budget, and 2-stage AST-compact ``messages`` for LLM dispatch."""
        eff_window = window if window is not None else self.context_window
        res = compact_chain(
            messages,
            eff_window,
            tools=tools,
            summarizer=summarizer,
            circuit_breaker=self.circuit_breaker,
            session_memory=self.session_memory,
        )
        if res.session_memory is not None:
            self.session_memory = res.session_memory
        self.accountant.recompute(res.messages)
        return res

    @classmethod
    def prepare_compact_task_context(
        cls,
        raw_payload: Dict[str, Any],
        max_token_budget: int = 8000,
    ) -> Dict[str, Any]:
        """Compress a task payload while ALWAYS returning a valid structured dict.

        Eliminates legacy ``json.dumps(compact)[:N]`` JSON corruption by
        progressively shrinking fields and lists structurally until the
        serialized object fits inside ``max_token_budget``.
        """
        compact = copy.deepcopy(raw_payload) if isinstance(raw_payload, dict) else {"value": raw_payload}

        if "headers" in compact and isinstance(compact["headers"], dict):
            compact["headers"] = compress_http_headers(compact["headers"])

        if "endpoints" in compact and isinstance(compact["endpoints"], list):
            compact["endpoints"] = deduplicate_endpoints(compact["endpoints"])

        if "response_body" in compact and isinstance(compact["response_body"], str):
            marker = compact.get("canary_marker")
            compact["response_body"] = compress_response_body(
                compact["response_body"],
                max_chars=3000,
                reflection_marker=str(marker) if marker else None,
            )

        budget = max(64, int(max_token_budget))
        if cls.estimate_tokens(compact) <= budget:
            return compact

        # Progressively shrink nested string & list fields structurally so JSON
        # structure is ALWAYS preserved and parseable.
        for str_cap, list_cap in ((2048, 40), (1024, 20), (512, 10), (256, 5), (128, 3)):
            candidate = _trim_structured_value(compact, max_str_bytes=str_cap, max_list_items=list_cap)
            if cls.estimate_tokens(candidate) <= budget:
                candidate["_context_compacted"] = True
                return candidate
            compact = candidate

        # Final structured fallback: retain high-priority keys + sanitized summary
        # (valid dict, never truncated raw JSON string).
        max_bytes = budget * 4
        compact_out: Dict[str, Any] = {"_context_compacted": True}
        used_bytes = len(json.dumps(compact_out).encode("utf-8"))
        for k, v in compact.items():
            if k == "_context_compacted":
                continue
            item_val = _trim_structured_value(v, max_str_bytes=128, max_list_items=3)
            entry_bytes = len(json.dumps({k: item_val}, default=str).encode("utf-8"))
            if used_bytes + entry_bytes <= max_bytes:
                compact_out[k] = item_val
                used_bytes += entry_bytes
            else:
                compact_out.setdefault("_omitted_keys", []).append(k)
        return compact_out


__all__ = [
    "ContextManager",
    "HEADERS_TO_STRIP",
    "compress_http_headers",
    "compress_response_body",
    "deduplicate_endpoints",
]
