"""Tool-call reconciliation and synthetic error responses for interrupted turns.

Adapted from PentesterFlow/agent ``src/agent/agent.ts``
(``reconcileToolCalls`` & ``synthesizeUnansweredToolResults``;
commit ``0759d873a07350a70283c9751f7d136905f777c7``, licensed under Apache-2.0;
see ``THIRD_PARTY_LICENSES/PENTESTERFLOW_APACHE2.txt`` and ``NOTICE``).
"""
from __future__ import annotations

import copy
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set

SYNTHETIC_INTERRUPTED_ERROR = (
    "ERROR: tool call did not complete (the turn was interrupted before this tool produced a result)."
)


def _get_tool_calls(msg: Dict[str, Any]) -> List[Dict[str, Any]]:
    raw = msg.get("tool_calls")
    if raw is None:
        raw = msg.get("toolCalls")
    if isinstance(raw, list):
        return [tc for tc in raw if isinstance(tc, dict)]
    return []


def _get_tool_call_id(msg_or_tc: Dict[str, Any]) -> str:
    val = (
        msg_or_tc.get("tool_call_id")
        if "tool_call_id" in msg_or_tc
        else msg_or_tc.get("toolCallID", msg_or_tc.get("id", ""))
    )
    return "" if val is None else str(val)


def _get_tool_call_name(tc: Dict[str, Any]) -> Optional[str]:
    fn = tc.get("function")
    if isinstance(fn, dict) and fn.get("name"):
        return str(fn["name"])
    if tc.get("name"):
        return str(tc["name"])
    return None


def synthesize_unanswered_tool_results(
    tool_calls: Sequence[Dict[str, Any]],
    answered_ids: Iterable[str],
    *,
    error_message: str = SYNTHETIC_INTERRUPTED_ERROR,
    working: Optional[List[Dict[str, Any]]] = None,
) -> List[Dict[str, Any]]:
    """Build synthetic ``role='tool'`` error messages for every unanswered tool call.

    Also repairs calls whose ``id`` is missing or empty so strict OpenAI/Anthropic/
    Gemini wire validators never reject a resumed conversation with HTTP 400.
    If ``working`` is provided, appends synthesized messages to ``working`` as well.
    """
    answered: Set[str] = {str(x) for x in answered_ids}
    synthesized: List[Dict[str, Any]] = []
    for tc in tool_calls:
        tc_id = _get_tool_call_id(tc)
        if tc_id in answered:
            continue
        msg: Dict[str, Any] = {
            "role": "tool",
            "tool_call_id": tc_id,
            "content": error_message,
        }
        name = _get_tool_call_name(tc)
        if name:
            msg["name"] = name
        synthesized.append(msg)
        answered.add(tc_id)
        if working is not None:
            working.append(msg)
    return synthesized


def reconcile_tool_calls(messages: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Repair dangling assistant ``tool_calls`` without mutating the input list.

    Every ``assistant`` message containing ``tool_calls`` MUST be immediately
    followed by a ``role='tool'`` message for every emitted call ID before the
    next user/assistant turn. Returns a deep-enough repaired copy; acts as a
    clean copy when nothing is dangling.
    """
    out: List[Dict[str, Any]] = []
    n = len(messages)
    i = 0
    while i < n:
        msg = messages[i]
        if not isinstance(msg, dict):
            i += 1
            continue
        out.append(copy.deepcopy(msg))

        tool_calls = _get_tool_calls(msg)
        if msg.get("role") != "assistant" or not tool_calls:
            i += 1
            continue

        answered: Set[str] = set()
        j = i + 1
        while j < n:
            nxt = messages[j]
            if not isinstance(nxt, dict) or nxt.get("role") != "tool":
                break
            tid = _get_tool_call_id(nxt)
            answered.add(tid)
            out.append(copy.deepcopy(nxt))
            j += 1

        missing = synthesize_unanswered_tool_results(tool_calls, answered)
        out.extend(missing)
        i = j

    return out


__all__ = [
    "SYNTHETIC_INTERRUPTED_ERROR",
    "reconcile_tool_calls",
    "synthesize_unanswered_tool_results",
]
